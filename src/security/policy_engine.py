"""
Policy Engine

Implements security policy validation and credential selection logic
based on organizational policies and compliance requirements.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..config import PoliciesConfig


@dataclass
class PolicyResult:
    """Result of a policy evaluation."""
    allowed: bool
    reason: str
    warnings: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.metadata is None:
            self.metadata = {}


class PolicyEngine:
    """Engine for evaluating signing policies and making credential decisions."""
    
    def __init__(self, policies_config: PoliciesConfig):
        self.config = policies_config
        self.default_policy_set = policies_config.default_policy_set
        self.policy_sets = policies_config.policy_sets
    
    async def validate_signing_request(
        self,
        file_info: Dict[str, Any],
        credential: Dict[str, Any],
        user_did: str,
        policy_set_name: Optional[str] = None
    ) -> PolicyResult:
        """
        Validate a signing request against security policies.
        
        Args:
            file_info: Information about the file to be signed
            credential: Credential to be used for signing
            user_did: User's DID making the request
            policy_set_name: Override policy set to use
            
        Returns:
            PolicyResult indicating if the request is allowed
        """
        policy_set_name = policy_set_name or self.default_policy_set
        policy_set = self.policy_sets.get(policy_set_name)
        
        if not policy_set:
            return PolicyResult(
                allowed=False,
                reason=f"Unknown policy set: {policy_set_name}"
            )
        
        warnings = []
        metadata = {
            "policy_set": policy_set_name,
            "evaluated_policies": []
        }
        
        # 1. Validate file size
        max_file_size = getattr(policy_set, 'max_file_size', 100 * 1024 * 1024)  # 100MB default
        if file_info.get("size", 0) > max_file_size:
            return PolicyResult(
                allowed=False,
                reason=f"File size {file_info['size']} exceeds maximum {max_file_size} bytes"
            )
        metadata["evaluated_policies"].append("file_size")
        
        # 2. Validate file type
        file_type = file_info.get("type", "unknown")
        allowed_types = getattr(policy_set, 'allowed_file_types', None)
        if allowed_types and file_type not in allowed_types:
            return PolicyResult(
                allowed=False,
                reason=f"File type '{file_type}' not allowed by policy"
            )
        metadata["evaluated_policies"].append("file_type")
        
        # 3. Validate credential requirements
        credential_result = self._validate_credential_policy(credential, policy_set, file_info)
        if not credential_result.allowed:
            return credential_result
        warnings.extend(credential_result.warnings)
        metadata["evaluated_policies"].append("credential_validation")
        
        # 4. Validate algorithm requirements
        algorithm_result = self._validate_algorithm_policy(credential, policy_set)
        if not algorithm_result.allowed:
            return algorithm_result
        warnings.extend(algorithm_result.warnings)
        metadata["evaluated_policies"].append("algorithm_validation")
        
        # 5. Validate certificate chain requirements
        if policy_set.require_certificate_chain:
            if not credential.get("certificate_chain"):
                return PolicyResult(
                    allowed=False,
                    reason="Policy requires certificate chain but none provided"
                )
        metadata["evaluated_policies"].append("certificate_chain")
        
        # 6. Validate certificate age
        if policy_set.max_certificate_age_days:
            cert_age_result = self._validate_certificate_age(credential, policy_set.max_certificate_age_days)
            if not cert_age_result.allowed:
                return cert_age_result
            warnings.extend(cert_age_result.warnings)
        metadata["evaluated_policies"].append("certificate_age")
        
        # 7. Validate HSM requirements
        hsm_result = self._validate_hsm_requirements(credential, policy_set, file_info)
        if not hsm_result.allowed:
            return hsm_result
        warnings.extend(hsm_result.warnings)
        metadata["evaluated_policies"].append("hsm_requirements")
        
        # 8. Validate user authorization
        user_result = self._validate_user_authorization(user_did, credential, file_info)
        if not user_result.allowed:
            return user_result
        warnings.extend(user_result.warnings)
        metadata["evaluated_policies"].append("user_authorization")
        
        return PolicyResult(
            allowed=True,
            reason="All policy checks passed",
            warnings=warnings,
            metadata=metadata
        )
    
    def _validate_credential_policy(
        self,
        credential: Dict[str, Any],
        policy_set,
        file_info: Dict[str, Any]
    ) -> PolicyResult:
        """Validate credential against policy requirements."""
        
        warnings = []
        
        # Check if self-signed certificates are allowed
        if not policy_set.allow_self_signed:
            if credential.get("self_signed", False):
                return PolicyResult(
                    allowed=False,
                    reason="Self-signed certificates not allowed by policy"
                )
        
        # Check minimum key size
        key_size = credential.get("key_size", 0)
        if key_size < policy_set.min_key_size:
            return PolicyResult(
                allowed=False,
                reason=f"Key size {key_size} below minimum {policy_set.min_key_size}"
            )
        
        # Check credential type restrictions
        credential_type = credential.get("type", "unknown")
        if hasattr(policy_set, 'allowed_credential_types'):
            if credential_type not in policy_set.allowed_credential_types:
                return PolicyResult(
                    allowed=False,
                    reason=f"Credential type '{credential_type}' not allowed by policy"
                )
        
        return PolicyResult(allowed=True, reason="Credential validation passed", warnings=warnings)
    
    def _validate_algorithm_policy(self, credential: Dict[str, Any], policy_set) -> PolicyResult:
        """Validate cryptographic algorithms against policy."""
        
        warnings = []
        
        # Check signing algorithm
        signing_algorithm = credential.get("signing_algorithm", "SHA256")
        if signing_algorithm not in policy_set.allowed_algorithms:
            return PolicyResult(
                allowed=False,
                reason=f"Signing algorithm '{signing_algorithm}' not allowed by policy"
            )
        
        # Warn about deprecated algorithms
        deprecated_algorithms = ["MD5", "SHA1"]
        if signing_algorithm in deprecated_algorithms:
            warnings.append(f"Using deprecated algorithm: {signing_algorithm}")
        
        return PolicyResult(allowed=True, reason="Algorithm validation passed", warnings=warnings)
    
    def _validate_certificate_age(self, credential: Dict[str, Any], max_age_days: int) -> PolicyResult:
        """Validate certificate age."""
        
        from datetime import datetime, timezone
        
        warnings = []
        
        # Check certificate expiry
        expiry_date_str = credential.get("expires_at")
        if expiry_date_str:
            try:
                expiry_date = datetime.fromisoformat(expiry_date_str.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc)
                days_until_expiry = (expiry_date - now).days
                
                if days_until_expiry < 0:
                    return PolicyResult(
                        allowed=False,
                        reason="Certificate has expired"
                    )
                
                if days_until_expiry < 30:
                    warnings.append(f"Certificate expires in {days_until_expiry} days")
                
                # Check if certificate is older than max age
                issued_date_str = credential.get("issued_at")
                if issued_date_str:
                    issued_date = datetime.fromisoformat(issued_date_str.replace('Z', '+00:00'))
                    age_days = (now - issued_date).days
                    
                    if age_days > max_age_days:
                        return PolicyResult(
                            allowed=False,
                            reason=f"Certificate age {age_days} days exceeds maximum {max_age_days} days"
                        )
                
            except ValueError:
                warnings.append("Could not parse certificate dates")
        
        return PolicyResult(allowed=True, reason="Certificate age validation passed", warnings=warnings)
    
    def _validate_hsm_requirements(
        self,
        credential: Dict[str, Any],
        policy_set,
        file_info: Dict[str, Any]
    ) -> PolicyResult:
        """Validate HSM requirements."""
        
        warnings = []
        credential_type = credential.get("type", "software")
        file_type = file_info.get("type", "unknown")
        file_size = file_info.get("size", 0)
        
        # Check if HSM is required for all operations
        if getattr(policy_set, 'require_hsm', False):
            if credential_type != "hsm":
                return PolicyResult(
                    allowed=False,
                    reason="Policy requires HSM but credential is not HSM-based"
                )
        
        # Check if HSM is required for critical files
        if getattr(policy_set, 'require_hsm_for_critical', False):
            critical_file_types = ["exe", "msi", "dmg", "pkg", "deb", "rpm"]
            large_file_threshold = 50 * 1024 * 1024  # 50MB
            
            is_critical = (
                file_type in critical_file_types or
                file_size > large_file_threshold or
                "production" in file_info.get("name", "").lower()
            )
            
            if is_critical and credential_type != "hsm":
                return PolicyResult(
                    allowed=False,
                    reason=f"Policy requires HSM for critical files (type: {file_type}, size: {file_size})"
                )
        
        # Check FIPS compliance
        if getattr(policy_set, 'fips_140_2_compliance', False):
            if not credential.get("fips_compliant", False):
                return PolicyResult(
                    allowed=False,
                    reason="Policy requires FIPS 140-2 compliance but credential is not FIPS compliant"
                )
        
        return PolicyResult(allowed=True, reason="HSM validation passed", warnings=warnings)
    
    def _validate_user_authorization(
        self,
        user_did: str,
        credential: Dict[str, Any],
        file_info: Dict[str, Any]
    ) -> PolicyResult:
        """Validate user authorization for the signing operation."""
        
        warnings = []
        
        # Check if user is authorized to use this credential
        authorized_users = credential.get("authorized_users", [])
        if authorized_users and user_did not in authorized_users:
            return PolicyResult(
                allowed=False,
                reason=f"User {user_did} not authorized to use credential {credential.get('id')}"
            )
        
        # Check user permissions for file type
        # This would integrate with a user permissions system
        # For now, implement basic checks
        
        return PolicyResult(allowed=True, reason="User authorization passed", warnings=warnings)
    
    async def select_credential(
        self,
        available_credentials: List[Dict[str, Any]],
        artifact_type: str,
        file_info: Dict[str, Any],
        policy_set_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Select the best credential for signing based on policies and context.
        
        Args:
            available_credentials: List of available credentials
            artifact_type: Type of artifact being signed
            file_info: Information about the file
            policy_set_name: Policy set to apply
            
        Returns:
            Selected credential or None if no suitable credential found
        """
        policy_set_name = policy_set_name or self.default_policy_set
        policy_set = self.policy_sets.get(policy_set_name)
        
        if not policy_set:
            return None
        
        # Score credentials based on suitability
        scored_credentials = []
        
        for credential in available_credentials:
            score = 0
            
            # Prefer HSM for critical files
            if credential.get("type") == "hsm":
                score += 100
            
            # Prefer higher security levels
            security_level = credential.get("security_level", "standard")
            if security_level == "enterprise":
                score += 50
            elif security_level == "high":
                score += 30
            elif security_level == "standard":
                score += 10
            
            # Prefer credentials with longer validity
            try:
                from datetime import datetime, timezone
                expiry_str = credential.get("expires_at")
                if expiry_str:
                    expiry_date = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                    days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                    score += min(days_until_expiry // 30, 12)  # Max 12 points for 1+ year validity
            except:
                pass
            
            # Prefer credentials suitable for artifact type
            supported_types = credential.get("supported_artifact_types", [])
            if not supported_types or artifact_type in supported_types:
                score += 20
            
            # Apply policy-specific scoring
            if getattr(policy_set, 'require_hsm', False) and credential.get("type") != "hsm":
                score = 0  # Disqualify non-HSM
            
            if getattr(policy_set, 'fips_140_2_compliance', False) and not credential.get("fips_compliant", False):
                score = 0  # Disqualify non-FIPS
            
            if score > 0:
                scored_credentials.append((score, credential))
        
        # Return the highest scoring credential
        if scored_credentials:
            scored_credentials.sort(key=lambda x: x[0], reverse=True)
            return scored_credentials[0][1]
        
        return None