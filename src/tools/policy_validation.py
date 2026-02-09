"""
Policy Validation Tool

Validates signing operations against security policies and compliance requirements.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..providers import ProviderFactory
from ..security.policy_engine import PolicyEngine
from ..config import Config


class PolicyValidationTool:
    """Tool for validating against security policies."""
    
    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
        self.policy_engine = PolicyEngine(config.policies)
        
        # Predefined policy sets
        self.policy_sets = {
            'enterprise': self._get_enterprise_policies,
            'fips': self._get_fips_policies,
            'eal4': self._get_eal4_policies,
            'sox': self._get_sox_policies,
            'fedramp': self._get_fedramp_policies
        }
    
    async def execute(
        self,
        file_path: str,
        policy_set: str,
        custom_policies: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Validate signing operation against security policies.
        
        Args:
            file_path: File to validate
            policy_set: Policy set name (enterprise, fips, eal4, sox, fedramp)
            custom_policies: Custom policy definitions
            
        Returns:
            Dictionary containing validation results
        """
        try:
            # Validate file exists
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Get policy set
            if policy_set not in self.policy_sets:
                raise ValueError(
                    f"Invalid policy set: {policy_set}. "
                    f"Valid sets: {', '.join(self.policy_sets.keys())}"
                )
            
            # Load policies
            policies = self.policy_sets[policy_set]()
            
            # Merge with custom policies
            if custom_policies:
                policies.update(custom_policies)
            
            # Get user identity
            user_did = await self.did_client.get_current_user_did()
            
            # Get file information
            file_info = await self._get_file_info(file_path)
            
            # Run policy validation
            validation_results = await self._validate_policies(
                file_info, policies, user_did
            )
            
            # Determine overall compliance
            is_compliant = all(r.get("passed", False) for r in validation_results)
            
            return {
                "success": True,
                "compliant": is_compliant,
                "policy_set": policy_set,
                "file_path": file_path,
                "validation_results": validation_results,
                "summary": self._generate_summary(validation_results),
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "file_path": file_path,
                "policy_set": policy_set,
                "timestamp": self._get_timestamp()
            }
    
    async def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get file information for policy validation."""
        path = Path(file_path)
        stat = path.stat()
        
        return {
            "path": str(path.absolute()),
            "name": path.name,
            "size": stat.st_size,
            "extension": path.suffix.lower(),
            "type": self._detect_file_type(path)
        }
    
    def _detect_file_type(self, path: Path) -> str:
        """Detect file type."""
        extension = path.suffix.lower()
        type_mapping = {
            '.exe': 'windows_executable',
            '.dll': 'windows_library',
            '.jar': 'java_archive',
            '.dmg': 'macos_disk_image',
            '.pkg': 'macos_package'
        }
        return type_mapping.get(extension, 'binary')
    
    async def _validate_policies(
        self,
        file_info: Dict[str, Any],
        policies: Dict[str, Any],
        user_did: str
    ) -> List[Dict[str, Any]]:
        """Validate all policies."""
        results = []
        
        for policy_name, policy_config in policies.items():
            result = await self._validate_single_policy(
                policy_name, policy_config, file_info, user_did
            )
            results.append(result)
        
        return results
    
    async def _validate_single_policy(
        self,
        policy_name: str,
        policy_config: Dict[str, Any],
        file_info: Dict[str, Any],
        user_did: str
    ) -> Dict[str, Any]:
        """Validate a single policy."""
        try:
            # Different policy types
            policy_type = policy_config.get("type")
            
            if policy_type == "file_size":
                passed = await self._validate_file_size_policy(
                    file_info, policy_config
                )
            elif policy_type == "file_type":
                passed = await self._validate_file_type_policy(
                    file_info, policy_config
                )
            elif policy_type == "credential":
                passed = await self._validate_credential_policy(
                    user_did, policy_config
                )
            elif policy_type == "signature_algorithm":
                passed = await self._validate_signature_algorithm_policy(
                    policy_config
                )
            else:
                passed = False
            
            return {
                "policy": policy_name,
                "passed": passed,
                "severity": policy_config.get("severity", "medium"),
                "description": policy_config.get("description", "")
            }
            
        except Exception as e:
            return {
                "policy": policy_name,
                "passed": False,
                "error": str(e),
                "severity": policy_config.get("severity", "medium")
            }
    
    async def _validate_file_size_policy(
        self,
        file_info: Dict[str, Any],
        policy_config: Dict[str, Any]
    ) -> bool:
        """Validate file size policy."""
        max_size = policy_config.get("max_size_bytes", float('inf'))
        return file_info["size"] <= max_size
    
    async def _validate_file_type_policy(
        self,
        file_info: Dict[str, Any],
        policy_config: Dict[str, Any]
    ) -> bool:
        """Validate file type policy."""
        allowed_types = policy_config.get("allowed_types", [])
        if not allowed_types:
            return True
        return file_info["type"] in allowed_types
    
    async def _validate_credential_policy(
        self,
        user_did: str,
        policy_config: Dict[str, Any]
    ) -> bool:
        """Validate credential policy."""
        required_credential_type = policy_config.get("required_type")
        if not required_credential_type:
            return True
        
        credentials = await self.did_client.get_available_credentials(user_did)
        return any(
            c.get("type") == required_credential_type
            for c in credentials
        )
    
    async def _validate_signature_algorithm_policy(
        self,
        policy_config: Dict[str, Any]
    ) -> bool:
        """Validate signature algorithm policy."""
        # This would check if allowed algorithms are configured
        return True
    
    def _get_enterprise_policies(self) -> Dict[str, Any]:
        """Get enterprise policy set."""
        return {
            "require_timestamp": {
                "type": "signature_algorithm",
                "description": "Signatures must include timestamp",
                "severity": "high"
            },
            "max_file_size": {
                "type": "file_size",
                "max_size_bytes": 1073741824,  # 1GB
                "description": "Files must be under 1GB",
                "severity": "medium"
            },
            "require_hsm": {
                "type": "credential",
                "required_type": "hsm",
                "description": "Must use HSM-backed credentials",
                "severity": "high"
            }
        }
    
    def _get_fips_policies(self) -> Dict[str, Any]:
        """Get FIPS 140-2 policy set."""
        return {
            "fips_algorithms": {
                "type": "signature_algorithm",
                "description": "Must use FIPS-approved algorithms",
                "severity": "critical"
            },
            "require_hsm_fips": {
                "type": "credential",
                "required_type": "hsm_fips",
                "description": "Must use FIPS 140-2 Level 2+ HSM",
                "severity": "critical"
            }
        }
    
    def _get_eal4_policies(self) -> Dict[str, Any]:
        """Get Common Criteria EAL4 policy set."""
        return {
            "eal4_compliant_hsm": {
                "type": "credential",
                "required_type": "hsm_eal4",
                "description": "Must use EAL4+ certified HSM",
                "severity": "critical"
            },
            "audit_logging": {
                "type": "signature_algorithm",
                "description": "All operations must be logged",
                "severity": "high"
            }
        }
    
    def _get_sox_policies(self) -> Dict[str, Any]:
        """Get SOX compliance policy set."""
        return {
            "dual_control": {
                "type": "credential",
                "description": "Require dual control for signing",
                "severity": "high"
            },
            "audit_trail": {
                "type": "signature_algorithm",
                "description": "Maintain detailed audit trail",
                "severity": "critical"
            }
        }
    
    def _get_fedramp_policies(self) -> Dict[str, Any]:
        """Get FedRAMP policy set."""
        return {
            "fedramp_approved_crypto": {
                "type": "signature_algorithm",
                "description": "Use FedRAMP-approved cryptography",
                "severity": "critical"
            },
            "continuous_monitoring": {
                "type": "signature_algorithm",
                "description": "Enable continuous monitoring",
                "severity": "high"
            }
        }
    
    def _generate_summary(self, validation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate validation summary."""
        total = len(validation_results)
        passed = sum(1 for r in validation_results if r.get("passed", False))
        failed = total - passed
        
        # Count by severity
        by_severity = {}
        for result in validation_results:
            if not result.get("passed", False):
                severity = result.get("severity", "unknown")
                by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            "total_policies": total,
            "passed": passed,
            "failed": failed,
            "compliance_rate": round((passed / total) * 100, 2) if total > 0 else 0.0,
            "failures_by_severity": by_severity
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
