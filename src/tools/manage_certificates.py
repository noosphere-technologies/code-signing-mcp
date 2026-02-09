"""
Manage Certificates Tool

Handles certificate lifecycle operations: rotation, revocation, renewal, and installation.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..providers import ProviderFactory
from ..config import Config


class ManageCertificatesTool:
    """Tool for managing certificate lifecycle."""
    
    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
        
        self.operations = {
            'rotate': self._rotate_certificate,
            'revoke': self._revoke_certificate,
            'renew': self._renew_certificate,
            'install': self._install_certificate
        }
    
    async def execute(
        self,
        operation: str,
        credential_id: str,
        new_certificate: Optional[str] = None,
        revocation_reason: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Manage certificate lifecycle.
        
        Args:
            operation: Operation to perform (rotate, revoke, renew, install)
            credential_id: Target credential
            new_certificate: New certificate for installation
            revocation_reason: Reason for revocation
            
        Returns:
            Dictionary containing operation results
        """
        try:
            # Validate operation
            if operation not in self.operations:
                raise ValueError(
                    f"Invalid operation: {operation}. "
                    f"Valid operations: {', '.join(self.operations.keys())}"
                )
            
            # Get user identity
            user_did = await self.did_client.get_current_user_did()
            
            # Verify credential exists
            credential = await self.did_client.get_credential(user_did, credential_id)
            if not credential:
                raise ValueError(f"Credential not found: {credential_id}")
            
            # Execute operation
            handler = self.operations[operation]
            result = await handler(
                user_did, credential, new_certificate, revocation_reason
            )
            
            return {
                "success": True,
                "operation": operation,
                "credential_id": credential_id,
                "result": result,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "success": False,
                "operation": operation,
                "credential_id": credential_id,
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    async def _rotate_certificate(
        self,
        user_did: str,
        credential: Dict[str, Any],
        new_certificate: Optional[str],
        revocation_reason: Optional[str]
    ) -> Dict[str, Any]:
        """Rotate certificate to a new one."""
        if not new_certificate:
            raise ValueError("new_certificate is required for rotation")
        
        # Validate new certificate
        new_cert_info = await self._validate_certificate(new_certificate)
        
        # Install new certificate
        install_result = await self.did_client.install_certificate(
            user_did=user_did,
            credential_id=credential["id"],
            certificate_data=new_cert_info["certificate_data"],
            replace_existing=True
        )
        
        # Optionally revoke old certificate
        old_cert_revoked = False
        if revocation_reason:
            try:
                await self.did_client.revoke_certificate(
                    credential["id"],
                    reason=revocation_reason
                )
                old_cert_revoked = True
            except Exception:
                pass  # Continue even if revocation fails
        
        return {
            "new_certificate_installed": True,
            "new_certificate_fingerprint": new_cert_info["fingerprint"],
            "old_certificate_revoked": old_cert_revoked,
            "credential_updated": install_result["credential_id"],
            "details": "Certificate successfully rotated"
        }
    
    async def _revoke_certificate(
        self,
        user_did: str,
        credential: Dict[str, Any],
        new_certificate: Optional[str],
        revocation_reason: Optional[str]
    ) -> Dict[str, Any]:
        """Revoke a certificate."""
        reason = revocation_reason or "unspecified"
        
        # Perform revocation
        revocation_result = await self.did_client.revoke_certificate(
            credential_id=credential["id"],
            reason=reason
        )
        
        return {
            "certificate_revoked": True,
            "revocation_reason": reason,
            "revocation_timestamp": revocation_result.get("revoked_at"),
            "crl_updated": revocation_result.get("crl_updated", False),
            "details": f"Certificate revoked: {reason}"
        }
    
    async def _renew_certificate(
        self,
        user_did: str,
        credential: Dict[str, Any],
        new_certificate: Optional[str],
        revocation_reason: Optional[str]
    ) -> Dict[str, Any]:
        """Renew a certificate."""
        # Get current certificate info
        current_cert = await self.did_client.get_certificate_details(credential["id"])
        
        # Generate renewal CSR with same subject
        csr_result = await self.did_client.create_certificate_request(
            subject_components=current_cert.get("subject", {}),
            san_entries=current_cert.get("san", []),
            key_reference=credential.get("key_reference"),
            public_key=current_cert.get("public_key")
        )
        
        return {
            "renewal_csr_generated": True,
            "csr_pem": csr_result["csr_pem"],
            "subject": current_cert.get("subject"),
            "next_steps": [
                "Submit the CSR to your Certificate Authority",
                "Wait for the renewed certificate",
                "Install using operation='install' with the new certificate"
            ],
            "details": "Renewal CSR generated successfully"
        }
    
    async def _install_certificate(
        self,
        user_did: str,
        credential: Dict[str, Any],
        new_certificate: Optional[str],
        revocation_reason: Optional[str]
    ) -> Dict[str, Any]:
        """Install a new certificate."""
        if not new_certificate:
            raise ValueError("new_certificate is required for installation")
        
        # Validate certificate
        cert_info = await self._validate_certificate(new_certificate)
        
        # Install certificate
        install_result = await self.did_client.install_certificate(
            user_did=user_did,
            credential_id=credential["id"],
            certificate_data=cert_info["certificate_data"],
            replace_existing=False
        )
        
        return {
            "certificate_installed": True,
            "certificate_fingerprint": cert_info["fingerprint"],
            "credential_id": install_result["credential_id"],
            "valid_from": cert_info["valid_from"],
            "valid_to": cert_info["valid_to"],
            "details": "Certificate installed successfully"
        }
    
    async def _validate_certificate(self, certificate_data: str) -> Dict[str, Any]:
        """Validate certificate data."""
        # Check if it's a file path or PEM data
        if certificate_data.strip().startswith('-----BEGIN CERTIFICATE-----'):
            # It's PEM data
            cert_pem = certificate_data
        else:
            # It's a file path
            path = Path(certificate_data)
            if not path.exists():
                raise FileNotFoundError(f"Certificate file not found: {certificate_data}")
            
            with open(path, 'r') as f:
                cert_pem = f.read()
        
        # Parse and validate certificate
        cert_details = await self.did_client.parse_certificate_pem(cert_pem)
        
        return {
            "certificate_data": cert_pem,
            "fingerprint": cert_details.get("fingerprint_sha256"),
            "subject": cert_details.get("subject"),
            "issuer": cert_details.get("issuer"),
            "valid_from": cert_details.get("valid_from"),
            "valid_to": cert_details.get("valid_to")
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
