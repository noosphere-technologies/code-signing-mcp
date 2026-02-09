"""
Get Certificate Info Tool

Retrieves certificate details, expiry information, and validation status.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..providers import ProviderFactory
from ..config import Config


class GetCertificateInfoTool:
    """Tool for retrieving certificate information."""
    
    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
    
    async def execute(
        self,
        credential_id: Optional[str] = None,
        certificate_path: Optional[str] = None,
        check_revocation: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Get certificate information.
        
        Args:
            credential_id: Specific credential to inspect
            certificate_path: Path to certificate file
            check_revocation: Whether to check CRL/OCSP
            
        Returns:
            Dictionary containing certificate details
        """
        try:
            if credential_id:
                # Get certificate from credential
                user_did = await self.did_client.get_current_user_did()
                credential = await self.did_client.get_credential(user_did, credential_id)
                
                if not credential:
                    raise ValueError(f"Credential not found: {credential_id}")
                
                cert_info = await self._get_credential_certificate_info(
                    credential, check_revocation
                )
                
            elif certificate_path:
                # Load certificate from file
                cert_info = await self._get_file_certificate_info(
                    certificate_path, check_revocation
                )
                
            else:
                # List all available certificates
                user_did = await self.did_client.get_current_user_did()
                credentials = await self.did_client.get_available_credentials(user_did)
                
                cert_list = []
                for cred in credentials:
                    info = await self._get_credential_certificate_info(cred, False)
                    cert_list.append(info)
                
                return {
                    "success": True,
                    "certificates": cert_list,
                    "count": len(cert_list),
                    "timestamp": self._get_timestamp()
                }
            
            return {
                "success": True,
                "certificate": cert_info,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    async def _get_credential_certificate_info(
        self,
        credential: Dict[str, Any],
        check_revocation: bool
    ) -> Dict[str, Any]:
        """Get certificate info from credential."""
        # Get certificate details from DID client
        cert_details = await self.did_client.get_certificate_details(
            credential["id"]
        )
        
        # Check revocation if requested
        revocation_status = None
        if check_revocation:
            revocation_status = await self._check_revocation_status(cert_details)
        
        # Calculate expiry warnings
        expiry_info = self._calculate_expiry_info(cert_details)
        
        return {
            "credential_id": credential["id"],
            "subject": cert_details.get("subject", {}),
            "issuer": cert_details.get("issuer", {}),
            "serial_number": cert_details.get("serial_number"),
            "fingerprint_sha256": cert_details.get("fingerprint_sha256"),
            "fingerprint_sha1": cert_details.get("fingerprint_sha1"),
            "valid_from": cert_details.get("valid_from"),
            "valid_to": cert_details.get("valid_to"),
            "expiry": expiry_info,
            "key_usage": cert_details.get("key_usage", []),
            "extended_key_usage": cert_details.get("extended_key_usage", []),
            "subject_alternative_names": cert_details.get("san", []),
            "signature_algorithm": cert_details.get("signature_algorithm"),
            "public_key": {
                "algorithm": cert_details.get("public_key_algorithm"),
                "size": cert_details.get("public_key_size")
            },
            "revocation": revocation_status,
            "certificate_chain": cert_details.get("chain_length", 0)
        }
    
    async def _get_file_certificate_info(
        self,
        certificate_path: str,
        check_revocation: bool
    ) -> Dict[str, Any]:
        """Get certificate info from file."""
        path = Path(certificate_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Certificate not found: {certificate_path}")
        
        # Parse certificate file
        cert_details = await self.did_client.parse_certificate_file(str(path))
        
        # Check revocation if requested
        revocation_status = None
        if check_revocation:
            revocation_status = await self._check_revocation_status(cert_details)
        
        # Calculate expiry warnings
        expiry_info = self._calculate_expiry_info(cert_details)
        
        return {
            "file_path": str(path.absolute()),
            "subject": cert_details.get("subject", {}),
            "issuer": cert_details.get("issuer", {}),
            "serial_number": cert_details.get("serial_number"),
            "fingerprint_sha256": cert_details.get("fingerprint_sha256"),
            "valid_from": cert_details.get("valid_from"),
            "valid_to": cert_details.get("valid_to"),
            "expiry": expiry_info,
            "key_usage": cert_details.get("key_usage", []),
            "extended_key_usage": cert_details.get("extended_key_usage", []),
            "subject_alternative_names": cert_details.get("san", []),
            "signature_algorithm": cert_details.get("signature_algorithm"),
            "public_key": {
                "algorithm": cert_details.get("public_key_algorithm"),
                "size": cert_details.get("public_key_size")
            },
            "revocation": revocation_status
        }
    
    async def _check_revocation_status(
        self,
        cert_details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check certificate revocation status via CRL/OCSP."""
        try:
            status = await self.did_client.check_certificate_revocation(
                cert_details.get("serial_number"),
                cert_details.get("issuer")
            )
            
            return {
                "checked": True,
                "revoked": status.get("revoked", False),
                "method": status.get("method"),  # "crl" or "ocsp"
                "checked_at": self._get_timestamp()
            }
        except Exception as e:
            return {
                "checked": False,
                "error": str(e)
            }
    
    def _calculate_expiry_info(self, cert_details: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate expiry warnings and status."""
        valid_to = cert_details.get("valid_to")
        
        if not valid_to:
            return {"status": "unknown"}
        
        # Parse expiry date
        try:
            if isinstance(valid_to, str):
                expiry_date = datetime.fromisoformat(valid_to.replace('Z', '+00:00'))
            else:
                expiry_date = valid_to
            
            now = datetime.now(timezone.utc)
            days_until_expiry = (expiry_date - now).days
            
            # Determine status
            if days_until_expiry < 0:
                status = "expired"
                warning = "critical"
            elif days_until_expiry <= 7:
                status = "expiring_soon"
                warning = "critical"
            elif days_until_expiry <= 30:
                status = "expiring_soon"
                warning = "high"
            elif days_until_expiry <= 90:
                status = "valid"
                warning = "medium"
            else:
                status = "valid"
                warning = "none"
            
            return {
                "status": status,
                "days_until_expiry": days_until_expiry,
                "expiry_date": valid_to,
                "warning_level": warning,
                "renewal_recommended": days_until_expiry <= 30
            }
            
        except Exception:
            return {"status": "unknown"}
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
