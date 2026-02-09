"""
Create Signing Request Tool

Generates Certificate Signing Requests (CSRs) for obtaining code signing certificates.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..providers import ProviderFactory
from ..config import Config


class CreateSigningRequestTool:
    """Tool for generating Certificate Signing Requests."""
    
    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
    
    async def execute(
        self,
        subject_dn: str,
        key_algorithm: str = "RSA",
        key_size: int = 2048,
        san_entries: Optional[List[str]] = None,
        use_hsm: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a Certificate Signing Request.
        
        Args:
            subject_dn: Distinguished name for the certificate
            key_algorithm: Key algorithm (RSA, ECDSA)
            key_size: Key size in bits
            san_entries: Subject Alternative Names
            use_hsm: Whether to generate key in HSM
            
        Returns:
            Dictionary containing CSR and key reference
        """
        try:
            # Validate parameters
            self._validate_parameters(subject_dn, key_algorithm, key_size)
            
            # Get user identity
            user_did = await self.did_client.get_current_user_did()
            
            # Parse subject DN
            subject_components = self._parse_subject_dn(subject_dn)
            
            # Generate key pair
            key_info = await self._generate_key_pair(
                key_algorithm, key_size, use_hsm, user_did
            )
            
            # Create CSR
            csr_data = await self.did_client.create_certificate_request(
                subject_components=subject_components,
                san_entries=san_entries or [],
                key_reference=key_info["key_reference"],
                public_key=key_info["public_key"]
            )
            
            return {
                "success": True,
                "csr": {
                    "pem": csr_data["csr_pem"],
                    "der": csr_data.get("csr_der"),
                    "subject": subject_components,
                    "san_entries": san_entries or []
                },
                "key": {
                    "algorithm": key_algorithm,
                    "size": key_size,
                    "reference": key_info["key_reference"],
                    "location": "hsm" if use_hsm else "software",
                    "public_key_pem": key_info.get("public_key_pem")
                },
                "next_steps": [
                    "Submit CSR to your Certificate Authority",
                    "Wait for CA to issue the certificate",
                    "Install the certificate using manage_certificates tool"
                ],
                "metadata": {
                    "user_did": user_did,
                    "created_at": self._get_timestamp(),
                    "request_id": self._generate_request_id()
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    def _validate_parameters(
        self,
        subject_dn: str,
        key_algorithm: str,
        key_size: int
    ):
        """Validate CSR parameters."""
        if not subject_dn:
            raise ValueError("subject_dn is required")
        
        # Validate key algorithm
        valid_algorithms = ["RSA", "ECDSA", "EC"]
        if key_algorithm.upper() not in valid_algorithms:
            raise ValueError(
                f"Invalid key algorithm: {key_algorithm}. "
                f"Valid options: {', '.join(valid_algorithms)}"
            )
        
        # Validate key size
        if key_algorithm.upper() == "RSA":
            valid_sizes = [2048, 3072, 4096]
            if key_size not in valid_sizes:
                raise ValueError(
                    f"Invalid RSA key size: {key_size}. "
                    f"Valid options: {', '.join(map(str, valid_sizes))}"
                )
        elif key_algorithm.upper() in ["ECDSA", "EC"]:
            valid_sizes = [256, 384, 521]
            if key_size not in valid_sizes:
                raise ValueError(
                    f"Invalid EC key size: {key_size}. "
                    f"Valid options: {', '.join(map(str, valid_sizes))}"
                )
    
    def _parse_subject_dn(self, subject_dn: str) -> Dict[str, str]:
        """Parse subject distinguished name."""
        components = {}
        
        # Split by commas
        parts = subject_dn.split(',')
        
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip().upper()
                value = value.strip()
                
                # Map common DN components
                component_map = {
                    'CN': 'common_name',
                    'O': 'organization',
                    'OU': 'organizational_unit',
                    'L': 'locality',
                    'ST': 'state',
                    'C': 'country',
                    'E': 'email',
                    'EMAILADDRESS': 'email'
                }
                
                if key in component_map:
                    components[component_map[key]] = value
        
        # Validate required components
        if 'common_name' not in components:
            raise ValueError("Common Name (CN) is required in subject DN")
        
        return components
    
    async def _generate_key_pair(
        self,
        algorithm: str,
        key_size: int,
        use_hsm: bool,
        user_did: str
    ) -> Dict[str, Any]:
        """Generate key pair for CSR."""
        if use_hsm:
            # Generate key in HSM
            key_info = await self.did_client.generate_hsm_key(
                algorithm=algorithm,
                key_size=key_size,
                user_did=user_did,
                key_label=f"csr_key_{self._generate_request_id()}"
            )
        else:
            # Generate software key
            key_info = await self.did_client.generate_software_key(
                algorithm=algorithm,
                key_size=key_size,
                user_did=user_did
            )
        
        return key_info
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
