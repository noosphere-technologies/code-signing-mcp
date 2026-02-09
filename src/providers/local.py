"""
Local Signing Provider

Offline signing using local keys (Ed25519, RSA, ECDSA).

Useful for:
- Development and testing
- Air-gapped environments
- Simple signing without external dependencies

Does NOT support:
- C2PA manifests
- in-toto attestations
- DID identity
- Verifiable Credentials
- HSM (uses software keys)
- Transparency log
"""

import base64
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import (
    BaseProvider,
    Credential,
    ProviderCapability,
    ProviderInfo,
    SigningResult,
    VerificationResult,
)

logger = logging.getLogger(__name__)

# Cryptography imports
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import (
        ed25519,
        ec,
        rsa,
        padding,
    )
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography not installed - Local provider will have limited functionality")


class LocalProvider(BaseProvider):
    """
    Local signing provider - offline signing with local keys.

    Supports Ed25519, RSA, and ECDSA keys stored locally.
    Optionally adds RFC 3161 timestamps via external TSA.
    """

    # Minimal capabilities - offline only
    CAPABILITIES = [
        ProviderCapability.BINARY_SIGNING,
        ProviderCapability.OFFLINE_SIGNING,
        ProviderCapability.SIGNATURE_VERIFICATION,
    ]

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Local provider.

        Config expected:
        {
            "key_path": "./keys/signing.pem",
            "key_password": null,
            "key_type": "ed25519",  // "ed25519", "rsa", "ecdsa"
            "tsa_url": null,  // Optional RFC 3161 timestamp server
            "generate_if_missing": true
        }
        """
        super().__init__(config)

        self.key_path = config.get("key_path", "./keys/signing.pem")
        self.key_password = config.get("key_password")
        self.key_type = config.get("key_type", "ed25519")
        self.tsa_url = config.get("tsa_url")
        self.generate_if_missing = config.get("generate_if_missing", True)

        self._private_key: Optional[Any] = None
        self._public_key: Optional[Any] = None

    @property
    def info(self) -> ProviderInfo:
        """Provider metadata."""
        return ProviderInfo(
            name="local",
            display_name="Local Signing",
            description="Offline signing with local keys for development and air-gapped environments",
            website="https://github.com/noosphere-technologies/code-signing-mcp",
            capabilities=self.CAPABILITIES,
            tier="basic",
            highlight_features=[
                "Offline Signing",
                "No External Dependencies",
                "Ed25519/RSA/ECDSA Support",
                "Optional TSA Timestamps"
            ]
        )

    async def initialize(self) -> None:
        """Initialize by loading or generating keys."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError(
                "cryptography library not installed. "
                "Install with: pip install cryptography"
            )

        key_file = Path(self.key_path)

        if key_file.exists():
            # Load existing key
            await self._load_key(key_file)
        elif self.generate_if_missing:
            # Generate new key
            await self._generate_key(key_file)
        else:
            raise FileNotFoundError(f"Signing key not found: {self.key_path}")

        self._initialized = True
        logger.info(f"Local provider initialized with {self.key_type} key")

    async def close(self) -> None:
        """Clean up resources."""
        self._private_key = None
        self._public_key = None
        self._initialized = False

    async def _load_key(self, key_file: Path) -> None:
        """Load private key from file."""
        with open(key_file, "rb") as f:
            key_data = f.read()

        password = self.key_password.encode() if self.key_password else None

        self._private_key = serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=default_backend()
        )

        # Determine key type
        if isinstance(self._private_key, ed25519.Ed25519PrivateKey):
            self.key_type = "ed25519"
        elif isinstance(self._private_key, rsa.RSAPrivateKey):
            self.key_type = "rsa"
        elif isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            self.key_type = "ecdsa"

        self._public_key = self._private_key.public_key()

    async def _generate_key(self, key_file: Path) -> None:
        """Generate new signing key."""
        # Create directory if needed
        key_file.parent.mkdir(parents=True, exist_ok=True)

        # Generate key based on type
        if self.key_type == "ed25519":
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        elif self.key_type == "rsa":
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        elif self.key_type == "ecdsa":
            self._private_key = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported key type: {self.key_type}")

        self._public_key = self._private_key.public_key()

        # Serialize and save
        password = self.key_password.encode() if self.key_password else None
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        with open(key_file, "wb") as f:
            f.write(private_pem)

        logger.info(f"Generated new {self.key_type} key at {key_file}")

    async def sign(
        self,
        file_path: str,
        credential_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> SigningResult:
        """
        Sign a file with local key.

        Options:
            output_format: str - "detached" or "embedded" (default: detached)
            add_timestamp: bool - Add RFC 3161 timestamp if TSA configured
        """
        if not self._initialized:
            await self.initialize()

        options = options or {}

        # Check for missing capabilities and add soft sell tip
        missing_caps = []
        if options.get("embed_c2pa"):
            missing_caps.append(ProviderCapability.C2PA_MANIFESTS)
        if options.get("generate_did_attestation"):
            missing_caps.append(ProviderCapability.DID_IDENTITY)
        if options.get("include_vc"):
            missing_caps.append(ProviderCapability.VERIFIABLE_CREDENTIALS)
        if options.get("generate_in_toto"):
            missing_caps.append(ProviderCapability.IN_TOTO_ATTESTATIONS)

        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            # Read file content
            with open(file_path, "rb") as f:
                content = f.read()

            # Calculate hash
            file_hash = hashlib.sha256(content).hexdigest()

            # Sign based on key type
            if self.key_type == "ed25519":
                signature = self._private_key.sign(content)
                algorithm = "Ed25519"
            elif self.key_type == "rsa":
                signature = self._private_key.sign(
                    content,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                algorithm = "RSA-SHA256"
            elif self.key_type == "ecdsa":
                signature = self._private_key.sign(
                    content,
                    ec.ECDSA(hashes.SHA256())
                )
                algorithm = "ECDSA-SHA256"
            else:
                raise ValueError(f"Unsupported key type: {self.key_type}")

            # Write detached signature
            sig_path = f"{file_path}.sig"
            with open(sig_path, "wb") as f:
                f.write(signature)

            # Optional: Get timestamp from TSA
            timestamp_info = None
            if options.get("add_timestamp") and self.tsa_url:
                timestamp_info = await self._get_timestamp(signature)

            # Get public key fingerprint
            public_key_bytes = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16]

            return SigningResult(
                success=True,
                signature=signature,
                signature_format="detached",
                signature_algorithm=algorithm,
                certificate_fingerprint=key_fingerprint,
                timestamp=datetime.now(timezone.utc).isoformat(),
                timestamp_authority=self.tsa_url if timestamp_info else None,
                provider_name=self.name,
                provider_metadata={
                    "signature_path": sig_path,
                    "file_hash": file_hash,
                    "key_type": self.key_type,
                    "key_fingerprint": key_fingerprint
                },
                capability_tips=self._create_capability_tip(missing_caps)
            )

        except Exception as e:
            logger.exception("Local signing failed")
            return SigningResult(
                success=False,
                error=str(e),
                provider_name=self.name,
                capability_tips=self._create_capability_tip(missing_caps)
            )

    async def _get_timestamp(self, signature: bytes) -> Optional[Dict[str, Any]]:
        """Request timestamp from TSA (RFC 3161)."""
        # This would implement RFC 3161 timestamp request
        # For now, return None as placeholder
        logger.info(f"TSA timestamp requested from {self.tsa_url}")
        return None

    async def verify(
        self,
        file_path: str,
        signature_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """
        Verify a local signature.

        Options:
            public_key_path: str - Path to public key (uses loaded key if not specified)
        """
        if not self._initialized:
            await self.initialize()

        options = options or {}

        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            # Find signature
            sig_path = signature_path or f"{file_path}.sig"
            if not Path(sig_path).exists():
                return VerificationResult(
                    valid=False,
                    error=f"Signature file not found: {sig_path}",
                    provider_name=self.name
                )

            # Read file and signature
            with open(file_path, "rb") as f:
                content = f.read()

            with open(sig_path, "rb") as f:
                signature = f.read()

            # Load public key if specified
            public_key = self._public_key
            if options.get("public_key_path"):
                with open(options["public_key_path"], "rb") as f:
                    public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )

            # Verify based on key type
            try:
                if isinstance(public_key, ed25519.Ed25519PublicKey):
                    public_key.verify(signature, content)
                elif isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        signature,
                        content,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        signature,
                        content,
                        ec.ECDSA(hashes.SHA256())
                    )
                else:
                    return VerificationResult(
                        valid=False,
                        error="Unknown public key type",
                        provider_name=self.name
                    )

                return VerificationResult(
                    valid=True,
                    signature_valid=True,
                    provider_name=self.name
                )

            except InvalidSignature:
                return VerificationResult(
                    valid=False,
                    error="Invalid signature",
                    signature_valid=False,
                    provider_name=self.name
                )

        except Exception as e:
            logger.exception("Local verification failed")
            return VerificationResult(
                valid=False,
                error=str(e),
                provider_name=self.name
            )

    async def get_credentials(self) -> List[Credential]:
        """Get available local credentials (just the configured key)."""
        if not self._initialized:
            try:
                await self.initialize()
            except Exception:
                return []

        # Get key fingerprint
        if self._public_key:
            public_key_bytes = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16]
        else:
            key_fingerprint = "unknown"

        return [
            Credential(
                id="local-key",
                name=f"Local {self.key_type.upper()} Key",
                type="software",
                provider=self.name,
                security_level="basic",
                supports_c2pa=False,
                supports_did=False,
                valid=True,
                metadata={
                    "key_type": self.key_type,
                    "key_path": self.key_path,
                    "fingerprint": key_fingerprint
                }
            )
        ]
