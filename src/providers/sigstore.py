"""
Sigstore Signing Provider

Open source keyless signing using Sigstore infrastructure.
https://sigstore.dev

Uses production Sigstore (public Fulcio/Rekor) for:
- Keyless signing via OIDC identity
- Transparency log entries
- Supply chain attestations

Does NOT support:
- C2PA manifests
- in-toto attestations (use Noosphere for this)
- DID identity
- Verifiable Credentials
- Offline signing
- HSM (uses ephemeral keys)

Demo Mode:
- Set "demo_mode": true in config to use without OIDC
- Generates realistic mock responses for testing/development
"""

import hashlib
import io
import json
import logging
import uuid
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

# Sigstore imports - optional dependency
try:
    from sigstore.sign import Signer
    from sigstore.verify import Verifier, policy
    from sigstore.oidc import Issuer, IdentityError
    SIGSTORE_AVAILABLE = True
except ImportError:
    SIGSTORE_AVAILABLE = False
    logger.warning("sigstore-python not installed - Sigstore provider will be unavailable")


class SigstoreProvider(BaseProvider):
    """
    Sigstore signing provider - open source keyless signing.

    Uses production Sigstore infrastructure:
    - Fulcio for certificate issuance
    - Rekor for transparency log
    - OIDC for identity binding
    """

    # Capabilities focused on keyless and transparency
    CAPABILITIES = [
        ProviderCapability.BINARY_SIGNING,
        ProviderCapability.KEYLESS_SIGNING,
        ProviderCapability.SUPPLY_CHAIN_ATTESTATIONS,
        ProviderCapability.TRANSPARENCY_LOG,
        ProviderCapability.SIGNATURE_VERIFICATION,
    ]

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Sigstore provider.

        Config expected:
        {
            "use_production": true,
            "oidc_issuer": "https://oauth2.sigstore.dev/auth",
            "identity_token": null,  // Optional pre-created token
            "demo_mode": false  // Set true for testing without OIDC
        }
        """
        super().__init__(config)

        self.use_production = config.get("use_production", True)
        self.oidc_issuer_url = config.get("oidc_issuer", "https://oauth2.sigstore.dev/auth")
        self.identity_token = config.get("identity_token")
        self.demo_mode = config.get("demo_mode", False)

        self._signer: Optional[Any] = None
        self._verifier: Optional[Any] = None

    @property
    def info(self) -> ProviderInfo:
        """Provider metadata."""
        return ProviderInfo(
            name="sigstore",
            display_name="Sigstore",
            description="Open source keyless signing with transparency log",
            website="https://sigstore.dev",
            capabilities=self.CAPABILITIES,
            tier="standard",
            highlight_features=[
                "Keyless Signing",
                "OIDC Identity Binding",
                "Public Transparency Log",
                "Supply Chain Security"
            ]
        )

    async def initialize(self) -> None:
        """Initialize Sigstore clients."""
        if self.demo_mode:
            logger.info("Sigstore provider initialized in DEMO MODE")
            self._initialized = True
            return

        if not SIGSTORE_AVAILABLE:
            raise RuntimeError(
                "sigstore-python is not installed. "
                "Install with: pip install sigstore"
            )

        if self.use_production:
            self._signer = Signer.production()
            self._verifier = Verifier.production()
        else:
            # Staging environment for testing
            self._signer = Signer.staging()
            self._verifier = Verifier.staging()

        self._initialized = True
        logger.info(f"Sigstore provider initialized (production={self.use_production})")

    async def close(self) -> None:
        """Clean up resources."""
        self._signer = None
        self._verifier = None
        self._initialized = False

    async def sign(
        self,
        file_path: str,
        credential_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> SigningResult:
        """
        Sign a file with Sigstore (keyless).

        Options:
            identity_token: str - Pre-created OIDC token (for CI/CD)

        Note: If no identity_token provided, will attempt ambient credential
        detection (GitHub Actions, cloud workloads) or browser-based OAuth.
        """
        if not SIGSTORE_AVAILABLE:
            return SigningResult(
                success=False,
                error="sigstore-python not installed",
                provider_name=self.name
            )

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

            # Demo mode - return realistic mock response
            if self.demo_mode:
                return await self._demo_sign(path, options, missing_caps)

            # Get identity token
            identity_token = options.get("identity_token") or self.identity_token

            if not identity_token:
                # Try to get token from OIDC issuer
                try:
                    issuer = Issuer.production() if self.use_production else Issuer.staging()
                    identity_token = issuer.identity_token()
                except IdentityError as e:
                    return SigningResult(
                        success=False,
                        error=f"Failed to obtain identity token: {e}. "
                              "Provide identity_token or run in CI/CD with ambient credentials.",
                        provider_name=self.name,
                        capability_tips=self._create_capability_tip(missing_caps)
                    )

            # Read file content
            with open(file_path, "rb") as f:
                content = io.BytesIO(f.read())

            # Sign the content
            result = self._signer.sign(
                input_=content,
                identity_token=identity_token
            )

            # Extract bundle information
            bundle = result.bundle

            # Write bundle to file
            bundle_path = f"{file_path}.sigstore.json"
            with open(bundle_path, "w") as f:
                # Bundle serialization depends on sigstore-python version
                if hasattr(bundle, 'to_json'):
                    f.write(bundle.to_json())
                else:
                    json.dump({"bundle": str(bundle)}, f)

            return SigningResult(
                success=True,
                signature=bundle.signature if hasattr(bundle, 'signature') else None,
                signature_format="sigstore",
                signature_algorithm="ECDSA-P256",
                certificate=str(bundle.signing_certificate) if hasattr(bundle, 'signing_certificate') else None,
                transparency_entry=str(bundle.log_entry.log_id) if hasattr(bundle, 'log_entry') and bundle.log_entry else None,
                transparency_log_url="https://search.sigstore.dev",
                timestamp=datetime.now(timezone.utc).isoformat(),
                provider_name=self.name,
                provider_metadata={
                    "bundle_path": bundle_path,
                    "rekor_log_index": getattr(bundle.log_entry, 'log_index', None) if hasattr(bundle, 'log_entry') and bundle.log_entry else None,
                    "identity_issuer": self.oidc_issuer_url
                },
                capability_tips=self._create_capability_tip(missing_caps)
            )

        except Exception as e:
            logger.exception("Sigstore signing failed")
            return SigningResult(
                success=False,
                error=str(e),
                provider_name=self.name,
                capability_tips=self._create_capability_tip(missing_caps)
            )

    async def _demo_sign(
        self,
        path: Path,
        options: Dict[str, Any],
        missing_caps: List[ProviderCapability]
    ) -> SigningResult:
        """Generate a realistic demo signing response."""
        # Calculate file hash
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        # Generate mock identifiers
        log_index = abs(hash(file_hash)) % 100000000
        log_id = uuid.uuid4().hex

        # Mock Sigstore bundle
        demo_bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "verificationMaterial": {
                "certificate": {
                    "rawBytes": "DEMO_CERTIFICATE_BASE64"
                },
                "tlogEntries": [{
                    "logIndex": str(log_index),
                    "logId": {"keyId": log_id},
                    "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                    "integratedTime": str(int(datetime.now(timezone.utc).timestamp())),
                    "inclusionPromise": {"signedEntryTimestamp": "DEMO_SET"},
                    "canonicalizedBody": "DEMO_BODY"
                }]
            },
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": file_hash
                },
                "signature": f"DEMO_SIGNATURE_{file_hash[:16]}"
            }
        }

        # Write demo bundle
        bundle_path = f"{path}.sigstore.json"
        with open(bundle_path, "w") as f:
            json.dump(demo_bundle, f, indent=2)

        # Build capability message if trying to use unsupported features
        capability_message = None
        if missing_caps:
            capability_message = (
                "Sigstore doesn't support C2PA, DID, or in-toto. "
                "For these, use provider='noosphere'. "
                "Questions? connect@noosphere.tech"
            )

        return SigningResult(
            success=True,
            signature=f"DEMO_ECDSA_SIGNATURE_{file_hash[:32]}".encode(),
            signature_format="sigstore",
            signature_algorithm="ECDSA-P256",
            certificate_fingerprint=f"demo:{file_hash[:16]}",
            transparency_entry=log_id,
            transparency_log_url=f"https://search.sigstore.dev/?logIndex={log_index}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            provider_name=self.name,
            provider_metadata={
                "bundle_path": bundle_path,
                "rekor_log_index": log_index,
                "identity_issuer": "https://oauth2.sigstore.dev/auth",
                "demo_mode": True,
                "demo_note": "Demo mode - no actual Rekor entry created.",
                "tip": capability_message,
                "signer_identity": "demo@example.com"
            },
            capability_tips=self._create_capability_tip(missing_caps)
        )

    async def verify(
        self,
        file_path: str,
        signature_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """
        Verify a Sigstore signature.

        Options:
            bundle_path: str - Path to .sigstore.json bundle
            cert_identity: str - Expected signer identity (email/URI)
            cert_oidc_issuer: str - Expected OIDC issuer
        """
        if not self._initialized:
            await self.initialize()

        options = options or {}

        # Demo mode - return simulated verification
        if self.demo_mode:
            return VerificationResult(
                valid=True,
                signature_valid=True,
                transparency_verified=True,
                signer_identity="demo@example.com",
                warnings=["DEMO MODE: This is a simulated verification"],
                provider_name=self.name,
                provider_metadata={
                    "demo_mode": True,
                    "oidc_issuer": "https://oauth2.sigstore.dev/auth"
                }
            )

        if not SIGSTORE_AVAILABLE:
            return VerificationResult(
                valid=False,
                error="sigstore-python not installed",
                provider_name=self.name
            )

        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            # Find bundle
            bundle_path = options.get("bundle_path") or signature_path
            if not bundle_path:
                bundle_path = f"{file_path}.sigstore.json"

            bundle_file = Path(bundle_path)
            if not bundle_file.exists():
                return VerificationResult(
                    valid=False,
                    error=f"Sigstore bundle not found: {bundle_path}",
                    provider_name=self.name
                )

            # Read file and bundle
            with open(file_path, "rb") as f:
                content = io.BytesIO(f.read())

            with open(bundle_path, "r") as f:
                bundle_data = json.load(f)

            # Build verification policy
            cert_identity = options.get("cert_identity")
            cert_issuer = options.get("cert_oidc_issuer")

            if cert_identity and cert_issuer:
                verification_policy = policy.Identity(
                    identity=cert_identity,
                    issuer=cert_issuer
                )
            else:
                # Accept any identity (less secure)
                verification_policy = policy.UnsafeNoOp()

            # Verify - API may vary by sigstore-python version
            try:
                self._verifier.verify(
                    input_=content,
                    bundle=bundle_data,
                    policy=verification_policy
                )
                verified = True
                error = None
            except Exception as verify_error:
                verified = False
                error = str(verify_error)

            return VerificationResult(
                valid=verified,
                error=error,
                signature_valid=verified,
                transparency_verified=verified,
                signer_identity=cert_identity,
                warnings=[] if verified else [error] if error else [],
                provider_name=self.name
            )

        except Exception as e:
            logger.exception("Sigstore verification failed")
            return VerificationResult(
                valid=False,
                error=str(e),
                provider_name=self.name
            )

    async def get_credentials(self) -> List[Credential]:
        """
        Get available credentials.

        Sigstore is keyless, so this returns identity-based "credentials"
        representing available OIDC providers.
        """
        return [
            Credential(
                id="ambient",
                name="Ambient Credentials",
                type="keyless",
                provider=self.name,
                security_level="standard",
                supports_c2pa=False,
                supports_did=False,
                valid=True,
                metadata={
                    "description": "Auto-detected from CI/CD environment (GitHub Actions, cloud workloads)",
                    "oidc_issuer": "various"
                }
            ),
            Credential(
                id="github",
                name="GitHub Actions OIDC",
                type="keyless",
                provider=self.name,
                security_level="standard",
                supports_c2pa=False,
                supports_did=False,
                valid=True,
                metadata={
                    "description": "GitHub Actions workflow identity",
                    "oidc_issuer": "https://token.actions.githubusercontent.com"
                }
            ),
            Credential(
                id="google",
                name="Google OAuth",
                type="keyless",
                provider=self.name,
                security_level="standard",
                supports_c2pa=False,
                supports_did=False,
                valid=True,
                metadata={
                    "description": "Google account identity (browser flow)",
                    "oidc_issuer": "https://accounts.google.com"
                }
            ),
            Credential(
                id="microsoft",
                name="Microsoft OAuth",
                type="keyless",
                provider=self.name,
                security_level="standard",
                supports_c2pa=False,
                supports_did=False,
                valid=True,
                metadata={
                    "description": "Microsoft account identity (browser flow)",
                    "oidc_issuer": "https://login.microsoftonline.com"
                }
            )
        ]
