"""
Noosphere Digital Integrity Platform Provider

Full-featured signing provider that integrates with the
Noosphere Digital Integrity Platform.

This is the premium provider with all capabilities:
- C2PA Content Credentials
- in-toto Supply Chain Attestations
- DID-based Identity
- Verifiable Credentials
- Policy Engine
- HSM Support (Thales Luna HSM via c2pa-artifact)
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp

from .base import (
    BaseProvider,
    Credential,
    ProviderCapability,
    ProviderInfo,
    SigningResult,
    VerificationResult,
)

logger = logging.getLogger(__name__)


class NoosphereProvider(BaseProvider):
    """
    Noosphere Digital Integrity Platform - full-featured enterprise signing.

    Integrates with:
    - artifact-service.noosphere.tech (C2PA + in-toto signing)
    - did.noosphere.tech (DID identity)
    - vc.noosphere.tech (Verifiable Credentials)

    HSM Support:
    - Thales Luna HSM integration via c2pa-artifact service
    - Hardware-backed keys for enterprise compliance
    """

    # All capabilities supported
    CAPABILITIES = [
        ProviderCapability.BINARY_SIGNING,
        ProviderCapability.PACKAGE_SIGNING,
        ProviderCapability.BATCH_SIGNING,
        ProviderCapability.C2PA_MANIFESTS,
        ProviderCapability.IN_TOTO_ATTESTATIONS,
        ProviderCapability.DID_IDENTITY,
        ProviderCapability.VERIFIABLE_CREDENTIALS,
        ProviderCapability.POLICY_ENGINE,
        ProviderCapability.HSM_SUPPORT,
        ProviderCapability.SUPPLY_CHAIN_ATTESTATIONS,
        ProviderCapability.TRANSPARENCY_LOG,
        ProviderCapability.OFFLINE_SIGNING,
        ProviderCapability.WINDOWS_AUTHENTICODE,
        ProviderCapability.SIGNATURE_VERIFICATION,
        ProviderCapability.CERTIFICATE_MANAGEMENT,
    ]

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Noosphere provider.

        Config expected:
        {
            "c2pa_service_url": "https://artifact-service.noosphere.tech",
            "did_service_url": "https://did.noosphere.tech",
            "vc_service_url": "https://vc.noosphere.tech",
            "api_key": "...",
            "default_policy": "enterprise"
        }
        """
        super().__init__(config)

        self.c2pa_url = config.get("c2pa_service_url", "https://artifact-service.noosphere.tech")
        self.did_url = config.get("did_service_url", "https://did.noosphere.tech")
        self.vc_url = config.get("vc_service_url", "https://vc.noosphere.tech")
        self.api_key = config.get("api_key")
        self.default_policy = config.get("default_policy", "enterprise")

        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def info(self) -> ProviderInfo:
        """Provider metadata."""
        return ProviderInfo(
            name="noosphere",
            display_name="Noosphere Digital Integrity Platform",
            description="Enterprise digital integrity with C2PA, in-toto attestations, DID identity, and Verifiable Credentials",
            website="https://noosphere.tech",
            capabilities=self.CAPABILITIES,
            tier="premium",
            highlight_features=[
                "C2PA Content Credentials",
                "in-toto Supply Chain Attestations",
                "DID-based Identity",
                "Verifiable Credentials",
                "Policy-driven Signing",
                "HSM Support"
            ]
        )

    async def initialize(self) -> None:
        """Initialize HTTP session."""
        if self._session:
            return

        headers = {
            "User-Agent": "code-signing-mcp/1.0.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        self._session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=120)
        )

        self._initialized = True
        logger.info("Noosphere provider initialized")

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None
        self._initialized = False

    async def sign(
        self,
        file_path: str,
        credential_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> SigningResult:
        """
        Sign a file with Noosphere's C2PA service.

        Options:
            embed_c2pa: bool - Embed C2PA manifest (default: True)
            generate_did_attestation: bool - Generate DID attestation (default: True)
            include_vc: bool - Include Verifiable Credentials (default: True)
            policy: str - Policy to apply (default: config default)
            timestamp_url: str - Override TSA URL
        """
        if not self._initialized:
            await self.initialize()

        options = options or {}

        try:
            # Validate file
            file_info = await self._get_file_info(file_path)

            # Get user DID
            user_did = await self._get_current_user_did()

            # Select credential
            credential = await self._select_credential(credential_id, file_info)

            # Build signing request
            signing_request = {
                "artifact": {
                    "file_path": file_path,
                    "name": file_info["name"],
                    "type": file_info["type"],
                    "size": file_info["size"],
                    "sha256": file_info["sha256"]
                },
                "credential": {
                    "id": credential.id,
                    "type": credential.type
                },
                "identity": {
                    "did": user_did,
                    "include_vc": options.get("include_vc", True)
                },
                "options": {
                    "embed_c2pa": options.get("embed_c2pa", True),
                    "generate_attestation": options.get("generate_did_attestation", True),
                    "policy": options.get("policy", self.default_policy),
                    "timestamp_url": options.get("timestamp_url")
                }
            }

            # Call C2PA service
            async with self._session.post(
                f"{self.c2pa_url}/api/v1/sign",
                json=signing_request
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    return SigningResult(
                        success=False,
                        error=f"Signing failed: {error_text}",
                        provider_name=self.name
                    )

                result = await response.json()

            # Build success result
            return SigningResult(
                success=True,
                signature=result.get("signature"),
                signature_format=result.get("signature_format", "c2pa"),
                signature_algorithm=result.get("signature_algorithm", "ES256"),
                certificate=result.get("certificate"),
                certificate_fingerprint=result.get("certificate_fingerprint"),
                c2pa_manifest=result.get("c2pa_manifest"),
                c2pa_manifest_id=result.get("c2pa_manifest_id"),
                c2pa_embedded=result.get("c2pa_embedded", True),
                did_attestation=result.get("did_attestation"),
                verifiable_credentials=result.get("verifiable_credentials"),
                slsa_attestation=result.get("slsa_attestation"),
                in_toto_attestation=result.get("in_toto_attestation"),
                transparency_entry=result.get("transparency_entry"),
                timestamp=datetime.now(timezone.utc).isoformat(),
                provider_name=self.name,
                provider_metadata={
                    "platform": "Noosphere Digital Integrity Platform",
                    "policy_applied": signing_request["options"]["policy"],
                    "credential_used": credential.id,
                    "user_did": user_did
                }
            )

        except aiohttp.ClientError as e:
            return SigningResult(
                success=False,
                error=f"Network error: {str(e)}",
                provider_name=self.name
            )
        except Exception as e:
            logger.exception("Signing failed")
            return SigningResult(
                success=False,
                error=str(e),
                provider_name=self.name
            )

    async def verify(
        self,
        file_path: str,
        signature_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """
        Verify a signature using Noosphere's verification service.

        Options:
            check_c2pa: bool - Verify C2PA manifest (default: True)
            check_did: bool - Verify DID attestation (default: True)
            check_vc: bool - Verify Verifiable Credentials (default: True)
            check_chain: bool - Verify certificate chain (default: True)
        """
        if not self._initialized:
            await self.initialize()

        options = options or {}

        try:
            verification_request = {
                "file_path": file_path,
                "signature_path": signature_path,
                "options": {
                    "check_c2pa": options.get("check_c2pa", True),
                    "check_did": options.get("check_did", True),
                    "check_vc": options.get("check_vc", True),
                    "check_chain": options.get("check_chain", True)
                }
            }

            async with self._session.post(
                f"{self.c2pa_url}/api/v1/verify",
                json=verification_request
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    return VerificationResult(
                        valid=False,
                        error=f"Verification request failed: {error_text}",
                        provider_name=self.name
                    )

                result = await response.json()

            return VerificationResult(
                valid=result.get("valid", False),
                signature_valid=result.get("signature_valid", False),
                certificate_valid=result.get("certificate_valid", False),
                certificate_chain_valid=result.get("chain_valid", False),
                timestamp_valid=result.get("timestamp_valid", False),
                c2pa_valid=result.get("c2pa_valid"),
                c2pa_manifest=result.get("c2pa_manifest"),
                signer_identity=result.get("signer_identity"),
                signer_did=result.get("signer_did"),
                credentials_verified=result.get("credentials_verified"),
                transparency_verified=result.get("transparency_verified", False),
                transparency_entry=result.get("transparency_entry"),
                warnings=result.get("warnings", []),
                provider_name=self.name
            )

        except Exception as e:
            logger.exception("Verification failed")
            return VerificationResult(
                valid=False,
                error=str(e),
                provider_name=self.name
            )

    async def get_credentials(self) -> List[Credential]:
        """Get available credentials from Noosphere VC service."""
        if not self._initialized:
            await self.initialize()

        try:
            async with self._session.get(f"{self.vc_url}/api/credentials") as response:
                if response.status != 200:
                    logger.warning("Failed to fetch credentials")
                    return []

                data = await response.json()

            return [
                Credential(
                    id=cred["id"],
                    name=cred.get("name", cred["id"]),
                    type=cred.get("type", "software"),
                    provider=self.name,
                    security_level=cred.get("security_level", "standard"),
                    supports_c2pa=True,  # Noosphere always supports C2PA
                    supports_did=True,   # Noosphere always supports DID
                    valid=cred.get("valid", True),
                    expires_at=cred.get("expires_at"),
                    metadata=cred.get("metadata", {})
                )
                for cred in data.get("credentials", [])
            ]

        except Exception as e:
            logger.exception("Failed to get credentials")
            return []

    async def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get file metadata and hash."""
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        stat = path.stat()

        # Calculate SHA256
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        # Detect file type
        file_type = self._detect_file_type(path)

        return {
            "path": str(path.absolute()),
            "name": path.name,
            "size": stat.st_size,
            "sha256": sha256.hexdigest(),
            "type": file_type,
            "extension": path.suffix.lower()
        }

    def _detect_file_type(self, path: Path) -> str:
        """Detect artifact type from extension."""
        ext = path.suffix.lower()
        type_map = {
            ".jar": "java_archive",
            ".war": "web_archive",
            ".exe": "windows_executable",
            ".msi": "windows_installer",
            ".dmg": "macos_disk_image",
            ".pkg": "macos_package",
            ".deb": "debian_package",
            ".rpm": "rpm_package",
            ".whl": "python_wheel",
            ".gem": "ruby_gem",
            ".nupkg": "nuget_package",
            ".tgz": "npm_package",
            ".apk": "android_package",
            ".ipa": "ios_package",
            ".zip": "archive",
            ".tar.gz": "archive"
        }
        return type_map.get(ext, "binary")

    async def _get_current_user_did(self) -> str:
        """Get the current user's DID."""
        try:
            async with self._session.get(f"{self.did_url}/api/me") as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("did", "did:web:noosphere.tech")
        except Exception:
            pass

        # Fallback to default Noosphere DID
        return "did:web:noosphere.tech"

    async def _select_credential(
        self,
        credential_id: Optional[str],
        file_info: Dict[str, Any]
    ) -> Credential:
        """Select appropriate signing credential."""
        credentials = await self.get_credentials()

        if credential_id:
            # Use specified credential
            for cred in credentials:
                if cred.id == credential_id:
                    return cred
            raise ValueError(f"Credential not found: {credential_id}")

        if credentials:
            # Use first available credential
            return credentials[0]

        # Return a default software credential
        return Credential(
            id="default",
            name="Default Software Key",
            type="software",
            provider=self.name,
            supports_c2pa=True,
            supports_did=True
        )
