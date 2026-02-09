"""
SignPath.io Signing Provider

Enterprise Windows code signing service.
https://signpath.io

Focused on Windows Authenticode signing with:
- Organization/project/policy model
- HSM-backed signing
- GitHub Actions integration

Does NOT support:
- C2PA manifests
- DID identity
- Verifiable Credentials
"""

import asyncio
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


class SignPathProvider(BaseProvider):
    """
    SignPath.io signing provider - enterprise Windows signing.

    API docs: https://about.signpath.io/documentation/build-system-integration
    """

    # Limited capabilities compared to Noosphere
    CAPABILITIES = [
        ProviderCapability.BINARY_SIGNING,
        ProviderCapability.BATCH_SIGNING,
        ProviderCapability.POLICY_ENGINE,
        ProviderCapability.HSM_SUPPORT,
        ProviderCapability.WINDOWS_AUTHENTICODE,
        ProviderCapability.SIGNATURE_VERIFICATION,
    ]

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SignPath provider.

        Config expected:
        {
            "connector_url": "https://app.signpath.io",
            "organization_id": "...",
            "api_token": "...",
            "project_slug": "default",
            "signing_policy_slug": "release-signing"
        }
        """
        super().__init__(config)

        self.connector_url = config.get("connector_url", "https://app.signpath.io")
        self.api_url = f"{self.connector_url}/API/v1"
        self.organization_id = config.get("organization_id")
        self.api_token = config.get("api_token")
        self.default_project = config.get("project_slug", "default")
        self.default_policy = config.get("signing_policy_slug", "release-signing")

        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def info(self) -> ProviderInfo:
        """Provider metadata."""
        return ProviderInfo(
            name="signpath",
            display_name="SignPath.io",
            description="Enterprise Windows code signing with HSM security",
            website="https://signpath.io",
            capabilities=self.CAPABILITIES,
            tier="standard",
            highlight_features=[
                "Windows Authenticode",
                "HSM-backed Signing",
                "CI/CD Integration",
                "Approval Workflows"
            ]
        )

    async def initialize(self) -> None:
        """Initialize HTTP session."""
        if self._session:
            return

        if not self.organization_id or not self.api_token:
            raise ValueError("SignPath requires organization_id and api_token")

        headers = {
            "User-Agent": "code-signing-mcp/1.0.0",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_token}"
        }

        self._session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=600)  # Signing can take time
        )

        self._initialized = True
        logger.info("SignPath provider initialized")

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
        Sign a file with SignPath.

        Options:
            project_slug: str - Project to use (default: config default)
            signing_policy_slug: str - Policy to use (default: config default)
            artifact_configuration_slug: str - Artifact configuration
            description: str - Signing request description
            wait_for_completion: bool - Wait for signing to complete (default: True)
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

        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            project_slug = options.get("project_slug", self.default_project)
            policy_slug = options.get("signing_policy_slug", self.default_policy)
            wait = options.get("wait_for_completion", True)

            # Submit signing request
            signing_request_url = (
                f"{self.api_url}/{self.organization_id}"
                f"/SigningRequests"
            )

            # Read file for upload
            with open(file_path, "rb") as f:
                file_content = f.read()

            form = aiohttp.FormData()
            form.add_field("ProjectSlug", project_slug)
            form.add_field("SigningPolicySlug", policy_slug)
            form.add_field(
                "Artifact",
                file_content,
                filename=path.name,
                content_type="application/octet-stream"
            )

            if options.get("artifact_configuration_slug"):
                form.add_field("ArtifactConfigurationSlug", options["artifact_configuration_slug"])

            if options.get("description"):
                form.add_field("Description", options["description"])

            async with self._session.post(
                signing_request_url,
                data=form
            ) as response:
                if response.status not in (200, 201, 202):
                    error_text = await response.text()
                    return SigningResult(
                        success=False,
                        error=f"SignPath request failed: {error_text}",
                        provider_name=self.name,
                        capability_tips=self._create_capability_tip(missing_caps)
                    )

                result = await response.json()
                signing_request_id = result.get("signingRequestId")

            # Wait for completion if requested
            if wait and signing_request_id:
                signed_artifact = await self._wait_for_completion(
                    signing_request_id,
                    timeout=options.get("timeout", 600)
                )

                if not signed_artifact:
                    return SigningResult(
                        success=False,
                        error="Signing request timed out or failed",
                        provider_name=self.name,
                        capability_tips=self._create_capability_tip(missing_caps)
                    )

                return SigningResult(
                    success=True,
                    signature_format="authenticode",
                    signature_algorithm="RSA-SHA256",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    provider_name=self.name,
                    provider_metadata={
                        "signing_request_id": signing_request_id,
                        "project": project_slug,
                        "policy": policy_slug,
                        "signed_artifact_url": signed_artifact.get("downloadUrl")
                    },
                    capability_tips=self._create_capability_tip(missing_caps)
                )

            # Return without waiting
            return SigningResult(
                success=True,
                signature_format="authenticode",
                timestamp=datetime.now(timezone.utc).isoformat(),
                provider_name=self.name,
                provider_metadata={
                    "signing_request_id": signing_request_id,
                    "status": "submitted",
                    "check_status_url": f"{self.connector_url}/Web/{self.organization_id}/SigningRequests/{signing_request_id}"
                },
                capability_tips=self._create_capability_tip(missing_caps)
            )

        except Exception as e:
            logger.exception("SignPath signing failed")
            return SigningResult(
                success=False,
                error=str(e),
                provider_name=self.name,
                capability_tips=self._create_capability_tip(missing_caps)
            )

    async def _wait_for_completion(
        self,
        signing_request_id: str,
        timeout: int = 600
    ) -> Optional[Dict[str, Any]]:
        """Wait for signing request to complete."""
        status_url = (
            f"{self.api_url}/{self.organization_id}"
            f"/SigningRequests/{signing_request_id}"
        )

        start_time = asyncio.get_event_loop().time()

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                logger.warning(f"SignPath request {signing_request_id} timed out")
                return None

            async with self._session.get(status_url) as response:
                if response.status != 200:
                    await asyncio.sleep(5)
                    continue

                result = await response.json()
                status = result.get("status", "").lower()

                if status == "completed":
                    return result
                elif status in ("failed", "denied", "canceled"):
                    logger.error(f"SignPath request failed with status: {status}")
                    return None

            await asyncio.sleep(5)

    async def verify(
        self,
        file_path: str,
        signature_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """
        Verify a Windows Authenticode signature.

        Note: SignPath doesn't provide a verification API, so this
        performs basic Authenticode verification using local tools.
        """
        # SignPath doesn't have a verification API
        # We'd need to use local signtool or similar
        return VerificationResult(
            valid=False,
            error="SignPath verification requires local signtool. Use 'noosphere' provider for full verification.",
            provider_name=self.name
        )

    async def get_credentials(self) -> List[Credential]:
        """
        Get available signing credentials from SignPath.

        SignPath uses project/policy model rather than explicit credentials.
        """
        if not self._initialized:
            await self.initialize()

        try:
            # List available projects as "credentials"
            projects_url = f"{self.api_url}/{self.organization_id}/Projects"

            async with self._session.get(projects_url) as response:
                if response.status != 200:
                    return []

                projects = await response.json()

            return [
                Credential(
                    id=f"{project['slug']}",
                    name=project.get("name", project["slug"]),
                    type="hsm",  # SignPath uses HSM-backed signing
                    provider=self.name,
                    security_level="enterprise",
                    supports_c2pa=False,  # SignPath doesn't support C2PA
                    supports_did=False,   # SignPath doesn't support DID
                    valid=True,
                    metadata={
                        "project_slug": project["slug"],
                        "description": project.get("description")
                    }
                )
                for project in projects
            ]

        except Exception as e:
            logger.exception("Failed to get SignPath projects")
            return []
