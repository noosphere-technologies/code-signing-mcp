"""
Verify Signature Tool

Verifies digital signatures using pluggable provider architecture.
Supports multiple providers: Noosphere, SignPath, Sigstore, Local.
"""

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

import aiofiles

from ..providers import ProviderFactory, ProviderCapability, VerificationResult
from ..config import Config


class VerifySignatureTool:
    """
    Tool for verifying signatures using pluggable providers.

    Providers:
    - noosphere: Full verification (signatures, C2PA, in-toto, DID)
    - signpath: Windows Authenticode verification
    - sigstore: Sigstore signature and Rekor verification
    - local: Local key verification
    """

    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config

    async def execute(
        self,
        file_path: str,
        provider: Optional[str] = None,
        signature_path: Optional[str] = None,
        check_certificate_chain: bool = True,
        check_timestamp: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Verify signature on a file.

        Args:
            file_path: Path to the signed file
            provider: Provider to use for verification
            signature_path: Path to detached signature (optional)
            check_certificate_chain: Whether to validate certificate chain
            check_timestamp: Whether to validate timestamps

        Returns:
            Dictionary containing verification results
        """
        try:
            # Get the appropriate provider
            verification_provider = self.provider_factory.get_provider(provider)

            # Validate file exists
            file_info = await self._validate_file(file_path)

            # Check provider capabilities
            capability_notes = []
            if not verification_provider.supports(ProviderCapability.C2PA_MANIFESTS):
                capability_notes.append({
                    "feature": "c2pa_verification",
                    "message": f"C2PA manifest verification not available with {verification_provider.name}",
                    "tip": "Use 'noosphere' provider for full C2PA verification"
                })

            # Prepare verification options
            options = {
                "check_certificate_chain": check_certificate_chain,
                "check_timestamp": check_timestamp,
                "file_info": file_info
            }

            # Call provider to verify
            result = await verification_provider.verify(
                file_path=file_path,
                signature_path=signature_path,
                options=options
            )

            # Format and return result
            response = self._format_result(result, file_info, verification_provider.name)

            # Add capability notes if any
            if capability_notes:
                response["capability_notes"] = capability_notes

            return response

        except Exception as e:
            return {
                "success": False,
                "valid": False,
                "error": str(e),
                "file_path": file_path,
                "timestamp": self._get_timestamp()
            }

    async def _validate_file(self, file_path: str) -> Dict[str, Any]:
        """Validate file exists and get metadata."""
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        stat = path.stat()

        # Calculate hash
        hash_sha256 = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(8192):
                hash_sha256.update(chunk)

        return {
            "path": str(path.absolute()),
            "name": path.name,
            "size": stat.st_size,
            "sha256": hash_sha256.hexdigest(),
            "extension": path.suffix.lower()
        }

    def _format_result(
        self,
        result,
        file_info: Dict[str, Any],
        provider_name: str
    ) -> Dict[str, Any]:
        """Format verification result."""

        # Handle VerificationResult dataclass or dict
        if isinstance(result, VerificationResult):
            valid = result.valid
            error = result.error
        else:
            valid = result.get("valid", False)
            error = result.get("error")

        if error:
            return {
                "success": True,  # Tool succeeded, but verification found issues
                "valid": valid,
                "error": error,
                "file_path": file_info["path"],
                "provider": provider_name,
                "timestamp": self._get_timestamp()
            }

        response = {
            "success": True,
            "valid": valid,
            "file": {
                "name": file_info["name"],
                "path": file_info["path"],
                "size": file_info["size"],
                "sha256": file_info["sha256"]
            },
            "signature": {
                "valid": getattr(result, 'signature_valid', valid) if hasattr(result, 'signature_valid') else valid,
                "algorithm": getattr(result, 'signature_algorithm', None) if hasattr(result, 'signature_algorithm') else None,
                "timestamp_valid": getattr(result, 'timestamp_valid', None) if hasattr(result, 'timestamp_valid') else None
            },
            "provider": provider_name,
            "verified_at": self._get_timestamp()
        }

        # Add certificate info if available
        if hasattr(result, 'certificate_info') and result.certificate_info:
            response["certificate"] = result.certificate_info

        # Add C2PA info if available
        if hasattr(result, 'c2pa_manifest') and result.c2pa_manifest:
            response["c2pa"] = {
                "manifest_found": True,
                "manifest_valid": result.c2pa_manifest.get("valid", False),
                "manifest": result.c2pa_manifest
            }

        # Add attestation info if available
        if hasattr(result, 'attestation') and result.attestation:
            response["attestations"] = result.attestation

        # Add transparency log info if available
        if hasattr(result, 'transparency_entry') and result.transparency_entry:
            response["transparency_log"] = {
                "entry": result.transparency_entry,
                "verified": True
            }

        # Calculate trust level
        response["trust_level"] = self._calculate_trust_level(response)

        # Add provider tip for enhanced capabilities
        if hasattr(result, 'capability_tips') and result.capability_tips:
            response["provider_tip"] = result.capability_tips

        return response

    def _calculate_trust_level(self, response: Dict[str, Any]) -> str:
        """Calculate overall trust level."""
        if not response.get("valid"):
            return "invalid"

        # Check for advanced verification features
        has_c2pa = response.get("c2pa", {}).get("manifest_valid", False)
        has_attestations = bool(response.get("attestations"))
        has_transparency = bool(response.get("transparency_log"))

        if has_c2pa and has_attestations:
            return "enterprise"
        elif has_c2pa or has_transparency:
            return "high"
        elif response.get("certificate", {}).get("chain_valid"):
            return "medium"
        else:
            return "basic"

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
