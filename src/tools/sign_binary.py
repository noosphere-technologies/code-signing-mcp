"""
Sign Binary Tool

Handles binary file signing through pluggable provider architecture.
Supports multiple providers: Noosphere, SignPath, Sigstore, Local.
"""

import asyncio
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, Optional

import aiofiles

from ..providers import ProviderFactory, ProviderCapability
from ..config import Config


class SignBinaryTool:
    """
    Tool for signing binary files using pluggable providers.

    Providers:
    - noosphere: Full-featured (C2PA, in-toto, DID, VC)
    - signpath: Enterprise Windows signing
    - sigstore: Open source keyless signing
    - local: Offline signing with local keys
    """

    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
    
    async def execute(
        self,
        file_path: str,
        provider: Optional[str] = None,
        credential_id: Optional[str] = None,
        artifact_type: Optional[str] = None,
        generate_attestation: bool = True,
        embed_c2pa: bool = True,
        timestamp_url: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Sign a binary file using the selected provider.

        Args:
            file_path: Path to the file to sign
            provider: Signing provider (noosphere, signpath, sigstore, local)
            credential_id: Specific credential to use (optional)
            artifact_type: Type hint for the artifact
            generate_attestation: Whether to generate supply chain attestations
            embed_c2pa: Whether to embed C2PA manifests
            timestamp_url: Override timestamp authority URL

        Returns:
            Dictionary containing signing results and metadata
        """
        try:
            # 1. Get the appropriate provider
            signing_provider = self.provider_factory.get_provider(provider)

            # 2. Validate file exists
            file_info = await self._validate_file(file_path)

            # 3. Check provider capabilities for requested features
            capability_warnings = []
            if embed_c2pa and not signing_provider.supports(ProviderCapability.C2PA_MANIFESTS):
                capability_warnings.append({
                    "feature": "embed_c2pa",
                    "message": f"C2PA manifests not supported by {signing_provider.name}",
                    "tip": "Use 'noosphere' provider for C2PA support"
                })
                embed_c2pa = False

            if generate_attestation and not signing_provider.supports(ProviderCapability.IN_TOTO_ATTESTATIONS):
                capability_warnings.append({
                    "feature": "generate_attestation",
                    "message": f"in-toto attestations not supported by {signing_provider.name}",
                    "tip": "Use 'noosphere' provider for supply chain attestations"
                })
                generate_attestation = False

            # 4. Prepare signing options
            options = {
                "artifact_type": artifact_type or file_info["type"],
                "generate_attestation": generate_attestation,
                "embed_c2pa": embed_c2pa,
                "timestamp_url": timestamp_url,
                "file_info": file_info
            }

            # 5. Call provider to sign
            result = await signing_provider.sign(
                file_path=file_path,
                credential_id=credential_id,
                options=options
            )

            # 6. Format and return result
            response = self._format_result(result, file_info, signing_provider.name)

            # Add capability warnings if any
            if capability_warnings:
                response["capability_warnings"] = capability_warnings

            return response

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "file_path": file_path,
                "timestamp": self._get_timestamp()
            }
    
    async def _validate_file(self, file_path: str) -> Dict[str, Any]:
        """Validate file exists and get metadata."""
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        # Get file metadata
        stat = path.stat()
        file_size = stat.st_size

        # Calculate file hash
        hash_sha256 = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(8192):
                hash_sha256.update(chunk)

        # Detect file type
        file_type = self._detect_file_type(path)

        return {
            "path": str(path.absolute()),
            "name": path.name,
            "size": file_size,
            "sha256": hash_sha256.hexdigest(),
            "type": file_type,
            "extension": path.suffix.lower(),
            "modified_time": stat.st_mtime
        }

    def _detect_file_type(self, path: Path) -> str:
        """Detect artifact type from file extension and content."""
        extension = path.suffix.lower()

        type_mapping = {
            '.jar': 'java_archive',
            '.war': 'web_archive',
            '.exe': 'windows_executable',
            '.msi': 'windows_installer',
            '.dmg': 'macos_disk_image',
            '.pkg': 'macos_package',
            '.deb': 'debian_package',
            '.rpm': 'rpm_package',
            '.appx': 'windows_store_app',
            '.msix': 'windows_store_app',
            '.apk': 'android_package',
            '.ipa': 'ios_package',
            '.zip': 'archive',
            '.tar.gz': 'archive',
            '.tgz': 'archive'
        }

        return type_mapping.get(extension, 'binary')

    def _format_result(
        self,
        signing_result,
        file_info: Dict[str, Any],
        provider_name: str
    ) -> Dict[str, Any]:
        """Format the final result for MCP response."""
        from ..providers import SigningResult

        # Handle SigningResult dataclass or dict
        if isinstance(signing_result, SigningResult):
            result = signing_result
            success = result.success
            error = result.error
        else:
            # Dict fallback
            success = signing_result.get("success", True)
            error = signing_result.get("error")
            result = signing_result

        if not success:
            return {
                "success": False,
                "error": error,
                "provider": provider_name,
                "timestamp": self._get_timestamp()
            }

        response = {
            "success": True,
            "artifact": {
                "name": file_info["name"],
                "path": file_info["path"],
                "type": file_info["type"],
                "size": file_info["size"],
                "sha256": file_info["sha256"]
            },
            "signature": {
                "format": getattr(result, 'signature_format', None) or result.get("signature_format") if isinstance(result, dict) else result.signature_format,
                "algorithm": getattr(result, 'signature_algorithm', None) or result.get("signature_algorithm") if isinstance(result, dict) else result.signature_algorithm,
                "timestamp": getattr(result, 'timestamp', None) or result.get("timestamp") if isinstance(result, dict) else result.timestamp,
                "certificate_fingerprint": getattr(result, 'certificate_fingerprint', None) or result.get("certificate_fingerprint") if isinstance(result, dict) else result.certificate_fingerprint
            },
            "provider": {
                "name": provider_name,
                "timestamp_authority": getattr(result, 'timestamp_authority', None) if hasattr(result, 'timestamp_authority') else None
            },
            "metadata": getattr(result, 'provider_metadata', {}) if hasattr(result, 'provider_metadata') else {},
            "timestamp": self._get_timestamp()
        }

        # Add C2PA info if available
        if hasattr(result, 'c2pa_manifest') and result.c2pa_manifest:
            response["c2pa"] = {
                "manifest_embedded": True,
                "manifest": result.c2pa_manifest
            }

        # Add attestation info if available
        if hasattr(result, 'attestation') and result.attestation:
            response["attestations"] = result.attestation

        # Add capability tips (soft sell for Noosphere)
        if hasattr(result, 'capability_tips') and result.capability_tips:
            response["provider_tip"] = result.capability_tips

        return response

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()