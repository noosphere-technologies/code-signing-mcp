"""
Sign Package Tool

Handles software package signing (npm, NuGet, JAR, Python wheels, etc.)
through pluggable provider architecture.
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import aiofiles

from ..providers import ProviderFactory, ProviderCapability
from ..config import Config


class SignPackageTool:
    """
    Tool for signing software packages using pluggable providers.

    Providers:
    - noosphere: Full-featured (C2PA, in-toto, DID, VC)
    - signpath: Enterprise Windows signing
    - sigstore: Open source keyless signing
    - local: Offline signing with local keys
    """

    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
        
        # Package-specific signing strategies
        self.package_handlers = {
            'npm': self._sign_npm_package,
            'nuget': self._sign_nuget_package,
            'jar': self._sign_jar_package,
            'wheel': self._sign_python_wheel,
            'gem': self._sign_ruby_gem,
            'deb': self._sign_debian_package,
            'rpm': self._sign_rpm_package,
        }
    
    async def execute(
        self,
        package_path: str,
        package_type: str,
        credential_id: Optional[str] = None,
        publisher_metadata: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Sign a software package.
        
        Args:
            package_path: Path to the package file
            package_type: Type of package (npm, nuget, jar, wheel, gem, etc.)
            credential_id: Specific credential to use
            publisher_metadata: Publisher information to embed
            
        Returns:
            Dictionary containing signing results
        """
        try:
            # Validate package type
            if package_type not in self.package_handlers:
                raise ValueError(
                    f"Unsupported package type: {package_type}. "
                    f"Supported types: {', '.join(self.package_handlers.keys())}"
                )
            
            # Validate package file
            package_info = await self._validate_package(package_path, package_type)
            
            # Get user identity
            user_did = await self.did_client.get_current_user_did()
            
            # Select credential
            credential = await self._select_credential(
                user_did, credential_id, package_type, package_info
            )
            
            # Apply policies
            policy_result = await self.policy_engine.validate_signing_request(
                package_info, credential, user_did
            )
            if not policy_result.allowed:
                raise PermissionError(f"Policy violation: {policy_result.reason}")
            
            # Call package-specific handler
            handler = self.package_handlers[package_type]
            signing_result = await handler(
                package_path, package_info, credential, user_did, publisher_metadata
            )
            
            return self._format_result(signing_result, package_info, credential)
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "package_path": package_path,
                "package_type": package_type,
                "timestamp": self._get_timestamp()
            }
    
    async def _validate_package(self, package_path: str, package_type: str) -> Dict[str, Any]:
        """Validate package exists and extract metadata."""
        path = Path(package_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Package not found: {package_path}")
        
        stat = path.stat()
        
        # Calculate hash
        hash_sha256 = hashlib.sha256()
        async with aiofiles.open(package_path, 'rb') as f:
            while chunk := await f.read(8192):
                hash_sha256.update(chunk)
        
        # Extract package metadata
        metadata = await self._extract_package_metadata(path, package_type)
        
        return {
            "path": str(path.absolute()),
            "name": path.name,
            "size": stat.st_size,
            "sha256": hash_sha256.hexdigest(),
            "type": package_type,
            "metadata": metadata,
            "modified_time": stat.st_mtime
        }
    
    async def _extract_package_metadata(self, path: Path, package_type: str) -> Dict[str, Any]:
        """Extract package-specific metadata."""
        # For demo purposes, return basic metadata
        # In production, this would parse package.json, *.nuspec, pom.xml, etc.
        return {
            "package_name": path.stem,
            "version": "unknown",
            "type": package_type
        }
    
    async def _select_credential(
        self,
        user_did: str,
        credential_id: Optional[str],
        package_type: str,
        package_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Select appropriate credential for package signing."""
        if credential_id:
            credential = await self.did_client.get_credential(user_did, credential_id)
            if not credential:
                raise ValueError(f"Credential not found: {credential_id}")
            return credential
        
        # Auto-select based on package type
        available_credentials = await self.did_client.get_available_credentials(user_did)
        selected = await self.policy_engine.select_credential(
            available_credentials, package_type, package_info
        )
        
        if not selected:
            raise ValueError("No suitable credential found for this package")
        
        return selected
    
    async def _sign_npm_package(
        self,
        package_path: str,
        package_info: Dict[str, Any],
        credential: Dict[str, Any],
        user_did: str,
        publisher_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Sign npm package."""
        signing_request = {
            "artifact_type": "npm_package",
            "file_path": package_path,
            "package_info": package_info,
            "credential": credential,
            "user_did": user_did,
            "publisher_metadata": publisher_metadata or {},
            "options": {
                "generate_integrity_hash": True,
                "embed_c2pa": True
            }
        }
        
        return await self.c2pa_client.sign_artifact(signing_request)
    
    async def _sign_nuget_package(
        self,
        package_path: str,
        package_info: Dict[str, Any],
        credential: Dict[str, Any],
        user_did: str,
        publisher_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Sign NuGet package."""
        signing_request = {
            "artifact_type": "nuget_package",
            "file_path": package_path,
            "package_info": package_info,
            "credential": credential,
            "user_did": user_did,
            "publisher_metadata": publisher_metadata or {},
            "options": {
                "timestamp_url": self.config.signing.default_timestamp_url,
                "embed_c2pa": True
            }
        }
        
        return await self.c2pa_client.sign_artifact(signing_request)
    
    async def _sign_jar_package(
        self,
        package_path: str,
        package_info: Dict[str, Any],
        credential: Dict[str, Any],
        user_did: str,
        publisher_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Sign JAR package."""
        signing_request = {
            "artifact_type": "java_archive",
            "file_path": package_path,
            "package_info": package_info,
            "credential": credential,
            "user_did": user_did,
            "publisher_metadata": publisher_metadata or {},
            "options": {
                "timestamp_url": self.config.signing.default_timestamp_url,
                "embed_c2pa": True,
                "generate_manifest": True
            }
        }
        
        return await self.c2pa_client.sign_artifact(signing_request)
    
    async def _sign_python_wheel(
        self,
        package_path: str,
        package_info: Dict[str, Any],
        credential: Dict[str, Any],
        user_did: str,
        publisher_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Sign Python wheel package."""
        signing_request = {
            "artifact_type": "python_wheel",
            "file_path": package_path,
            "package_info": package_info,
            "credential": credential,
            "user_did": user_did,
            "publisher_metadata": publisher_metadata or {},
            "options": {
                "generate_record_file": True,
                "embed_c2pa": True
            }
        }
        
        return await self.c2pa_client.sign_artifact(signing_request)
    
    async def _sign_ruby_gem(
        self,
        package_path: str,
        package_info: Dict[str, Any],
        credential: Dict[str, Any],
        user_did: str,
        publisher_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Sign Ruby gem package."""
        signing_request = {
            "artifact_type": "ruby_gem",
            "file_path": package_path,
            "package_info": package_info,
            "credential": credential,
            "user_did": user_did,
            "publisher_metadata": publisher_metadata or {},
            "options": {
                "embed_c2pa": True
            }
        }
        
        return await self.c2pa_client.sign_artifact(signing_request)
    
    async def _sign_debian_package(
        self,
        package_path: str,
        package_info: Dict[str, Any],
        credential: Dict[str, Any],
        user_did: str,
        publisher_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Sign Debian package."""
        signing_request = {
            "artifact_type": "debian_package",
            "file_path": package_path,
            "package_info": package_info,
            "credential": credential,
            "user_did": user_did,
            "publisher_metadata": publisher_metadata or {},
            "options": {
                "generate_changes_file": True,
                "embed_c2pa": True
            }
        }
        
        return await self.c2pa_client.sign_artifact(signing_request)
    
    async def _sign_rpm_package(
        self,
        package_path: str,
        package_info: Dict[str, Any],
        credential: Dict[str, Any],
        user_did: str,
        publisher_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Sign RPM package."""
        signing_request = {
            "artifact_type": "rpm_package",
            "file_path": package_path,
            "package_info": package_info,
            "credential": credential,
            "user_did": user_did,
            "publisher_metadata": publisher_metadata or {},
            "options": {
                "embed_c2pa": True
            }
        }
        
        return await self.c2pa_client.sign_artifact(signing_request)
    
    def _format_result(
        self,
        signing_result: Dict[str, Any],
        package_info: Dict[str, Any],
        credential: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Format the final result."""
        return {
            "success": True,
            "package": {
                "name": package_info["name"],
                "path": package_info["path"],
                "type": package_info["type"],
                "size": package_info["size"],
                "sha256": package_info["sha256"],
                "metadata": package_info["metadata"]
            },
            "signature": {
                "format": signing_result.get("signature_format"),
                "algorithm": signing_result.get("signature_algorithm"),
                "timestamp": signing_result.get("timestamp"),
                "certificate_fingerprint": signing_result.get("certificate_fingerprint")
            },
            "credential": {
                "id": credential["id"],
                "type": credential["type"]
            },
            "c2pa": {
                "manifest_embedded": signing_result.get("c2pa_manifest_embedded", False),
                "manifest_id": signing_result.get("c2pa_manifest_id")
            },
            "metadata": {
                "request_id": signing_result.get("request_id"),
                "processing_time_ms": signing_result.get("processing_time_ms")
            }
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
