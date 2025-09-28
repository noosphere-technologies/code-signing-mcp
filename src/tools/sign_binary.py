"""
Sign Binary Tool

Handles binary file signing by interfacing with the C2PA Artifact cloud service.
Integrates with DID/VC infrastructure for identity and credential management.
"""

import asyncio
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, Optional

import aiofiles
import aiohttp

from ..integrations.c2pa_client import C2PArtifactClient
from ..integrations.did_client import DIDClient
from ..security.policy_engine import PolicyEngine
from ..config import Config


class SignBinaryTool:
    """Tool for signing binary files using C2PA cloud service."""
    
    def __init__(self, c2pa_client: C2PArtifactClient, did_client: DIDClient, config: Config):
        self.c2pa_client = c2pa_client
        self.did_client = did_client
        self.config = config
        self.policy_engine = PolicyEngine(config.policies)
    
    async def execute(
        self,
        file_path: str,
        credential_id: Optional[str] = None,
        artifact_type: Optional[str] = None,
        generate_attestation: bool = True,
        embed_c2pa: bool = True,
        timestamp_url: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Sign a binary file using the C2PA cloud service.
        
        Args:
            file_path: Path to the file to sign
            credential_id: Specific credential to use (optional)
            artifact_type: Type hint for the artifact
            generate_attestation: Whether to generate supply chain attestations
            embed_c2pa: Whether to embed C2PA manifests
            timestamp_url: Override timestamp authority URL
            
        Returns:
            Dictionary containing signing results and metadata
        """
        try:
            # 1. Validate file and permissions
            file_info = await self._validate_file(file_path)
            
            # 2. Get user identity from DID
            user_did = await self.did_client.get_current_user_did()
            
            # 3. Select appropriate credential
            credential = await self._select_credential(
                user_did, credential_id, artifact_type, file_info
            )
            
            # 4. Apply signing policies
            policy_result = await self.policy_engine.validate_signing_request(
                file_info, credential, user_did
            )
            if not policy_result.allowed:
                raise PermissionError(f"Policy violation: {policy_result.reason}")
            
            # 5. Prepare signing request for C2PA service
            signing_request = await self._prepare_signing_request(
                file_path, file_info, credential, user_did, 
                generate_attestation, embed_c2pa, timestamp_url
            )
            
            # 6. Call C2PA cloud service
            signing_result = await self.c2pa_client.sign_artifact(signing_request)
            
            # 7. Generate DID-based attestations if requested
            if generate_attestation:
                attestation = await self._generate_did_attestation(
                    signing_result, user_did, credential
                )
                signing_result["did_attestation"] = attestation
            
            # 8. Return formatted result
            return self._format_result(signing_result, file_info, credential)
            
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
    
    async def _select_credential(
        self, 
        user_did: str, 
        credential_id: Optional[str],
        artifact_type: Optional[str],
        file_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Select appropriate signing credential based on policies and context."""
        
        # If credential explicitly specified, validate and use it
        if credential_id:
            credential = await self.did_client.get_credential(user_did, credential_id)
            if not credential:
                raise ValueError(f"Credential not found: {credential_id}")
            return credential
        
        # Otherwise, apply automatic credential selection
        available_credentials = await self.did_client.get_available_credentials(user_did)
        
        # Apply credential selection policies
        selected = await self.policy_engine.select_credential(
            available_credentials, artifact_type or file_info["type"], file_info
        )
        
        if not selected:
            raise ValueError("No suitable credential found for this artifact")
        
        return selected
    
    async def _prepare_signing_request(
        self,
        file_path: str,
        file_info: Dict[str, Any],
        credential: Dict[str, Any], 
        user_did: str,
        generate_attestation: bool,
        embed_c2pa: bool,
        timestamp_url: Optional[str]
    ) -> Dict[str, Any]:
        """Prepare signing request for C2PA cloud service."""
        
        return {
            "artifact": {
                "file_path": file_path,
                "name": file_info["name"],
                "type": file_info["type"],
                "size": file_info["size"],
                "sha256": file_info["sha256"],
                "metadata": {
                    "extension": file_info["extension"],
                    "modified_time": file_info["modified_time"]
                }
            },
            "credential": {
                "id": credential["id"],
                "type": credential["type"],
                "did": user_did,
                "verification_method": credential.get("verification_method")
            },
            "signing_options": {
                "timestamp_url": timestamp_url or self.config.signing.default_timestamp_url,
                "embed_c2pa": embed_c2pa,
                "generate_attestation": generate_attestation,
                "policy_set": self.config.policies.default_policy_set,
                "include_certificate_chain": True
            },
            "context": {
                "user_did": user_did,
                "mcp_server": "code-signing-mcp",
                "version": "1.0.0",
                "request_id": self._generate_request_id()
            }
        }
    
    async def _generate_did_attestation(
        self,
        signing_result: Dict[str, Any],
        user_did: str,
        credential: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate DID-based attestation for the signing operation."""
        
        attestation_payload = {
            "type": "CodeSigningAttestation",
            "issuer": user_did,
            "subject": signing_result["artifact"]["sha256"],
            "credential_used": credential["id"],
            "timestamp": signing_result["timestamp"],
            "signature_info": {
                "algorithm": signing_result.get("signature_algorithm"),
                "format": signing_result.get("signature_format"),
                "c2pa_manifest": signing_result.get("c2pa_manifest_id")
            }
        }
        
        # Sign the attestation with user's DID
        signed_attestation = await self.did_client.sign_attestation(
            user_did, attestation_payload
        )
        
        return signed_attestation
    
    def _format_result(
        self,
        signing_result: Dict[str, Any],
        file_info: Dict[str, Any],
        credential: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Format the final result for MCP response."""
        
        return {
            "success": True,
            "artifact": {
                "name": file_info["name"],
                "path": file_info["path"],
                "type": file_info["type"],
                "size": file_info["size"],
                "sha256": file_info["sha256"]
            },
            "signature": {
                "format": signing_result.get("signature_format"),
                "algorithm": signing_result.get("signature_algorithm"),
                "timestamp": signing_result.get("timestamp"),
                "certificate_fingerprint": signing_result.get("certificate_fingerprint")
            },
            "credential": {
                "id": credential["id"],
                "type": credential["type"],
                "name": credential.get("name", "Unknown")
            },
            "c2pa": {
                "manifest_embedded": signing_result.get("c2pa_manifest_embedded", False),
                "manifest_id": signing_result.get("c2pa_manifest_id"),
                "verification_url": signing_result.get("c2pa_verification_url")
            },
            "attestations": {
                "slsa_generated": signing_result.get("slsa_attestation_generated", False),
                "did_attestation": signing_result.get("did_attestation"),
                "in_toto_link": signing_result.get("in_toto_link")
            },
            "policy_compliance": {
                "policy_set": signing_result.get("policy_set_applied"),
                "compliance_verified": True,
                "violations": []
            },
            "metadata": {
                "request_id": signing_result.get("request_id"),
                "processing_time_ms": signing_result.get("processing_time_ms"),
                "mcp_server_version": "1.0.0"
            }
        }
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()