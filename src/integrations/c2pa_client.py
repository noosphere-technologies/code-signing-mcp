"""
C2PA Artifact Service Client

Handles communication with the C2PA Artifact cloud service which contains
the HSM integration and actual signing capabilities.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import aiohttp
import aiofiles

from ..config import ServiceConfig


class C2PArtifactClient:
    """Client for C2PA Artifact cloud signing service."""
    
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.base_url = config.url
        self.api_key = config.api_key
        self.timeout = aiohttp.ClientTimeout(total=config.timeout)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def initialize(self):
        """Initialize the HTTP client session."""
        headers = {
            "User-Agent": "code-signing-mcp/1.0.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=self.timeout,
            raise_for_status=True
        )
    
    async def close(self):
        """Close the HTTP client session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def sign_artifact(self, signing_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign an artifact using the C2PA cloud service.
        
        Args:
            signing_request: Complete signing request with artifact info, credential, and options
            
        Returns:
            Signing result with signature info, C2PA manifest, and attestations
        """
        if not self.session:
            await self.initialize()
        
        try:
            # Upload file if needed
            file_id = await self._upload_artifact(signing_request["artifact"])
            
            # Prepare signing request
            request_payload = {
                "file_id": file_id,
                "credential": signing_request["credential"],
                "signing_options": signing_request["signing_options"],
                "context": signing_request["context"]
            }
            
            # Call signing endpoint
            async with self.session.post(
                urljoin(self.base_url, "/api/v1/sign"),
                json=request_payload
            ) as response:
                result = await response.json()
                
                # Download signed artifact if applicable
                if result.get("signed_file_id"):
                    result["signed_file_path"] = await self._download_signed_artifact(
                        result["signed_file_id"],
                        signing_request["artifact"]["file_path"]
                    )
                
                return result
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"Signing operation failed: {str(e)}")
    
    async def verify_signature(self, verification_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a signature using the C2PA cloud service.
        
        Args:
            verification_request: Verification request with file info and options
            
        Returns:
            Verification result with signature validity and certificate details
        """
        if not self.session:
            await self.initialize()
        
        try:
            # Upload file for verification
            file_id = await self._upload_artifact(verification_request["artifact"])
            
            request_payload = {
                "file_id": file_id,
                "verification_options": verification_request.get("options", {}),
                "context": verification_request.get("context", {})
            }
            
            async with self.session.post(
                urljoin(self.base_url, "/api/v1/verify"),
                json=request_payload
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"Verification operation failed: {str(e)}")
    
    async def get_credentials(self, user_did: str) -> List[Dict[str, Any]]:
        """
        Get available signing credentials for a user.
        
        Args:
            user_did: User's DID identifier
            
        Returns:
            List of available credentials with metadata
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.base_url, f"/api/v1/credentials"),
                params={"user_did": user_did}
            ) as response:
                result = await response.json()
                return result.get("credentials", [])
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to get credentials: {str(e)}")
    
    async def get_credential_info(self, credential_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific credential.
        
        Args:
            credential_id: Credential identifier
            
        Returns:
            Credential details including certificate info and expiry
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.base_url, f"/api/v1/credentials/{credential_id}")
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to get credential info: {str(e)}")
    
    async def create_signing_request(self, csr_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a Certificate Signing Request.
        
        Args:
            csr_request: CSR generation request with subject DN and key parameters
            
        Returns:
            CSR in PEM format and key reference
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.post(
                urljoin(self.base_url, "/api/v1/csr/create"),
                json=csr_request
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"CSR creation failed: {str(e)}")
    
    async def install_certificate(self, install_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Install a new certificate for a credential.
        
        Args:
            install_request: Certificate installation request
            
        Returns:
            Installation result and updated credential info
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.post(
                urljoin(self.base_url, "/api/v1/certificates/install"),
                json=install_request
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"Certificate installation failed: {str(e)}")
    
    async def hsm_operations(self, operation_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform HSM operations (key generation, info, etc.).
        
        Args:
            operation_request: HSM operation request
            
        Returns:
            Operation result
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.post(
                urljoin(self.base_url, "/api/v1/hsm/operations"),
                json=operation_request
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"HSM operation failed: {str(e)}")
    
    async def get_audit_trail(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query audit trail from C2PA service.
        
        Args:
            query_params: Query parameters for audit trail
            
        Returns:
            Audit records matching the query
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.base_url, "/api/v1/audit"),
                params=query_params
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"Audit trail query failed: {str(e)}")
    
    async def batch_sign(self, batch_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform batch signing operations.
        
        Args:
            batch_request: Batch signing request with multiple artifacts
            
        Returns:
            Batch operation results
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.post(
                urljoin(self.base_url, "/api/v1/batch/sign"),
                json=batch_request
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"C2PA service communication error: {str(e)}")
        except Exception as e:
            raise Exception(f"Batch signing failed: {str(e)}")
    
    async def _upload_artifact(self, artifact_info: Dict[str, Any]) -> str:
        """Upload artifact file to C2PA service."""
        file_path = artifact_info["file_path"]
        
        data = aiohttp.FormData()
        
        # Add file
        async with aiofiles.open(file_path, 'rb') as f:
            file_content = await f.read()
            data.add_field(
                'file',
                file_content,
                filename=artifact_info["name"],
                content_type='application/octet-stream'
            )
        
        # Add metadata
        metadata = {
            "type": artifact_info["type"],
            "size": artifact_info["size"],
            "sha256": artifact_info["sha256"]
        }
        data.add_field('metadata', json.dumps(metadata))
        
        async with self.session.post(
            urljoin(self.base_url, "/api/v1/upload"),
            data=data
        ) as response:
            result = await response.json()
            return result["file_id"]
    
    async def _download_signed_artifact(self, file_id: str, original_path: str) -> str:
        """Download signed artifact from C2PA service."""
        async with self.session.get(
            urljoin(self.base_url, f"/api/v1/download/{file_id}")
        ) as response:
            # Save to same location with .signed suffix
            from pathlib import Path
            original = Path(original_path)
            signed_path = original.parent / f"{original.stem}.signed{original.suffix}"
            
            async with aiofiles.open(signed_path, 'wb') as f:
                async for chunk in response.content.iter_chunked(8192):
                    await f.write(chunk)
            
            return str(signed_path)