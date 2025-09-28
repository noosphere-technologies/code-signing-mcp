"""
Metadata Service Client

Handles communication with Noosphere metadata services including IPFS integration,
trust registry, and provenance tracking.
"""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import aiohttp

from ..config import ServiceConfig


class MetadataServiceClient:
    """Client for Noosphere metadata and trust services."""
    
    def __init__(self, config: ServiceConfig, ipfs_config: Dict[str, Any]):
        self.config = config
        self.ipfs_config = ipfs_config
        self.timeout = aiohttp.ClientTimeout(total=config.timeout)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def initialize(self):
        """Initialize the HTTP client session."""
        headers = {
            "User-Agent": "code-signing-mcp/1.0.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        
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
    
    async def publish_to_ipfs(self, file_path: str, metadata: Dict[str, Any]) -> str:
        """
        Publish a signed artifact to IPFS.
        
        Args:
            file_path: Path to the file to publish
            metadata: Additional metadata to include
            
        Returns:
            IPFS CID (Content Identifier)
        """
        if not self.session:
            await self.initialize()
        
        try:
            # Upload file to IPFS node at 35.223.165.115:5001 (from your GitHub Actions)
            ipfs_url = f"http://{self.ipfs_config['host']}:{self.ipfs_config['port']}/api/v0/add"
            
            data = aiohttp.FormData()
            
            # Add the file
            with open(file_path, 'rb') as f:
                data.add_field(
                    'file',
                    f,
                    filename=metadata.get('name', 'signed-artifact'),
                    content_type='application/octet-stream'
                )
            
            # Add metadata as additional file
            metadata_json = json.dumps(metadata, indent=2)
            data.add_field(
                'metadata',
                metadata_json,
                filename=f"{metadata.get('name', 'artifact')}.metadata.json",
                content_type='application/json'
            )
            
            async with self.session.post(ipfs_url, data=data, params={'wrap-with-directory': 'true'}) as response:
                result = await response.text()
                
                # Parse IPFS response (usually newline-delimited JSON)
                lines = result.strip().split('\n')
                directory_cid = None
                
                for line in lines:
                    ipfs_object = json.loads(line)
                    if ipfs_object.get('Name') == '':  # Directory object
                        directory_cid = ipfs_object['Hash']
                        break
                
                if not directory_cid:
                    raise Exception("Failed to get IPFS directory CID")
                
                return directory_cid
                
        except Exception as e:
            raise Exception(f"IPFS publishing failed: {str(e)}")
    
    async def get_ipfs_content(self, cid: str) -> bytes:
        """
        Retrieve content from IPFS by CID.
        
        Args:
            cid: IPFS Content Identifier
            
        Returns:
            File content as bytes
        """
        if not self.session:
            await self.initialize()
        
        try:
            ipfs_url = f"http://{self.ipfs_config['host']}:{self.ipfs_config['port']}/api/v0/cat"
            
            async with self.session.post(ipfs_url, params={'arg': cid}) as response:
                return await response.read()
                
        except Exception as e:
            raise Exception(f"IPFS retrieval failed: {str(e)}")
    
    async def store_attestation(self, attestation: Dict[str, Any]) -> str:
        """
        Store a supply chain attestation in the metadata service.
        
        Args:
            attestation: Attestation data to store
            
        Returns:
            Attestation ID
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.post(
                urljoin(self.config.url, "/api/v1/attestations"),
                json=attestation
            ) as response:
                result = await response.json()
                return result["attestation_id"]
                
        except Exception as e:
            raise Exception(f"Attestation storage failed: {str(e)}")
    
    async def get_attestation(self, attestation_id: str) -> Dict[str, Any]:
        """
        Retrieve an attestation by ID.
        
        Args:
            attestation_id: Attestation identifier
            
        Returns:
            Attestation data
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.config.url, f"/api/v1/attestations/{attestation_id}")
            ) as response:
                return await response.json()
                
        except Exception as e:
            raise Exception(f"Attestation retrieval failed: {str(e)}")
    
    async def query_attestations(self, query_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Query attestations based on criteria.
        
        Args:
            query_params: Query parameters (artifact_hash, issuer, etc.)
            
        Returns:
            List of matching attestations
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.config.url, "/api/v1/attestations"),
                params=query_params
            ) as response:
                result = await response.json()
                return result.get("attestations", [])
                
        except Exception as e:
            raise Exception(f"Attestation query failed: {str(e)}")
    
    async def store_provenance(self, provenance_data: Dict[str, Any]) -> str:
        """
        Store provenance information for an artifact.
        
        Args:
            provenance_data: Provenance metadata
            
        Returns:
            Provenance record ID
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.post(
                urljoin(self.config.url, "/api/v1/provenance"),
                json=provenance_data
            ) as response:
                result = await response.json()
                return result["provenance_id"]
                
        except Exception as e:
            raise Exception(f"Provenance storage failed: {str(e)}")
    
    async def get_trust_registry_entry(self, identifier: str) -> Dict[str, Any]:
        """
        Get trust registry information for an identifier.
        
        Args:
            identifier: DID, certificate fingerprint, or other identifier
            
        Returns:
            Trust registry entry
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.config.url, f"/api/v1/trust-registry/{identifier}")
            ) as response:
                return await response.json()
                
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                return {"trusted": False, "reason": "Identifier not found in trust registry"}
            raise Exception(f"Trust registry lookup failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Trust registry lookup failed: {str(e)}")
    
    async def add_trust_registry_entry(self, entry_data: Dict[str, Any]) -> bool:
        """
        Add an entry to the trust registry.
        
        Args:
            entry_data: Trust registry entry data
            
        Returns:
            Success status
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.post(
                urljoin(self.config.url, "/api/v1/trust-registry"),
                json=entry_data
            ) as response:
                result = await response.json()
                return result.get("success", False)
                
        except Exception as e:
            raise Exception(f"Trust registry entry creation failed: {str(e)}")
    
    async def get_artifact_metadata(self, artifact_hash: str) -> Dict[str, Any]:
        """
        Get stored metadata for an artifact.
        
        Args:
            artifact_hash: SHA256 hash of the artifact
            
        Returns:
            Artifact metadata
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.config.url, f"/api/v1/artifacts/{artifact_hash}")
            ) as response:
                return await response.json()
                
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                return {"found": False, "reason": "Artifact not found"}
            raise Exception(f"Artifact metadata lookup failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Artifact metadata lookup failed: {str(e)}")
    
    async def store_artifact_metadata(self, metadata: Dict[str, Any]) -> bool:
        """
        Store metadata for an artifact.
        
        Args:
            metadata: Artifact metadata to store
            
        Returns:
            Success status
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.post(
                urljoin(self.config.url, "/api/v1/artifacts"),
                json=metadata
            ) as response:
                result = await response.json()
                return result.get("success", False)
                
        except Exception as e:
            raise Exception(f"Artifact metadata storage failed: {str(e)}")
    
    async def pin_to_ipfs(self, cid: str, metadata: Dict[str, Any]) -> bool:
        """
        Pin content to IPFS for persistence.
        
        Args:
            cid: IPFS Content Identifier to pin
            metadata: Additional metadata for the pin
            
        Returns:
            Success status
        """
        if not self.session:
            await self.initialize()
        
        try:
            ipfs_url = f"http://{self.ipfs_config['host']}:{self.ipfs_config['port']}/api/v0/pin/add"
            
            async with self.session.post(ipfs_url, params={'arg': cid, 'recursive': 'true'}) as response:
                result = await response.json()
                
                # Also store pin metadata in our service
                pin_data = {
                    "cid": cid,
                    "pinned_at": self._get_timestamp(),
                    "metadata": metadata
                }
                
                await self.session.post(
                    urljoin(self.config.url, "/api/v1/ipfs/pins"),
                    json=pin_data
                )
                
                return True
                
        except Exception as e:
            raise Exception(f"IPFS pinning failed: {str(e)}")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()