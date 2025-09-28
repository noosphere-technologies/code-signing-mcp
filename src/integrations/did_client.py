"""
DID/VC Client

Handles communication with DID and Verifiable Credential services for
identity management and credential verification.
"""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import aiohttp

from ..config import ServiceConfig


class DIDClient:
    """Client for DID and Verifiable Credential services."""
    
    def __init__(self, did_service_config: ServiceConfig, vc_service_config: ServiceConfig):
        self.did_config = did_service_config
        self.vc_config = vc_service_config
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def initialize(self):
        """Initialize the HTTP client session."""
        headers = {
            "User-Agent": "code-signing-mcp/1.0.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
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
    
    async def get_current_user_did(self) -> str:
        """
        Get the current user's DID from authentication context.
        
        Returns:
            User's DID identifier
        """
        # In a real implementation, this would extract the DID from:
        # - JWT token claims
        # - API key metadata
        # - Session information
        # For now, return a placeholder
        return "did:web:example.com:users:current"
    
    async def resolve_did(self, did: str) -> Dict[str, Any]:
        """
        Resolve a DID to its DID document.
        
        Args:
            did: DID identifier to resolve
            
        Returns:
            DID document with verification methods and services
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.did_config.url, f"/resolve/{did}")
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"DID resolution failed: {str(e)}")
    
    async def get_available_credentials(self, user_did: str) -> List[Dict[str, Any]]:
        """
        Get available signing credentials for a user DID.
        
        Args:
            user_did: User's DID identifier
            
        Returns:
            List of available credentials with metadata
        """
        if not self.session:
            await self.initialize()
        
        try:
            headers = {}
            if self.vc_config.api_key:
                headers["Authorization"] = f"Bearer {self.vc_config.api_key}"
            
            async with self.session.get(
                urljoin(self.vc_config.url, f"/credentials"),
                params={"holder": user_did, "type": "CodeSigningCredential"},
                headers=headers
            ) as response:
                result = await response.json()
                return result.get("credentials", [])
                
        except aiohttp.ClientError as e:
            raise Exception(f"Failed to get credentials: {str(e)}")
    
    async def get_credential(self, user_did: str, credential_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific credential by ID.
        
        Args:
            user_did: User's DID identifier
            credential_id: Credential identifier
            
        Returns:
            Credential details or None if not found
        """
        if not self.session:
            await self.initialize()
        
        try:
            headers = {}
            if self.vc_config.api_key:
                headers["Authorization"] = f"Bearer {self.vc_config.api_key}"
            
            async with self.session.get(
                urljoin(self.vc_config.url, f"/credentials/{credential_id}"),
                params={"holder": user_did},
                headers=headers
            ) as response:
                return await response.json()
                
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                return None
            raise Exception(f"Failed to get credential: {str(e)}")
        except aiohttp.ClientError as e:
            raise Exception(f"Failed to get credential: {str(e)}")
    
    async def verify_credential(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a Verifiable Credential.
        
        Args:
            credential: Verifiable Credential to verify
            
        Returns:
            Verification result with validity and trust information
        """
        if not self.session:
            await self.initialize()
        
        try:
            headers = {}
            if self.vc_config.api_key:
                headers["Authorization"] = f"Bearer {self.vc_config.api_key}"
            
            async with self.session.post(
                urljoin(self.vc_config.url, "/verify"),
                json={"credential": credential},
                headers=headers
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"Credential verification failed: {str(e)}")
    
    async def issue_credential(self, credential_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Issue a new Verifiable Credential.
        
        Args:
            credential_request: Credential issuance request
            
        Returns:
            Newly issued Verifiable Credential
        """
        if not self.session:
            await self.initialize()
        
        try:
            headers = {}
            if self.vc_config.api_key:
                headers["Authorization"] = f"Bearer {self.vc_config.api_key}"
            
            async with self.session.post(
                urljoin(self.vc_config.url, "/issue"),
                json=credential_request,
                headers=headers
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"Credential issuance failed: {str(e)}")
    
    async def sign_attestation(self, user_did: str, attestation_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign an attestation with the user's DID.
        
        Args:
            user_did: User's DID for signing
            attestation_payload: Attestation data to sign
            
        Returns:
            Signed attestation with proof
        """
        if not self.session:
            await self.initialize()
        
        try:
            headers = {}
            if self.did_config.api_key:
                headers["Authorization"] = f"Bearer {self.did_config.api_key}"
            
            request_payload = {
                "issuer": user_did,
                "payload": attestation_payload,
                "proof_purpose": "assertionMethod"
            }
            
            async with self.session.post(
                urljoin(self.did_config.url, "/sign"),
                json=request_payload,
                headers=headers
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"Attestation signing failed: {str(e)}")
    
    async def verify_attestation(self, signed_attestation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a signed attestation.
        
        Args:
            signed_attestation: Signed attestation to verify
            
        Returns:
            Verification result
        """
        if not self.session:
            await self.initialize()
        
        try:
            headers = {}
            if self.did_config.api_key:
                headers["Authorization"] = f"Bearer {self.did_config.api_key}"
            
            async with self.session.post(
                urljoin(self.did_config.url, "/verify"),
                json={"attestation": signed_attestation},
                headers=headers
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"Attestation verification failed: {str(e)}")
    
    async def create_presentation(self, presentation_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a Verifiable Presentation from credentials.
        
        Args:
            presentation_request: Presentation creation request
            
        Returns:
            Verifiable Presentation
        """
        if not self.session:
            await self.initialize()
        
        try:
            headers = {}
            if self.vc_config.api_key:
                headers["Authorization"] = f"Bearer {self.vc_config.api_key}"
            
            async with self.session.post(
                urljoin(self.vc_config.url, "/presentations/create"),
                json=presentation_request,
                headers=headers
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"Presentation creation failed: {str(e)}")
    
    async def verify_presentation(self, presentation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a Verifiable Presentation.
        
        Args:
            presentation: Verifiable Presentation to verify
            
        Returns:
            Verification result with credential validity
        """
        if not self.session:
            await self.initialize()
        
        try:
            headers = {}
            if self.vc_config.api_key:
                headers["Authorization"] = f"Bearer {self.vc_config.api_key}"
            
            async with self.session.post(
                urljoin(self.vc_config.url, "/presentations/verify"),
                json={"presentation": presentation},
                headers=headers
            ) as response:
                return await response.json()
                
        except aiohttp.ClientError as e:
            raise Exception(f"Presentation verification failed: {str(e)}")
    
    async def get_trust_registry_info(self, issuer_did: str) -> Dict[str, Any]:
        """
        Get trust registry information for an issuer DID.
        
        Args:
            issuer_did: Issuer DID to look up
            
        Returns:
            Trust registry information
        """
        if not self.session:
            await self.initialize()
        
        try:
            async with self.session.get(
                urljoin(self.did_config.url, f"/trust-registry/{issuer_did}")
            ) as response:
                return await response.json()
                
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                return {"trusted": False, "reason": "Issuer not found in trust registry"}
            raise Exception(f"Trust registry lookup failed: {str(e)}")
        except aiohttp.ClientError as e:
            raise Exception(f"Trust registry lookup failed: {str(e)}")