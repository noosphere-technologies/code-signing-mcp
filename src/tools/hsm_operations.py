"""
HSM Operations Tool

Manages Hardware Security Module operations for enterprise key management.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..providers import ProviderFactory
from ..config import Config


class HSMOperationsTool:
    """Tool for HSM operations."""
    
    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
        
        self.operations = {
            'list_keys': self._list_keys,
            'generate_key': self._generate_key,
            'get_info': self._get_info,
            'backup': self._backup_keys
        }
    
    async def execute(
        self,
        operation: str,
        key_label: Optional[str] = None,
        key_type: Optional[str] = None,
        backup_location: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Perform HSM operations.
        
        Args:
            operation: Operation to perform (list_keys, generate_key, get_info, backup)
            key_label: HSM key label
            key_type: Key type for generation
            backup_location: Backup destination
            
        Returns:
            Dictionary containing operation results
        """
        try:
            # Validate operation
            if operation not in self.operations:
                raise ValueError(
                    f"Invalid operation: {operation}. "
                    f"Valid operations: {', '.join(self.operations.keys())}"
                )
            
            # Check HSM availability
            hsm_available = await self._check_hsm_availability()
            if not hsm_available:
                raise RuntimeError("No HSM available or HSM not configured")
            
            # Get user identity
            user_did = await self.did_client.get_current_user_did()
            
            # Execute operation
            handler = self.operations[operation]
            result = await handler(user_did, key_label, key_type, backup_location)
            
            return {
                "success": True,
                "operation": operation,
                "result": result,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "success": False,
                "operation": operation,
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    async def _check_hsm_availability(self) -> bool:
        """Check if HSM is available and configured."""
        try:
            hsm_config = self.config.hsm
            if not hsm_config or not hsm_config.get("enabled"):
                return False
            
            # Test HSM connection
            hsm_info = await self.did_client.get_hsm_info()
            return hsm_info.get("available", False)
            
        except Exception:
            return False
    
    async def _list_keys(
        self,
        user_did: str,
        key_label: Optional[str],
        key_type: Optional[str],
        backup_location: Optional[str]
    ) -> Dict[str, Any]:
        """List keys in HSM."""
        # Get all keys from HSM
        keys = await self.did_client.list_hsm_keys(user_did)
        
        # Filter by label if provided
        if key_label:
            keys = [k for k in keys if k.get("label") == key_label]
        
        # Filter by type if provided
        if key_type:
            keys = [k for k in keys if k.get("type") == key_type]
        
        return {
            "keys": keys,
            "total_count": len(keys),
            "hsm_slot": self.config.hsm.get("slot", 0)
        }
    
    async def _generate_key(
        self,
        user_did: str,
        key_label: Optional[str],
        key_type: Optional[str],
        backup_location: Optional[str]
    ) -> Dict[str, Any]:
        """Generate a new key in HSM."""
        if not key_label:
            raise ValueError("key_label is required for key generation")
        
        if not key_type:
            key_type = "RSA"
        
        # Validate key type
        valid_types = ["RSA", "ECDSA", "EC", "AES"]
        if key_type.upper() not in valid_types:
            raise ValueError(
                f"Invalid key type: {key_type}. "
                f"Valid types: {', '.join(valid_types)}"
            )
        
        # Determine key size
        if key_type.upper() == "RSA":
            key_size = 2048
        elif key_type.upper() in ["ECDSA", "EC"]:
            key_size = 256
        else:
            key_size = 256
        
        # Generate key in HSM
        key_info = await self.did_client.generate_hsm_key(
            algorithm=key_type,
            key_size=key_size,
            user_did=user_did,
            key_label=key_label
        )
        
        return {
            "key_generated": True,
            "key_label": key_label,
            "key_type": key_type,
            "key_size": key_size,
            "key_id": key_info.get("key_id"),
            "public_key": key_info.get("public_key"),
            "hsm_slot": self.config.hsm.get("slot", 0)
        }
    
    async def _get_info(
        self,
        user_did: str,
        key_label: Optional[str],
        key_type: Optional[str],
        backup_location: Optional[str]
    ) -> Dict[str, Any]:
        """Get HSM information."""
        hsm_info = await self.did_client.get_hsm_info()
        
        # Get key count
        keys = await self.did_client.list_hsm_keys(user_did)
        
        return {
            "hsm_manufacturer": hsm_info.get("manufacturer", "Unknown"),
            "hsm_model": hsm_info.get("model", "Unknown"),
            "hsm_serial": hsm_info.get("serial_number", "Unknown"),
            "firmware_version": hsm_info.get("firmware_version", "Unknown"),
            "slot_id": hsm_info.get("slot_id", 0),
            "slot_description": hsm_info.get("slot_description", ""),
            "total_keys": len(keys),
            "available_algorithms": hsm_info.get("algorithms", [
                "RSA-2048", "RSA-3072", "RSA-4096",
                "ECDSA-P256", "ECDSA-P384", "ECDSA-P521"
            ]),
            "fips_mode": hsm_info.get("fips_mode", False),
            "free_storage": hsm_info.get("free_storage_bytes", 0),
            "total_storage": hsm_info.get("total_storage_bytes", 0)
        }
    
    async def _backup_keys(
        self,
        user_did: str,
        key_label: Optional[str],
        key_type: Optional[str],
        backup_location: Optional[str]
    ) -> Dict[str, Any]:
        """Backup HSM keys."""
        if not backup_location:
            raise ValueError("backup_location is required for backup operation")
        
        # Get keys to backup
        keys = await self.did_client.list_hsm_keys(user_did)
        
        # Filter by label if provided
        if key_label:
            keys = [k for k in keys if k.get("label") == key_label]
        
        if not keys:
            raise ValueError("No keys found to backup")
        
        # Perform backup
        backup_result = await self.did_client.backup_hsm_keys(
            keys=keys,
            destination=backup_location,
            user_did=user_did
        )
        
        return {
            "backup_completed": True,
            "keys_backed_up": len(keys),
            "backup_location": backup_location,
            "backup_file": backup_result.get("backup_file"),
            "backup_size_bytes": backup_result.get("size_bytes", 0),
            "encrypted": backup_result.get("encrypted", True),
            "backup_timestamp": self._get_timestamp()
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
