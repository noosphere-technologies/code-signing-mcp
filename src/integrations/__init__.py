"""
Integration clients for external services.

This module contains clients for interfacing with:
- C2PA Artifact cloud service (core signing engine)
- DID/VC services (identity and credential management)
- Metadata and trust services
"""

from .c2pa_client import C2PArtifactClient
from .did_client import DIDClient
from .metadata_client import MetadataServiceClient

__all__ = [
    "C2PArtifactClient",
    "DIDClient", 
    "MetadataServiceClient"
]