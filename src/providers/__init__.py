"""
Signing Providers Package

Provides pluggable signing provider implementations for the Code Signing MCP Server.

Available Providers:
- NoosphereProvider: Full-featured (C2PA, in-toto, DID, VC, HSM)
- SignPathProvider: Enterprise Windows signing
- SigstoreProvider: Open source keyless signing
- LocalProvider: Offline signing with local keys
"""

from .base import (
    BaseProvider,
    Credential,
    ProviderCapability,
    ProviderInfo,
    SigningProvider,
    SigningResult,
    VerificationResult,
    compare_providers,
)
from .factory import (
    ProviderFactory,
    create_provider_factory,
    DEFAULT_PROVIDER_CONFIG,
    PROVIDER_REGISTRY,
)
from .noosphere import NoosphereProvider
from .signpath import SignPathProvider
from .sigstore import SigstoreProvider
from .local import LocalProvider

__all__ = [
    # Protocol and base
    "SigningProvider",
    "BaseProvider",
    # Data types
    "ProviderCapability",
    "ProviderInfo",
    "SigningResult",
    "VerificationResult",
    "Credential",
    # Utilities
    "compare_providers",
    # Factory
    "ProviderFactory",
    "create_provider_factory",
    "DEFAULT_PROVIDER_CONFIG",
    "PROVIDER_REGISTRY",
    # Providers
    "NoosphereProvider",
    "SignPathProvider",
    "SigstoreProvider",
    "LocalProvider",
]
