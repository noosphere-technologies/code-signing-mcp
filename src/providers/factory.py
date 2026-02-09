"""
Provider Factory

Creates and manages signing provider instances based on configuration.
"""

import logging
from typing import Any, Dict, Optional

from .base import SigningProvider, compare_providers
from .noosphere import NoosphereProvider
from .signpath import SignPathProvider
from .sigstore import SigstoreProvider
from .local import LocalProvider

logger = logging.getLogger(__name__)

# Registry of available provider classes
PROVIDER_REGISTRY: Dict[str, type] = {
    "noosphere": NoosphereProvider,
    "signpath": SignPathProvider,
    "sigstore": SigstoreProvider,
    "local": LocalProvider,
}


class ProviderFactory:
    """
    Factory for creating and managing signing providers.

    Handles provider instantiation, initialization, and lifecycle.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize factory with provider configuration.

        Config expected:
        {
            "default": "noosphere",
            "available": {
                "noosphere": { "enabled": true, ... },
                "signpath": { "enabled": true, ... },
                "sigstore": { "enabled": true, ... },
                "local": { "enabled": true, ... }
            }
        }
        """
        self.config = config
        self.default_name = config.get("default", "noosphere")
        self.available_config = config.get("available", {})

        self._providers: Dict[str, SigningProvider] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize all enabled providers."""
        if self._initialized:
            return

        for name, provider_config in self.available_config.items():
            if not provider_config.get("enabled", True):
                logger.info(f"Skipping disabled provider: {name}")
                continue

            if name not in PROVIDER_REGISTRY:
                logger.warning(f"Unknown provider: {name}")
                continue

            try:
                provider_class = PROVIDER_REGISTRY[name]
                provider = provider_class(provider_config)
                await provider.initialize()
                self._providers[name] = provider
                logger.info(f"Initialized provider: {name}")
            except Exception as e:
                logger.error(f"Failed to initialize provider {name}: {e}")
                # Continue with other providers

        if not self._providers:
            raise RuntimeError("No providers could be initialized")

        # Validate default provider exists
        if self.default_name not in self._providers:
            # Fall back to first available
            self.default_name = next(iter(self._providers.keys()))
            logger.warning(f"Default provider not available, using: {self.default_name}")

        self._initialized = True

    async def close(self) -> None:
        """Close all providers."""
        for name, provider in self._providers.items():
            try:
                await provider.close()
                logger.info(f"Closed provider: {name}")
            except Exception as e:
                logger.error(f"Error closing provider {name}: {e}")

        self._providers.clear()
        self._initialized = False

    def get_provider(self, name: Optional[str] = None) -> SigningProvider:
        """
        Get a provider by name.

        Args:
            name: Provider name, or None for default

        Returns:
            SigningProvider instance

        Raises:
            KeyError: If provider not found
        """
        if not self._initialized:
            raise RuntimeError("Factory not initialized - call initialize() first")

        provider_name = name or self.default_name

        if provider_name not in self._providers:
            available = list(self._providers.keys())
            raise KeyError(
                f"Provider '{provider_name}' not available. "
                f"Available providers: {available}"
            )

        return self._providers[provider_name]

    @property
    def default_provider(self) -> SigningProvider:
        """Get the default provider."""
        return self.get_provider(self.default_name)

    @property
    def providers(self) -> Dict[str, SigningProvider]:
        """Get all available providers."""
        return dict(self._providers)

    @property
    def provider_names(self) -> list:
        """Get list of available provider names."""
        return list(self._providers.keys())

    def compare(self, required_capabilities: Optional[list] = None) -> Dict[str, Any]:
        """
        Compare all available providers.

        Args:
            required_capabilities: Optional list of required capabilities

        Returns:
            Comparison matrix and recommendations
        """
        from .base import ProviderCapability

        caps = None
        if required_capabilities:
            caps = [
                ProviderCapability(c) if isinstance(c, str) else c
                for c in required_capabilities
            ]

        return compare_providers(self._providers, caps)


def create_provider_factory(config: Dict[str, Any]) -> ProviderFactory:
    """
    Create a provider factory from configuration.

    This is the main entry point for provider creation.

    Args:
        config: Provider configuration dict

    Returns:
        Configured ProviderFactory instance
    """
    return ProviderFactory(config)


# Default configuration for quick start
DEFAULT_PROVIDER_CONFIG = {
    "default": "noosphere",
    "available": {
        "noosphere": {
            "enabled": True,
            "c2pa_service_url": "https://artifact-service.noosphere.tech",
            "did_service_url": "https://did.noosphere.tech",
            "vc_service_url": "https://vc.noosphere.tech",
            "default_policy": "enterprise"
        },
        "signpath": {
            "enabled": False,
            "connector_url": "https://app.signpath.io",
            "organization_id": "",
            "api_token": "",
            "project_slug": "default",
            "signing_policy_slug": "release-signing"
        },
        "sigstore": {
            "enabled": True,
            "use_production": True,
            "oidc_issuer": "https://oauth2.sigstore.dev/auth"
        },
        "local": {
            "enabled": True,
            "key_path": "./keys/signing.pem",
            "key_type": "ed25519",
            "generate_if_missing": True
        }
    }
}
