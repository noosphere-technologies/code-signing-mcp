"""Tests for provider abstraction layer."""

import pytest
from src.providers import (
    ProviderFactory,
    ProviderCapability,
    LocalProvider,
    DEFAULT_PROVIDER_CONFIG,
)


class TestProviderCapability:
    """Test provider capability enumeration."""

    def test_all_capabilities_defined(self):
        """Ensure all expected capabilities exist."""
        expected = [
            "binary_signing",
            "c2pa_manifests",
            "in_toto_attestations",
            "did_identity",
            "verifiable_credentials",
        ]
        for cap in expected:
            assert hasattr(ProviderCapability, cap.upper())

    def test_capability_values(self):
        """Ensure capability values are strings."""
        assert ProviderCapability.BINARY_SIGNING.value == "binary_signing"
        assert ProviderCapability.C2PA_MANIFESTS.value == "c2pa_manifests"


class TestLocalProvider:
    """Test local signing provider."""

    @pytest.fixture
    def local_config(self, tmp_path):
        """Create config for local provider."""
        return {
            "enabled": True,
            "key_path": str(tmp_path / "test_key.pem"),
            "key_type": "ed25519",
            "generate_if_missing": True,
        }

    def test_local_provider_info(self, local_config):
        """Test local provider info."""
        provider = LocalProvider(local_config)
        info = provider.info

        assert info.name == "local"
        assert info.tier == "basic"
        assert ProviderCapability.BINARY_SIGNING in info.capabilities
        assert ProviderCapability.OFFLINE_SIGNING in info.capabilities

    def test_local_provider_does_not_support_c2pa(self, local_config):
        """Local provider should not support C2PA."""
        provider = LocalProvider(local_config)

        assert not provider.supports(ProviderCapability.C2PA_MANIFESTS)
        assert not provider.supports(ProviderCapability.DID_IDENTITY)

    @pytest.mark.asyncio
    async def test_local_provider_initialize(self, local_config):
        """Test local provider initialization generates key."""
        provider = LocalProvider(local_config)
        await provider.initialize()

        assert provider._initialized
        assert provider._private_key is not None

        await provider.close()

    @pytest.mark.asyncio
    async def test_local_provider_get_credentials(self, local_config):
        """Test getting credentials from local provider."""
        provider = LocalProvider(local_config)
        await provider.initialize()

        creds = await provider.get_credentials()

        assert len(creds) == 1
        assert creds[0].id == "local-key"
        assert creds[0].type == "software"

        await provider.close()


class TestProviderFactory:
    """Test provider factory."""

    def test_default_config_structure(self):
        """Test default config has expected structure."""
        config = DEFAULT_PROVIDER_CONFIG

        assert "default" in config
        assert "available" in config
        assert "noosphere" in config["available"]
        assert "sigstore" in config["available"]
        assert "local" in config["available"]

    @pytest.mark.asyncio
    async def test_factory_initializes_local_provider(self, tmp_path):
        """Test factory can initialize local provider."""
        config = {
            "default": "local",
            "available": {
                "local": {
                    "enabled": True,
                    "key_path": str(tmp_path / "test_key.pem"),
                    "key_type": "ed25519",
                    "generate_if_missing": True,
                }
            }
        }

        factory = ProviderFactory(config)
        await factory.initialize()

        assert "local" in factory.provider_names
        assert factory.default_name == "local"

        provider = factory.get_provider("local")
        assert provider is not None

        await factory.close()

    @pytest.mark.asyncio
    async def test_factory_compare_providers(self, tmp_path):
        """Test provider comparison."""
        config = {
            "default": "local",
            "available": {
                "local": {
                    "enabled": True,
                    "key_path": str(tmp_path / "test_key.pem"),
                    "key_type": "ed25519",
                    "generate_if_missing": True,
                }
            }
        }

        factory = ProviderFactory(config)
        await factory.initialize()

        comparison = factory.compare()

        assert "providers" in comparison or "matrix" in comparison or len(comparison) > 0

        await factory.close()
