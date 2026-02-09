"""Pytest configuration and fixtures."""

import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def tmp_keys_dir(tmp_path):
    """Create a temporary directory for keys."""
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    return keys_dir


@pytest.fixture
def sample_binary(tmp_path):
    """Create a sample binary file for signing tests."""
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"Hello, World!" * 100)
    return str(binary_path)


@pytest.fixture
def local_provider_config(tmp_keys_dir):
    """Configuration for local provider tests."""
    return {
        "enabled": True,
        "key_path": str(tmp_keys_dir / "test_signing.pem"),
        "key_type": "ed25519",
        "generate_if_missing": True,
    }
