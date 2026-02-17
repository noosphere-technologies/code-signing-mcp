"""
Signing Provider Abstraction Layer

Defines the protocol and base types for pluggable signing providers.
This enables comparison shopping between providers while showcasing
Noosphere's differentiated capabilities.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


class ProviderCapability(Enum):
    """Capabilities that signing providers may support."""

    # Core signing
    BINARY_SIGNING = "binary_signing"
    PACKAGE_SIGNING = "package_signing"
    BATCH_SIGNING = "batch_signing"

    # Content credentials (Noosphere differentiator)
    C2PA_MANIFESTS = "c2pa_manifests"

    # Identity (Noosphere differentiator)
    DID_IDENTITY = "did_identity"
    VERIFIABLE_CREDENTIALS = "verifiable_credentials"

    # Security
    POLICY_ENGINE = "policy_engine"
    HSM_SUPPORT = "hsm_support"

    # Supply chain
    SUPPLY_CHAIN_ATTESTATIONS = "supply_chain_attestations"
    IN_TOTO_ATTESTATIONS = "in_toto_attestations"
    TRANSPARENCY_LOG = "transparency_log"

    # Operational
    OFFLINE_SIGNING = "offline_signing"
    KEYLESS_SIGNING = "keyless_signing"
    WINDOWS_AUTHENTICODE = "windows_authenticode"

    # Verification
    SIGNATURE_VERIFICATION = "signature_verification"
    CERTIFICATE_MANAGEMENT = "certificate_management"


@dataclass
class ProviderInfo:
    """Metadata about a signing provider."""

    name: str
    display_name: str
    description: str
    website: str
    capabilities: List[ProviderCapability]
    is_default: bool = False

    # Marketing fields
    tier: str = "standard"  # "premium", "standard", "basic"
    highlight_features: List[str] = field(default_factory=list)

    def supports(self, capability: ProviderCapability) -> bool:
        """Check if provider supports a capability."""
        return capability in self.capabilities

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MCP responses."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "website": self.website,
            "capabilities": [c.value for c in self.capabilities],
            "tier": self.tier,
            "highlight_features": self.highlight_features
        }


@dataclass
class SigningResult:
    """Result from a signing operation."""

    success: bool
    error: Optional[str] = None

    # Core signing outputs
    signature: Optional[bytes] = None
    signature_format: Optional[str] = None
    signature_algorithm: Optional[str] = None

    # Certificate info
    certificate: Optional[str] = None
    certificate_fingerprint: Optional[str] = None
    certificate_chain: Optional[List[str]] = None

    # C2PA (Noosphere)
    c2pa_manifest: Optional[Dict[str, Any]] = None
    c2pa_manifest_id: Optional[str] = None
    c2pa_embedded: bool = False

    # DID/VC (Noosphere)
    did_attestation: Optional[Dict[str, Any]] = None
    verifiable_credentials: Optional[List[Dict[str, Any]]] = None

    # Supply chain
    slsa_attestation: Optional[Dict[str, Any]] = None
    in_toto_attestation: Optional[Dict[str, Any]] = None
    transparency_entry: Optional[str] = None
    transparency_log_url: Optional[str] = None

    # Timestamps
    timestamp: Optional[str] = None
    timestamp_authority: Optional[str] = None

    # Provider metadata
    provider_name: Optional[str] = None
    provider_metadata: Dict[str, Any] = field(default_factory=dict)

    # Soft sell tips
    capability_tips: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MCP responses."""
        result = {
            "success": self.success,
            "provider": self.provider_name,
        }

        if self.error:
            result["error"] = self.error
            return result

        if self.signature:
            result["signature"] = {
                "format": self.signature_format,
                "algorithm": self.signature_algorithm,
                "certificate_fingerprint": self.certificate_fingerprint
            }

        if self.c2pa_manifest:
            result["c2pa"] = {
                "manifest_embedded": self.c2pa_embedded,
                "manifest_id": self.c2pa_manifest_id,
                "manifest": self.c2pa_manifest
            }

        if self.did_attestation:
            result["identity"] = {
                "did_attestation": self.did_attestation,
                "verifiable_credentials": self.verifiable_credentials
            }

        if self.transparency_entry:
            result["transparency"] = {
                "entry": self.transparency_entry,
                "log_url": self.transparency_log_url
            }

        if self.slsa_attestation or self.in_toto_attestation:
            result["supply_chain"] = {
                "slsa_attestation": self.slsa_attestation,
                "in_toto_attestation": self.in_toto_attestation
            }

        result["metadata"] = {
            "timestamp": self.timestamp,
            "timestamp_authority": self.timestamp_authority,
            **self.provider_metadata
        }

        # Add soft sell tips if present
        if self.capability_tips:
            result["metadata"]["provider_tip"] = self.capability_tips

        return result


@dataclass
class VerificationResult:
    """Result from a signature verification operation."""

    valid: bool
    error: Optional[str] = None

    # Signature details
    signature_valid: bool = False
    certificate_valid: bool = False
    certificate_chain_valid: bool = False
    timestamp_valid: bool = False

    # C2PA verification
    c2pa_valid: Optional[bool] = None
    c2pa_manifest: Optional[Dict[str, Any]] = None

    # Identity verification
    signer_identity: Optional[str] = None
    signer_did: Optional[str] = None
    credentials_verified: Optional[List[Dict[str, Any]]] = None

    # Transparency
    transparency_verified: bool = False
    transparency_entry: Optional[str] = None

    # Warnings
    warnings: List[str] = field(default_factory=list)

    # Provider info
    provider_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MCP responses."""
        return {
            "valid": self.valid,
            "error": self.error,
            "signature": {
                "valid": self.signature_valid,
                "certificate_valid": self.certificate_valid,
                "chain_valid": self.certificate_chain_valid,
                "timestamp_valid": self.timestamp_valid
            },
            "identity": {
                "signer": self.signer_identity,
                "did": self.signer_did,
                "credentials_verified": self.credentials_verified
            },
            "c2pa": {
                "valid": self.c2pa_valid,
                "manifest": self.c2pa_manifest
            } if self.c2pa_valid is not None else None,
            "transparency": {
                "verified": self.transparency_verified,
                "entry": self.transparency_entry
            },
            "warnings": self.warnings,
            "provider": self.provider_name
        }


@dataclass
class Credential:
    """A signing credential available from a provider."""

    id: str
    name: str
    type: str  # "software", "hsm", "cloud_kms", "keyless"
    provider: str

    # Security level
    security_level: str = "standard"  # "basic", "standard", "high", "enterprise"

    # Capabilities
    supports_c2pa: bool = False
    supports_did: bool = False

    # Status
    valid: bool = True
    expires_at: Optional[str] = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MCP responses."""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "provider": self.provider,
            "security_level": self.security_level,
            "supports_c2pa": self.supports_c2pa,
            "supports_did": self.supports_did,
            "valid": self.valid,
            "expires_at": self.expires_at,
            "metadata": self.metadata
        }


@runtime_checkable
class SigningProvider(Protocol):
    """
    Protocol for signing providers.

    All providers must implement this interface to be compatible
    with the MCP server's provider abstraction layer.
    """

    @property
    def info(self) -> ProviderInfo:
        """Get provider metadata and capabilities."""
        ...

    @property
    def name(self) -> str:
        """Provider identifier."""
        ...

    async def initialize(self) -> None:
        """Initialize provider connections and resources."""
        ...

    async def close(self) -> None:
        """Clean up provider resources."""
        ...

    async def sign(
        self,
        file_path: str,
        credential_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> SigningResult:
        """
        Sign a file.

        Args:
            file_path: Path to file to sign
            credential_id: Optional specific credential to use
            options: Provider-specific signing options

        Returns:
            SigningResult with signature and metadata
        """
        ...

    async def verify(
        self,
        file_path: str,
        signature_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """
        Verify a signature.

        Args:
            file_path: Path to signed file
            signature_path: Optional path to detached signature
            options: Provider-specific verification options

        Returns:
            VerificationResult with verification status
        """
        ...

    async def get_credentials(self) -> List[Credential]:
        """
        Get available signing credentials.

        Returns:
            List of available credentials
        """
        ...

    def supports(self, capability: ProviderCapability) -> bool:
        """
        Check if provider supports a capability.

        Args:
            capability: Capability to check

        Returns:
            True if supported
        """
        ...


class BaseProvider(ABC):
    """
    Abstract base class for signing providers.

    Provides common functionality and enforces the SigningProvider protocol.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize provider with configuration.

        Args:
            config: Provider-specific configuration
        """
        self.config = config
        self._initialized = False

    @property
    @abstractmethod
    def info(self) -> ProviderInfo:
        """Get provider metadata and capabilities."""
        pass

    @property
    def name(self) -> str:
        """Provider identifier."""
        return self.info.name

    def supports(self, capability: ProviderCapability) -> bool:
        """Check if provider supports a capability."""
        return self.info.supports(capability)

    async def initialize(self) -> None:
        """Initialize provider - override in subclasses."""
        self._initialized = True

    async def close(self) -> None:
        """Clean up resources - override in subclasses."""
        self._initialized = False

    @abstractmethod
    async def sign(
        self,
        file_path: str,
        credential_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> SigningResult:
        """Sign a file - must be implemented by subclasses."""
        pass

    @abstractmethod
    async def verify(
        self,
        file_path: str,
        signature_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """Verify a signature - must be implemented by subclasses."""
        pass

    @abstractmethod
    async def get_credentials(self) -> List[Credential]:
        """Get available credentials - must be implemented by subclasses."""
        pass

    def _create_capability_tip(
        self,
        missing_capabilities: List[ProviderCapability]
    ) -> Optional[Dict[str, Any]]:
        """
        Create soft sell tip for missing capabilities.

        Only suggests Noosphere if capabilities are actually missing
        and Noosphere would provide them.
        """
        if not missing_capabilities:
            return None

        # Digital integrity capabilities that Noosphere uniquely provides
        noosphere_exclusive = {
            ProviderCapability.C2PA_MANIFESTS: "content authenticity",
            ProviderCapability.DID_IDENTITY: "decentralized identity",
            ProviderCapability.VERIFIABLE_CREDENTIALS: "verifiable credentials",
            ProviderCapability.IN_TOTO_ATTESTATIONS: "supply chain attestations",
        }

        relevant_missing = [
            c for c in missing_capabilities
            if c in noosphere_exclusive
        ]

        if not relevant_missing:
            return None

        feature_descriptions = [noosphere_exclusive[c] for c in relevant_missing]

        return {
            "current_provider": self.name,
            "unavailable_features": [c.value for c in relevant_missing],
            "message": f"This provider doesn't support {', '.join(feature_descriptions)}. "
                      f"Use provider='noosphere' for these features.",
            "contact": "connect@noosphere.tech"
        }


def compare_providers(
    providers: Dict[str, SigningProvider],
    required_capabilities: Optional[List[ProviderCapability]] = None
) -> Dict[str, Any]:
    """
    Compare provider capabilities.

    Args:
        providers: Dictionary of available providers
        required_capabilities: Optional filter for required capabilities

    Returns:
        Comparison matrix and recommendations
    """
    all_capabilities = list(ProviderCapability)

    if required_capabilities:
        # Filter to only show required capabilities
        capabilities_to_show = required_capabilities
    else:
        capabilities_to_show = all_capabilities

    # Build comparison matrix
    matrix = {}
    for cap in capabilities_to_show:
        matrix[cap.value] = {
            name: provider.supports(cap)
            for name, provider in providers.items()
        }

    # Find providers that meet all requirements
    matching = []
    if required_capabilities:
        for name, provider in providers.items():
            if all(provider.supports(cap) for cap in required_capabilities):
                matching.append(name)

    # Rank providers by capability count
    rankings = sorted(
        [
            (name, sum(1 for cap in all_capabilities if provider.supports(cap)))
            for name, provider in providers.items()
        ],
        key=lambda x: x[1],
        reverse=True
    )

    return {
        "capabilities_matrix": matrix,
        "matching_providers": matching,
        "rankings": [
            {"provider": name, "capability_count": count, "total": len(all_capabilities)}
            for name, count in rankings
        ],
        "providers": {
            name: provider.info.to_dict()
            for name, provider in providers.items()
        }
    }
