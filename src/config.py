#!/usr/bin/env python3
"""
Configuration management for the Code Signing MCP Server.

Handles loading, validation, and management of server configuration
including credentials, security policies, and service endpoints.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator
import yaml


class ServerConfig(BaseModel):
    """Server configuration settings."""
    name: str = "code-signing-mcp"
    version: str = "1.0.0"
    description: str = "Enterprise code signing MCP server"
    port: int = 8080
    host: str = "0.0.0.0"
    log_level: str = "INFO"
    enable_cors: bool = True
    cors_origins: List[str] = ["*"]
    max_workers: int = 10


class ServiceConfig(BaseModel):
    """External service configuration."""
    url: str
    api_key: Optional[str] = None
    timeout: int = 30
    retry_attempts: int = 3
    retry_delay: float = 1.0


class ServicesConfig(BaseModel):
    """Configuration for all external services."""
    code_signing_agent: ServiceConfig
    c2pa_artifact: ServiceConfig
    metadata_service: Optional[ServiceConfig] = None
    trust_engine: Optional[ServiceConfig] = None


class CredentialConfig(BaseModel):
    """Individual credential configuration."""
    id: str
    name: str
    type: str = Field(..., regex="^(software|hsm|cloud_kms)$")
    security_level: str = Field(..., regex="^(standard|high|enterprise)$")
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Software key specific
    keystore_path: Optional[str] = None
    keystore_password: Optional[str] = None
    key_alias: Optional[str] = None
    
    # HSM specific
    pkcs11_config: Optional[Dict[str, Any]] = None
    key_label: Optional[str] = None
    
    # Cloud KMS specific
    provider: Optional[str] = None
    key_id: Optional[str] = None
    region: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None
    
    # Certificate chain
    certificate_chain: List[str] = field(default_factory=list)


class TimestampAuthorityConfig(BaseModel):
    """Timestamp authority configuration."""
    name: str
    url: str
    enabled: bool = True


class BatchSettingsConfig(BaseModel):
    """Batch operation settings."""
    max_concurrent: int = 5
    max_batch_size: int = 100
    timeout_per_file: int = 60


class SigningConfig(BaseModel):
    """Signing operation configuration."""
    default_credential: str
    timestamp_authorities: List[TimestampAuthorityConfig] = field(default_factory=list)
    default_timestamp_url: str
    max_file_size: int = 104857600  # 100MB
    supported_formats: List[str] = field(default_factory=lambda: [
        "jar", "exe", "msi", "dmg", "pkg", "deb", "rpm",
        "appx", "msix", "apk", "ipa", "tar.gz", "zip"
    ])
    batch_settings: BatchSettingsConfig = field(default_factory=BatchSettingsConfig)


class AuthenticationConfig(BaseModel):
    """Authentication configuration."""
    required: bool = True
    methods: List[str] = ["api_key", "jwt"]
    api_key_header: str = "X-API-Key"
    jwt_secret: Optional[str] = None
    jwt_expiration: int = 3600


class RoleConfig(BaseModel):
    """Role-based access control configuration."""
    permissions: List[str]


class AuthorizationConfig(BaseModel):
    """Authorization configuration."""
    enabled: bool = True
    default_role: str = "user"
    roles: Dict[str, RoleConfig] = field(default_factory=dict)


class RateLimitingConfig(BaseModel):
    """Rate limiting configuration."""
    enabled: bool = True
    requests_per_minute: int = 100
    burst_allowance: int = 10


class AuditConfig(BaseModel):
    """Audit logging configuration."""
    enabled: bool = True
    log_all_operations: bool = True
    log_file: str = "/var/log/code-signing-mcp/audit.log"
    retention_days: int = 90
    include_request_data: bool = False
    include_response_data: bool = False


class SecurityConfig(BaseModel):
    """Security configuration."""
    authentication: AuthenticationConfig = field(default_factory=AuthenticationConfig)
    authorization: AuthorizationConfig = field(default_factory=AuthorizationConfig)
    rate_limiting: RateLimitingConfig = field(default_factory=RateLimitingConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)


class PolicySetConfig(BaseModel):
    """Security policy set configuration."""
    require_timestamp: bool = False
    allow_self_signed: bool = True
    min_key_size: int = 2048
    allowed_algorithms: List[str] = ["SHA256", "SHA384", "SHA512"]
    require_certificate_chain: bool = False
    max_certificate_age_days: Optional[int] = None
    require_hsm_for_critical: bool = False
    require_hsm: bool = False
    fips_140_2_compliance: bool = False


class PoliciesConfig(BaseModel):
    """Security policies configuration."""
    default_policy_set: str = "enterprise"
    policy_sets: Dict[str, PolicySetConfig] = field(default_factory=dict)


class C2PAConfig(BaseModel):
    """C2PA configuration."""
    enabled: bool = True
    default_embed: bool = True
    supported_formats: List[str] = ["jpg", "jpeg", "png", "webp", "pdf", "mp4"]
    manifest_settings: Dict[str, Any] = field(default_factory=lambda: {
        "include_provenance": True,
        "include_thumbnails": True,
        "compression_level": 6
    })


class SLSAConfig(BaseModel):
    """SLSA attestation configuration."""
    enabled: bool = True
    default_level: str = "3"
    builder_id: str = "https://github.com/noosphere-technologies/code-signing-mcp"
    build_type: str = "https://github.com/noosphere-technologies/code-signing-mcp/build-type/v1"


class InTotoConfig(BaseModel):
    """In-toto attestation configuration."""
    enabled: bool = True
    layout_key: Optional[str] = None
    metadata_dir: str = "/var/lib/code-signing-mcp/attestations"


class AttestationsConfig(BaseModel):
    """Attestations configuration."""
    slsa: SLSAConfig = field(default_factory=SLSAConfig)
    in_toto: InTotoConfig = field(default_factory=InTotoConfig)


class GitHubIntegrationConfig(BaseModel):
    """GitHub integration configuration."""
    enabled: bool = True
    webhook_secret: Optional[str] = None
    default_events: List[str] = ["push", "release", "workflow_run"]
    auto_sign_releases: bool = True


class GitHubAPIConfig(BaseModel):
    """GitHub API configuration."""
    token: Optional[str] = None
    base_url: str = "https://api.github.com"


class GitHubConfig(BaseModel):
    """GitHub configuration."""
    integration: GitHubIntegrationConfig = field(default_factory=GitHubIntegrationConfig)
    api: GitHubAPIConfig = field(default_factory=GitHubAPIConfig)


class MetricsConfig(BaseModel):
    """Metrics configuration."""
    enabled: bool = True
    endpoint: str = "/metrics"
    include_detailed_timing: bool = True


class HealthCheckConfig(BaseModel):
    """Health check configuration."""
    enabled: bool = True
    endpoint: str = "/health"
    check_services: bool = True
    check_credentials: bool = False


class TracingConfig(BaseModel):
    """Distributed tracing configuration."""
    enabled: bool = False
    jaeger_endpoint: str = "http://localhost:14268/api/traces"


class MonitoringConfig(BaseModel):
    """Monitoring configuration."""
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    health_check: HealthCheckConfig = field(default_factory=HealthCheckConfig)
    tracing: TracingConfig = field(default_factory=TracingConfig)


class StorageConfig(BaseModel):
    """Storage configuration."""
    temp_dir: str = "/tmp/code-signing-mcp"
    cache_dir: str = "/var/cache/code-signing-mcp"
    cache_ttl: int = 3600
    max_cache_size: str = "1GB"


class ExperimentalFeaturesConfig(BaseModel):
    """Experimental features configuration."""
    quantum_resistant_signatures: bool = False
    distributed_signing: bool = False
    ai_policy_recommendations: bool = False


class FeaturesConfig(BaseModel):
    """Features configuration."""
    experimental: ExperimentalFeaturesConfig = field(default_factory=ExperimentalFeaturesConfig)


class NoosphereProviderConfig(BaseModel):
    """Noosphere Digital Integrity Platform provider configuration."""
    enabled: bool = True
    c2pa_service_url: str = "https://artifact-service.noosphere.tech"
    did_service_url: str = "https://did.noosphere.tech"
    vc_service_url: str = "https://vc.noosphere.tech"
    api_key: Optional[str] = None
    default_policy: str = "enterprise"


class SignPathProviderConfig(BaseModel):
    """SignPath.io provider configuration."""
    enabled: bool = False
    connector_url: str = "https://app.signpath.io"
    organization_id: Optional[str] = None
    api_token: Optional[str] = None
    project_slug: str = "default"
    signing_policy_slug: str = "release-signing"


class SigstoreProviderConfig(BaseModel):
    """Sigstore provider configuration."""
    enabled: bool = True
    use_production: bool = True
    oidc_issuer: str = "https://oauth2.sigstore.dev/auth"
    identity_token: Optional[str] = None


class LocalProviderConfig(BaseModel):
    """Local signing provider configuration."""
    enabled: bool = True
    key_path: str = "./keys/signing.pem"
    key_password: Optional[str] = None
    key_type: str = "ed25519"
    tsa_url: Optional[str] = None
    generate_if_missing: bool = True


class ProvidersConfig(BaseModel):
    """
    Signing providers configuration.

    Supports multiple pluggable providers:
    - noosphere: Full-featured (C2PA, in-toto, DID, VC)
    - signpath: Enterprise Windows signing
    - sigstore: Open source keyless signing
    - local: Offline signing with local keys
    """
    default: str = "noosphere"
    noosphere: NoosphereProviderConfig = field(default_factory=NoosphereProviderConfig)
    signpath: SignPathProviderConfig = field(default_factory=SignPathProviderConfig)
    sigstore: SigstoreProviderConfig = field(default_factory=SigstoreProviderConfig)
    local: LocalProviderConfig = field(default_factory=LocalProviderConfig)

    def to_factory_config(self) -> Dict[str, Any]:
        """Convert to format expected by ProviderFactory."""
        return {
            "default": self.default,
            "available": {
                "noosphere": self.noosphere.dict(),
                "signpath": self.signpath.dict(),
                "sigstore": self.sigstore.dict(),
                "local": self.local.dict(),
            }
        }


class Config(BaseModel):
    """Main configuration class."""
    server: ServerConfig = field(default_factory=ServerConfig)
    services: Optional[ServicesConfig] = None  # Made optional - providers handle services now
    providers: ProvidersConfig = field(default_factory=ProvidersConfig)
    credentials: Dict[str, CredentialConfig] = field(default_factory=dict)
    signing: Optional[SigningConfig] = None  # Made optional - providers handle this now
    security: SecurityConfig = field(default_factory=SecurityConfig)
    policies: PoliciesConfig = field(default_factory=PoliciesConfig)
    c2pa: C2PAConfig = field(default_factory=C2PAConfig)
    attestations: AttestationsConfig = field(default_factory=AttestationsConfig)
    github: GitHubConfig = field(default_factory=GitHubConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    features: FeaturesConfig = field(default_factory=FeaturesConfig)
    
    @validator('credentials')
    def validate_credentials(cls, v):
        """Validate credential configurations."""
        for cred_id, cred in v.items():
            if cred.type == "hsm" and not cred.pkcs11_config:
                raise ValueError(f"HSM credential {cred_id} missing PKCS#11 configuration")
            if cred.type == "cloud_kms" and not cred.provider:
                raise ValueError(f"Cloud KMS credential {cred_id} missing provider")
        return v

    @validator('signing')
    def validate_signing_config(cls, v, values):
        """Validate signing configuration."""
        if v is None:
            return v  # Optional now - providers handle signing config
        credentials = values.get('credentials', {})
        if credentials and v.default_credential not in credentials:
            raise ValueError(f"Default credential {v.default_credential} not found in credentials")
        return v

    @validator('providers')
    def validate_providers(cls, v):
        """Validate at least one provider is enabled."""
        enabled = []
        if v.noosphere.enabled:
            enabled.append("noosphere")
        if v.signpath.enabled:
            enabled.append("signpath")
        if v.sigstore.enabled:
            enabled.append("sigstore")
        if v.local.enabled:
            enabled.append("local")

        if not enabled:
            raise ValueError("At least one provider must be enabled")

        if v.default not in enabled:
            raise ValueError(f"Default provider '{v.default}' is not enabled")

        return v


def substitute_environment_variables(config_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively substitute environment variables in configuration.
    
    Variables in the format ${VAR_NAME} will be replaced with their environment values.
    """
    def substitute_value(value):
        if isinstance(value, str):
            # Handle environment variable substitution
            if value.startswith("${") and value.endswith("}"):
                env_var = value[2:-1]
                env_value = os.environ.get(env_var)
                if env_value is None:
                    raise ValueError(f"Environment variable {env_var} not set")
                return env_value
            return value
        elif isinstance(value, dict):
            return {k: substitute_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [substitute_value(item) for item in value]
        else:
            return value
    
    return substitute_value(config_data)


def load_config(config_path: Union[str, Path]) -> Config:
    """
    Load configuration from file with environment variable substitution.
    
    Args:
        config_path: Path to configuration file (JSON or YAML)
        
    Returns:
        Validated configuration object
        
    Raises:
        FileNotFoundError: If configuration file doesn't exist
        ValueError: If configuration is invalid
    """
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    # Load configuration data
    with open(config_path, 'r') as f:
        if config_path.suffix.lower() in ['.yaml', '.yml']:
            config_data = yaml.safe_load(f)
        else:
            config_data = json.load(f)
    
    # Substitute environment variables
    config_data = substitute_environment_variables(config_data)
    
    # Validate and create configuration object
    try:
        config = Config(**config_data)
        return config
    except Exception as e:
        raise ValueError(f"Invalid configuration: {e}")


def create_default_config() -> Config:
    """Create a default configuration for testing/development."""
    return Config(
        providers=ProvidersConfig(
            default="noosphere",
            noosphere=NoosphereProviderConfig(
                enabled=True,
                c2pa_service_url="https://artifact-service.noosphere.tech",
                did_service_url="https://did.noosphere.tech",
                vc_service_url="https://vc.noosphere.tech"
            ),
            sigstore=SigstoreProviderConfig(
                enabled=True,
                use_production=True
            ),
            local=LocalProviderConfig(
                enabled=True,
                key_path="./keys/signing.pem",
                generate_if_missing=True
            )
        )
    )


def validate_config_file(config_path: Union[str, Path]) -> bool:
    """
    Validate a configuration file without loading it fully.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        True if configuration is valid, False otherwise
    """
    try:
        load_config(config_path)
        return True
    except Exception:
        return False