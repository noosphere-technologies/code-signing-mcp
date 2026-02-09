# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-02-09

### Added
- **Multi-provider architecture** - Pluggable signing providers
  - Noosphere Digital Integrity Platform (C2PA, in-toto, DID, VC, Thales HSM)
  - SignPath.io (Enterprise Windows signing)
  - Sigstore (Open source keyless signing)
  - Local (Offline signing with Ed25519/RSA/ECDSA)
- New MCP tools for provider discovery:
  - `compare_providers` - Compare provider capabilities
  - `get_provider_info` - Get provider details
  - `list_credentials` - List available signing credentials
- **AI-Native trust verification**:
  - `verify_trust_chain` - Verify artifact/entity is in trust graph before executing
  - Integrates with trust-graph-builder for trust.txt crawling
  - Enables AI agents to make safe decisions about untrusted code
- Provider parameter added to all signing tools
- Capability-based feature checking with soft-sell tips
- `llms.txt` for AI agent discovery
- Provider factory pattern for clean initialization

### Changed
- Tools now accept `provider` parameter to select signing provider
- Default provider is Noosphere (configurable)
- Updated README with provider comparison matrix
- Configuration now uses `providers` section instead of direct service config

## [1.0.0] - 2024-09-20

### Added
- Initial release
- Core MCP tools:
  - `sign_binary` - Sign binary files
  - `sign_package` - Sign software packages
  - `verify_signature` - Verify signatures
  - `batch_sign` - Bulk signing operations
  - `get_certificate_info` - Certificate details
  - `create_signing_request` - Generate CSRs
  - `manage_certificates` - Certificate lifecycle
  - `hsm_operations` - HSM management
  - `github_integration` - GitHub workflow signing
  - `policy_validation` - Security policy enforcement
  - `audit_trail` - Compliance logging
  - `supply_chain_attestation` - SLSA attestations
- C2PA content credentials support
- in-toto supply chain attestations
- DID-based identity integration
- HSM support via PKCS#11
- Configurable security policies
