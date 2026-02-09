# Code Signing MCP Server - Tools Plan

## Overview
This MCP server provides AI agents with enterprise-grade code signing capabilities by wrapping existing Noosphere infrastructure including the LangGraph code-signing-agent and c2pa-artifact service.

## Core MCP Tools

### 1. **sign_binary** - Primary Signing Tool
**Description**: Sign any binary file with specified credentials
**Parameters**:
- `file_path` (string): Path to binary file to sign
- `credential_id` (string, optional): Specific credential to use
- `artifact_type` (string, optional): Type hint (jar, exe, msi, dmg, etc.)
- `generate_attestation` (boolean, default: true): Create in-toto attestation
- `embed_c2pa` (boolean, default: true): Embed C2PA manifest
- `timestamp_url` (string, optional): Override timestamp authority

**Returns**: Signing result with signature path, attestation, and verification status

### 2. **sign_package** - Package-Specific Signing
**Description**: Sign software packages (npm, NuGet, JAR, Python wheels)
**Parameters**:
- `package_path` (string): Path to package file
- `package_type` (string): npm, nuget, jar, wheel, gem, etc.
- `credential_id` (string, optional): Specific credential to use
- `publisher_metadata` (object, optional): Package publisher information

**Returns**: Signed package with embedded metadata and attestations

### 3. **verify_signature** - Signature Verification
**Description**: Verify signatures and C2PA manifests
**Parameters**:
- `file_path` (string): Path to signed file
- `signature_path` (string, optional): Detached signature path
- `check_certificate_chain` (boolean, default: true): Validate cert chain
- `check_timestamp` (boolean, default: true): Validate timestamps

**Returns**: Verification results with certificate details and trust status

### 4. **get_certificate_info** - Certificate Management
**Description**: Get certificate details and expiry warnings
**Parameters**:
- `credential_id` (string, optional): Specific credential to inspect
- `certificate_path` (string, optional): Path to certificate file
- `check_revocation` (boolean, default: true): Check CRL/OCSP

**Returns**: Certificate details, expiry dates, and validity status

### 5. **create_signing_request** - CSR Generation
**Description**: Generate Certificate Signing Requests
**Parameters**:
- `subject_dn` (string): Distinguished name for certificate
- `key_algorithm` (string, default: "RSA"): Key algorithm (RSA, ECDSA)
- `key_size` (number, default: 2048): Key size in bits
- `san_entries` (array, optional): Subject Alternative Names
- `use_hsm` (boolean, default: false): Generate key in HSM

**Returns**: CSR in PEM format and key reference

### 6. **manage_certificates** - Certificate Lifecycle
**Description**: Rotate, revoke, and renew certificates
**Parameters**:
- `operation` (string): "rotate", "revoke", "renew", "install"
- `credential_id` (string): Target credential
- `new_certificate` (string, optional): New certificate for installation
- `revocation_reason` (string, optional): Reason for revocation

**Returns**: Operation status and updated credential information

### 7. **audit_trail** - Compliance Logging
**Description**: Query signing operations audit trail
**Parameters**:
- `start_date` (string, optional): ISO date for query start
- `end_date` (string, optional): ISO date for query end
- `credential_id` (string, optional): Filter by credential
- `artifact_type` (string, optional): Filter by artifact type
- `export_format` (string, default: "json"): json, csv, xml

**Returns**: Audit records with timestamps, users, and operation details

### 8. **batch_sign** - Bulk Operations
**Description**: Sign multiple files in batch with optimization
**Parameters**:
- `file_patterns` (array): Glob patterns for files to sign
- `credential_id` (string): Credential for all signings
- `parallel_limit` (number, default: 5): Max concurrent signings
- `skip_existing` (boolean, default: true): Skip already signed files

**Returns**: Batch operation results with success/failure counts

### 9. **github_integration** - Repository Signing
**Description**: Set up automated signing for GitHub repositories
**Parameters**:
- `repository` (string): GitHub repo (owner/name)
- `webhook_events` (array): Events to trigger signing (push, release, etc.)
- `signing_rules` (object): Rules for which files to sign
- `credential_mapping` (object): Map artifact types to credentials

**Returns**: Webhook configuration and integration status

### 10. **hsm_operations** - Hardware Security Module
**Description**: Direct HSM operations for enterprise security
**Parameters**:
- `operation` (string): "list_keys", "generate_key", "get_info", "backup"
- `key_label` (string, optional): HSM key label
- `key_type` (string, optional): Key type for generation
- `backup_location` (string, optional): Backup destination

**Returns**: HSM operation results and key metadata

### 11. **policy_validation** - Security Policy Enforcement
**Description**: Validate signing operations against security policies
**Parameters**:
- `file_path` (string): File to validate
- `policy_set` (string): Policy set name ("enterprise", "fips", "eal4")
- `custom_policies` (object, optional): Custom policy definitions

**Returns**: Policy validation results and compliance status

### 12. **supply_chain_attestation** - SLSA Compliance
**Description**: Generate comprehensive supply chain attestations
**Parameters**:
- `build_artifacts` (array): List of build outputs
- `source_repository` (string): Source code repository
- `build_environment` (object): Build environment metadata
- `attestation_level` (string): SLSA level (1, 2, 3, 4)

**Returns**: SLSA attestation bundle with provenance statements

## Advanced Integration Features

### C2PA Integration
- Automatic C2PA manifest generation for media files
- Content credentials with publisher information
- Verification of embedded manifests
- Integration with content authenticity services

### HSM Support
- PKCS#11 integration for hardware security modules
- Cloud HSM support (AWS CloudHSM, Azure Key Vault)
- Key generation and management within HSMs
- FIPS 140-2 compliance for regulated environments

### Enterprise Features
- Multi-tenant credential isolation
- Role-based access control integration
- Compliance reporting (SOX, FedRAMP, Common Criteria)
- Integration with enterprise PKI infrastructure

### Performance Optimizations
- Batch signing with parallel processing
- Credential caching and session management
- Signature format optimization based on use case
- Automatic retry with exponential backoff

## Tool Categories for AI Discovery

**Security & Compliance**: sign_binary, verify_signature, policy_validation, audit_trail
**Certificate Management**: get_certificate_info, create_signing_request, manage_certificates
**Enterprise Operations**: hsm_operations, batch_sign, github_integration
**Supply Chain Security**: supply_chain_attestation, sign_package

This comprehensive tool set enables AI agents to:
1. **Secure Development Workflows**: Automatically sign build artifacts
2. **Compliance Automation**: Generate audit trails and policy validations
3. **Certificate Lifecycle Management**: Handle enterprise certificate operations
4. **Supply Chain Security**: Create SLSA-compliant attestations
5. **Multi-Platform Support**: Sign artifacts for Windows, macOS, Linux, and containers

## Implementation Strategy

The MCP server will:
1. **Wrap Existing Services**: Delegate to code-signing-agent and c2pa-artifact
2. **Provide Simplified Interface**: Abstract complex LangGraph workflows
3. **Add Enterprise Features**: HSM integration, batch operations, audit trails
4. **Ensure Security**: Secure credential handling and access control
5. **Enable AI Integration**: Clear, discoverable tools for AI agents