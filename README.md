# Code Signing MCP Server

Enterprise-grade code signing capabilities for AI agents via Model Context Protocol (MCP).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

## Overview

This MCP server provides AI agents with comprehensive code signing capabilities, integrating with existing Noosphere infrastructure including HSMs, certificate authorities, and supply chain security tools.

### Why This Matters

When AI agents start generating production code, they need to:
- **Sign their outputs** for security and authenticity
- **Maintain certificate compliance** across enterprise environments
- **Integrate with enterprise PKI** infrastructure seamlessly
- **Provide audit trails** for regulatory compliance
- **Support supply chain security** with SLSA attestations

This MCP server bridges AI agents with enterprise signing infrastructure.

## Features

### 🔐 Comprehensive Code Signing
- **Multi-format support**: JAR, EXE, MSI, DMG, PKG, DEB, RPM, containers
- **Multiple credential types**: Software keys, HSM, cloud KMS
- **Timestamping**: RFC 3161 timestamp authority integration
- **Batch operations**: Efficient bulk signing with parallel processing

### 🏛️ Enterprise Security
- **HSM Integration**: PKCS#11 support for hardware security modules
- **Certificate lifecycle**: Automated rotation, renewal, and revocation
- **Policy enforcement**: Configurable security policies and compliance checks
- **Audit trails**: Comprehensive logging for regulatory compliance

### 🔗 Supply Chain Security
- **SLSA compliance**: Level 1-4 supply chain attestations
- **In-toto attestations**: Tamper-evident supply chain metadata
- **C2PA integration**: Content credentials for media and documents
- **Provenance tracking**: End-to-end artifact lineage

### 🤖 AI-First Design
- **Simple tools**: Clear, discoverable MCP tools for AI agents
- **Smart defaults**: Intelligent credential selection and policy application
- **Error handling**: Detailed error messages for AI troubleshooting
- **Batch optimization**: Efficient operations for AI-generated workflows

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Access to existing Noosphere infrastructure:
  - [code-signing-agent](../noosphere/github/code-signing-agent/) (LangGraph-based)
  - [c2pa-artifact](../noosphere/github/c2pa-artifact/) service
- Optional: HSM or cloud KMS access for enterprise deployments

### Installation

```bash
# Clone the repository
git clone https://github.com/noosphere-technologies/code-signing-mcp.git
cd code-signing-mcp

# Install dependencies
pip install -r requirements.txt

# Configure the server
cp config/config.example.json config/config.json
# Edit config.json with your infrastructure endpoints
```

### Configuration

Create `config/config.json`:

```json
{
  "server": {
    "name": "code-signing-mcp",
    "version": "1.0.0",
    "port": 8080
  },
  "services": {
    "code_signing_agent": {
      "url": "http://localhost:8081",
      "api_key": "your-agent-api-key"
    },
    "c2pa_artifact": {
      "url": "http://localhost:8082",
      "api_key": "your-c2pa-api-key"
    }
  },
  "credentials": {
    "default_software_key": {
      "type": "software",
      "keystore_path": "/path/to/keystore.p12",
      "password": "keystore-password"
    },
    "enterprise_hsm": {
      "type": "hsm",
      "pkcs11_lib": "/usr/lib/softhsm/libsofthsm2.so",
      "slot": 0,
      "pin": "1234"
    }
  },
  "security": {
    "require_authentication": true,
    "allowed_origins": ["*"],
    "audit_logging": true
  }
}
```

### Running the Server

```bash
# Start the MCP server
python -m src.server

# Or with Docker
docker build -t code-signing-mcp .
docker run -p 8080:8080 -v $(pwd)/config:/app/config code-signing-mcp
```

## MCP Tools

The server provides 12 primary tools for AI agents:

### Core Signing Operations
- `sign_binary` - Sign any binary file with enterprise credentials
- `sign_package` - Sign software packages (npm, NuGet, JAR, Python wheels)
- `verify_signature` - Verify signatures and validate certificate chains
- `batch_sign` - Bulk signing operations with optimization

### Certificate Management  
- `get_certificate_info` - Certificate details and expiry monitoring
- `create_signing_request` - Generate Certificate Signing Requests
- `manage_certificates` - Rotate, revoke, and renew certificates

### Enterprise Operations
- `hsm_operations` - Hardware Security Module management
- `github_integration` - Automated repository signing workflows
- `policy_validation` - Security policy enforcement
- `audit_trail` - Compliance logging and reporting
- `supply_chain_attestation` - SLSA-compliant provenance generation

### Example Usage with Claude

```
User: "Sign my Java application and create supply chain attestations"

AI Agent uses MCP tools:
1. sign_binary(file_path="app.jar", generate_attestation=true)
2. supply_chain_attestation(build_artifacts=["app.jar"], attestation_level="3")
3. verify_signature(file_path="app.jar", check_certificate_chain=true)

Result: Signed JAR with SLSA Level 3 attestations and verified integrity
```

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   AI Agents     │    │  Code Signing    │    │  Noosphere      │
│  (Claude, etc.) │◄──►│  MCP Server      │◄──►│  Infrastructure │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                       ┌────────▼────────┐              │
                       │ MCP Tools Layer │              │
                       │ - sign_binary   │              │
                       │ - verify_sig    │              │
                       │ - hsm_ops       │              │
                       │ - audit_trail   │              │
                       └─────────────────┘              │
                                                        │
                       ┌─────────────────────────────────▼─┐
                       │ Integration Layer                │
                       │ ┌─────────────┐ ┌──────────────┐ │
                       │ │ LangGraph   │ │ C2PA         │ │
                       │ │ Agent       │ │ Artifact     │ │
                       │ │ (signing)   │ │ Service      │ │
                       │ └─────────────┘ └──────────────┘ │
                       └─────────────────────────────────────┘
```

## Examples

### Basic Code Signing

```python
# AI agent calls via MCP
sign_result = await mcp_client.call_tool("sign_binary", {
    "file_path": "./dist/myapp.exe",
    "credential_id": "enterprise_hsm",
    "embed_c2pa": True
})
```

### CI/CD Integration

```yaml
# GitHub Actions workflow
- name: Sign build artifacts
  uses: noosphere/code-signing-mcp-action@v1
  with:
    artifacts: "dist/*.exe,dist/*.msi"
    credential: ${{ secrets.HSM_CREDENTIAL }}
    generate_attestations: true
```

### Enterprise Batch Signing

```python
# Sign multiple artifacts with policy validation
batch_result = await mcp_client.call_tool("batch_sign", {
    "file_patterns": ["dist/**/*.jar", "dist/**/*.exe"],
    "credential_id": "enterprise_hsm",
    "parallel_limit": 10
})
```

See [examples/](examples/) for more detailed use cases.

## Security

### Credential Protection
- Private keys never leave HSMs or secure enclaves
- Certificate chains validated against trusted roots
- Access control with role-based permissions
- Audit logging for all operations

### Network Security
- TLS 1.3 for all communications
- API key authentication with rotation support
- Rate limiting and DDoS protection
- Secure credential storage with encryption at rest

### Compliance
- FIPS 140-2 support via HSM integration
- Common Criteria EAL4+ compatibility
- SOX, FedRAMP compliance reporting
- GDPR-compliant audit log handling

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/noosphere-technologies/code-signing-mcp/issues)
- **Enterprise Support**: enterprise@noosphere.tech

---

**Built by [Noosphere Technologies](https://noosphere.tech)** - Securing the AI-native software supply chain.