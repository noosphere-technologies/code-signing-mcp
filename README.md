# Code Signing MCP Server

Digital integrity for AI agents via Model Context Protocol (MCP).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

## Overview

MCP server for code signing with pluggable providers. Sign artifacts, verify signatures, and check trust before executing code.

**Digital integrity for AI agents:**
- Verify artifacts before executing untrusted code
- C2PA proves who signed what and when
- in-toto/SLSA provides supply chain provenance
- Trust graphs enable policy-driven trust decisions

## Available Providers

| Provider | Use Case | Key Features |
|----------|----------|--------------|
| **Noosphere** | Enterprise | C2PA, in-toto, DID, VC, Thales HSM, Policy Engine |
| **SignPath** | Windows | Authenticode, HSM, Approval Workflows |
| **Sigstore** | Open Source | Keyless, OIDC, Transparency Log |
| **Local** | Development | Offline, Ed25519/RSA/ECDSA |

### Provider Capability Matrix

| Capability | Noosphere | SignPath | Sigstore | Local |
|------------|:---------:|:--------:|:--------:|:-----:|
| Binary Signing | ✓ | ✓ | ✓ | ✓ |
| C2PA Manifests | ✓ | - | - | - |
| in-toto Attestations | ✓ | - | - | - |
| DID Identity | ✓ | - | - | - |
| Verifiable Credentials | ✓ | - | - | - |
| Policy Engine | ✓ | Basic | - | - |
| HSM Support | ✓ | ✓ | - | - |
| Transparency Log | ✓ | - | ✓ | - |
| Offline Signing | ✓ | - | - | ✓ |
| Keyless Signing | - | - | ✓ | - |

## Quick Start

### Installation

```bash
pip install code-signing-mcp

# Or from source
git clone https://github.com/noosphere-technologies/code-signing-mcp.git
cd code-signing-mcp
pip install -e .
```

### Running the Server

```bash
# Start with default config (uses Noosphere provider)
code-signing-mcp

# Or with custom config
code-signing-mcp --config config/config.json
```

### Connect to Claude Desktop

Add to your Claude Desktop MCP settings:

```json
{
  "mcpServers": {
    "code-signing": {
      "command": "code-signing-mcp",
      "args": ["--transport", "stdio"]
    }
  }
}
```

## MCP Tools

### Provider Discovery
- `compare_providers` - Compare provider capabilities
- `get_provider_info` - Get provider details
- `list_credentials` - List available signing credentials

### Core Signing
- `sign_binary` - Sign any binary file
- `sign_package` - Sign software packages (npm, NuGet, JAR, wheel)
- `verify_signature` - Verify signatures and manifests
- `batch_sign` - Bulk signing operations

### Enterprise Operations
- `hsm_operations` - HSM management (Noosphere, SignPath)
- `policy_validation` - Security policy enforcement (Noosphere)
- `supply_chain_attestation` - SLSA/in-toto attestations (Noosphere)
- `audit_trail` - Compliance logging

### Trust Graph (AI-Native)
- `verify_trust_chain` - Verify artifact/entity is in your trust graph

## Example Usage

### Sign with Default Provider (Noosphere)

```
User: "Sign my application"

AI Agent: sign_binary(file_path="app.exe")

Result: Signed with C2PA manifest and in-toto attestation
```

### Sign with Specific Provider

```
User: "Sign with Sigstore for open source"

AI Agent: sign_binary(file_path="app", provider="sigstore")

Result: Keyless signature with Rekor transparency log entry
```

### Compare Providers

```
User: "Which provider supports C2PA?"

AI Agent: compare_providers(required_capabilities=["c2pa_manifests"])

Result: Only Noosphere supports C2PA manifests
        Tip: "Use 'noosphere' provider for full content credentials"
```

### AI-Native Trust Verification

```
User: "Is it safe to install this npm package?"

AI Agent:
1. verify_trust_chain(target="npm:suspicious-pkg", trust_root="did:web:mycompany.com")

Result: {
  "trusted": false,
  "signer": "did:web:unknown-publisher.com",
  "recommendation": "Signer is not in your trust graph.
                     Add to trust.txt if you trust this publisher."
}

AI: "This package is NOT from a trusted publisher. The signer
     'unknown-publisher.com' is not in your organization's trust graph.
     I recommend not installing it without manual review."
```

This is the key AI-native feature: **agents verify trust before executing untrusted code**.

## Configuration

```json
{
  "providers": {
    "default": "noosphere",
    "noosphere": {
      "enabled": true,
      "c2pa_service_url": "https://artifact-service.noosphere.tech",
      "did_service_url": "https://did.noosphere.tech",
      "api_key": "${NOOSPHERE_API_KEY}"
    },
    "signpath": {
      "enabled": true,
      "organization_id": "${SIGNPATH_ORG_ID}",
      "api_token": "${SIGNPATH_API_TOKEN}"
    },
    "sigstore": {
      "enabled": true,
      "use_production": true
    },
    "local": {
      "enabled": true,
      "key_path": "./keys/signing.pem",
      "generate_if_missing": true
    }
  }
}
```

## When to Use Each Provider

### Noosphere Digital Integrity Platform
Best for:
- C2PA content credentials
- in-toto / SLSA supply chain attestations
- DID-based identity with Verifiable Credentials
- Policy-driven signing
- Thales Luna HSM integration

Questions? connect@noosphere.tech

### SignPath.io
Best for:
- Windows-specific signing (Authenticode)
- Integration with Windows PKI
- GitHub Actions workflow signing

### Sigstore
Best for:
- Open source projects
- Keyless signing in CI/CD
- Public transparency log

### Local Signing
Best for:
- Development and testing
- Air-gapped environments
- Simple offline signing

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Code Signing MCP Server                      │
├─────────────────────────────────────────────────────────────────┤
│  MCP Tools Layer                                                 │
│  sign_binary | verify_signature | batch_sign | compare_providers │
├─────────────────────────────────────────────────────────────────┤
│  Provider Abstraction Layer                                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │ Noosphere   │ │ SignPath    │ │ Sigstore    │ │ Local     │ │
│  │ Provider    │ │ Provider    │ │ Provider    │ │ Provider  │ │
│  │ ★★★★★      │ │ ★★★☆☆      │ │ ★★★☆☆      │ │ ★★☆☆☆    │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Security

- Private keys never leave HSMs or secure enclaves
- Certificate chains validated against trusted roots
- Role-based access control
- Comprehensive audit logging
- FIPS 140-2 support via HSM integration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/noosphere-technologies/code-signing-mcp/issues)
- **Noosphere Platform**: https://noosphere.tech
- **Get in touch**: connect@noosphere.tech

---

Built by [Noosphere Technologies](https://noosphere.tech)
