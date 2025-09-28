# Quick Start Guide: AI-Powered Code Signing

## Prerequisites

1. **Environment Setup**
```bash
export C2PA_ARTIFACT_API_KEY="your-c2pa-service-key"
export CA_API_TOKEN="your-ca-token" 
export DID_SERVICE_API_KEY="your-did-service-key"
export VC_SERVICE_API_KEY="your-vc-service-key"
export METADATA_SERVICE_API_KEY="your-metadata-service-key"
```

2. **Install Dependencies**
```bash
cd /Users/andrewbrown/Sites/code-signing-mcp
pip install -e .
```

## Connect to Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "code-signing": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/Users/andrewbrown/Sites/code-signing-mcp",
      "env": {
        "CONFIG_PATH": "config/production.json"
      }
    }
  }
}
```

## Test AI Agent Interactions

### 1. Basic Binary Signing

**Conversation with AI:**
```
User: "I have a Windows executable at ./myapp.exe that needs to be signed for production. Can you help?"

AI: "I'll sign your Windows executable using enterprise-grade security. Let me:
1. Analyze the binary and apply appropriate policies
2. Use HSM credentials for production signing
3. Generate C2PA manifests and SLSA attestations
4. Publish to IPFS for distribution

[Calls sign_binary tool with enterprise policies]

✅ Successfully signed myapp.exe
📋 Applied enterprise policy set (HSM required)
🔐 Used enterprise_hsm credential 
📜 Generated C2PA manifest with provenance
🌐 Published to IPFS: QmXYZ...
🏷️  Created SLSA Level 3 attestation
```

### 2. Batch Signing with Intelligence

**Conversation:**
```
User: "I have a release directory with multiple artifacts. Sign everything appropriately."

AI: "I'll analyze each file and apply the right signing approach:

[Scans ./release/ directory]

Found:
- myapp.exe (Windows) → HSM + Authenticode
- MyApp.dmg (macOS) → HSM + Notarization prep  
- myapp.deb (Linux) → GPG signing
- docs.pdf (Document) → C2PA manifest only

[Calls batch_sign tool with intelligent credential selection]

✅ All 4 artifacts signed with appropriate methods
📦 Complete provenance package created
🌐 Published batch to IPFS: QmABC...
```

### 3. Policy Validation and Compliance

**Conversation:**
```
User: "This binary needs FIPS 140-2 compliance. Can you verify and sign it?"

AI: "I'll validate FIPS compliance and sign accordingly:

[Calls policy validation]

✅ Binary analysis complete
🔒 FIPS 140-2 compliance: REQUIRED  
🔑 HSM credential: enterprise_hsm (FIPS compliant)
📋 Applied FIPS policy set
🏭 Generated compliance attestations

Your binary now meets FIPS 140-2 requirements with full audit trail.
```

### 4. Supply Chain Attestation

**Conversation:**
```
User: "Create a complete supply chain attestation package for our latest release"

AI: "I'll generate comprehensive supply chain documentation:

[Analyzes release artifacts and creates attestation package]

📋 SLSA Level 3 provenance ✓
🔗 In-toto layout and metadata ✓  
🆔 DID-based attestations ✓
🌐 IPFS publishing with metadata ✓
📊 Trust registry updates ✓

Complete attestation package: https://ipfs.noosphere.tech/QmDEF...
```

## Available AI Commands

| **Natural Language** | **What AI Does** |
|---------------------|------------------|
| "Sign this binary for production" | Analyzes file, applies enterprise policies, HSM signing |
| "Verify this signature" | Validates signatures, checks certificates, policy compliance |
| "Create release package" | Batch signs all artifacts with appropriate methods |
| "Check compliance status" | Validates against security policies (FIPS, enterprise, etc.) |
| "Generate attestations" | Creates SLSA, in-toto, DID attestations |
| "Publish to IPFS" | Uploads signed artifacts with metadata |
| "Audit this signing operation" | Retrieves complete audit trail and attestations |

## Policy Sets Available

### Basic Policy
- Software keys allowed
- Self-signed certificates OK
- Minimal compliance requirements

**AI Usage:** `"Sign this for development testing"`

### Enterprise Policy  
- HSM required for critical files
- Certificate chain validation
- C2PA manifests + SLSA attestations
- IPFS publishing

**AI Usage:** `"Sign this for production release"`

### FIPS Policy
- HSM required for all operations
- FIPS 140-2 compliance mandatory
- DID attestations required
- Maximum security

**AI Usage:** `"Sign this with FIPS compliance"`

## Integration Examples

### GitHub Actions Integration
```yaml
- name: AI-Powered Signing
  run: |
    echo "Sign all release artifacts with enterprise policies" | claude-desktop
```

### CI/CD Pipeline
```python
# In your build script
result = subprocess.run([
    "claude-desktop", 
    "--prompt", 
    "Sign ./dist/* for production with full attestations"
])
```

## Troubleshooting

### Common Issues

**"Credential not found"**
```
User: "The signing failed with credential error"
AI: "I'll check your credential configuration and suggest fixes:
- Verifying HSM connection to c2pa-artifact service
- Checking API key validity
- Testing certificate chain
```

**"Policy violation"** 
```
User: "Why was my file rejected?"
AI: "Let me analyze the policy violation:
- File size exceeds policy limit (50MB max)
- Self-signed cert not allowed in enterprise mode
- Suggestion: Use HSM credential or switch to basic policy
```

**"Service unavailable"**
```
User: "Signing service seems down"
AI: "I'll check service health and provide alternatives:
- Testing connection to ca.noosphere.tech
- Checking IPFS node availability  
- Suggesting offline signing mode if needed
```

## Advanced Features

### Custom Policies
Define organization-specific signing policies in `config/production.json`

### Multi-Platform Signing
AI automatically handles Windows, macOS, and Linux artifact differences

### Quantum-Resistant Options
Future-proof signing with post-quantum cryptographic algorithms

### Distributed Signing
Multi-region HSM support for global organizations

## Next Steps

1. **Try the examples above** with your own binaries
2. **Explore policy customization** for your organization
3. **Integrate with CI/CD** pipelines
4. **Set up monitoring** and audit reporting
5. **Customize AI workflows** for your specific needs

The AI agent makes enterprise code signing as easy as having a conversation while maintaining the highest security standards.