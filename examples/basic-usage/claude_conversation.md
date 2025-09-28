# Claude + Code Signing MCP: Basic Usage Examples

This document shows realistic conversations between users and Claude when the Code Signing MCP server is connected.

## Example 1: Signing a Java Application

**User:** "I just built my Java application. Can you sign it and create supply chain attestations?"

**Claude:** I'll help you sign your Java application and create supply chain attestations. Let me start by signing the JAR file and then generate the attestations.

```mcp
sign_binary({
  "file_path": "./target/myapp.jar",
  "artifact_type": "jar",
  "generate_attestation": true,
  "embed_c2pa": true
})
```

Great! Your JAR file has been successfully signed. Now let me create comprehensive supply chain attestations:

```mcp
supply_chain_attestation({
  "build_artifacts": ["./target/myapp.jar"],
  "source_repository": "github.com/yourorg/myapp",
  "build_environment": {
    "builder": "maven",
    "java_version": "17",
    "maven_version": "3.8.6"
  },
  "attestation_level": "3"
})
```

Perfect! I've completed both tasks:

✅ **Signed your JAR file** with enterprise credentials
✅ **Generated SLSA Level 3 attestations** for supply chain security
✅ **Embedded C2PA manifest** for content authenticity

Your application is now ready for distribution with full provenance tracking and authenticity guarantees.

---

## Example 2: Enterprise Certificate Management

**User:** "Our code signing certificate expires next month. Can you check the status and help me renew it?"

**Claude:** I'll check your certificate status and help you with renewal. Let me start by examining your current certificates:

```mcp
get_certificate_info({
  "check_revocation": true
})
```

I can see your enterprise certificate expires in 28 days. Let me help you with the renewal process by creating a new Certificate Signing Request:

```mcp
create_signing_request({
  "subject_dn": "CN=YourCompany Code Signing,O=YourCompany Inc,L=San Francisco,ST=CA,C=US",
  "key_algorithm": "RSA",
  "key_size": 2048,
  "san_entries": ["codesigning@yourcompany.com"],
  "use_hsm": true
})
```

Now let me set up automated certificate management for the future:

```mcp
manage_certificates({
  "operation": "rotate",
  "credential_id": "enterprise_hsm",
  "new_certificate": "[new certificate PEM data would go here]"
})
```

✅ **Certificate expires in 28 days** - I've flagged this for urgent attention
✅ **Generated new CSR** using your HSM for maximum security
✅ **Set up rotation process** to install the new certificate when ready

Next steps: Submit the CSR to your Certificate Authority and I can install the new certificate when it arrives.

---

## Example 3: CI/CD Integration

**User:** "Set up automated code signing for our GitHub repository releases"

**Claude:** I'll set up automated code signing for your GitHub releases. This will ensure all your release artifacts are automatically signed when you create a new release.

```mcp
github_integration({
  "repository": "yourorg/yourproject",
  "webhook_events": ["release", "push"],
  "signing_rules": {
    "release_artifacts": ["*.jar", "*.exe", "*.msi", "*.dmg"],
    "branch_restrictions": ["main", "release/*"],
    "require_approval": false
  },
  "credential_mapping": {
    "jar": "enterprise_hsm",
    "exe": "enterprise_hsm", 
    "msi": "enterprise_hsm",
    "dmg": "apple_developer_id"
  }
})
```

Let me also set up batch signing for existing artifacts:

```mcp
batch_sign({
  "file_patterns": ["./dist/*.jar", "./dist/*.exe", "./release/*.msi"],
  "credential_id": "enterprise_hsm",
  "parallel_limit": 3,
  "skip_existing": true
})
```

✅ **GitHub integration configured** - Releases will be automatically signed
✅ **Multi-platform support** - Different credentials for different artifact types
✅ **Batch signed existing artifacts** - Your current releases are now secured

Your repository is now configured for automatic code signing on every release!

---

## Example 4: Security Policy Compliance

**User:** "We need to ensure our signing process meets FIPS 140-2 requirements for government contracts"

**Claude:** I'll help you configure and validate FIPS 140-2 compliance for your code signing process. Let me start by validating your current setup against FIPS requirements:

```mcp
policy_validation({
  "file_path": "./dist/government-app.exe",
  "policy_set": "fips",
  "custom_policies": {
    "require_dual_control": true,
    "minimum_key_ceremony_participants": 2,
    "require_hardware_attestation": true
  }
})
```

Now let me check your HSM configuration for FIPS compliance:

```mcp
hsm_operations({
  "operation": "get_info",
  "include_fips_status": true
})
```

Let me also generate a compliance audit trail:

```mcp
audit_trail({
  "start_date": "2024-01-01",
  "end_date": "2024-12-31",
  "export_format": "xml",
  "include_fips_events": true
})
```

✅ **FIPS 140-2 compliance verified** - Your HSM meets Level 2 requirements
✅ **Policy validation passed** - All signing operations comply with government standards
✅ **Audit trail generated** - Ready for compliance review and certification

Your code signing infrastructure is fully compliant with FIPS 140-2 requirements for government contracts.

---

## Example 5: Supply Chain Security Investigation

**User:** "We found a suspicious binary in our software supply chain. Can you help me verify its authenticity and trace its origin?"

**Claude:** I'll help you investigate this suspicious binary by verifying its signatures and tracing its supply chain provenance. Let me start with comprehensive verification:

```mcp
verify_signature({
  "file_path": "./suspicious/binary.exe",
  "check_certificate_chain": true,
  "check_timestamp": true,
  "check_revocation": true
})
```

Now let me check if there are any supply chain attestations:

```mcp
supply_chain_attestation({
  "operation": "verify",
  "artifact_path": "./suspicious/binary.exe",
  "require_slsa_level": "2"
})
```

Let me also search our audit logs for any records of this binary:

```mcp
audit_trail({
  "artifact_hash": "sha256:abcdef123456...",
  "include_all_operations": true,
  "export_format": "json"
})
```

🚨 **SECURITY FINDINGS:**

❌ **Invalid signature** - Certificate chain verification failed
❌ **No supply chain attestations** - Missing SLSA provenance data  
❌ **Not in audit trail** - No record of this binary being signed by your infrastructure
⚠️  **Timestamp verification failed** - Signature timestamp is suspicious

**RECOMMENDATION:** This binary appears to be unauthorized and potentially malicious. I recommend:
1. **Quarantine immediately** - Remove from production systems
2. **Investigate source** - Determine how it entered your supply chain
3. **Scan for indicators** - Check for other similar unauthorized binaries
4. **Review access controls** - Ensure signing infrastructure hasn't been compromised

---

## Example 6: Multi-Platform Release Signing

**User:** "We're releasing our app on Windows, macOS, and Linux. Can you sign all the platform-specific binaries?"

**Claude:** I'll sign your multi-platform release binaries using the appropriate credentials for each platform. Let me handle this systematically:

```mcp
batch_sign({
  "file_patterns": [
    "./release/windows/*.exe",
    "./release/windows/*.msi", 
    "./release/macos/*.dmg",
    "./release/macos/*.pkg",
    "./release/linux/*.deb",
    "./release/linux/*.rpm"
  ],
  "credential_mapping": {
    "exe": "authenticode_certificate",
    "msi": "authenticode_certificate",
    "dmg": "apple_developer_id",
    "pkg": "apple_developer_id", 
    "deb": "gpg_signing_key",
    "rpm": "gpg_signing_key"
  },
  "parallel_limit": 6,
  "skip_existing": false
})
```

Now let me create platform-specific supply chain attestations:

```mcp
supply_chain_attestation({
  "build_artifacts": [
    "./release/windows/myapp.exe",
    "./release/macos/MyApp.dmg", 
    "./release/linux/myapp.deb"
  ],
  "source_repository": "github.com/yourorg/myapp",
  "build_environment": {
    "platforms": ["windows-2022", "macos-12", "ubuntu-20.04"],
    "cross_compiled": false,
    "build_matrix": true
  },
  "attestation_level": "3"
})
```

✅ **Windows binaries signed** - Authenticode certificates applied to .exe and .msi files
✅ **macOS binaries signed** - Apple Developer ID certificates with notarization
✅ **Linux packages signed** - GPG signatures for .deb and .rpm packages
✅ **Supply chain attestations** - SLSA Level 3 provenance for all platforms
✅ **Cross-platform verification** - All signatures validated successfully

Your multi-platform release is now fully signed and ready for distribution across all target operating systems!

---

These examples demonstrate how Claude can seamlessly integrate with your code signing infrastructure to provide enterprise-grade security operations through natural conversation.