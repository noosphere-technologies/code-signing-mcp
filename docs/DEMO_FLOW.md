# Code Signing MCP Demo Flow

## Demo Narrative: "AI-Powered Enterprise Code Signing"

**Duration**: 10-15 minutes
**Audience**: Technical stakeholders, security teams, DevOps engineers

---

## Act 1: The Setup (2 minutes)

### Opening Hook
"Today I'll show you how AI agents can handle enterprise code signing operations that normally require deep security expertise. Instead of developers memorizing certificate policies, HSM configurations, and compliance requirements, they just ask Claude."

### Show the Stack
```
┌─────────────────────────────────────────┐
│  Claude (AI Agent via MCP)              │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│  Code Signing MCP Server (12 tools)    │
│  - sign_binary, batch_sign              │
│  - verify_signature, audit_trail        │
│  - policy_validation, certificates      │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│  Noosphere Infrastructure               │
│  - C2PA Artifact Service                │
│  - DID/VC Identity System               │
│  - HSM Integration                      │
└─────────────────────────────────────────┘
```

---

## Act 2: Basic Signing - "The Easy Win" (3 minutes)

### Scenario: Developer needs to sign a release

**User**: "I just built myapp.jar and need to sign it for production release"

**Claude uses**: `sign_binary`

**What happens**:
1. Validates the JAR file exists
2. Retrieves user's DID and credentials
3. Selects appropriate code signing certificate (auto-detected for Java)
4. Applies enterprise security policies
5. Signs with C2PA manifest embedded
6. Generates SLSA attestation
7. Returns signed artifact with verification URL

**Show the output**:
```json
{
  "success": true,
  "artifact": {
    "name": "myapp.jar",
    "type": "java_archive",
    "sha256": "abc123..."
  },
  "signature": {
    "algorithm": "SHA256withRSA",
    "timestamp": "2025-10-08T10:30:00Z",
    "certificate_fingerprint": "4A:5B:6C..."
  },
  "c2pa": {
    "manifest_embedded": true,
    "verification_url": "https://verify.c2pa.org/..."
  },
  "policy_compliance": {
    "policy_set": "enterprise",
    "compliance_verified": true
  }
}
```

**Key takeaway**: "What used to require knowing jarsigner commands, finding the right keystore, and remembering timestamp URLs - now just works."

---

## Act 3: Batch Operations - "Scale" (3 minutes)

### Scenario: CI/CD pipeline produces multiple artifacts

**User**: "I have a release build with Windows, Mac, and Linux binaries in ./dist. Sign everything appropriate for distribution."

**Claude uses**: `batch_sign`

**What happens**:
1. Scans dist folder: finds myapp.exe, myapp.dmg, myapp.deb
2. Auto-detects artifact types
3. Selects appropriate credentials per platform:
   - Windows Authenticode for .exe
   - Apple Developer ID for .dmg
   - GPG key for .deb
4. Signs 5 files in parallel
5. Skips already-signed files
6. Generates summary

**Show the output**:
```json
{
  "success": true,
  "summary": {
    "total_files": 5,
    "successful": 5,
    "failed": 0,
    "success_rate": 100.0,
    "total_processing_time_ms": 3420,
    "average_time_per_file_ms": 684
  },
  "results": [
    {"file_name": "myapp.exe", "success": true},
    {"file_name": "myapp.dmg", "success": true},
    {"file_name": "myapp.deb", "success": true},
    {"file_name": "myapp-installer.msi", "success": true},
    {"file_name": "myapp.rpm", "success": true}
  ]
}
```

**Follow-up question**: "Can you verify all those signatures?"

**Claude uses**: `verify_signature` (loop through files)

**Key takeaway**: "Cross-platform signing that would take 30 minutes of manual work - done in 3.4 seconds."

---

## Act 4: Certificate Management - "Enterprise Reality" (2 minutes)

### Scenario: Certificate expiring soon

**User**: "Check if any of my code signing certificates are expiring soon"

**Claude uses**: `get_certificate_info`

**What happens**:
1. Lists all certificates
2. Checks expiry dates
3. Checks revocation status
4. Flags warnings

**Show the output**:
```json
{
  "success": true,
  "certificates": [
    {
      "credential_id": "windows-codesign-2024",
      "subject": {"CN": "Acme Corp", "O": "Acme Corporation"},
      "expiry": {
        "status": "expiring_soon",
        "days_until_expiry": 14,
        "warning_level": "high",
        "renewal_recommended": true
      }
    }
  ]
}
```

**Follow-up**: "Generate a renewal CSR for that certificate"

**Claude uses**: `create_signing_request`

**Key takeaway**: "Proactive certificate management prevents expired cert emergencies at 5pm on Friday."

---

## Act 5: Compliance & Audit - "The CFO Cares" (3 minutes)

### Scenario: SOX compliance audit

**User**: "I need a report of all code signing operations from last quarter for our SOX audit"

**Claude uses**: `audit_trail`

**What happens**:
1. Queries last 90 days
2. Exports to CSV format
3. Generates summary statistics

**Show the output**:
```json
{
  "summary": {
    "total_operations": 1847,
    "successful_operations": 1842,
    "failed_operations": 5,
    "success_rate": 99.73,
    "operations_by_type": {
      "sign_binary": 1654,
      "batch_sign": 143,
      "verify_signature": 50
    }
  },
  "formatted_output": "<CSV data with timestamps, users, artifacts>"
}
```

**Follow-up**: "Validate one of those signed files against FIPS 140-2 requirements"

**Claude uses**: `policy_validation`

**Show the output**:
```json
{
  "compliant": true,
  "policy_set": "fips",
  "validation_results": [
    {
      "policy": "fips_algorithms",
      "passed": true,
      "description": "Must use FIPS-approved algorithms"
    },
    {
      "policy": "require_hsm_fips",
      "passed": true,
      "description": "Must use FIPS 140-2 Level 2+ HSM"
    }
  ],
  "summary": {
    "compliance_rate": 100.0
  }
}
```

**Key takeaway**: "Compliance isn't an afterthought - it's built into every operation."

---

## Act 6: Supply Chain Security - "The Future" (2 minutes)

### Scenario: Generate SLSA attestations

**User**: "Create SLSA Level 3 attestations for my release artifacts in GitHub Actions"

**Claude uses**: `supply_chain_attestation`

**What happens**:
1. Collects artifact hashes
2. Gathers build environment metadata
3. Generates provenance statements
4. Creates in-toto link metadata
5. Signs with DID
6. Returns SLSA bundle

**Show the output**:
```json
{
  "success": true,
  "attestation_level": "SLSA Level 3",
  "provenance": {
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://slsa.dev/provenance/v0.2",
    "predicate": {
      "builder": {"id": "did:web:builder.acme.com"},
      "metadata": {
        "reproducible": true,
        "completeness": {
          "parameters": true,
          "environment": true,
          "materials": true
        }
      }
    }
  },
  "compliance_report": {
    "slsa_level": "Level 3",
    "description": "Hardened builds, non-falsifiable provenance",
    "compliance_status": "compliant"
  }
}
```

**Follow-up**: "Set up automated signing for my GitHub repo so this happens on every release"

**Claude uses**: `github_integration`

**Key takeaway**: "Supply chain security that meets executive order requirements - automated end-to-end."

---

## Closing: The Big Picture (1 minute)

### What We Just Did

1. **Simplified complexity**: Enterprise code signing without reading documentation
2. **Cross-platform**: Windows, macOS, Linux - all handled automatically
3. **Compliance-first**: FIPS, SOX, SLSA built-in, not bolted-on
4. **Audit-ready**: Every operation logged for compliance
5. **AI-native**: The AI agent understands security policies and best practices

### Why This Matters

**For Developers**:
- Sign code in seconds, not hours
- No more "how do I sign this?" questions
- Automatic best practices

**For Security Teams**:
- Centralized policy enforcement
- Complete audit trails
- HSM-backed credentials

**For The Business**:
- Faster releases
- Compliance automation
- Reduced security incidents

### The Demo Closer

"This is what happens when you give AI agents the right tools. Not replacing security teams - augmenting them. Developers get unblocked, security gets enforced, compliance gets automated. And it all happens through natural language."

---

## Technical Notes for Demo Prep

### What to have ready:

1. **Sample artifacts** (create dummy files):
   - myapp.jar (Java application)
   - myapp.exe (Windows executable)
   - myapp.dmg (macOS disk image)
   - myapp.deb (Debian package)
   - myapp.rpm (RPM package)

2. **Mock credentials** in DID system:
   - "windows-codesign-2024" (Authenticode)
   - "apple-developer-2024" (Apple Developer ID)
   - "linux-gpg-key" (GPG for Linux packages)

3. **Pre-recorded audit data**:
   - 90 days of synthetic signing operations
   - Mix of success/failure
   - Multiple users and artifact types

4. **Demo environment**:
   - Claude Desktop with MCP configured
   - Code-signing-mcp server running
   - Mock C2PA and DID services responding

### Backup demos if something breaks:

1. Show just `get_certificate_info` - low risk
2. Show `audit_trail` with pre-generated data
3. Show `policy_validation` with example files
4. Walk through the tool schemas in server.py

### Questions to anticipate:

**Q**: "What if I don't have an HSM?"
**A**: "It gracefully falls back to software keys, with appropriate policy warnings."

**Q**: "Can this work with our existing CA?"
**A**: "Yes - it integrates with your existing PKI infrastructure."

**Q**: "What about air-gapped environments?"
**A**: "The MCP server can run on-prem behind your firewall."

**Q**: "How do you prevent the AI from signing malicious code?"
**A**: "The policy engine validates every request. Plus audit logs for forensics."

### Demo safety tips:

- Have screenshots/recordings as backup
- Test the entire flow 3x before the demo
- Have a "Plan B" slide deck ready
- Keep the terminal font LARGE
- Slow down when typing prompts
