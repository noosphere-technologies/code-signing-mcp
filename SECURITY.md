# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in code-signing-mcp, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email security details to: **security@noosphere.tech**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Scope

The following are in scope:

- Authentication/authorization bypasses
- Cryptographic weaknesses
- Private key exposure
- Signature forgery
- Policy engine bypasses
- Injection vulnerabilities (command, SQL, etc.)
- Secrets leakage

### Out of Scope

- Vulnerabilities in dependencies (report to upstream)
- Social engineering attacks
- Physical attacks
- Denial of service (unless trivially exploitable)

## Security Best Practices

When using code-signing-mcp:

1. **Protect API Keys**: Use environment variables, never commit secrets
2. **Use HSM for Production**: Software keys are for development only
3. **Enable Audit Logging**: Track all signing operations
4. **Rotate Credentials**: Regularly rotate API keys and certificates
5. **Apply Least Privilege**: Use role-based access control
6. **Monitor Certificate Expiry**: Set up alerts for expiring certs

## Security Features

- Environment variable substitution for secrets (`${VAR_NAME}`)
- HSM support for hardware-backed keys
- Certificate chain validation
- Policy engine for signing rules
- Comprehensive audit logging
- Rate limiting
- Role-based access control

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (with permission).
