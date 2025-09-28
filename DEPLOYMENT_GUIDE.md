# Code Signing MCP Server - Deployment Guide

This guide provides step-by-step instructions for deploying the Code Signing MCP Server in various environments, from development to enterprise production.

## 🚀 Quick Start (Development)

### Prerequisites

- Python 3.8 or higher
- Access to existing Noosphere infrastructure:
  - [code-signing-agent](../noosphere/github/code-signing-agent/) (LangGraph-based)
  - [c2pa-artifact](../noosphere/github/c2pa-artifact/) service
- Docker (optional, for containerized deployment)

### Local Development Setup

```bash
# 1. Clone and setup
git clone https://github.com/noosphere-technologies/code-signing-mcp.git
cd code-signing-mcp

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure the server
cp config/config.example.json config/config.json
# Edit config.json with your service endpoints

# 5. Start the MCP server
python -m src.server --config config/config.json --transport stdio
```

### Connecting to Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "code-signing": {
      "command": "python",
      "args": ["-m", "src.server", "--config", "/path/to/config.json"],
      "cwd": "/path/to/code-signing-mcp"
    }
  }
}
```

## 🏢 Enterprise Production Deployment

### Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Load Balancer │    │  Code Signing    │    │  Noosphere      │
│   (nginx/HAProxy│◄──►│  MCP Server      │◄──►│  Infrastructure │
│   + TLS)        │    │  (clustered)     │    │  (existing)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                        │
         │              ┌────────▼────────┐              │
         │              │ Enterprise HSM  │              │
         │              │ (FIPS 140-2)    │              │
         │              └─────────────────┘              │
         │                                               │
┌────────▼────────┐                            ┌─────────▼────────┐
│   Monitoring    │                            │  Audit & Backup │
│ - Prometheus    │                            │ - PostgreSQL     │
│ - Grafana       │                            │ - S3/MinIO       │
│ - Jaeger        │                            │ - Log rotation   │
└─────────────────┘                            └──────────────────┘
```

### Option 1: Docker Compose (Recommended)

Use the comprehensive Docker Compose setup in `examples/enterprise-deployment/`:

```bash
# 1. Prepare the environment
cd examples/enterprise-deployment
cp .env.example .env
# Edit .env with your production values

# 2. Configure services
cp config.example/* config/
# Edit configuration files for your environment

# 3. Start infrastructure services
docker-compose up -d postgres redis hsm-proxy

# 4. Initialize databases
docker-compose exec postgres psql -U postgres -c "CREATE DATABASE certificates;"
docker-compose exec postgres psql -U postgres -c "CREATE DATABASE metadata;"

# 5. Start application services
docker-compose up -d code-signing-agent c2pa-artifact metadata-service

# 6. Start MCP server
docker-compose up -d code-signing-mcp

# 7. Start monitoring
docker-compose up -d prometheus grafana jaeger loki promtail

# 8. Start reverse proxy
docker-compose up -d nginx
```

### Option 2: Kubernetes (Enterprise Scale)

```bash
# 1. Create namespace
kubectl create namespace code-signing

# 2. Deploy secrets
kubectl create secret generic code-signing-secrets \
  --from-literal=postgres-password='your-password' \
  --from-literal=hsm-pin='your-hsm-pin' \
  --from-literal=jwt-secret='your-jwt-secret' \
  -n code-signing

# 3. Deploy infrastructure
kubectl apply -f k8s/infrastructure/ -n code-signing

# 4. Deploy application
kubectl apply -f k8s/application/ -n code-signing

# 5. Deploy monitoring
kubectl apply -f k8s/monitoring/ -n code-signing
```

### Option 3: Cloud Native (AWS/GCP/Azure)

#### AWS Deployment

```bash
# 1. Create EKS cluster
eksctl create cluster --name code-signing-cluster --region us-west-2

# 2. Deploy AWS Load Balancer Controller
kubectl apply -f https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases/download/v2.4.4/v2_4_4_full.yaml

# 3. Configure AWS KMS integration
aws kms create-key --description "Code Signing MCP Key" --key-usage SIGN_VERIFY

# 4. Deploy with AWS integrations
helm install code-signing-mcp ./helm/code-signing-mcp \
  --set aws.region=us-west-2 \
  --set aws.kms.keyId=your-kms-key-id \
  --set ingress.enabled=true \
  --set ingress.annotations."kubernetes\.io/ingress\.class"=alb
```

## 🔒 Security Configuration

### HSM Integration

#### SoftHSM (Development/Testing)

```bash
# Initialize SoftHSM
softhsm2-util --init-token --slot 0 --label "CodeSigning" --pin 1234 --so-pin 1234

# Generate signing key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
  --keypairgen --key-type rsa:2048 --label "signing-key"
```

#### Thales Luna HSM (Production)

```json
{
  "credentials": {
    "enterprise_hsm": {
      "type": "hsm",
      "pkcs11_config": {
        "library_path": "/usr/lib/libCryptoki2_64.so",
        "slot": 1,
        "pin": "${HSM_PIN}",
        "token_label": "CodeSigning"
      }
    }
  }
}
```

#### AWS CloudHSM

```json
{
  "credentials": {
    "aws_cloudhsm": {
      "type": "cloud_kms",
      "provider": "aws",
      "key_id": "${AWS_KMS_KEY_ID}",
      "region": "us-west-2"
    }
  }
}
```

### Certificate Management

#### Automated Certificate Renewal

```bash
# Setup certificate renewal with Let's Encrypt
certbot certonly --webroot \
  --webroot-path=/var/www/html \
  --email admin@yourcompany.com \
  --agree-tos \
  --no-eff-email \
  -d code-signing.yourcompany.com

# Add renewal cron job
echo "0 12 * * * /usr/bin/certbot renew --quiet" | crontab -
```

#### Enterprise CA Integration

```json
{
  "certificate_authorities": {
    "enterprise_ca": {
      "type": "internal",
      "ca_url": "https://ca.yourcompany.com/api",
      "auth_method": "client_cert",
      "client_cert": "/etc/ssl/client.pem",
      "client_key": "/etc/ssl/client.key"
    }
  }
}
```

## 📊 Monitoring and Observability

### Metrics Dashboard

The deployment includes a comprehensive Grafana dashboard with:

- **MCP Server Metrics**: Request rates, latencies, error rates
- **Signing Operations**: Success/failure rates, queue depths, throughput
- **HSM Health**: Connection status, key usage, performance
- **Security Events**: Failed authentications, policy violations
- **Resource Usage**: CPU, memory, disk, network

Access Grafana at: `http://your-domain/grafana` (admin/admin)

### Alerting Rules

Key alerts configured in Prometheus:

```yaml
groups:
  - name: code-signing-alerts
    rules:
      - alert: HSMConnectionDown
        expr: hsm_connection_status == 0
        for: 5m
        annotations:
          summary: "HSM connection is down"
          
      - alert: SigningFailureRate
        expr: rate(signing_failures_total[5m]) > 0.1
        for: 2m
        annotations:
          summary: "High signing failure rate detected"
          
      - alert: CertificateExpiringSoon
        expr: certificate_expiry_days < 30
        annotations:
          summary: "Certificate expires in {{ $value }} days"
```

### Log Aggregation

Logs are collected via Promtail and stored in Loki:

```yaml
# promtail configuration
clients:
  - url: http://loki:3100/loki/api/v1/push
    
scrape_configs:
  - job_name: code-signing
    static_configs:
      - targets:
          - localhost
        labels:
          job: code-signing-mcp
          __path__: /var/log/code-signing/*.log
```

## 🔍 Health Checks and Monitoring

### Health Check Endpoints

- **MCP Server**: `GET /health`
- **Code Signing Agent**: `GET /health`
- **C2PA Artifact**: `GET /health`
- **Metadata Service**: `GET /health`

### Monitoring Commands

```bash
# Check overall system health
curl -f http://localhost:8080/health

# Check HSM connectivity
curl -X POST http://localhost:8080/tools/hsm_operations \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"operation": "get_info"}'

# Verify certificate status
curl -X POST http://localhost:8080/tools/get_certificate_info \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"check_revocation": true}'

# Test signing operation
curl -X POST http://localhost:8080/tools/sign_binary \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"file_path": "/tmp/test.jar", "credential_id": "test_credential"}'
```

## 🚦 Testing and Validation

### Integration Tests

```bash
# Run comprehensive test suite
python -m pytest tests/ -v --cov=src

# Run HSM integration tests (requires HSM)
python -m pytest tests/integration/test_hsm.py -v

# Run signing workflow tests
python -m pytest tests/workflows/test_signing.py -v

# Performance tests
python -m pytest tests/performance/ -v --benchmark-only
```

### Manual Testing

```bash
# Test basic signing
echo "test content" > test.txt
python test_client.py sign_binary test.txt

# Test batch operations
python test_client.py batch_sign "*.jar" enterprise_hsm

# Test policy validation
python test_client.py policy_validation test.jar fips
```

## 🛠️ Troubleshooting

### Common Issues

#### HSM Connection Problems

```bash
# Check HSM status
softhsm2-util --show-slots

# Test PKCS#11 library
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots

# Verify permissions
ls -la /var/lib/softhsm/tokens/
```

#### Certificate Issues

```bash
# Check certificate validity
openssl x509 -in certificate.pem -text -noout

# Verify certificate chain
openssl verify -CAfile ca-chain.pem certificate.pem

# Check certificate expiration
openssl x509 -in certificate.pem -checkend 86400
```

#### Network Connectivity

```bash
# Test service connectivity
curl -v http://localhost:8081/health  # Code Signing Agent
curl -v http://localhost:8082/health  # C2PA Artifact
curl -v http://localhost:8083/health  # Metadata Service

# Check DNS resolution
nslookup code-signing.yourcompany.com

# Test load balancer
curl -H "Host: code-signing.yourcompany.com" http://load-balancer-ip/health
```

### Log Analysis

```bash
# View MCP server logs
docker-compose logs -f code-signing-mcp

# Check HSM logs
tail -f /var/log/code-signing/hsm.log

# Monitor signing operations
grep "SIGNING_OPERATION" /var/log/code-signing/audit.log | tail -10

# Check for errors
grep -i error /var/log/code-signing/*.log
```

## 📋 Maintenance

### Regular Maintenance Tasks

#### Daily
- Check service health status
- Review error logs
- Monitor certificate expiration warnings

#### Weekly
- Review audit logs for security events
- Check disk space and cleanup old logs
- Verify backup integrity

#### Monthly
- Update security patches
- Review and rotate API keys
- Performance optimization review

#### Quarterly
- Certificate renewal planning
- Security policy review
- Disaster recovery testing

### Backup and Recovery

```bash
# Backup configuration
tar -czf config-backup-$(date +%Y%m%d).tar.gz config/

# Backup HSM data (if applicable)
softhsm2-util --export --slot 0 --pin 1234 --file hsm-backup.key

# Backup database
pg_dump -h localhost -U postgres codesigning > db-backup-$(date +%Y%m%d).sql

# Backup to S3
aws s3 sync ./backups/ s3://code-signing-backups/$(date +%Y%m%d)/
```

### Disaster Recovery

```bash
# Restore from backup
tar -xzf config-backup-20240101.tar.gz
psql -h localhost -U postgres codesigning < db-backup-20240101.sql

# Restore HSM keys
softhsm2-util --import --slot 0 --pin 1234 --file hsm-backup.key

# Restart services
docker-compose restart
```

## 📞 Support

### Enterprise Support Contacts

- **Technical Support**: support@noosphere.tech
- **Security Issues**: security@noosphere.tech  
- **Emergency Response**: +1-800-NOOSPHERE

### Documentation

- **API Reference**: https://docs.noosphere.tech/code-signing-mcp/api
- **User Guide**: https://docs.noosphere.tech/code-signing-mcp/guide
- **Security Best Practices**: https://docs.noosphere.tech/code-signing-mcp/security

### Community

- **GitHub Issues**: https://github.com/noosphere-technologies/code-signing-mcp/issues
- **Discussions**: https://github.com/noosphere-technologies/code-signing-mcp/discussions
- **Slack Channel**: #code-signing-mcp in Noosphere Workspace