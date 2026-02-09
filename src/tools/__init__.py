"""
MCP Tools for Code Signing

This module contains all the MCP tools that provide code signing capabilities
through pluggable provider architecture.

Supported Providers:
- noosphere: Full-featured (C2PA, in-toto, DID, VC, HSM)
- signpath: Enterprise Windows signing
- sigstore: Open source keyless signing
- local: Offline signing with local keys
"""

from .sign_binary import SignBinaryTool
from .sign_package import SignPackageTool
from .verify_signature import VerifySignatureTool
from .get_certificate_info import GetCertificateInfoTool
from .create_signing_request import CreateSigningRequestTool
from .manage_certificates import ManageCertificatesTool
from .audit_trail import AuditTrailTool
from .batch_sign import BatchSignTool
from .github_integration import GitHubIntegrationTool
from .hsm_operations import HSMOperationsTool
from .policy_validation import PolicyValidationTool
from .supply_chain_attestation import SupplyChainAttestationTool
from .verify_trust_chain import VerifyTrustChainTool

__all__ = [
    "SignBinaryTool",
    "SignPackageTool", 
    "VerifySignatureTool",
    "GetCertificateInfoTool",
    "CreateSigningRequestTool",
    "ManageCertificatesTool",
    "AuditTrailTool",
    "BatchSignTool",
    "GitHubIntegrationTool",
    "HSMOperationsTool",
    "PolicyValidationTool",
    "SupplyChainAttestationTool",
    "VerifyTrustChainTool",
]