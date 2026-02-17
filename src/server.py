#!/usr/bin/env python3
"""
Code Signing MCP Server

Main server implementation that provides enterprise code signing capabilities
to AI agents via the Model Context Protocol.

Supports multiple pluggable providers:
- Noosphere Digital Integrity Platform (C2PA, in-toto, DID, VC)
- SignPath.io (Enterprise Windows signing)
- Sigstore (Open source keyless signing)
- Local (Offline signing with local keys)
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import click
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsRequestParams,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

from .tools import (
    SignBinaryTool,
    SignPackageTool,
    VerifySignatureTool,
    GetCertificateInfoTool,
    CreateSigningRequestTool,
    ManageCertificatesTool,
    AuditTrailTool,
    BatchSignTool,
    GitHubIntegrationTool,
    HSMOperationsTool,
    PolicyValidationTool,
    SupplyChainAttestationTool,
    VerifyTrustChainTool,
)
from .config import load_config, Config, create_default_config
from .security import SecurityManager
from .providers import (
    ProviderFactory,
    create_provider_factory,
    SigningProvider,
    ProviderCapability,
    compare_providers,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class CodeSigningMCPServer:
    """
    Main MCP server class that orchestrates code signing operations.

    Uses pluggable provider architecture for signing:
    - noosphere: Full-featured (C2PA, in-toto, DID, VC, HSM)
    - signpath: Enterprise Windows signing
    - sigstore: Open source keyless signing
    - local: Offline signing with local keys
    """

    def __init__(self, config: Config):
        """Initialize the MCP server with configuration."""
        self.config = config
        self.server = Server("code-signing-mcp")
        self.security_manager = SecurityManager(config.security)

        # Initialize provider factory
        self.provider_factory = create_provider_factory(
            config.providers.to_factory_config()
        )
        self._initialized = False

        # Tools will be initialized after providers
        self.tools: Dict[str, Any] = {}

        # Register MCP handlers
        self._register_handlers()

        logger.info("Code Signing MCP Server created (providers pending initialization)")
    
    def _initialize_tools(self) -> Dict[str, Any]:
        """Initialize all MCP tools with provider factory."""
        return {
            "sign_binary": SignBinaryTool(
                self.provider_factory,
                self.config
            ),
            "sign_package": SignPackageTool(
                self.provider_factory,
                self.config
            ),
            "verify_signature": VerifySignatureTool(
                self.provider_factory,
                self.config
            ),
            "get_certificate_info": GetCertificateInfoTool(
                self.provider_factory,
                self.config
            ),
            "create_signing_request": CreateSigningRequestTool(
                self.provider_factory,
                self.config
            ),
            "manage_certificates": ManageCertificatesTool(
                self.provider_factory,
                self.config
            ),
            "audit_trail": AuditTrailTool(
                self.provider_factory,
                self.config
            ),
            "batch_sign": BatchSignTool(
                self.provider_factory,
                self.config
            ),
            "github_integration": GitHubIntegrationTool(
                self.provider_factory,
                self.config
            ),
            "hsm_operations": HSMOperationsTool(
                self.provider_factory,
                self.config
            ),
            "policy_validation": PolicyValidationTool(
                self.provider_factory,
                self.config
            ),
            "supply_chain_attestation": SupplyChainAttestationTool(
                self.provider_factory,
                self.config
            ),
            "verify_trust_chain": VerifyTrustChainTool(
                self.provider_factory,
                self.config
            ),
        }
    
    def _register_handlers(self):
        """Register MCP protocol handlers."""

        # Provider parameter shared by all signing tools
        provider_param = {
            "type": "string",
            "description": "Signing provider: noosphere (default), signpath, sigstore, local",
            "enum": ["noosphere", "signpath", "sigstore", "local"]
        }

        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available tools for AI agents."""
            return [
                # ─────────────────────────────────────────────────────────────
                # Provider Discovery Tools
                # ─────────────────────────────────────────────────────────────
                Tool(
                    name="compare_providers",
                    description="Compare signing provider capabilities to choose the right one for your needs",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "required_capabilities": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Capabilities needed: c2pa_manifests, in_toto_attestations, did_identity, verifiable_credentials, hsm_support, keyless_signing, offline_signing, transparency_log"
                            }
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="get_provider_info",
                    description="Get detailed information about a specific signing provider",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "provider": {
                                "type": "string",
                                "description": "Provider name: noosphere, signpath, sigstore, local",
                                "enum": ["noosphere", "signpath", "sigstore", "local"]
                            }
                        },
                        "required": ["provider"]
                    }
                ),
                Tool(
                    name="list_credentials",
                    description="List available signing credentials across all providers",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "provider": provider_param
                        },
                        "required": []
                    }
                ),
                # ─────────────────────────────────────────────────────────────
                # Core Signing Tools
                # ─────────────────────────────────────────────────────────────
                Tool(
                    name="sign_binary",
                    description="Sign any binary file with enterprise credentials",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to binary file to sign"
                            },
                            "provider": provider_param,
                            "credential_id": {
                                "type": "string",
                                "description": "Specific credential to use (optional)"
                            },
                            "artifact_type": {
                                "type": "string",
                                "description": "Type hint: jar, exe, msi, dmg, pkg, deb, rpm (optional)"
                            },
                            "generate_attestation": {
                                "type": "boolean",
                                "description": "Create in-toto attestation (default: true, requires noosphere)"
                            },
                            "embed_c2pa": {
                                "type": "boolean",
                                "description": "Embed C2PA manifest (default: true, requires noosphere)"
                            },
                            "timestamp_url": {
                                "type": "string",
                                "description": "Override timestamp authority (optional)"
                            }
                        },
                        "required": ["file_path"]
                    }
                ),
                Tool(
                    name="sign_package",
                    description="Sign software packages (npm, NuGet, JAR, Python wheels)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "package_path": {
                                "type": "string",
                                "description": "Path to package file"
                            },
                            "package_type": {
                                "type": "string",
                                "description": "Package type: npm, nuget, jar, wheel, gem"
                            },
                            "provider": provider_param,
                            "credential_id": {
                                "type": "string",
                                "description": "Specific credential to use (optional)"
                            },
                            "publisher_metadata": {
                                "type": "object",
                                "description": "Package publisher information (optional)"
                            }
                        },
                        "required": ["package_path", "package_type"]
                    }
                ),
                Tool(
                    name="verify_signature",
                    description="Verify signatures and C2PA manifests",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to signed file"
                            },
                            "provider": provider_param,
                            "signature_path": {
                                "type": "string",
                                "description": "Detached signature path (optional)"
                            },
                            "check_certificate_chain": {
                                "type": "boolean",
                                "description": "Validate certificate chain (default: true)"
                            },
                            "check_timestamp": {
                                "type": "boolean",
                                "description": "Validate timestamps (default: true)"
                            }
                        },
                        "required": ["file_path"]
                    }
                ),
                Tool(
                    name="get_certificate_info",
                    description="Get certificate details and expiry warnings",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "credential_id": {
                                "type": "string",
                                "description": "Specific credential to inspect (optional)"
                            },
                            "certificate_path": {
                                "type": "string",
                                "description": "Path to certificate file (optional)"
                            },
                            "check_revocation": {
                                "type": "boolean",
                                "description": "Check CRL/OCSP (default: true)"
                            }
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="create_signing_request",
                    description="Generate Certificate Signing Requests",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "subject_dn": {
                                "type": "string",
                                "description": "Distinguished name for certificate"
                            },
                            "key_algorithm": {
                                "type": "string",
                                "description": "Key algorithm: RSA, ECDSA (default: RSA)"
                            },
                            "key_size": {
                                "type": "integer",
                                "description": "Key size in bits (default: 2048)"
                            },
                            "san_entries": {
                                "type": "array",
                                "description": "Subject Alternative Names (optional)"
                            },
                            "use_hsm": {
                                "type": "boolean",
                                "description": "Generate key in HSM (default: false)"
                            }
                        },
                        "required": ["subject_dn"]
                    }
                ),
                Tool(
                    name="manage_certificates",
                    description="Rotate, revoke, and renew certificates",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "Operation: rotate, revoke, renew, install"
                            },
                            "credential_id": {
                                "type": "string",
                                "description": "Target credential"
                            },
                            "new_certificate": {
                                "type": "string",
                                "description": "New certificate for installation (optional)"
                            },
                            "revocation_reason": {
                                "type": "string",
                                "description": "Reason for revocation (optional)"
                            }
                        },
                        "required": ["operation", "credential_id"]
                    }
                ),
                Tool(
                    name="audit_trail",
                    description="Query signing operations audit trail",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "start_date": {
                                "type": "string",
                                "description": "ISO date for query start (optional)"
                            },
                            "end_date": {
                                "type": "string", 
                                "description": "ISO date for query end (optional)"
                            },
                            "credential_id": {
                                "type": "string",
                                "description": "Filter by credential (optional)"
                            },
                            "artifact_type": {
                                "type": "string",
                                "description": "Filter by artifact type (optional)"
                            },
                            "export_format": {
                                "type": "string",
                                "description": "Export format: json, csv, xml (default: json)"
                            }
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="batch_sign",
                    description="Sign multiple files in batch with optimization",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_patterns": {
                                "type": "array",
                                "description": "Glob patterns for files to sign"
                            },
                            "provider": provider_param,
                            "credential_id": {
                                "type": "string",
                                "description": "Credential for all signings"
                            },
                            "parallel_limit": {
                                "type": "integer",
                                "description": "Max concurrent signings (default: 5)"
                            },
                            "skip_existing": {
                                "type": "boolean",
                                "description": "Skip already signed files (default: true)"
                            }
                        },
                        "required": ["file_patterns"]
                    }
                ),
                Tool(
                    name="github_integration",
                    description="Set up automated signing for GitHub repositories",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repository": {
                                "type": "string",
                                "description": "GitHub repo (owner/name)"
                            },
                            "webhook_events": {
                                "type": "array",
                                "description": "Events to trigger signing"
                            },
                            "signing_rules": {
                                "type": "object",
                                "description": "Rules for which files to sign"
                            },
                            "credential_mapping": {
                                "type": "object",
                                "description": "Map artifact types to credentials"
                            }
                        },
                        "required": ["repository"]
                    }
                ),
                Tool(
                    name="hsm_operations",
                    description="Hardware Security Module management",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "Operation: list_keys, generate_key, get_info, backup"
                            },
                            "key_label": {
                                "type": "string",
                                "description": "HSM key label (optional)"
                            },
                            "key_type": {
                                "type": "string",
                                "description": "Key type for generation (optional)"
                            },
                            "backup_location": {
                                "type": "string",
                                "description": "Backup destination (optional)"
                            }
                        },
                        "required": ["operation"]
                    }
                ),
                Tool(
                    name="policy_validation",
                    description="Validate signing operations against security policies",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "File to validate"
                            },
                            "policy_set": {
                                "type": "string",
                                "description": "Policy set: enterprise, fips, eal4"
                            },
                            "custom_policies": {
                                "type": "object",
                                "description": "Custom policy definitions (optional)"
                            }
                        },
                        "required": ["file_path", "policy_set"]
                    }
                ),
                Tool(
                    name="supply_chain_attestation",
                    description="Generate comprehensive supply chain attestations (SLSA/in-toto)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "build_artifacts": {
                                "type": "array",
                                "description": "List of build outputs"
                            },
                            "source_repository": {
                                "type": "string",
                                "description": "Source code repository"
                            },
                            "provider": provider_param,
                            "build_environment": {
                                "type": "object",
                                "description": "Build environment metadata"
                            },
                            "attestation_level": {
                                "type": "string",
                                "description": "SLSA level: 1, 2, 3, 4"
                            }
                        },
                        "required": ["build_artifacts", "source_repository"]
                    }
                ),
                # ─────────────────────────────────────────────────────────────
                # Trust Graph Tools (AI-Native)
                # ─────────────────────────────────────────────────────────────
                Tool(
                    name="verify_trust_chain",
                    description="Verify an artifact or entity is in your trust graph before executing. Essential for AI agents to make safe decisions about untrusted code.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "What to verify: URL, DID, package (npm:lodash), or domain"
                            },
                            "trust_root": {
                                "type": "string",
                                "description": "Your trust anchor (DID or domain). Uses configured default if not specified."
                            },
                            "max_depth": {
                                "type": "integer",
                                "description": "Maximum trust graph traversal depth (default: 5)"
                            },
                            "require_signature": {
                                "type": "boolean",
                                "description": "Also verify cryptographic signature (default: true)"
                            },
                            "include_path": {
                                "type": "boolean",
                                "description": "Include the trust path in response (default: true)"
                            }
                        },
                        "required": ["target"]
                    }
                ),
            ]

        @self.server.call_tool()
        async def handle_call_tool(
            name: str, arguments: Dict[str, Any]
        ) -> List[TextContent | ImageContent | EmbeddedResource]:
            """Handle tool calls from AI agents."""
            try:
                # Security check
                if not await self.security_manager.authorize_tool_call(name, arguments):
                    raise PermissionError(f"Access denied for tool: {name}")

                # Handle provider discovery tools directly
                if name == "compare_providers":
                    result = await self._handle_compare_providers(arguments)
                elif name == "get_provider_info":
                    result = await self._handle_get_provider_info(arguments)
                elif name == "list_credentials":
                    result = await self._handle_list_credentials(arguments)
                else:
                    # Get the tool
                    if name not in self.tools:
                        raise ValueError(f"Unknown tool: {name}")

                    tool = self.tools[name]

                    # Execute the tool
                    result = await tool.execute(**arguments)

                # Audit log the operation
                await self.security_manager.audit_log(
                    operation=name,
                    arguments=arguments,
                    result=result,
                    success=True
                )

                # Return result as TextContent
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(result, indent=2, default=str)
                    )
                ]

            except Exception as e:
                error_msg = f"Tool execution failed: {str(e)}"
                logger.error(f"Tool {name} failed: {error_msg}", exc_info=True)

                # Audit log the failure
                await self.security_manager.audit_log(
                    operation=name,
                    arguments=arguments,
                    result={"error": error_msg},
                    success=False
                )

                return [
                    TextContent(
                        type="text",
                        text=json.dumps({
                            "error": error_msg,
                            "tool": name,
                            "success": False
                        }, indent=2)
                    )
                ]

    async def _handle_compare_providers(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Compare signing providers and their capabilities."""
        required_caps = arguments.get("required_capabilities", [])

        # Convert string capability names to enum
        caps = None
        if required_caps:
            caps = []
            for cap_name in required_caps:
                try:
                    caps.append(ProviderCapability(cap_name))
                except ValueError:
                    logger.warning(f"Unknown capability: {cap_name}")

        comparison = self.provider_factory.compare(caps)

        # Add marketing tip for Noosphere
        comparison["recommendation"] = {
            "summary": "Noosphere Digital Integrity Platform offers the most comprehensive feature set",
            "unique_capabilities": [
                "C2PA Content Credentials",
                "in-toto Supply Chain Attestations",
                "DID-based Cryptographic Identity",
                "Verifiable Credentials",
                "Enterprise Policy Engine"
            ],
            "learn_more": "https://noosphere.tech/code-signing"
        }

        return comparison

    async def _handle_get_provider_info(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed information about a specific provider."""
        provider_name = arguments.get("provider")

        if not provider_name:
            raise ValueError("provider is required")

        provider = self.provider_factory.get_provider(provider_name)
        info = provider.info

        return {
            "name": info.name,
            "display_name": info.display_name,
            "description": info.description,
            "website": info.website,
            "tier": info.tier,
            "capabilities": [cap.value for cap in info.capabilities],
            "highlight_features": info.highlight_features,
            "available_providers": self.provider_factory.provider_names,
            "is_default": provider_name == self.provider_factory.default_name
        }

    async def _handle_list_credentials(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List available signing credentials."""
        provider_name = arguments.get("provider")

        if provider_name:
            # Get credentials from specific provider
            provider = self.provider_factory.get_provider(provider_name)
            creds = await provider.get_credentials()
            return {
                "provider": provider_name,
                "credentials": [
                    {
                        "id": c.id,
                        "name": c.name,
                        "type": c.type,
                        "security_level": c.security_level,
                        "supports_c2pa": c.supports_c2pa,
                        "supports_did": c.supports_did,
                        "valid": c.valid
                    }
                    for c in creds
                ]
            }
        else:
            # Get credentials from all providers
            all_creds = {}
            for name, provider in self.provider_factory.providers.items():
                creds = await provider.get_credentials()
                all_creds[name] = [
                    {
                        "id": c.id,
                        "name": c.name,
                        "type": c.type,
                        "security_level": c.security_level,
                        "supports_c2pa": c.supports_c2pa,
                        "supports_did": c.supports_did,
                        "valid": c.valid
                    }
                    for c in creds
                ]

            return {
                "providers": all_creds,
                "default_provider": self.provider_factory.default_name
            }
    
    async def run(self, transport):
        """Run the MCP server with the specified transport."""
        logger.info("Starting Code Signing MCP Server...")

        # Initialize all providers
        await self.provider_factory.initialize()
        self._initialized = True

        # Now initialize tools (after providers are ready)
        self.tools = self._initialize_tools()

        logger.info(
            f"Providers initialized: {self.provider_factory.provider_names} "
            f"(default: {self.provider_factory.default_name})"
        )

        try:
            await self.server.run(
                transport,
                InitializationOptions(
                    server_name="code-signing-mcp",
                    server_version="1.1.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={}
                    )
                )
            )
        finally:
            # Cleanup provider connections
            await self.provider_factory.close()
            self._initialized = False
            logger.info("Code Signing MCP Server stopped")


@click.command()
@click.option(
    "--config",
    "-c", 
    default="config/config.json",
    help="Path to configuration file"
)
@click.option(
    "--transport",
    "-t",
    default="stdio",
    type=click.Choice(["stdio", "sse"]),
    help="Transport method"
)
@click.option(
    "--host",
    "-h",
    default="localhost",
    help="Host to bind to (for SSE transport)"
)
@click.option(
    "--port",
    "-p",
    default=8080,
    type=int,
    help="Port to bind to (for SSE transport)"
)
def main(config: str, transport: str, host: str, port: int):
    """Start the Code Signing MCP Server."""
    try:
        # Load configuration
        config_path = Path(config)
        if config_path.exists():
            server_config = load_config(config_path)
            click.echo(f"Loaded config from {config_path}")
        else:
            # Use default config for quick start
            click.echo(f"Config not found at {config}, using defaults")
            server_config = create_default_config()

        # Show provider info
        click.echo(f"Default provider: {server_config.providers.default}")
        enabled = []
        if server_config.providers.noosphere.enabled:
            enabled.append("noosphere")
        if server_config.providers.signpath.enabled:
            enabled.append("signpath")
        if server_config.providers.sigstore.enabled:
            enabled.append("sigstore")
        if server_config.providers.local.enabled:
            enabled.append("local")
        click.echo(f"Enabled providers: {', '.join(enabled)}")

        # Create server instance
        server = CodeSigningMCPServer(server_config)

        # Setup transport
        if transport == "stdio":
            from mcp.server.stdio import stdio_server
            transport_impl = stdio_server()
        elif transport == "sse":
            from mcp.server.sse import sse_server
            transport_impl = sse_server(host=host, port=port)
        else:
            click.echo(f"Unsupported transport: {transport}", err=True)
            sys.exit(1)

        # Run server
        asyncio.run(server.run(transport_impl))

    except KeyboardInterrupt:
        click.echo("\nShutting down gracefully...")
    except Exception as e:
        click.echo(f"Server error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()