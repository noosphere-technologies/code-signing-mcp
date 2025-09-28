#!/usr/bin/env python3
"""
Code Signing MCP Server

Main server implementation that provides enterprise code signing capabilities
to AI agents via the Model Context Protocol.
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
)
from .config import load_config, Config
from .security import SecurityManager
from .integrations import CodeSigningAgentClient, C2PArtifactClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class CodeSigningMCPServer:
    """
    Main MCP server class that orchestrates code signing operations.
    """
    
    def __init__(self, config: Config):
        """Initialize the MCP server with configuration."""
        self.config = config
        self.server = Server("code-signing-mcp")
        self.security_manager = SecurityManager(config.security)
        
        # Initialize service clients
        self.code_signing_client = CodeSigningAgentClient(
            config.services.code_signing_agent
        )
        self.c2pa_client = C2PArtifactClient(
            config.services.c2pa_artifact
        )
        
        # Initialize tools
        self.tools = self._initialize_tools()
        
        # Register MCP handlers
        self._register_handlers()
        
        logger.info("Code Signing MCP Server initialized")
    
    def _initialize_tools(self) -> Dict[str, Any]:
        """Initialize all MCP tools."""
        return {
            "sign_binary": SignBinaryTool(
                self.code_signing_client,
                self.c2pa_client, 
                self.config
            ),
            "sign_package": SignPackageTool(
                self.code_signing_client,
                self.c2pa_client,
                self.config
            ),
            "verify_signature": VerifySignatureTool(
                self.code_signing_client,
                self.c2pa_client,
                self.config
            ),
            "get_certificate_info": GetCertificateInfoTool(
                self.code_signing_client,
                self.config
            ),
            "create_signing_request": CreateSigningRequestTool(
                self.code_signing_client,
                self.config
            ),
            "manage_certificates": ManageCertificatesTool(
                self.code_signing_client,
                self.config
            ),
            "audit_trail": AuditTrailTool(
                self.code_signing_client,
                self.config
            ),
            "batch_sign": BatchSignTool(
                self.code_signing_client,
                self.c2pa_client,
                self.config
            ),
            "github_integration": GitHubIntegrationTool(
                self.code_signing_client,
                self.config
            ),
            "hsm_operations": HSMOperationsTool(
                self.code_signing_client,
                self.config
            ),
            "policy_validation": PolicyValidationTool(
                self.code_signing_client,
                self.config
            ),
            "supply_chain_attestation": SupplyChainAttestationTool(
                self.code_signing_client,
                self.config
            ),
        }
    
    def _register_handlers(self):
        """Register MCP protocol handlers."""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available tools for AI agents."""
            return [
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
                                "description": "Create in-toto attestation (default: true)"
                            },
                            "embed_c2pa": {
                                "type": "boolean", 
                                "description": "Embed C2PA manifest (default: true)"
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
                        "required": ["file_patterns", "credential_id"]
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
                    description="Generate comprehensive supply chain attestations",
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
    
    async def run(self, transport):
        """Run the MCP server with the specified transport."""
        logger.info("Starting Code Signing MCP Server...")
        
        # Initialize service connections
        await self.code_signing_client.initialize()
        await self.c2pa_client.initialize()
        
        try:
            await self.server.run(
                transport,
                InitializationOptions(
                    server_name="code-signing-mcp",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={}
                    )
                )
            )
        finally:
            # Cleanup service connections
            await self.code_signing_client.close()
            await self.c2pa_client.close()
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
        if not config_path.exists():
            click.echo(f"Configuration file not found: {config}", err=True)
            sys.exit(1)
        
        server_config = load_config(config_path)
        
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