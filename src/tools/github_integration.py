"""
GitHub Integration Tool

Sets up automated code signing for GitHub repositories via webhooks.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..providers import ProviderFactory
from ..config import Config


class GitHubIntegrationTool:
    """Tool for GitHub repository signing integration."""
    
    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
    
    async def execute(
        self,
        repository: str,
        webhook_events: Optional[List[str]] = None,
        signing_rules: Optional[Dict[str, Any]] = None,
        credential_mapping: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Set up automated signing for GitHub repositories.
        
        Args:
            repository: GitHub repository (owner/name)
            webhook_events: Events to trigger signing
            signing_rules: Rules for which files to sign
            credential_mapping: Map artifact types to credentials
            
        Returns:
            Dictionary containing integration configuration
        """
        try:
            # Validate repository format
            if '/' not in repository:
                raise ValueError("Repository must be in format 'owner/name'")
            
            owner, repo_name = repository.split('/', 1)
            
            # Get user identity
            user_did = await self.did_client.get_current_user_did()
            
            # Set default webhook events
            if not webhook_events:
                webhook_events = ['release', 'push', 'workflow_run']
            
            # Set default signing rules
            if not signing_rules:
                signing_rules = self._get_default_signing_rules()
            
            # Set default credential mapping
            if not credential_mapping:
                credential_mapping = await self._get_default_credential_mapping(user_did)
            
            # Create webhook configuration
            webhook_config = await self._create_webhook_config(
                repository, webhook_events, signing_rules, credential_mapping, user_did
            )
            
            # Generate GitHub Actions workflow
            workflow_yaml = self._generate_github_actions_workflow(
                signing_rules, credential_mapping
            )
            
            return {
                "success": True,
                "repository": repository,
                "owner": owner,
                "repo_name": repo_name,
                "webhook": {
                    "url": webhook_config["webhook_url"],
                    "secret": webhook_config["webhook_secret"],
                    "events": webhook_events,
                    "active": True
                },
                "signing_rules": signing_rules,
                "credential_mapping": credential_mapping,
                "github_actions_workflow": workflow_yaml,
                "setup_instructions": self._generate_setup_instructions(
                    repository, webhook_config, workflow_yaml
                ),
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "repository": repository,
                "timestamp": self._get_timestamp()
            }
    
    def _get_default_signing_rules(self) -> Dict[str, Any]:
        """Get default signing rules."""
        return {
            "file_patterns": [
                "dist/**/*.exe",
                "dist/**/*.msi",
                "dist/**/*.dmg",
                "dist/**/*.pkg",
                "dist/**/*.jar",
                "dist/**/*.apk",
                "*.whl",
                "*.gem"
            ],
            "exclude_patterns": [
                "**/*.map",
                "**/*.debug",
                "**/test/**"
            ],
            "sign_on_events": {
                "release": {
                    "enabled": True,
                    "require_tag": True
                },
                "push": {
                    "enabled": True,
                    "branches": ["main", "master", "production"]
                },
                "workflow_run": {
                    "enabled": True,
                    "workflow_name": "build"
                }
            }
        }
    
    async def _get_default_credential_mapping(self, user_did: str) -> Dict[str, str]:
        """Get default credential mapping."""
        credentials = await self.did_client.get_available_credentials(user_did)
        
        # Try to find appropriate credentials for common artifact types
        mapping = {}
        
        for cred in credentials:
            cred_type = cred.get("type", "").lower()
            cred_id = cred.get("id")
            
            if "windows" in cred_type or "authenticode" in cred_type:
                mapping["exe"] = cred_id
                mapping["msi"] = cred_id
            elif "apple" in cred_type or "macos" in cred_type:
                mapping["dmg"] = cred_id
                mapping["pkg"] = cred_id
            elif "java" in cred_type or "codesign" in cred_type:
                mapping["jar"] = cred_id
        
        # Use first available credential as default
        if credentials and "default" not in mapping:
            mapping["default"] = credentials[0].get("id")
        
        return mapping
    
    async def _create_webhook_config(
        self,
        repository: str,
        events: List[str],
        signing_rules: Dict[str, Any],
        credential_mapping: Dict[str, str],
        user_did: str
    ) -> Dict[str, Any]:
        """Create webhook configuration."""
        import uuid
        import secrets
        
        # Generate webhook URL and secret
        webhook_id = str(uuid.uuid4())
        webhook_secret = secrets.token_urlsafe(32)
        
        # In production, this would register with the MCP server's webhook handler
        webhook_url = f"{self.config.server.webhook_base_url}/github/{webhook_id}"
        
        # Store webhook configuration
        await self.did_client.store_webhook_config({
            "webhook_id": webhook_id,
            "repository": repository,
            "user_did": user_did,
            "events": events,
            "signing_rules": signing_rules,
            "credential_mapping": credential_mapping,
            "secret": webhook_secret,
            "created_at": self._get_timestamp()
        })
        
        return {
            "webhook_id": webhook_id,
            "webhook_url": webhook_url,
            "webhook_secret": webhook_secret
        }
    
    def _generate_github_actions_workflow(
        self,
        signing_rules: Dict[str, Any],
        credential_mapping: Dict[str, str]
    ) -> str:
        """Generate GitHub Actions workflow YAML."""
        workflow = f"""name: Code Signing

on:
  release:
    types: [published]
  push:
    branches:
      - main
      - master
      - production
  workflow_run:
    workflows: ["build"]
    types: [completed]

jobs:
  sign-artifacts:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Download artifacts
        uses: actions/download-artifact@v3
        with:
          path: ./artifacts
      
      - name: Sign artifacts
        uses: noosphere/code-signing-action@v1
        with:
          file_patterns: {', '.join(signing_rules.get('file_patterns', []))}
          credential_mapping: ${{{{ secrets.SIGNING_CREDENTIAL_MAPPING }}}}
          mcp_server_url: ${{{{ secrets.MCP_SERVER_URL }}}}
          api_key: ${{{{ secrets.MCP_API_KEY }}}}
      
      - name: Upload signed artifacts
        uses: actions/upload-artifact@v3
        with:
          name: signed-artifacts
          path: ./artifacts/**/*
"""
        return workflow
    
    def _generate_setup_instructions(
        self,
        repository: str,
        webhook_config: Dict[str, Any],
        workflow_yaml: str
    ) -> List[str]:
        """Generate setup instructions."""
        return [
            f"1. Go to https://github.com/{repository}/settings/hooks",
            "2. Click 'Add webhook'",
            f"3. Set Payload URL to: {webhook_config['webhook_url']}",
            "4. Set Content type to: application/json",
            f"5. Set Secret to: {webhook_config['webhook_secret']}",
            "6. Select events: release, push, workflow_run",
            "7. Click 'Add webhook'",
            "",
            "To add GitHub Actions workflow:",
            "1. Create .github/workflows/code-signing.yml in your repository",
            "2. Copy the generated workflow YAML into this file",
            "3. Add required secrets in repository settings:",
            "   - MCP_SERVER_URL",
            "   - MCP_API_KEY",
            "   - SIGNING_CREDENTIAL_MAPPING",
            "4. Commit and push the workflow file"
        ]
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
