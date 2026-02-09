"""
Verify Trust Chain Tool

Verifies that an artifact or entity is within the user's trust graph.
Queries the trust-graph-builder to find trust paths from the user's
trust root to the signer of an artifact.

This is the key AI-native feature: before executing untrusted code,
an AI agent can verify it's signed by someone in the trust graph.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from ..providers import ProviderFactory
from ..config import Config

logger = logging.getLogger(__name__)


class VerifyTrustChainTool:
    """
    Tool for verifying trust chains via the trust graph.

    Use Cases:
    - "Is this npm package from a trusted publisher?"
    - "Should I run this GitHub Action?"
    - "Is this container image from my supply chain?"

    The tool queries the trust-graph-builder to find trust paths
    from your configured trust root to the artifact's signer.
    """

    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config

        # Trust graph configuration
        self.trust_graph_url = getattr(
            config, 'trust_graph_url',
            'http://localhost:8085'  # Default trust-graph-builder endpoint
        )
        self.default_trust_root = getattr(
            config, 'default_trust_root',
            None  # e.g., "did:web:mycompany.com"
        )

    async def execute(
        self,
        target: str,
        trust_root: Optional[str] = None,
        max_depth: int = 5,
        require_signature: bool = True,
        include_path: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Verify an artifact or entity is in the trust graph.

        Args:
            target: What to verify - can be:
                - URL (https://example.com/package.tar.gz)
                - DID (did:web:publisher.com)
                - Package identifier (npm:lodash, pypi:requests)
                - Domain (example.com - checks /.well-known/trust.txt)
            trust_root: Your trust anchor (DID or domain).
                        Defaults to configured root.
            max_depth: Maximum trust graph traversal depth
            require_signature: Also verify cryptographic signature
            include_path: Include the trust path in response

        Returns:
            Trust verification result with path and recommendations
        """
        try:
            # Determine trust root
            root = trust_root or self.default_trust_root
            if not root:
                return {
                    "trusted": False,
                    "error": "No trust root configured. Set trust_root parameter or configure default_trust_root.",
                    "recommendation": "Add a trust root to your config, e.g., 'did:web:yourcompany.com'",
                    "timestamp": self._get_timestamp()
                }

            # Parse target to determine type
            target_info = self._parse_target(target)

            # Step 1: Get signer identity (if verifying artifact)
            signer_identity = None
            signature_valid = None

            if target_info["type"] == "artifact" and require_signature:
                sig_result = await self._verify_artifact_signature(target_info)
                if not sig_result["valid"]:
                    return {
                        "trusted": False,
                        "signature_valid": False,
                        "error": f"Artifact signature invalid: {sig_result.get('error', 'unknown')}",
                        "target": target,
                        "timestamp": self._get_timestamp()
                    }
                signer_identity = sig_result.get("signer_did") or sig_result.get("signer_domain")
                signature_valid = True
            elif target_info["type"] in ["did", "domain"]:
                signer_identity = target_info["identifier"]

            if not signer_identity:
                return {
                    "trusted": False,
                    "error": "Could not determine signer identity",
                    "target": target,
                    "timestamp": self._get_timestamp()
                }

            # Step 2: Query trust graph for path
            trust_result = await self._query_trust_graph(
                root, signer_identity, max_depth
            )

            # Step 3: Build response
            response = {
                "trusted": trust_result["path_exists"],
                "target": target,
                "target_type": target_info["type"],
                "signer": signer_identity,
                "trust_root": root,
                "timestamp": self._get_timestamp()
            }

            if signature_valid is not None:
                response["signature_valid"] = signature_valid

            if include_path and trust_result.get("path"):
                response["trust_path"] = trust_result["path"]
                response["path_length"] = len(trust_result["path"])

            if trust_result["path_exists"]:
                response["trust_level"] = self._calculate_trust_level(trust_result)
                response["recommendation"] = "Safe to proceed - entity is in your trust graph"
            else:
                response["recommendation"] = self._generate_distrust_recommendation(
                    target_info, signer_identity, root
                )

            # Add provenance info if available
            if trust_result.get("provenance"):
                response["provenance"] = trust_result["provenance"]

            return response

        except aiohttp.ClientError as e:
            logger.error(f"Trust graph query failed: {e}")
            return {
                "trusted": False,
                "error": f"Could not reach trust graph service: {e}",
                "target": target,
                "recommendation": "Verify trust-graph-builder is running",
                "timestamp": self._get_timestamp()
            }
        except Exception as e:
            logger.exception("Trust chain verification failed")
            return {
                "trusted": False,
                "error": str(e),
                "target": target,
                "timestamp": self._get_timestamp()
            }

    def _parse_target(self, target: str) -> Dict[str, Any]:
        """Parse target string to determine type and identifier."""

        # DID
        if target.startswith("did:"):
            return {
                "type": "did",
                "identifier": target,
                "method": target.split(":")[1] if ":" in target else "unknown"
            }

        # Package identifier (npm:package, pypi:package, etc.)
        if ":" in target and not target.startswith("http"):
            parts = target.split(":", 1)
            if parts[0] in ["npm", "pypi", "gem", "cargo", "go", "maven"]:
                return {
                    "type": "package",
                    "ecosystem": parts[0],
                    "name": parts[1],
                    "identifier": target
                }

        # URL (artifact)
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            return {
                "type": "artifact",
                "url": target,
                "domain": parsed.netloc,
                "identifier": target
            }

        # Domain (check for trust.txt)
        if "." in target and "/" not in target:
            return {
                "type": "domain",
                "identifier": target,
                "trust_txt_url": f"https://{target}/.well-known/trust.txt"
            }

        # File path
        return {
            "type": "artifact",
            "path": target,
            "identifier": target
        }

    async def _verify_artifact_signature(
        self,
        target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify artifact signature and extract signer identity."""

        # Use default provider for verification
        provider = self.provider_factory.default_provider

        target = target_info.get("url") or target_info.get("path")
        if not target:
            return {"valid": False, "error": "No artifact path"}

        try:
            result = await provider.verify(
                file_path=target,
                options={"extract_signer": True}
            )

            return {
                "valid": result.valid,
                "signer_did": getattr(result, 'signer_did', None),
                "signer_domain": getattr(result, 'signer_domain', None),
                "error": result.error if not result.valid else None
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    async def _query_trust_graph(
        self,
        trust_root: str,
        target_identity: str,
        max_depth: int
    ) -> Dict[str, Any]:
        """Query trust-graph-builder for trust path."""

        # Try the trust graph API
        try:
            async with aiohttp.ClientSession() as session:
                # Query for path between root and target
                url = f"{self.trust_graph_url}/api/trust/path"
                params = {
                    "from": trust_root,
                    "to": target_identity,
                    "max_depth": max_depth
                }

                async with session.get(url, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "path_exists": data.get("path_exists", False),
                            "path": data.get("path", []),
                            "provenance": data.get("provenance")
                        }
                    elif resp.status == 404:
                        # No path found
                        return {"path_exists": False, "path": []}
                    else:
                        logger.warning(f"Trust graph returned {resp.status}")
                        return {"path_exists": False, "error": f"HTTP {resp.status}"}

        except aiohttp.ClientError as e:
            logger.warning(f"Trust graph unavailable: {e}")

            # Fallback: Check if target is directly the trust root
            if self._normalize_identity(trust_root) == self._normalize_identity(target_identity):
                return {
                    "path_exists": True,
                    "path": [trust_root],
                    "note": "Direct match (trust graph unavailable)"
                }

            return {
                "path_exists": False,
                "error": "Trust graph service unavailable",
                "note": "Configure trust_graph_url or run trust-graph-builder"
            }

    def _normalize_identity(self, identity: str) -> str:
        """Normalize identity for comparison."""
        # Remove protocol, trailing slashes, etc.
        identity = identity.lower().strip()
        if identity.startswith("did:web:"):
            # did:web:example.com -> example.com
            return identity[8:].replace(":", "/")
        if identity.startswith("https://"):
            identity = identity[8:]
        if identity.startswith("http://"):
            identity = identity[7:]
        return identity.rstrip("/")

    def _calculate_trust_level(self, trust_result: Dict[str, Any]) -> str:
        """Calculate trust level based on path."""
        path = trust_result.get("path", [])
        path_length = len(path)

        if path_length <= 1:
            return "direct"  # Directly trusted
        elif path_length == 2:
            return "high"    # One hop
        elif path_length <= 4:
            return "medium"  # 2-3 hops
        else:
            return "low"     # Long chain

    def _generate_distrust_recommendation(
        self,
        target_info: Dict[str, Any],
        signer: str,
        trust_root: str
    ) -> str:
        """Generate helpful recommendation when trust verification fails."""

        target_type = target_info["type"]

        if target_type == "package":
            ecosystem = target_info.get("ecosystem", "")
            return (
                f"Package signer '{signer}' is not in your trust graph. "
                f"To trust {ecosystem} packages from this publisher, add them to your trust.txt: "
                f"trusted_publishers: [{signer}]"
            )

        if target_type == "domain":
            return (
                f"Domain '{signer}' is not in your trust graph. "
                f"Check {signer}/.well-known/trust.txt or add to your trust.yml"
            )

        return (
            f"Signer '{signer}' is not in your trust graph rooted at '{trust_root}'. "
            f"If you trust this entity, add them to your trust.txt or trust.yml"
        )

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
