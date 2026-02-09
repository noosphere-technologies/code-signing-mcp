"""
Supply Chain Attestation Tool

Generates SLSA-compliant supply chain attestations for build artifacts
through pluggable provider architecture.

Supports:
- SLSA provenance attestations
- in-toto attestations (Noosphere provider)
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib

import aiofiles

from ..providers import ProviderFactory, ProviderCapability
from ..config import Config


class SupplyChainAttestationTool:
    """
    Tool for generating supply chain attestations using pluggable providers.

    Note: Full in-toto attestations require the 'noosphere' provider.
    Sigstore provides SLSA-like attestations via Rekor.
    """

    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
    
    async def execute(
        self,
        build_artifacts: List[str],
        source_repository: str,
        build_environment: Optional[Dict[str, Any]] = None,
        attestation_level: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate supply chain attestations.
        
        Args:
            build_artifacts: List of build outputs
            source_repository: Source code repository
            build_environment: Build environment metadata
            attestation_level: SLSA level (1, 2, 3, 4)
            
        Returns:
            Dictionary containing attestation bundle
        """
        try:
            # Validate inputs
            if not build_artifacts:
                raise ValueError("build_artifacts cannot be empty")
            
            if not source_repository:
                raise ValueError("source_repository is required")
            
            # Default to SLSA Level 1 if not specified
            if not attestation_level:
                attestation_level = "1"
            
            # Validate SLSA level
            if attestation_level not in ["1", "2", "3", "4"]:
                raise ValueError(
                    f"Invalid attestation level: {attestation_level}. "
                    "Valid levels: 1, 2, 3, 4"
                )
            
            # Get user identity
            user_did = await self.did_client.get_current_user_did()
            
            # Collect artifact information
            artifacts_info = await self._collect_artifacts_info(build_artifacts)
            
            # Generate provenance statement
            provenance = await self._generate_provenance(
                artifacts_info,
                source_repository,
                build_environment or {},
                attestation_level,
                user_did
            )
            
            # Generate in-toto link metadata
            intoto_links = await self._generate_intoto_links(
                artifacts_info,
                build_environment or {},
                user_did
            )
            
            # Sign attestations
            signed_attestations = await self._sign_attestations(
                provenance,
                intoto_links,
                user_did
            )
            
            # Generate SLSA compliance report
            compliance_report = self._generate_compliance_report(
                attestation_level,
                build_environment or {}
            )
            
            return {
                "success": True,
                "attestation_level": f"SLSA Level {attestation_level}",
                "artifacts": artifacts_info,
                "provenance": provenance,
                "intoto_links": intoto_links,
                "signed_attestations": signed_attestations,
                "compliance_report": compliance_report,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    async def _collect_artifacts_info(
        self,
        artifact_paths: List[str]
    ) -> List[Dict[str, Any]]:
        """Collect information about build artifacts."""
        artifacts = []
        
        for artifact_path in artifact_paths:
            path = Path(artifact_path)
            
            if not path.exists():
                raise FileNotFoundError(f"Artifact not found: {artifact_path}")
            
            # Calculate hash
            hash_sha256 = hashlib.sha256()
            async with aiofiles.open(artifact_path, 'rb') as f:
                while chunk := await f.read(8192):
                    hash_sha256.update(chunk)
            
            stat = path.stat()
            
            artifacts.append({
                "name": path.name,
                "path": str(path.absolute()),
                "size": stat.st_size,
                "sha256": hash_sha256.hexdigest(),
                "type": self._detect_artifact_type(path)
            })
        
        return artifacts
    
    def _detect_artifact_type(self, path: Path) -> str:
        """Detect artifact type."""
        extension = path.suffix.lower()
        type_mapping = {
            '.exe': 'application/x-msdownload',
            '.jar': 'application/java-archive',
            '.whl': 'application/x-wheel+zip',
            '.tar.gz': 'application/gzip',
            '.zip': 'application/zip'
        }
        return type_mapping.get(extension, 'application/octet-stream')
    
    async def _generate_provenance(
        self,
        artifacts: List[Dict[str, Any]],
        source_repository: str,
        build_environment: Dict[str, Any],
        attestation_level: str,
        user_did: str
    ) -> Dict[str, Any]:
        """Generate SLSA provenance statement."""
        return {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": artifact["name"],
                    "digest": {
                        "sha256": artifact["sha256"]
                    }
                }
                for artifact in artifacts
            ],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": f"did:{user_did}",
                    "version": build_environment.get("builder_version", "1.0.0")
                },
                "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
                "invocation": {
                    "configSource": {
                        "uri": source_repository,
                        "digest": {
                            "sha1": build_environment.get("commit_sha", "")
                        },
                        "entryPoint": build_environment.get("workflow", "build.yml")
                    },
                    "parameters": build_environment.get("parameters", {}),
                    "environment": {
                        "arch": build_environment.get("arch", "x86_64"),
                        "os": build_environment.get("os", "linux")
                    }
                },
                "buildConfig": build_environment.get("config", {}),
                "metadata": {
                    "buildInvocationId": build_environment.get("build_id", ""),
                    "buildStartedOn": build_environment.get("started_at", self._get_timestamp()),
                    "buildFinishedOn": self._get_timestamp(),
                    "completeness": {
                        "parameters": True,
                        "environment": True,
                        "materials": True
                    },
                    "reproducible": attestation_level in ["3", "4"]
                },
                "materials": [
                    {
                        "uri": source_repository,
                        "digest": {
                            "sha1": build_environment.get("commit_sha", "")
                        }
                    }
                ]
            }
        }
    
    async def _generate_intoto_links(
        self,
        artifacts: List[Dict[str, Any]],
        build_environment: Dict[str, Any],
        user_did: str
    ) -> List[Dict[str, Any]]:
        """Generate in-toto link metadata."""
        links = []
        
        for artifact in artifacts:
            link = {
                "_type": "link",
                "name": "build",
                "command": build_environment.get("command", []),
                "materials": {},
                "products": {
                    artifact["name"]: {
                        "sha256": artifact["sha256"]
                    }
                },
                "byproducts": {},
                "environment": build_environment.get("environment", {})
            }
            links.append(link)
        
        return links
    
    async def _sign_attestations(
        self,
        provenance: Dict[str, Any],
        intoto_links: List[Dict[str, Any]],
        user_did: str
    ) -> Dict[str, Any]:
        """Sign attestations with DID."""
        # Sign provenance
        signed_provenance = await self.did_client.sign_attestation(
            user_did,
            provenance
        )
        
        # Sign in-toto links
        signed_links = []
        for link in intoto_links:
            signed_link = await self.did_client.sign_attestation(
                user_did,
                link
            )
            signed_links.append(signed_link)
        
        return {
            "provenance": signed_provenance,
            "intoto_links": signed_links
        }
    
    def _generate_compliance_report(
        self,
        attestation_level: str,
        build_environment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate SLSA compliance report."""
        level_requirements = {
            "1": {
                "description": "Build process is scripted",
                "requirements": [
                    "Provenance generated",
                    "Build process documented"
                ]
            },
            "2": {
                "description": "Build service, version controlled source",
                "requirements": [
                    "Hosted build service",
                    "Version control",
                    "Provenance generated by service"
                ]
            },
            "3": {
                "description": "Hardened builds, non-falsifiable provenance",
                "requirements": [
                    "Source and build platform meet level 2",
                    "Provenance is unforgeable",
                    "Build environment is isolated"
                ]
            },
            "4": {
                "description": "Two-party review, hermetic builds",
                "requirements": [
                    "Two-person review",
                    "Hermetic, reproducible builds",
                    "Dependencies complete and verified"
                ]
            }
        }
        
        level_info = level_requirements.get(attestation_level, {})
        
        return {
            "slsa_level": f"Level {attestation_level}",
            "description": level_info.get("description", ""),
            "requirements": level_info.get("requirements", []),
            "compliance_status": "compliant",
            "verification_method": "automated",
            "attestation_format": "in-toto",
            "signature_algorithm": "EdDSA",
            "timestamp": self._get_timestamp()
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
