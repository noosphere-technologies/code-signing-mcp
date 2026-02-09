"""
Batch Sign Tool

Performs bulk signing operations with parallel processing through pluggable providers.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import glob

from ..providers import ProviderFactory, ProviderCapability
from ..config import Config


class BatchSignTool:
    """
    Tool for batch signing operations using pluggable providers.

    Providers:
    - noosphere: Full-featured (C2PA, in-toto, DID, VC)
    - signpath: Enterprise Windows signing
    - sigstore: Open source keyless signing
    - local: Offline signing with local keys
    """

    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config

    async def execute(
        self,
        file_patterns: List[str],
        provider: Optional[str] = None,
        credential_id: Optional[str] = None,
        parallel_limit: int = 5,
        skip_existing: bool = True,
        embed_c2pa: bool = True,
        generate_attestation: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Sign multiple files in batch.

        Args:
            file_patterns: Glob patterns for files to sign
            provider: Signing provider to use
            credential_id: Credential for all signings (optional)
            parallel_limit: Max concurrent signings
            skip_existing: Skip already signed files
            embed_c2pa: Embed C2PA manifests (requires noosphere)
            generate_attestation: Generate in-toto attestations (requires noosphere)

        Returns:
            Dictionary containing batch operation results
        """
        try:
            # Get the appropriate provider
            signing_provider = self.provider_factory.get_provider(provider)

            # Check provider capabilities
            capability_warnings = []
            if embed_c2pa and not signing_provider.supports(ProviderCapability.C2PA_MANIFESTS):
                capability_warnings.append({
                    "feature": "embed_c2pa",
                    "message": f"C2PA not supported by {signing_provider.name}",
                    "tip": "Use 'noosphere' provider for C2PA support"
                })
                embed_c2pa = False

            if generate_attestation and not signing_provider.supports(ProviderCapability.IN_TOTO_ATTESTATIONS):
                capability_warnings.append({
                    "feature": "generate_attestation",
                    "message": f"in-toto attestations not supported by {signing_provider.name}",
                    "tip": "Use 'noosphere' provider for supply chain attestations"
                })
                generate_attestation = False

            # Resolve file patterns to list of files
            files_to_sign = self._resolve_file_patterns(file_patterns)

            if not files_to_sign:
                return {
                    "success": True,
                    "message": "No files matched the provided patterns",
                    "files_matched": 0,
                    "files_processed": 0,
                    "provider": signing_provider.name
                }

            # Filter already signed files if requested
            if skip_existing:
                files_to_sign = await self._filter_unsigned_files(
                    files_to_sign, signing_provider
                )

            # Process files in parallel batches
            options = {
                "embed_c2pa": embed_c2pa,
                "generate_attestation": generate_attestation
            }

            results = await self._process_batch(
                files_to_sign, signing_provider, credential_id,
                options, parallel_limit
            )

            # Generate summary
            summary = self._generate_summary(results)

            response = {
                "success": True,
                "provider": signing_provider.name,
                "summary": summary,
                "results": results,
                "timestamp": self._get_timestamp()
            }

            if capability_warnings:
                response["capability_warnings"] = capability_warnings

            return response

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": self._get_timestamp()
            }

    def _resolve_file_patterns(self, patterns: List[str]) -> List[str]:
        """Resolve glob patterns to list of files."""
        files = []

        for pattern in patterns:
            # Expand glob pattern
            matched_files = glob.glob(pattern, recursive=True)

            # Filter to only files (not directories)
            matched_files = [f for f in matched_files if Path(f).is_file()]

            files.extend(matched_files)

        # Remove duplicates
        files = list(set(files))

        return files

    async def _filter_unsigned_files(
        self,
        files: List[str],
        provider
    ) -> List[str]:
        """Filter out already signed files."""
        unsigned_files = []

        for file_path in files:
            is_signed = await self._check_if_signed(file_path, provider)
            if not is_signed:
                unsigned_files.append(file_path)

        return unsigned_files

    async def _check_if_signed(self, file_path: str, provider) -> bool:
        """Check if a file is already signed."""
        try:
            result = await provider.verify(
                file_path=file_path,
                options={"quick_check": True}
            )
            return result.valid
        except Exception:
            return False

    async def _process_batch(
        self,
        files: List[str],
        provider,
        credential_id: Optional[str],
        options: Dict[str, Any],
        parallel_limit: int
    ) -> List[Dict[str, Any]]:
        """Process files in parallel batches."""
        semaphore = asyncio.Semaphore(parallel_limit)

        async def sign_with_semaphore(file_path: str) -> Dict[str, Any]:
            async with semaphore:
                return await self._sign_single_file(
                    file_path, provider, credential_id, options
                )

        # Create tasks for all files
        tasks = [sign_with_semaphore(f) for f in files]

        # Execute with progress tracking
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "file_path": files[i],
                    "success": False,
                    "error": str(result)
                })
            else:
                processed_results.append(result)

        return processed_results

    async def _sign_single_file(
        self,
        file_path: str,
        provider,
        credential_id: Optional[str],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Sign a single file."""
        try:
            import time
            start_time = time.time()

            result = await provider.sign(
                file_path=file_path,
                credential_id=credential_id,
                options=options
            )

            processing_time = int((time.time() - start_time) * 1000)

            if result.success:
                return {
                    "file_path": file_path,
                    "file_name": Path(file_path).name,
                    "success": True,
                    "signature_format": result.signature_format,
                    "signature_algorithm": result.signature_algorithm,
                    "processing_time_ms": processing_time,
                    "file_size": Path(file_path).stat().st_size
                }
            else:
                return {
                    "file_path": file_path,
                    "file_name": Path(file_path).name,
                    "success": False,
                    "error": result.error
                }

        except Exception as e:
            return {
                "file_path": file_path,
                "file_name": Path(file_path).name,
                "success": False,
                "error": str(e)
            }

    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics."""
        total = len(results)
        successful = sum(1 for r in results if r.get("success", False))
        failed = total - successful

        total_size = sum(r.get("file_size", 0) for r in results if r.get("success"))
        total_time = sum(r.get("processing_time_ms", 0) for r in results if r.get("success"))

        return {
            "total_files": total,
            "successful": successful,
            "failed": failed,
            "success_rate": round((successful / total) * 100, 2) if total > 0 else 0.0,
            "total_size_bytes": total_size,
            "total_processing_time_ms": total_time,
            "average_time_per_file_ms": round(total_time / successful, 2) if successful > 0 else 0
        }

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
