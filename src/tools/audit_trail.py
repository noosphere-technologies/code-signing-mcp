"""
Audit Trail Tool

Queries and exports signing operation audit logs for compliance and reporting.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
import json
import csv
import io

from ..providers import ProviderFactory
from ..config import Config


class AuditTrailTool:
    """Tool for querying signing operation audit logs."""
    
    def __init__(self, provider_factory: ProviderFactory, config: Config):
        self.provider_factory = provider_factory
        self.config = config
    
    async def execute(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        credential_id: Optional[str] = None,
        artifact_type: Optional[str] = None,
        export_format: str = "json",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Query signing operations audit trail.
        
        Args:
            start_date: ISO date for query start
            end_date: ISO date for query end
            credential_id: Filter by credential
            artifact_type: Filter by artifact type
            export_format: Export format (json, csv, xml)
            
        Returns:
            Dictionary containing audit records
        """
        try:
            # Parse dates
            start_dt, end_dt = self._parse_date_range(start_date, end_date)
            
            # Build query filters
            filters = self._build_filters(
                start_dt, end_dt, credential_id, artifact_type
            )
            
            # Query audit logs
            audit_records = await self.did_client.query_audit_logs(filters)
            
            # Format output based on requested format
            if export_format.lower() == "csv":
                formatted_output = self._format_as_csv(audit_records)
            elif export_format.lower() == "xml":
                formatted_output = self._format_as_xml(audit_records)
            else:
                formatted_output = self._format_as_json(audit_records)
            
            # Generate summary statistics
            summary = self._generate_summary(audit_records)
            
            return {
                "success": True,
                "audit_records": audit_records,
                "summary": summary,
                "export_format": export_format,
                "formatted_output": formatted_output,
                "filters_applied": filters,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    def _parse_date_range(
        self,
        start_date: Optional[str],
        end_date: Optional[str]
    ) -> tuple:
        """Parse and validate date range."""
        now = datetime.now(timezone.utc)
        
        # Default to last 30 days if no dates provided
        if not start_date:
            start_dt = now - timedelta(days=30)
        else:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError(f"Invalid start_date format: {start_date}")
        
        if not end_date:
            end_dt = now
        else:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError(f"Invalid end_date format: {end_date}")
        
        if start_dt > end_dt:
            raise ValueError("start_date must be before end_date")
        
        return start_dt, end_dt
    
    def _build_filters(
        self,
        start_dt: datetime,
        end_dt: datetime,
        credential_id: Optional[str],
        artifact_type: Optional[str]
    ) -> Dict[str, Any]:
        """Build query filters."""
        filters = {
            "start_date": start_dt.isoformat(),
            "end_date": end_dt.isoformat()
        }
        
        if credential_id:
            filters["credential_id"] = credential_id
        
        if artifact_type:
            filters["artifact_type"] = artifact_type
        
        return filters
    
    def _format_as_json(self, audit_records: List[Dict[str, Any]]) -> str:
        """Format audit records as JSON."""
        return json.dumps(audit_records, indent=2, default=str)
    
    def _format_as_csv(self, audit_records: List[Dict[str, Any]]) -> str:
        """Format audit records as CSV."""
        if not audit_records:
            return ""
        
        output = io.StringIO()
        
        # Define CSV columns
        fieldnames = [
            'timestamp', 'operation', 'credential_id', 'artifact_name',
            'artifact_type', 'artifact_size', 'user_did', 'success',
            'signature_algorithm', 'request_id'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for record in audit_records:
            # Flatten nested structures
            flat_record = {
                'timestamp': record.get('timestamp'),
                'operation': record.get('operation'),
                'credential_id': record.get('credential', {}).get('id'),
                'artifact_name': record.get('artifact', {}).get('name'),
                'artifact_type': record.get('artifact', {}).get('type'),
                'artifact_size': record.get('artifact', {}).get('size'),
                'user_did': record.get('user_did'),
                'success': record.get('success'),
                'signature_algorithm': record.get('signature', {}).get('algorithm'),
                'request_id': record.get('request_id')
            }
            writer.writerow(flat_record)
        
        return output.getvalue()
    
    def _format_as_xml(self, audit_records: List[Dict[str, Any]]) -> str:
        """Format audit records as XML."""
        xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<audit_records>']
        
        for record in audit_records:
            xml_parts.append('  <record>')
            xml_parts.append(f'    <timestamp>{record.get("timestamp")}</timestamp>')
            xml_parts.append(f'    <operation>{record.get("operation")}</operation>')
            xml_parts.append(f'    <user_did>{record.get("user_did")}</user_did>')
            xml_parts.append(f'    <success>{record.get("success")}</success>')
            
            if 'credential' in record:
                xml_parts.append('    <credential>')
                xml_parts.append(f'      <id>{record["credential"].get("id")}</id>')
                xml_parts.append('    </credential>')
            
            if 'artifact' in record:
                xml_parts.append('    <artifact>')
                xml_parts.append(f'      <name>{record["artifact"].get("name")}</name>')
                xml_parts.append(f'      <type>{record["artifact"].get("type")}</type>')
                xml_parts.append('    </artifact>')
            
            xml_parts.append('  </record>')
        
        xml_parts.append('</audit_records>')
        return '\n'.join(xml_parts)
    
    def _generate_summary(self, audit_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics from audit records."""
        total = len(audit_records)
        
        if total == 0:
            return {
                "total_operations": 0,
                "successful_operations": 0,
                "failed_operations": 0,
                "success_rate": 0.0
            }
        
        successful = sum(1 for r in audit_records if r.get('success', False))
        failed = total - successful
        
        # Count by operation type
        operations_by_type = {}
        for record in audit_records:
            op = record.get('operation', 'unknown')
            operations_by_type[op] = operations_by_type.get(op, 0) + 1
        
        # Count by artifact type
        artifacts_by_type = {}
        for record in audit_records:
            artifact_type = record.get('artifact', {}).get('type', 'unknown')
            artifacts_by_type[artifact_type] = artifacts_by_type.get(artifact_type, 0) + 1
        
        # Count by credential
        credentials_used = {}
        for record in audit_records:
            cred_id = record.get('credential', {}).get('id', 'unknown')
            credentials_used[cred_id] = credentials_used.get(cred_id, 0) + 1
        
        return {
            "total_operations": total,
            "successful_operations": successful,
            "failed_operations": failed,
            "success_rate": round((successful / total) * 100, 2),
            "operations_by_type": operations_by_type,
            "artifacts_by_type": artifacts_by_type,
            "credentials_used": credentials_used,
            "date_range": {
                "earliest": min(r.get('timestamp') for r in audit_records),
                "latest": max(r.get('timestamp') for r in audit_records)
            }
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
