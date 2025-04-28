"""
Vulnerability record deduplicator for CVE Remediation Tool.

This module handles deduplication of vulnerability records from multiple scanner sources.
It ensures that duplicate CVE IDs are merged into a single record with combined scanner information.
"""

from typing import Dict, List, Any


class Deduplicator:
    """
    Deduplicates vulnerability records by combining records with the same CVE ID.
    When duplicates are found, scanner information is merged to preserve data from all sources.
    """
    
    @staticmethod
    def deduplicate_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate vulnerability records by CVE ID, merging scanner information for duplicates.
        
        Args:
            records: List of normalized vulnerability records
            
        Returns:
            List of deduplicated vulnerability records
        """
        if not records:
            return []
            
        # Track unique records by CVE ID
        deduped = {}
        
        for record in records:
            cve_id = record.get('cve_id')
            if not cve_id:
                continue
                
            if cve_id not in deduped:
                # First time seeing this CVE ID, add the record
                deduped[cve_id] = record
            else:
                # Merge scanner info for duplicate CVE IDs
                existing = deduped[cve_id]
                
                # Ensure both scanner fields are lists
                if not isinstance(existing['scanner'], list):
                    existing['scanner'] = [existing['scanner']]
                if not isinstance(record['scanner'], list):
                    record['scanner'] = [record['scanner']]
                    
                # Add new scanner info if not already present
                for scanner_info in record['scanner']:
                    if scanner_info not in existing['scanner']:
                        existing['scanner'].append(scanner_info)
        
        # Return the deduplicated records
        return list(deduped.values())
