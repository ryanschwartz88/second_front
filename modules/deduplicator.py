"""
Vulnerability record deduplicator for CVE Remediation Tool.

This module handles deduplication of vulnerability records from multiple scanner sources.
It ensures that duplicate vulnerability IDs (CVE or GHSA) are merged into a single record 
with combined scanner information.
"""

from typing import Dict, List, Any


class Deduplicator:
    """
    Deduplicates vulnerability records by combining records with the same vulnerability ID.
    When duplicates are found, scanner information is merged to preserve data from all sources.
    Supports both CVE and GHSA ID formats.
    """
    
    @staticmethod
    def deduplicate_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate vulnerability records by ID (CVE or GHSA), merging packages and scanner information.
        
        Args:
            records: List of normalized vulnerability records
            
        Returns:
            List of deduplicated vulnerability records
        """
        if not records:
            return []
            
        # Track unique records by vulnerability ID only
        deduped = {}
        
        for record in records:
            vuln_id = record.get('cve_id')
            packages = record.get('package_name', [])
            if not vuln_id or not packages:
                continue

            if vuln_id not in deduped:
                # First time seeing this vulnerability ID, add the record
                deduped[vuln_id] = record
            else:
                existing = deduped[vuln_id]
                
                # Merge package_name lists, avoiding duplicates
                existing_packages = existing.get('package_name', [])
                for package in packages:
                    if package not in existing_packages:
                        existing_packages.append(package)
                existing['package_name'] = existing_packages
                
                # Handle scanners field (which should be a dict of scanner types to scanner data)
                if 'scanners' in record:
                    if 'scanners' not in existing:
                        existing['scanners'] = {}
                        
                    # Merge scanner data from the new record into existing record
                    for scanner_type, scanner_data in record['scanners'].items():
                        existing['scanners'][scanner_type] = scanner_data
                
                # Handle legacy scanner field (for backward compatibility)
                elif 'scanner' in record:
                    if 'scanner' not in existing:
                        existing['scanner'] = []
                    
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