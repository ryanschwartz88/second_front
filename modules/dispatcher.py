#!/usr/bin/env python3
"""
Dispatcher Module for Parallel Processing

This module handles parallel processing of vulnerability records through
the research and resolver modules.
"""
import concurrent.futures
import os
import multiprocessing
from typing import Dict, List, Any, Callable

from modules.research_module import ResearchModule
from modules.resolver_module import ResolverModule

class Dispatcher:
    """
    Dispatcher for parallel processing of vulnerability records.
    Manages a thread pool to process multiple vulnerabilities simultaneously.
    """
    
    def __init__(self, max_workers: int = None):
        """
        Initialize the dispatcher with a thread pool.
        
        Args:
            max_workers: Maximum number of worker threads. Defaults to CPU count.
        """
        self.max_workers = max_workers if max_workers else os.cpu_count()
        self.research_module = ResearchModule()
        self.resolver_module = ResolverModule()
    
    def process_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single vulnerability record through research and resolver modules.
        
        Args:
            record: Normalized vulnerability record
            
        Returns:
            Dictionary containing the original record, research summary and remediation plan
        """
        try:
            cve_id = record.get("cve_id")
            
            # Research the vulnerability
            vulnerability_info = self.research_module.research_cve(cve_id)
            
            # Generate a remediation plan
            remediation_plan = self.resolver_module.generate_remediation_plan(vulnerability_info)
            
            # Combine results
            result = {
                "record": record,
                "vulnerability_info": vulnerability_info,
                "remediation_plan": remediation_plan
            }
            
            return result
        
        except Exception as e:
            # Log and return partial results on error
            print(f"Error processing {record.get('cve_id', 'unknown')}: {str(e)}")
            return {
                "record": record,
                "error": str(e),
                "status": "failed"
            }
    
    def process_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process multiple vulnerability records in parallel.
        
        Args:
            records: List of normalized vulnerability records
            
        Returns:
            List of processed results
        """
        results = []
        
        # Process records in parallel using a thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all records to the executor
            future_to_record = {
                executor.submit(self.process_record, record): record 
                for record in records
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_record):
                record = future_to_record[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Print progress
                    cve_id = record.get("cve_id", "unknown")
                    status = "processed" if "error" not in result else "failed"
                    print(f"Processed {cve_id}: {status}")
                    
                except Exception as e:
                    # Catch any exceptions that weren't caught in process_record
                    cve_id = record.get("cve_id", "unknown")
                    print(f"Error processing {cve_id}: {str(e)}")
                    results.append({
                        "record": record,
                        "error": str(e),
                        "status": "failed"
                    })
        
        return results
