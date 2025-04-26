#!/usr/bin/env python3
"""
Writer Module for Persisting Results

This module handles writing processed vulnerability results to disk.
"""
import json
import os
import datetime
from pathlib import Path
from typing import Dict, List, Any

class ResultWriter:
    """
    Writes processed vulnerability results to disk.
    Creates organized output directories and files.
    """
    
    def __init__(self, base_output_dir: str = "results"):
        """
        Initialize the writer with a base output directory.
        
        Args:
            base_output_dir: Base directory for all outputs
        """
        self.base_output_dir = base_output_dir
        # Ensure the base directory exists
        os.makedirs(base_output_dir, exist_ok=True)
    
    def _get_output_dir(self, report_name: str) -> str:
        """
        Create a timestamped output directory for a report.
        
        Args:
            report_name: Name of the report file (without extension)
            
        Returns:
            Path to the created output directory
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(self.base_output_dir, f"{report_name}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    def save_json_file(self, data: Any, filepath: str) -> bool:
        """
        Save data to a JSON file.
        
        Args:
            data: Data to save
            filepath: Path to save the file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving data to {filepath}: {str(e)}")
            return False
    
    def save_text_file(self, text: str, filepath: str) -> bool:
        """
        Save text content to a file.
        
        Args:
            text: Text content to save
            filepath: Path to save the file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w') as f:
                f.write(text)
            return True
        except Exception as e:
            print(f"Error saving text to {filepath}: {str(e)}")
            return False
    
    def write_results(self, report_path: str, results: List[Dict[str, Any]]) -> str:
        """
        Write processed results to disk.
        
        Args:
            report_path: Path to the original report file
            results: List of processed vulnerability results
            
        Returns:
            Path to the output directory
        """
        # Get report filename without extension for output directory name
        report_name = Path(report_path).stem
        output_dir = self._get_output_dir(report_name)
        
        print(f"Writing results to: {output_dir}")
        
        # Save normalized findings
        normalized_findings = [result.get("record") for result in results]
        self.save_json_file(normalized_findings, os.path.join(output_dir, "normalized_findings.json"))
        
        # Create a master aggregated plan document
        aggregated_plans = "# Aggregated Remediation Plans\n\n"
        
        # Process each result
        for result in results:
            record = result.get("record", {})
            cve_id = record.get("cve_id", "unknown")
            
            if "error" in result:
                # Log error for failed records
                error_message = f"Failed to process {cve_id}: {result.get('error')}"
                self.save_text_file(error_message, os.path.join(output_dir, f"error_{cve_id}.txt"))
                continue
            
            vulnerability_info = result.get("vulnerability_info", {})
            remediation_plan = result.get("remediation_plan", {})
            
            # Save summary for this CVE
            if "summary" in vulnerability_info:
                summary_path = os.path.join(output_dir, f"summary_{cve_id}.md")
                self.save_text_file(vulnerability_info["summary"], summary_path)
            
            # Save remediation plan for this CVE
            if "raw_plan" in remediation_plan:
                plan_path = os.path.join(output_dir, f"plan_{cve_id}.md")
                self.save_text_file(remediation_plan["raw_plan"], plan_path)
                
                # Add to aggregated plans
                aggregated_plans += f"## {cve_id}\n\n"
                aggregated_plans += f"Package: {record.get('package_name')} "
                aggregated_plans += f"(Installed: {record.get('installed_version')}, "
                aggregated_plans += f"Fix: {record.get('fix_version', 'unknown')})\n\n"
                aggregated_plans += f"[See detailed plan](plan_{cve_id}.md)\n\n"
                aggregated_plans += "Summary: " + remediation_plan["raw_plan"].split("\n")[0] + "\n\n"
                aggregated_plans += "---\n\n"
        
        # Save aggregated plans
        self.save_text_file(aggregated_plans, os.path.join(output_dir, "aggregated_plans.md"))
        
        return output_dir
