#!/usr/bin/env python3
"""
Parser Module for Vulnerability Scanner Reports

This module parses vulnerability scanner reports (JSON) and normalizes 
them into a consistent format.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Generator, Optional, Any, Union

class VulnerabilityParser:
    """Parses and normalizes vulnerability scanner reports."""
    
    @staticmethod
    def detect_scanner_type(file_path: str) -> str:
        """
        Auto-detect scanner type from the JSON file structure.
        
        Args:
            file_path: Path to the scanner report file
            
        Returns:
            String indicating scanner type ('trivy', 'anchore', or 'unknown')
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Check for Trivy format
            if "scan" in data and data.get("scan", {}).get("analyzer", {}).get("id") == "trivy":
                return "trivy"
                
            # Check for Anchore format
            if "vulnerabilities" in data and "image_digest" in data:
                return "anchore"
                
            return "unknown"
        except Exception as e:
            print(f"Error detecting scanner type: {str(e)}")
            return "unknown"
    
    @staticmethod
    def parse_trivy_report(file_path: str) -> Generator[Dict[str, Any], None, None]:
        """
        Parse a Trivy vulnerability report and yield normalized records.
        
        Args:
            file_path: Path to the Trivy report file
            
        Yields:
            Normalized vulnerability records
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                # Extract CVE ID from identifiers
                cve_id = None
                for identifier in vuln.get("identifiers", []):
                    if identifier.get("type") == "cve":
                        cve_id = identifier.get("value")
                        break
                
                if not cve_id:
                    continue  # Skip if no CVE ID found
                
                # Extract package information
                package_name = vuln.get("location", {}).get("dependency", {}).get("package", {}).get("name")
                installed_version = vuln.get("location", {}).get("dependency", {}).get("version")
                
                # Extract fix version from solution field if available
                fix_version = None
                solution = vuln.get("solution", "")
                if "Upgrade" in solution and "to" in solution:
                    fix_version = solution.split("to")[-1].strip()
                
                # Create normalized record
                normalized_record = {
                    "cve_id": cve_id,
                    "package_name": package_name,
                    "installed_version": installed_version,
                    "fix_version": fix_version,
                    "severity": vuln.get("severity"),
                    "scanners": {
                        "trivy": {
                            "description": vuln.get("description", ""),
                            "links": [link.get("url") for link in vuln.get("links", [])]
                        }
                    }
                }
                
                yield normalized_record
                
        except Exception as e:
            print(f"Error parsing Trivy report: {str(e)}")
    
    @staticmethod
    def parse_anchore_report(file_path: str) -> Generator[Dict[str, Any], None, None]:
        """
        Parse an Anchore vulnerability report and yield normalized records.
        
        Args:
            file_path: Path to the Anchore report file
            
        Yields:
            Normalized vulnerability records
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                # Check if it's a CVE or GHSA
                vuln_id = vuln.get("vuln", "")
                if not vuln_id:
                    continue
                
                # Use CVE ID if available, otherwise use GHSA ID
                cve_id = vuln_id if vuln_id.startswith("CVE-") else vuln_id
                
                # Extract package information
                package_name = vuln.get("package_name", "")
                installed_version = vuln.get("package_version", "")
                fix_version = vuln.get("fix", None)
                
                # Create links list from available URLs
                links = []
                if vuln.get("url"):
                    links.append(vuln.get("url"))
                
                # Add links from extra data if available
                extra_refs = vuln.get("extra", {}).get("references", [])
                for ref in extra_refs:
                    if ref.get("url") and ref.get("url") not in links:
                        links.append(ref.get("url"))
                
                # Create normalized record
                normalized_record = {
                    "cve_id": cve_id,
                    "package_name": package_name,
                    "installed_version": installed_version,
                    "fix_version": fix_version,
                    "severity": vuln.get("severity", "Unknown"),
                    "scanners": {
                        "anchore": {
                            "description": vuln.get("extra", {}).get("description", ""),
                            "links": links
                        }
                    }
                }
                
                yield normalized_record
                
        except Exception as e:
            print(f"Error parsing Anchore report: {str(e)}")
    
    @staticmethod
    def parse_report(file_path: str, scanner_type: Optional[str] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Parse a vulnerability report and yield normalized records.
        
        Args:
            file_path: Path to the scanner report file
            scanner_type: Optional scanner type override
            
        Yields:
            Normalized vulnerability records
        """
        # Detect scanner type if not specified
        if not scanner_type:
            scanner_type = VulnerabilityParser.detect_scanner_type(file_path)
        
        # Parse based on scanner type
        if scanner_type == "trivy":
            yield from VulnerabilityParser.parse_trivy_report(file_path)
        elif scanner_type == "anchore":
            yield from VulnerabilityParser.parse_anchore_report(file_path)
        else:
            print(f"Unsupported scanner type for file: {file_path}")
    
    @staticmethod
    def parse_reports(report_paths: List[str], scanner_type: Optional[str] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Parse multiple vulnerability reports and yield normalized records.
        
        Args:
            report_paths: List of paths to scanner report files or directories
            scanner_type: Optional scanner type override for all files
            
        Yields:
            Normalized vulnerability records
        """
        for path in report_paths:
            path_obj = Path(path)
            
            if path_obj.is_file():
                # Process a single file
                yield from VulnerabilityParser.parse_report(str(path_obj), scanner_type)
            elif path_obj.is_dir():
                # Process all JSON files in the directory
                for file_path in path_obj.glob("**/*.json"):
                    yield from VulnerabilityParser.parse_report(str(file_path), scanner_type)
