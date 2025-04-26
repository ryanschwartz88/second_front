#!/usr/bin/env python3
"""
Agentic CVE Remediation Workflow CLI Tool

A command-line tool that processes vulnerability scanner reports (JSON)
and uses Gemini 2.5 Flash to research and generate remediation plans
for Common Vulnerabilities and Exposures (CVEs).
"""
import argparse
import json
import os
import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any
from dotenv import load_dotenv

from modules.parser import VulnerabilityParser
from modules.dispatcher import Dispatcher
from modules.writer import ResultWriter

def setup_argparser():
    """Set up the argument parser for the CLI tool."""
    parser = argparse.ArgumentParser(
        description="Agentic CVE Remediation - Research and remediate vulnerabilities using AI"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Legacy direct vulnerability ID command
    cve_parser = subparsers.add_parser("cve", help="Process a single vulnerability ID (CVE or GHSA)")
    cve_parser.add_argument(
        "--cve", 
        required=True, 
        help="Vulnerability ID to research and remediate (e.g., CVE-2017-16911 or GHSA-xxxx-yyyy-zzzz)"
    )
    cve_parser.add_argument(
        "--output", 
        help="Output file to save the results (JSON format)"
    )
    cve_parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Enable verbose output"
    )
    cve_parser.add_argument(
        "--research-only", 
        action="store_true", 
        help="Only perform research, do not generate remediation plan"
    )
    
    # New scan command for processing scanner reports
    scan_parser = subparsers.add_parser("scan", help="Process vulnerability scanner reports")
    scan_parser.add_argument(
        "report_paths",
        nargs="+",
        help="Paths to scanner report files or directories containing reports"
    )
    scan_parser.add_argument(
        "--scanner",
        choices=["trivy", "anchore"],
        help="Override scanner type detection (default: auto-detect)"
    )
    scan_parser.add_argument(
        "--parallel",
        type=int,
        help="Number of parallel processing threads (default: number of CPU cores)"
    )
    scan_parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Enable verbose output"
    )
    
    return parser

def validate_environment():
    """Validate that all required environment variables are set."""
    load_dotenv()
    
    required_vars = ["GHSA_API_KEY", "CVEDETAILS_API_KEY", "GEMINI_API_KEY"]
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these variables in your .env file or environment.")
        sys.exit(1)

def print_section(title, content, verbose=False):
    """Print a formatted section to the console."""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80 + "\n")
    
    if isinstance(content, dict) or isinstance(content, list):
        if verbose:
            print(json.dumps(content, indent=2))
        else:
            # Print a simplified version
            if isinstance(content, dict):
                for key, value in content.items():
                    if key != "raw_data" and key != "raw_plan":
                        if isinstance(value, (dict, list)):
                            print(f"{key}: [Complex data]")
                        else:
                            print(f"{key}: {value}")
            else:
                print(f"[List with {len(content)} items]")
    else:
        print(content)

def save_json_file(data, filepath):
    """Save data to a JSON file."""
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\nSaved data to {filepath}")
        return True
    except Exception as e:
        print(f"Error saving data to {filepath}: {str(e)}")
        return False

def save_text_file(text, filepath):
    """Save text content to a file."""
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(text)
        print(f"\nSaved text to {filepath}")
        return True
    except Exception as e:
        print(f"Error saving text to {filepath}: {str(e)}")
        return False

def create_output_directory(cve_id):
    """Create a timestamped directory for output files."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dir_name = f"cve_results_{cve_id}---{timestamp}"
    
    # Create the directory
    output_dir = os.path.join(os.getcwd(), "results", dir_name)
    os.makedirs(output_dir, exist_ok=True)
    
    return output_dir

def process_scan(args):
    """Process vulnerability scanner reports."""
    print("\n=== Agentic CVE Remediation Workflow - Scanner Mode ===\n")
    
    # Validate the report paths
    report_paths = []
    for path in args.report_paths:
        # Handle both forward and backward slashes and resolve the path
        normalized_path = os.path.normpath(path)
        abs_path = os.path.join(os.getcwd(), normalized_path) if not os.path.isabs(normalized_path) else normalized_path
        
        if not os.path.exists(abs_path):
            print(f"Error: Path does not exist: {path}")
            print(f"Resolved to: {abs_path}")
            
            # Try to provide helpful feedback on available files
            try:
                parent_dir = os.path.dirname(abs_path) or os.getcwd()
                if os.path.exists(parent_dir):
                    print(f"\nFiles available in parent directory:")
                    for item in os.listdir(parent_dir):
                        item_path = os.path.join(parent_dir, item)
                        item_type = "DIR" if os.path.isdir(item_path) else "FILE"
                        print(f"  {item} [{item_type}]")
            except Exception as e:
                print(f"Error listing directory contents: {str(e)}")
                
            return 1
            
        report_paths.append(abs_path)
    
    print(f"Processing {len(report_paths)} report path(s)...")
    
    # Initialize components
    parser = VulnerabilityParser()
    dispatcher = Dispatcher(max_workers=args.parallel)
    writer = ResultWriter()
    
    # Track overall success
    success = True
    
    # Process each report path
    for report_path in report_paths:
        try:
            path_obj = Path(report_path)
            print(f"\nProcessing: {path_obj.name}")
            
            # Collect normalized records
            records = list(parser.parse_reports([report_path], args.scanner))
            if not records:
                print(f"No vulnerability records found in {report_path}")
                continue
            
            print(f"Found {len(records)} vulnerability records")
            
            # Process records in parallel
            print("Processing vulnerability records...")
            results = dispatcher.process_records(records)
            
            # Check for failures
            failures = [r for r in results if "error" in r]
            if failures:
                print(f"Warning: Failed to process {len(failures)} records")
                success = False
            
            # Write results to disk
            output_dir = writer.write_results(report_path, results)
            print(f"Results saved to: {output_dir}")
            
        except Exception as e:
            print(f"Error processing {report_path}: {str(e)}")
            success = False
    
    # Return appropriate exit code
    return 0 if success else 1


def process_single_cve(args):
    """Process a single vulnerability ID (CVE or GHSA) in legacy mode."""
    vuln_id = args.cve
    is_ghsa = vuln_id.upper().startswith("GHSA-")
    mode_desc = "GHSA" if is_ghsa else "CVE"
    
    print(f"\n=== Agentic CVE Remediation Workflow - Single {mode_desc} Mode ===\n")
    print(f"Researching {vuln_id}...\n")
    
    try:
        # Import legacy modules (only when needed)
        from modules.research_module import ResearchModule
        from modules.resolver_module import ResolverModule
        
        # Create output directory
        output_dir = create_output_directory(args.cve)
        print(f"\nSaving all results to: {output_dir}\n")
        
        # Initialize the research module
        research_module = ResearchModule()
        
        # Research the CVE
        vulnerability_info = research_module.research_cve(args.cve)
        
        # Save the raw API data
        raw_data = vulnerability_info.get("raw_data", {})
        
        # Save CVE Details data
        cve_details = raw_data.get("cve_details", {})
        save_json_file(cve_details, os.path.join(output_dir, "cve_details.json"))
        
        # Save Remediation data
        remediations = raw_data.get("remediations", {})
        save_json_file(remediations, os.path.join(output_dir, "cve_remediations.json"))
        
        # Save GitHub Security Advisories
        github_advisories = raw_data.get("github_advisories", [])
        save_json_file(github_advisories, os.path.join(output_dir, "github_advisories.json"))
        
        # Save and print vulnerability summary
        save_text_file(vulnerability_info["summary"], os.path.join(output_dir, "vulnerability_summary.md"))
        print_section("VULNERABILITY SUMMARY", vulnerability_info["summary"])
        
        # Check if we should skip remediation plan generation
        if args.research_only:
            print("\nResearch completed. Skipping remediation plan generation as requested.")
            
            # Still save the full results JSON if output was specified
            if args.output:
                save_json_file(vulnerability_info, args.output)
            
            return 0
        
        print("\nGenerating remediation plan...\n")
        
        # Initialize the resolver module
        resolver_module = ResolverModule()
        
        # Generate remediation plan
        remediation_plan = resolver_module.generate_remediation_plan(vulnerability_info)
        
        # Save and print remediation plan
        save_text_file(remediation_plan["raw_plan"], os.path.join(output_dir, "remediation_plan.md"))
        print_section("REMEDIATION PLAN", remediation_plan["raw_plan"])
        
        # Save structured plan
        save_json_file(remediation_plan["structured_plan"], os.path.join(output_dir, "structured_plan.json"))
        
        # Print structured plan if verbose
        if args.verbose:
            print_section("STRUCTURED REMEDIATION PLAN", remediation_plan["structured_plan"], verbose=True)
        
        # Combine and save full results
        results = {
            "vulnerability_id": vulnerability_info.get("vulnerability_id", args.cve),
            "cve_id": vulnerability_info.get("cve_id"),
            "vulnerability_info": vulnerability_info,
            "remediation_plan": remediation_plan
        }
        
        # Save combined output if requested
        save_json_file(results, os.path.join(output_dir, "full_results.json"))
        if args.output:
            save_json_file(results, args.output)
        
        print(f"\nAll results saved to directory: {output_dir}")
        return 0
        
    except Exception as e:
        print(f"Error processing CVE {args.cve}: {str(e)}")
        return 1


def main():
    """Main entry point for the application."""
    parser = setup_argparser()
    args = parser.parse_args()
    
    # Validate environment variables
    validate_environment()
    
    # Dispatch to appropriate command handler
    if args.command == "cve":
        exit_code = process_single_cve(args)
    elif args.command == "scan":
        exit_code = process_scan(args)
    else:
        parser.print_help()
        exit_code = 1
    
    # Return proper exit code
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
