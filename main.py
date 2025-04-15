#!/usr/bin/env python3
"""
Agentic CVE Remediation Workflow CLI Tool

A command-line tool that uses Gemini 2.5 Flash to research and generate
remediation plans for Common Vulnerabilities and Exposures (CVEs).
"""
import argparse
import json
import os
import sys
import datetime
from pathlib import Path
from dotenv import load_dotenv

from modules.research_module import ResearchModule
from modules.resolver_module import ResolverModule

def setup_argparser():
    """Set up the argument parser for the CLI tool."""
    parser = argparse.ArgumentParser(
        description="Agentic CVE Remediation - Research and remediate vulnerabilities using AI"
    )
    parser.add_argument(
        "--cve", 
        required=True, 
        help="CVE ID to research and remediate (e.g., CVE-2017-16911)"
    )
    parser.add_argument(
        "--output", 
        help="Output file to save the results (JSON format)"
    )
    parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Enable verbose output"
    )
    parser.add_argument(
        "--research-only", 
        action="store_true", 
        help="Only perform research, do not generate remediation plan"
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
    dir_name = f"cve_results_{cve_id}_{timestamp}"
    
    # Create the directory
    output_dir = os.path.join(os.getcwd(), "results", dir_name)
    os.makedirs(output_dir, exist_ok=True)
    
    return output_dir

def main():
    """Main entry point for the application."""
    parser = setup_argparser()
    args = parser.parse_args()
    
    # Validate environment variables
    validate_environment()
    
    print("\n=== Agentic CVE Remediation Workflow ===\n")
    print(f"Researching {args.cve}...\n")
    
    try:
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
            
            return
        
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
            "vulnerability_info": vulnerability_info,
            "remediation_plan": remediation_plan
        }
        
        # Save combined output if requested
        save_json_file(results, os.path.join(output_dir, "full_results.json"))
        if args.output:
            save_json_file(results, args.output)
        
        print(f"\nAll results saved to directory: {output_dir}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
