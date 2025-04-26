"""
Research Module - Agentic RAG component for CVE information gathering
"""
import os
import google.generativeai as genai
from dotenv import load_dotenv
from api_clients.cvedetails import CVEDetailsClient
from api_clients.ghsa import GHSAClient
import requests
from bs4 import BeautifulSoup
import time

class ResearchModule:
    """
    Research Module that aggregates CVE information from multiple sources
    and uses Gemini to generate a comprehensive summary.
    """
    
    def __init__(self):
        """Initialize the Research Module with API clients."""
        load_dotenv()
        
        # Initialize API clients
        self.cvedetails_client = CVEDetailsClient()
        self.ghsa_client = GHSAClient()
        
        # Initialize Gemini AI
        gemini_api_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY in .env file.")
        
        genai.configure(api_key=gemini_api_key)
        self.model = genai.GenerativeModel('gemini-2.5-pro-exp-03-25')
    
    def research_cve(self, vuln_id):
        """
        Research a vulnerability by gathering information from multiple sources and generating a summary.
        
        Args:
            vuln_id: The vulnerability ID (CVE-XXXX-YYYY or GHSA-XXXX-YYYY-ZZZZ)
            
        Returns:
            dict: Comprehensive vulnerability information and summary
        """
        try:
            # Determine if this is a GHSA ID or CVE ID
            is_ghsa = vuln_id.upper().startswith("GHSA-")
            
            # If this is a GHSA ID, get the advisory and extract any CVE IDs
            cve_id = None
            primary_ghsa_advisory = None
            if is_ghsa:
                try:
                    # Get the full GHSA advisory
                    ghsa_id = vuln_id
                    primary_ghsa_advisory = self.ghsa_client.get_advisory_by_ghsa_id(ghsa_id)
                    
                    # Extract CVE ID if available
                    if "aliases" in primary_ghsa_advisory:
                        for alias in primary_ghsa_advisory["aliases"]:
                            if alias.upper().startswith("CVE-"):
                                cve_id = alias
                                print(f"Found related CVE ID: {cve_id}")
                                break
                    
                    if not cve_id:
                        print(f"No CVE ID found for {ghsa_id}. Will use GHSA information only.")
                except Exception as e:
                    print(f"Error fetching GHSA advisory: {str(e)}")
                    # Continue with just the GHSA ID
            else:
                # This is a CVE ID
                cve_id = vuln_id
            
            # Get information from GitHub Security Advisories
            ghsa_advisories = []
            if cve_id:
                # For CVE IDs, search for related GHSA advisories
                ghsa_advisories = self.ghsa_client.search_advisory_by_cve_id(cve_id)
            
            # For GHSA IDs, always include the primary advisory if available
            if primary_ghsa_advisory:
                # Process and enrich the primary advisory
                # Convert string references to dict format for enrichment
                if "references" in primary_ghsa_advisory and isinstance(primary_ghsa_advisory["references"], list):
                    # Check if we have simple strings or dict references
                    if primary_ghsa_advisory["references"] and isinstance(primary_ghsa_advisory["references"][0], str):
                        # Convert simple strings to dict format
                        ref_list = [{"url": url} for url in primary_ghsa_advisory["references"]]
                        # Enrich with content
                        enriched_refs = self._enrich_references_with_content(ref_list)
                        # Store the enriched references back in the advisory
                        # We'll keep both formats - the original string list and an enriched dict list
                        primary_ghsa_advisory["enriched_references"] = enriched_refs
                        print("GHSA References ENRICHED")
                    
                # Always add the primary advisory regardless of CVE ID presence
                ghsa_advisories = [primary_ghsa_advisory]
            
            # Get information from CVEDetails if a CVE ID is available
            cve_details = {}
            remediations = {}
            if cve_id:
                try:
                    cve_details = self.cvedetails_client.get_cve_json(cve_id)
                    
                    if "references" in cve_details and isinstance(cve_details["references"], list):
                        cve_details["references"] = self._enrich_references_with_content(cve_details["references"])
                        print("ENRICHED")
                    
                    remediations = self.cvedetails_client.get_remediations(cve_id)
                except Exception as e:
                    print(f"Error fetching CVE details: {str(e)}")
                    print("Continuing with available information")
            
            # Prepare data for summarization
            vulnerability_data = {
                "cve_details": cve_details,
                "remediations": remediations,
                "github_advisories": ghsa_advisories
            }
            
            # Generate a summary using Gemini
            summary = self._generate_summary(vuln_id, vulnerability_data)
            
            # Return combined results
            return {
                "vulnerability_id": vuln_id,
                "cve_id": cve_id,
                "raw_data": vulnerability_data,
                "summary": summary
            }
            
        except Exception as e:
            print(f"Error researching vulnerability {vuln_id}: {str(e)}")
            raise
    
    def _generate_summary(self, vuln_id, vulnerability_data):
        """
        Generate a comprehensive summary of the vulnerability using Gemini.
        
        Args:
            vuln_id: The vulnerability ID (CVE or GHSA)
            vulnerability_data: Dict containing raw vulnerability data from various sources
            
        Returns:
            str: A comprehensive summary of the vulnerability
        """
        # Prepare the prompt for Gemini
        
        prompt = f"""
        Generate a comprehensive summary of the vulnerability {vuln_id} based on the following information.
        
        CVE Details:
        {self._format_cve_details(vulnerability_data["cve_details"])}
        
        Remediations:
        {self._format_remediations(vulnerability_data['remediations'])}
        
        GitHub Security Advisories:
        {self._format_github_advisories(vulnerability_data['github_advisories'])}
        
        Please provide a structured summary including:
        1. Vulnerability Overview: A brief description of the vulnerability.
        2. Severity: How critical is this vulnerability (with CVSS score if available).
        3. Affected Systems/Software: Which systems or software packages are affected.
        4. Technical Details: How the vulnerability works (attack vectors, exploitation methods).
        5. Available Patches/Fixes: What official patches or fixes are available.
        6. References: Key references for more information.
        
        Make the summary detailed but concise, focusing on the most important and actionable information.
        """
        
        # Generate the summary
        response = self.model.generate_content(prompt)
        
        return response.text
    
    def _format_cve_details(self, cve_details):
        """Format CVE details for the prompt."""
        if not cve_details:
            return "No data available"
        
        try:
            # Extract the primary description if available
            description = "N/A"
            if "descriptions" in cve_details and isinstance(cve_details["descriptions"], list):
                for desc in cve_details["descriptions"]:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "N/A")
                        break
            
            # Extract CVSS score
            cvss_score = "N/A"
            if "metrics" in cve_details:
                metrics = cve_details["metrics"]
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_score = f"{metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 'N/A')} (v3.1)"
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_score = f"{metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 'N/A')} (v3.0)"
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_score = f"{metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 'N/A')} (v2.0)"
            
            # Extract CWE IDs
            cwe_ids = []
            if "weaknesses" in cve_details and isinstance(cve_details["weaknesses"], list):
                for weakness in cve_details["weaknesses"]:
                    for desc in weakness.get("description", []):
                        if desc.get("lang") == "en":
                            cwe_ids.append(desc.get("value", ""))
            
            cwe_text = ", ".join(cwe_ids) if cwe_ids else "N/A"
            
            # Format the output
            formatted = f"""
            CVE ID: {cve_details.get('id', 'N/A')}
            Published Date: {cve_details.get('published', 'N/A')}
            Last Modified: {cve_details.get('lastModified', 'N/A')}
            Description: {description}
            CVSS Score: {cvss_score}
            CWE: {cwe_text}
            """
            
            # Include reference titles if available
            if "references" in cve_details and isinstance(cve_details["references"], list):
                formatted += "\nReferences:\n"
                for i, ref in enumerate(cve_details["references"][:5], 1):  # Limit to first 5 references
                    formatted += f"  {i}. {ref.get('url', 'N/A')}\n"
                    
                # Include all available reference content
                refs_with_content = [ref for ref in cve_details["references"] if ref.get("content")]
                if refs_with_content:
                    formatted += "\nReference content:\n"
                    for i, ref in enumerate(refs_with_content, 1):
                        formatted += f"\nReference {i}: {ref.get('url', 'N/A')}\n"
                        content = ref.get("content", "")
                        if content:
                            formatted += f"{content}\n"
            
            return formatted
        except Exception as e:
            print(f"Error formatting CVE details: {str(e)}")
            return str(cve_details)
    
    def _format_remediations(self, remediations):
        """Format remediation data for the prompt."""
        if not remediations:
            return "No remediation data available"
        
        try:
            formatted = ""
            
            # Check if we have results
            if "results" not in remediations or not remediations["results"]:
                return "No remediation steps available"
            
            # Extract all remediation items across different products
            all_remediations = []
            for product, advisories in remediations.get("results", {}).items():
                for advisory_id, remediation_list in advisories.items():
                    for remediation in remediation_list:
                        all_remediations.append({
                            "product": product if product else "Generic/Unspecified",
                            "advisory": advisory_id,
                            **remediation
                        })
            
            if not all_remediations:
                return "No remediation steps available"
            
            formatted += "Remediation Steps:\n"
            
            # Group by type for better organization
            vendor_fixes = [r for r in all_remediations if r.get("remediationType") == "vendor_fix"]
            workarounds = [r for r in all_remediations if r.get("remediationType") == "workaround"]
            mitigations = [r for r in all_remediations if r.get("remediationType") == "mitigation"]
            others = [r for r in all_remediations if r.get("remediationType") not in ["vendor_fix", "workaround", "mitigation"]]
            
            # Format vendor fixes
            if vendor_fixes:
                formatted += "\nVendor Fixes:\n"
                for i, fix in enumerate(vendor_fixes[:3], 1):  # Limit to 3 items
                    formatted += f"  {i}. {fix.get('description', 'N/A')}\n"
                    if fix.get("referenceUrl"):
                        formatted += f"     Reference: {fix.get('referenceUrl')}\n"
                    formatted += f"     Source: {fix.get('sourceDataName', 'Unknown')}\n"
            
            # Format workarounds
            if workarounds:
                formatted += "\nWorkarounds:\n"
                for i, workaround in enumerate(workarounds[:3], 1):  # Limit to 3 items
                    formatted += f"  {i}. {workaround.get('description', 'N/A')}\n"
                    if workaround.get("referenceUrl"):
                        formatted += f"     Reference: {workaround.get('referenceUrl')}\n"
                    formatted += f"     Source: {workaround.get('sourceDataName', 'Unknown')}\n"
            
            # Format mitigations
            if mitigations:
                formatted += "\nMitigations:\n"
                for i, mitigation in enumerate(mitigations[:3], 1):  # Limit to 3 items
                    formatted += f"  {i}. {mitigation.get('description', 'N/A')}\n"
                    if mitigation.get("referenceUrl"):
                        formatted += f"     Reference: {mitigation.get('referenceUrl')}\n"
                    formatted += f"     Source: {mitigation.get('sourceDataName', 'Unknown')}\n"
            
            # If we have more than shown, note it
            total_count = len(all_remediations)
            shown_count = min(len(vendor_fixes), 3) + min(len(workarounds), 3) + min(len(mitigations), 3) + min(len(others), 3)
            if total_count > shown_count:
                formatted += f"\n(Additional {total_count - shown_count} remediation items available)\n"
            
            return formatted
        except Exception as e:
            print(f"Error formatting remediations: {str(e)}")
            return str(remediations)
    
    def _format_github_advisories(self, advisories):
        """Format GitHub Security Advisories for the prompt."""
        if not advisories:
            return "No GitHub Security Advisories available"
        
        # Apply enrichment to any advisories that haven't been enriched yet
        for advisory in advisories:
            # Check if we need to enrich references
            if "references" in advisory and isinstance(advisory["references"], list) and "enriched_references" not in advisory:
                # Only enrich simple string references
                if advisory["references"] and isinstance(advisory["references"][0], str):
                    ref_list = [{"url": url} for url in advisory["references"]]
                    advisory["enriched_references"] = self._enrich_references_with_content(ref_list)
                    print("Late GHSA References ENRICHED")
        
        try:
            formatted = ""
            
            for i, advisory in enumerate(advisories, 1):
                # Handle different formats - GraphQL API results vs REST API results
                ghsa_id = advisory.get('ghsaId') or advisory.get('ghsa_id', 'N/A')
                summary = advisory.get('summary', 'N/A')
                severity = advisory.get('severity', 'N/A')
                description = advisory.get('description', 'N/A')
                cve_id = advisory.get('cve_id', 'N/A')
                
                formatted += f"""
                Advisory {i}:
                GHSA ID: {ghsa_id}
                Summary: {summary}
                Severity: {severity}
                Description: {description}
                CVE ID: {cve_id}
                """
                
                # Handle the different vulnerability formats
                formatted += "\nAffected Packages:\n"
                
                # Check if we have GraphQL style vulnerabilities
                graphql_vulns = advisory.get('vulnerabilities', {}).get('nodes', [])
                if graphql_vulns:
                    for vuln in graphql_vulns:
                        package = vuln.get('package', {})
                        pkg_name = package.get('name', 'N/A')
                        pkg_ecosystem = package.get('ecosystem', 'N/A')
                        vuln_range = vuln.get('vulnerableVersionRange', 'N/A')
                        patched_version = vuln.get('firstPatchedVersion', {}).get('identifier', 'N/A')
                        
                        formatted += f"  - Name: {pkg_name}\n"
                        formatted += f"    Ecosystem: {pkg_ecosystem}\n"
                        formatted += f"    Vulnerable Version Range: {vuln_range}\n"
                        formatted += f"    First Patched Version: {patched_version}\n"
                # Check if we have REST API style vulnerabilities
                elif "vulnerabilities" in advisory and isinstance(advisory["vulnerabilities"], list):
                    for vuln in advisory["vulnerabilities"]:
                        package = vuln.get('package', {}) 
                        pkg_name = package.get('name', 'N/A')
                        pkg_ecosystem = package.get('ecosystem', 'N/A')
                        vuln_range = vuln.get('vulnerable_version_range', 'N/A')
                        patched_version = vuln.get('first_patched_version', 'N/A')
                        
                        formatted += f"  - Name: {pkg_name}\n"
                        formatted += f"    Ecosystem: {pkg_ecosystem}\n"
                        formatted += f"    Vulnerable Version Range: {vuln_range}\n"
                        formatted += f"    First Patched Version: {patched_version}\n"
                
                # Handle CVSS information if available
                if "cvss" in advisory:
                    cvss = advisory["cvss"]
                    formatted += f"\nCVSS Score: {cvss.get('score', 'N/A')}\n"
                    formatted += f"CVSS Vector: {cvss.get('vector_string', 'N/A')}\n"
                elif "cvss_severities" in advisory and advisory["cvss_severities"]:
                    cvss_info = advisory["cvss_severities"]
                    if "cvss_v3" in cvss_info and cvss_info["cvss_v3"]:
                        formatted += f"\nCVSS v3 Score: {cvss_info['cvss_v3'].get('score', 'N/A')}\n"
                        formatted += f"CVSS v3 Vector: {cvss_info['cvss_v3'].get('vector_string', 'N/A')}\n"
                
                # Handle References
                formatted += "\nReferences:\n"
                
                # Handle references based on their format
                if "enriched_references" in advisory and advisory["enriched_references"]:
                    # Handle enriched references (dictionary format with content)
                    # First check if they're all dictionaries
                    if all(isinstance(ref, dict) for ref in advisory["enriched_references"]):
                        # Find references that have content
                        refs_with_content = []
                        for ref in advisory["enriched_references"]:
                            if isinstance(ref, dict) and ref.get("content"):
                                refs_with_content.append(ref)
                        
                        # Display URLs
                        for i, ref in enumerate(advisory["enriched_references"][:5], 1):
                            if isinstance(ref, dict):
                                formatted += f"  {i}. {ref.get('url', 'N/A')}\n"
                            else:
                                formatted += f"  {i}. {str(ref)}\n"
                        
                        # Include all available reference content
                        if refs_with_content:
                            formatted += "\nReference content:\n"
                            for i, ref in enumerate(refs_with_content, 1):
                                formatted += f"\nReference {i}: {ref.get('url', 'N/A')}\n"
                                content = ref.get("content", "")
                                if content:
                                    formatted += f"{content}\n"
                    else:
                        # If not all are dictionaries, handle as mixed or string list
                        for i, ref in enumerate(advisory["enriched_references"][:5], 1):
                            if isinstance(ref, dict):
                                formatted += f"  {i}. {ref.get('url', 'N/A')}\n"
                            else:
                                formatted += f"  {i}. {str(ref)}\n"
                
                # Fall back to regular references if no enriched ones
                elif "references" in advisory and isinstance(advisory["references"], list):
                    # Handle different possible formats
                    for i, ref in enumerate(advisory["references"][:5], 1):
                        if isinstance(ref, dict) and "url" in ref:
                            formatted += f"  {i}. {ref.get('url', 'N/A')}\n"
                        else:
                            formatted += f"  {i}. {str(ref)}\n"
                
                formatted += "\n"
            
            return formatted
        except Exception as e:
            print(f"Error formatting GitHub advisories: {str(e)}")
            return str(advisories)

    def _enrich_references_with_content(self, references):
        """Fetch and add page content to each reference with a URL."""
        for ref in references:
            url = ref.get("url")
            if url:
                try:
                    print(f"[ResearchModule] Scraping content from: {url}")
                    headers = {"User-Agent": "Mozilla/5.0"}
                    resp = requests.get(url, headers=headers, timeout=10)
                    resp.raise_for_status()
                    soup = BeautifulSoup(resp.text, "html.parser")
                    main = soup.find("main") or soup.find("article") or soup.body
                    text = main.get_text(separator="\n", strip=True) if main else soup.get_text(separator="\n", strip=True)
                    ref["content"] = text[:5000]  # Limit for sanity
                except Exception as e:
                    print(f"[ResearchModule] Failed to scrape {url}: {e}")
                    ref["content"] = None
                time.sleep(1)  # Be polite to servers
        return references