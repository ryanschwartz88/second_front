"""
Research Module - Agentic RAG component for CVE information gathering
"""
import os
import google.generativeai as genai
from dotenv import load_dotenv
from api_clients.cvedetails import CVEDetailsClient
from api_clients.ghsa import GHSAClient

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
    
    def research_cve(self, cve_id):
        """
        Research a CVE by gathering information from multiple sources and generating a summary.
        
        Args:
            cve_id: The CVE ID to research
            
        Returns:
            dict: Comprehensive vulnerability information and summary
        """
        try:
            # Get information from CVEDetails
            cve_details = self.cvedetails_client.get_cve_json(cve_id)
            remediations = self.cvedetails_client.get_remediations(cve_id)
            
            # Get information from GitHub Security Advisories
            ghsa_advisories = self.ghsa_client.search_advisory_by_cve_id(cve_id)
            
            # Prepare data for summarization
            vulnerability_data = {
                "cve_details": cve_details,
                "remediations": remediations,
                "github_advisories": ghsa_advisories
            }
            
            # Generate a summary using Gemini
            summary = self._generate_summary(cve_id, vulnerability_data)
            
            # Return combined results
            return {
                "cve_id": cve_id,
                "raw_data": vulnerability_data,
                "summary": summary
            }
            
        except Exception as e:
            print(f"Error researching CVE {cve_id}: {str(e)}")
            raise
    
    def _generate_summary(self, cve_id, vulnerability_data):
        """
        Generate a comprehensive summary of the vulnerability using Gemini.
        
        Args:
            cve_id: The CVE ID
            vulnerability_data: Dict containing raw vulnerability data from various sources
            
        Returns:
            str: A comprehensive summary of the vulnerability
        """
        # Prepare the prompt for Gemini
        prompt = f"""
        Generate a comprehensive summary of the vulnerability {cve_id} based on the following information.
        
        CVE Details:
        {self._format_cve_details(vulnerability_data.get('cve_details', {}))}
        
        Remediations:
        {self._format_remediations(vulnerability_data.get('remediations', {}))}
        
        GitHub Security Advisories:
        {self._format_github_advisories(vulnerability_data.get('github_advisories', []))}
        
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
            formatted = f"""
            Summary: {cve_details.get('summary', 'N/A')}
            CVSS Score: {cve_details.get('cvss', 'N/A')}
            CWE: {cve_details.get('cwe', 'N/A')}
            Published Date: {cve_details.get('published', 'N/A')}
            Updated Date: {cve_details.get('updated', 'N/A')}
            """
            return formatted
        except Exception:
            return str(cve_details)
    
    def _format_remediations(self, remediations):
        """Format remediation data for the prompt."""
        if not remediations:
            return "No remediation data available"
        
        try:
            formatted = ""
            remediation_list = remediations.get('remediations', [])
            
            if not remediation_list:
                return "No remediation steps available"
            
            for i, remediation in enumerate(remediation_list, 1):
                formatted += f"""
                Remediation {i}:
                Type: {remediation.get('type', 'N/A')}
                Description: {remediation.get('description', 'N/A')}
                """
            
            return formatted
        except Exception:
            return str(remediations)
    
    def _format_github_advisories(self, advisories):
        """Format GitHub Security Advisories for the prompt."""
        if not advisories:
            return "No GitHub Security Advisories available"
        
        try:
            formatted = ""
            
            for i, advisory in enumerate(advisories, 1):
                formatted += f"""
                Advisory {i}:
                GHSA ID: {advisory.get('ghsaId', 'N/A')}
                Summary: {advisory.get('summary', 'N/A')}
                Severity: {advisory.get('severity', 'N/A')}
                Description: {advisory.get('description', 'N/A')}
                
                Affected Packages:
                """
                
                vulnerabilities = advisory.get('vulnerabilities', {}).get('nodes', [])
                for vuln in vulnerabilities:
                    package = vuln.get('package', {})
                    formatted += f"""
                    - Name: {package.get('name', 'N/A')}
                      Ecosystem: {package.get('ecosystem', 'N/A')}
                      Vulnerable Version Range: {vuln.get('vulnerableVersionRange', 'N/A')}
                      First Patched Version: {vuln.get('firstPatchedVersion', {}).get('identifier', 'N/A')}
                    """
                
                formatted += "References:\n"
                for ref in advisory.get('references', []):
                    formatted += f"- {ref.get('url', 'N/A')}\n"
            
            return formatted
        except Exception:
            return str(advisories)
