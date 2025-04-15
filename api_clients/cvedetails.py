"""
CVE Details API Client for retrieving vulnerability information
"""
import os
import requests
from dotenv import load_dotenv

class CVEDetailsClient:
    """Client for interacting with the CVEDetails.com API."""
    
    def __init__(self, api_key=None):
        """
        Initialize the CVE Details API client.
        
        Args:
            api_key: Optional API key, if not provided will look for CVEDETAILS_API_KEY in env
        """
        load_dotenv()
        self.api_key = api_key or os.environ.get("CVEDETAILS_API_KEY")
        if not self.api_key:
            raise ValueError("CVE Details API key is required. Set CVEDETAILS_API_KEY in .env file or pass it explicitly.")
        
        self.base_url = "https://www.cvedetails.com/api/v1/vulnerability"
        self.headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
    
    def get_cve_json(self, cve_id):
        """
        Get detailed information about a CVE in JSON format.
        
        Args:
            cve_id: The CVE ID (e.g., CVE-2017-16911)
            
        Returns:
            dict: The CVE details
        """
        url = f"{self.base_url}/cve-json"
        params = {"cveId": cve_id}
        
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        
        return response.json()
    
    def get_remediations(self, cve_id, page_number=1, results_per_page=20):
        """
        Get remediation information for a CVE.
        
        Args:
            cve_id: The CVE ID (e.g., CVE-2017-16911)
            page_number: Page number for pagination
            results_per_page: Number of results per page
            
        Returns:
            dict: The remediation details
        """
        url = f"{self.base_url}/remediations"
        params = {
            "cveId": cve_id,
            "pageNumber": page_number,
            "resultsPerPage": results_per_page
        }
        
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        
        return response.json()
