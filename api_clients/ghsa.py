"""
GitHub Security Advisory (GHSA) API Client for retrieving vulnerability information
"""
import os
import requests
from dotenv import load_dotenv

class GHSAClient:
    """Client for interacting with the GitHub Security Advisories API."""
    
    def __init__(self, api_key=None):
        """
        Initialize the GHSA API client.
        
        Args:
            api_key: Optional API key, if not provided will look for GHSA_API_KEY in env
        """
        load_dotenv()
        self.api_key = api_key or os.environ.get("GHSA_API_KEY")
        if not self.api_key:
            raise ValueError("GitHub API key is required. Set GHSA_API_KEY in .env file or pass it explicitly.")
        
        self.base_url = "https://api.github.com/advisories"
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.api_key}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
    
    def get_advisory_by_ghsa_id(self, ghsa_id):
        """
        Get GHSA advisory by its GHSA ID.
        
        Args:
            ghsa_id: The GHSA ID (e.g., GHSA-abcd-1234-efgh)
            
        Returns:
            dict: The advisory details
        """
        url = f"{self.base_url}/{ghsa_id}"
        
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        
        return response.json()
    
    def search_advisory_by_cve_id(self, cve_id):
        """
        Search for GitHub Security Advisories that reference a specific CVE ID.
        
        Args:
            cve_id: The CVE ID (e.g., CVE-2017-16911)
            
        Returns:
            list: List of advisories that reference the CVE
        """
        url = "https://api.github.com/graphql"
        
        # GraphQL query to search for advisories by CVE ID
        query = """
        query($cve_id: String!) {
          securityAdvisories(first: 10, orderBy: {field: PUBLISHED_AT, direction: DESC}, identifierFilter: {type: CVE, value: $cve_id}) {
            nodes {
              ghsaId
              summary
              description
              severity
              publishedAt
              updatedAt
              references {
                url
              }
              vulnerabilities(first: 10) {
                nodes {
                  package {
                    name
                    ecosystem
                  }
                  firstPatchedVersion {
                    identifier
                  }
                  vulnerableVersionRange
                }
              }
            }
          }
        }
        """
        
        variables = {"cve_id": cve_id}
        
        response = requests.post(
            url,
            headers=self.headers,
            json={"query": query, "variables": variables}
        )
        response.raise_for_status()
        
        data = response.json()
        return data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
