"""
Resolver Module - Agentic component for generating CVE remediation plans
"""
import os
import google.generativeai as genai
import cohere
from dotenv import load_dotenv

class ResolverModule:
    """
    Resolver Module that generates detailed remediation plans
    for vulnerabilities using AI models (Gemini or Cohere).
    """
    
    def __init__(self, llm_type="cohere"):
        """Initialize the Resolver Module.
        
        Args:
            llm_type: The LLM service to use ("gemini" or "cohere")
        """
        load_dotenv()
        
        self.llm_type = llm_type.lower()
        
        # Initialize LLM based on type
        if self.llm_type == "gemini":
            gemini_api_key = os.environ.get("GEMINI_API_KEY")
            if not gemini_api_key:
                raise ValueError("Gemini API key is required. Set GEMINI_API_KEY in .env file.")
            
            genai.configure(api_key=gemini_api_key)
            self.model = genai.GenerativeModel('gemini-2.5-pro-exp-03-25')
            
        elif self.llm_type == "cohere":
            cohere_api_key = os.environ.get("COHERE_API_KEY")
            if not cohere_api_key:
                raise ValueError("Cohere API key is required. Set COHERE_API_KEY in .env file.")
            
            self.co_client = cohere.ClientV2(cohere_api_key)
            
        else:
            raise ValueError(f"Unsupported LLM type: {llm_type}. Must be 'gemini' or 'cohere'.")
    
    def generate_remediation_plan(self, vulnerability_info):
        """
        Generate a detailed remediation plan for a vulnerability.
        
        Args:
            vulnerability_info: Dict containing vulnerability information and summary
            
        Returns:
            dict: A structured remediation plan
        """
        try:
            # Extract relevant information
            cve_id = vulnerability_info.get('cve_id')
            summary = vulnerability_info.get('summary', '')
            
            # Generate the remediation plan
            plan_text = self._generate_plan(cve_id, summary, vulnerability_info.get('raw_data', {}))
            
            # Parse and structure the remediation plan
            # FIXME: restore structured_plan. Removed for rate limiting issues
            # structured_plan = {}
            structured_plan = self._parse_remediation_plan(plan_text)
            
            return {
                "cve_id": cve_id,
                "raw_plan": plan_text,
                "structured_plan": structured_plan
            }
            
        except Exception as e:
            print(f"Error generating remediation plan: {str(e)}")
            raise
    
    def _generate_plan(self, cve_id, summary, raw_data):
        """
        Generate a detailed remediation plan using the configured LLM.
        
        Args:
            cve_id: The CVE ID
            summary: Vulnerability summary from the Research Module
            raw_data: Raw vulnerability data from various sources
            
        Returns:
            str: A detailed remediation plan
        """
        print(f"[ResolverModule] Generating plan for {cve_id}")
        # Prepare the prompt for the LLM
        prompt = f"""
        Based on the following vulnerability information for {cve_id}, generate a detailed and actionable remediation plan.
        
        Vulnerability Summary:
        {summary}
        
        You are an expert security engineer. Create a detailed step-by-step remediation plan that addresses this vulnerability.
        
        Your plan should include:
        
        1. **Overview**: A brief summary of the remediation approach.
        
        2. **Prerequisites**: Tools, access, or information needed before starting remediation.
        
        3. **Step-by-Step Remediation Instructions**: Detailed steps with:
           - Clear instructions for each action
           - Specific commands or code snippets where applicable
           - Verification steps to confirm the remediation worked
        
        4. **Alternative Approaches**: If multiple remediation options exist, list them with pros and cons.
        
        5. **Post-Remediation Tests**: How to verify the vulnerability is fully addressed.
        
        Format your response with clear markdown headings and structure. For any code or commands, use proper code blocks with appropriate syntax highlighting.
        """
        
        # Generate the remediation plan based on LLM type
        try:
            if self.llm_type == "gemini":
                response = self.model.generate_content(prompt)
                return response.text
            elif self.llm_type == "cohere":
                response = self.co_client.chat(
                    model="command-a-03-2025",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a security expert who specializes in creating detailed remediation plans for vulnerabilities."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.7
                )
                return response.message.content[0].text
        except Exception as e:
            print(f"Error generating remediation plan with {self.llm_type}: {str(e)}")
            return f"Failed to generate a remediation plan using {self.llm_type} due to an error."
    
    def _parse_remediation_plan(self, plan_text):
        """
        Parse the remediation plan text to extract structured information.
        
        Args:
            plan_text: The raw remediation plan text
            
        Returns:
            dict: A structured representation of the remediation plan
        """
        # Generate a more structured version of the plan using the configured LLM
        prompt = f"""
        Parse the following remediation plan into a structured format:
        
        {plan_text}
        
        Extract and organize the information into the following JSON structure:
        
        ```json
        {{
            "overview": "Brief summary of the remediation approach",
            "prerequisites": ["list", "of", "prerequisites"],
            "steps": [
                {{
                    "title": "Step title",
                    "description": "Step description",
                    "code": "Code or command if present (or null)",
                    "verification": "Verification step if present (or null)"
                }}
            ],
            "alternatives": [
                {{
                    "title": "Alternative approach title",
                    "description": "Description of the alternative",
                    "pros": ["list", "of", "pros"],
                    "cons": ["list", "of", "cons"]
                }}
            ],
            "verification_tests": ["list", "of", "verification", "tests"],
            "monitoring_recommendations": ["list", "of", "monitoring", "recommendations"]
        }}
        ```
        
        If a section is missing from the original plan, include an empty list or null value for that section.
        Ensure the output is valid JSON that can be parsed by Python's json.loads().
        """
        
        # Parse the plan into structured format
        import re
        import json
        
        # Use the configured LLM to parse the plan into structured format
        try:
            if self.llm_type == "gemini":
                response = self.model.generate_content(prompt)
                response_text = response.text
            elif self.llm_type == "cohere":
                response = self.co_client.chat(
                    model="command-a-03-2025",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a security expert who specializes in formatting remediation plans into structured JSON. Always return valid JSON that can be parsed by Python's json.loads()."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.2  # Lower temperature for more precise structured output
                )
                response_text = response.message.content[0].text
            
            # Try to find JSON in the response
            json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                return json.loads(json_str)
            
            # If no JSON block found, try to parse the entire response
            return json.loads(response_text)
        except json.JSONDecodeError:
            # If parsing fails, return a basic structure with the raw text
            return {
                "overview": "Could not parse the plan structure",
                "raw_text": plan_text
            }
