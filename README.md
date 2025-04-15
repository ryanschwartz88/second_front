# Agentic CVE Remediation Workflow

This project implements an intelligent, agent-driven command-line tool leveraging Gemini 2.5 Flash to automatically research and remediate Common Vulnerabilities and Exposures (CVEs). It integrates trusted vulnerability databases, providing comprehensive information and generating actionable remediation plans.

## Overview

The workflow consists of two core modules:

### 1. Research Module (Agentic RAG)
- **Purpose**: Gather detailed vulnerability information from trusted APIs.
- **Sources**:
  - GitHub Security Advisory (GHSA)
  - CVEdetails.org

- **Process**:
  1. Accepts a CVE identifier as input.
  2. Queries GHSA and CVEdetails.org APIs.
  3. Aggregates and summarizes the results using Gemini 2.5 Flash to provide concise vulnerability context.

### 2. Agentic Resolver Module
- **Purpose**: Generate a detailed and actionable remediation plan based on the summary context from the Research Module.
- **Process**:
  1. Receives summarized vulnerability information from the Research Module along with the CVE identifier.
  2. Utilizes Gemini 2.5 Flash to generate remediation steps, including specific textual guidance and parsed code blocks for easy implementation.

## Technical Implementation
- **LLM Provider**: Gemini 2.5 Flash
- **Tooling**:
  - Python CLI application
  - Requests library for API interactions

## Setup and Installation

### Prerequisites
- Python 3.10+
- API keys for:
  - GHSA
  - CVEdetails.org

### Installation
```bash
git clone https://github.com/ryan_schwartz88/second_front.git
cd agentic-cve-remediation
pip install -r requirements.txt
```

### Configuration
Create an `.env` file:
```env
GHSA_API_KEY=your_ghsa_key
CVEDETAILS_API_KEY=your_cvedetails_key
```

## Usage

### Running the CLI Tool
```bash
python main.py --cve CVE-XXXX-XXXX
```

### Data Output & Results Directory
Each time you run the tool, a timestamped directory is created under `results/` containing all data from the run:

```
results/cve_results_{CVE-ID}_{TIMESTAMP}/
├── cve_details.json           # Raw data from CVE Details API
├── cve_remediations.json      # Raw remediation data from CVE Details API
├── github_advisories.json     # Raw data from GitHub Security Advisory API
├── vulnerability_summary.md   # Generated vulnerability summary (markdown)
├── remediation_plan.md        # Generated remediation plan (markdown)
├── structured_plan.json       # Structured remediation plan (JSON format)
└── full_results.json          # Complete results including all of the above
```

You can use these files for audit, sharing, or further analysis.

### Example Output
- **Vulnerability Summary**: Detailed description, affected packages, and patches.
- **Remediation Plan**: Clearly outlined steps, recommended actions, and code snippets.

## Project Structure
```
agentic-cve-remediation/
├── api_clients/
│   ├── ghsa.py
│   ├── cvedetails.py
├── modules/
│   ├── research_module.py
│   └── resolver_module.py
├── main.py
├── requirements.txt
```

## Notes
This is a personal project and is not licensed for distribution. For personal or research use only.


