# Agentic CVE Remediation Workflow

This project implements an intelligent, agent-driven command-line tool leveraging Gemini 2.5 Flash to automatically research and remediate Common Vulnerabilities and Exposures (CVEs). It processes vulnerability scanner reports (Trivy, Anchore) or individual CVE IDs, integrates trusted vulnerability databases, and generates actionable remediation plans.

## Overview

The workflow consists of the following modules:

### 1. Parser Module
- **Purpose**: Parse and normalize vulnerability scanner reports.
- **Supported Scanners**:
  - Trivy
  - Anchore
- **Process**:
  1. Auto-detects scanner type from JSON structure.
  2. Extracts relevant vulnerability data.
  3. Normalizes findings into a consistent format.

### 2. Research Module (Agentic RAG)
- **Purpose**: Gather detailed vulnerability information from trusted APIs.
- **Sources**:
  - GitHub Security Advisory (GHSA)
  - CVEdetails.org
- **Process**:
  1. Accepts a CVE identifier as input.
  2. Queries GHSA and CVEdetails.org APIs.
  3. Aggregates and summarizes the results using Gemini 2.5 Flash to provide concise vulnerability context.

### 3. Agentic Resolver Module
- **Purpose**: Generate a detailed and actionable remediation plan based on the summary context from the Research Module.
- **Process**:
  1. Receives summarized vulnerability information from the Research Module along with the CVE identifier.
  2. Utilizes Gemini 2.5 Flash to generate remediation steps, including specific textual guidance and parsed code blocks for easy implementation.

### 4. Dispatcher Module
- **Purpose**: Coordinate parallel processing of multiple vulnerability records.
- **Process**:
  1. Creates a thread pool (default = CPU core count).
  2. Dispatches each unique vulnerability record for processing.
  3. Aggregates results and handles failures gracefully.

### 5. Writer Module
- **Purpose**: Persist processing results to disk in an organized structure.
- **Process**:
  1. Creates timestamped output directories.
  2. Writes normalized findings, summaries, and remediation plans.
  3. Generates an aggregated plan document with links to individual findings.

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
  - Gemini 2.5 Flash

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
GEMINI_API_KEY=your_gemini_key
```

## Usage

The tool supports two modes of operation:

### 1. CVE Mode (Single CVE Processing)
```bash
python main.py cve --cve CVE-XXXX-XXXX [--output OUTPUT_FILE] [--verbose] [--research-only]
```

### 2. Scanner Mode (Vulnerability Scanner Reports)
```bash
python main.py scan REPORT_PATHS... [--scanner {trivy,anchore}] [--parallel THREADS] [--verbose]
```

Examples:
```bash
# Process a single Trivy report
python main.py scan "excalidraw/trivy archive/trivy_container_scanning.json"

# Process an Anchore report with explicit scanner type
python main.py scan "excalidraw/anchore_inline_archive/scan_image/anchore/anchore_security.json" --scanner anchore

# Process multiple reports in parallel
python main.py scan "path/to/reports/" "another/report.json" --parallel 4
```

### Data Output & Results Directory
Each time you run the tool, a timestamped directory is created under `results/` containing all data from the run:

#### For CVE Mode:
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

#### For Scanner Mode:
```
results/{report_name}_{TIMESTAMP}/
├── normalized_findings.json   # Array of normalized vulnerability records
├── summary_{CVE-ID}.md        # Summary for each CVE found in the report
├── plan_{CVE-ID}.md           # Remediation plan for each CVE
├── error_{CVE-ID}.txt         # Error information (if processing failed)
└── aggregated_plans.md        # Master document with links to all CVE plans
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
│   └── cvedetails.py
├── modules/
│   ├── parser.py             # NEW: Parses and normalizes scanner reports
│   ├── dispatcher.py         # NEW: Manages parallel processing
│   ├── writer.py             # NEW: Handles result persistence
│   ├── research_module.py
│   └── resolver_module.py
├── main.py
├── requirements.txt
```

## Notes
This is a personal project and is not licensed for distribution. For personal or research use only.


