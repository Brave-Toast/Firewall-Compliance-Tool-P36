# Firewall Compliance Analysis

An advanced, LLM-assisted, vendor-agnostic firewall rule compliance analysis framework. It leverages the **Z3 SMT Solver** for mathematical rule verification (shadowing, redundancy, and correlation detection) and local **Ollama** models for AI-driven intent analysis and policy hardening recommendations.

## Core Features
- **Extensible Parser Factory**: Supports parsing rules from multiple vendors (Palo Alto currently fully supported, with stubs for Cisco ASA and Check Point).
- **Z3 Mathematical Verification**: Detects logical path violations, shadowing, correlation, and rule redundancy using mathematically proven SMT constraints (including IP/CIDR overlaps).
- **LLM-Assisted Intent Analysis**: Uses local LLMs (Ollama) to extract human-readable intent from rules and map them to compliance frameworks (MITRE, NIST, CIS).
- **Asynchronous Processing**: Non-blocking REST API utilizing FastAPI `BackgroundTasks`.
- **"What-If" Simulation**: Test proposed rules against your existing ruleset to mathematically guarantee no conflicts before deployment.
- **Unified Database Architecture**: Built-in SQLite persistence via SQLAlchemy to cache LLM responses, track rules, and log background task execution.

## Setup Instructions

### 1. Prerequisites
- **Python 3.9+**
- **Ollama**: Required for running local LLM analysis. Download at [ollama.com](https://ollama.com/).

### 2. Configure Local LLMs
We provide cross-platform scripts to easily bootstrap your local LLM environment.

**Windows:**
```cmd
setup_llm.bat
```

**Linux/macOS:**
```bash
chmod +x setup_llm.sh
./setup_llm.sh
```
This will download `llama3.2:3b` and `qwen2.5-coder:7b`. Copy `.env.example` to `.env` and set `LLM_MODEL=llama3.2:3b` (or your preferred model).

### 3. Python Environment Setup
Create a virtual environment and install dependencies:
```bash
python -m venv .venv

# On Windows:
.\.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

## How to Use

### Command-Line Interface (CLI)
The CLI automatically persists parsed rules and analysis issues into the local `firewall.db` SQLite database.

```bash
# Parse rules and verify schema
python -m src.main parse --vendor paloalto --file sample_rules.txt

# Run comprehensive Z3 SMT and LLM analysis
python -m src.main analyze --vendor paloalto --file sample_rules.txt

# Generate a policy hardening plan
python -m src.main recommend --vendor paloalto --file sample_rules.txt --top 5 --threshold 70

# Full scan outputting a JSON report
python -m src.main full_scan --vendor paloalto --file sample_rules.txt
```

### REST API
Start the FastAPI server:
```bash
uvicorn src.api:app --host 127.0.0.1 --port 8000
```
*(API Documentation is available at http://127.0.0.1:8000/docs)*

The API uses asynchronous background processing. 

**1. Trigger Analysis**
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"vendor":"paloalto","rules":["id:1|name:Allow-HTTP|from:internal|to:external|source:any|destination:any|application:web-browsing|service:tcp/80|action:allow"]}'
```
*Returns a `task_id` (e.g., `{"task_id": "1234-5678..."}`).*

**2. Poll Task Status**
```bash
curl http://127.0.0.1:8000/status/<task_id>
```
*Returns `pending`, `in_progress`, or `completed` with the final JSON result payload.*

**3. "What-If" Simulation**
Test a proposed rule to detect shadowing or redundancy before applying it.
```bash
curl -X POST http://127.0.0.1:8000/simulate \
  -H "Content-Type: application/json" \
  -d '{
        "vendor": "paloalto",
        "existing_rules": ["id:1|name:Allow-HTTP|from:internal|to:external|source:any|destination:any|application:web-browsing|service:tcp/80|action:allow"],
        "proposed_rule": {"id": "new-1", "name": "Test", "source_zones": ["internal"], "destination_zones": ["external"], "source_addresses": ["any"], "destination_addresses": ["any"], "application": "web-browsing", "service": "tcp/80", "action": "allow"}
      }'
```

## Project Structure
- `src/api.py`: FastAPI routes, endpoints, and asynchronous task execution mapping.
- `src/main.py`: Click-based CLI application identical in function to the API.
- `src/analysis.py`: Z3 SMT solver logic handling redundancy, shadowing, correlation, and rule simulation.
- `src/intent.py`: Ollama API integration and LLM prompt engineering for compliance checks.
- `src/database.py`: SQLAlchemy database models tracking tasks, firewall rules, analysis issues, and LLM cache.
- `src/schema.py`: Pydantic data models for validation.
- `src/parsers/`: Extensible parser factory with `BaseFirewallParser` interface and vendor-specific implementations.

## Future Roadmap
- **Phase 7**: UI Dashboard (React/Vue) for visualizing Z3 conflicts.
- **Phase 8**: Automate deployment configuration generation for validated rules.
- **Phase 9**: Finish Cisco ASA and Check Point regex parsing logic.
