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

We support three operational models: local CLI analysis, standard REST API scanning, and end-to-end simulated active firewall deployment.

---

### 1. Network Simulation & REST API Deployment (MVP Feature)
Validate your compliance pipeline by running a three-tier network simulation using Docker. This mode compiles normalized rules into native Suricata IPS syntax, prunes shadowed and redundant rules using Z3 SMT, and hot-reloads a live firewall.

#### Step A: Launch the Containerized Simulation
Start the 3-tier network topology (`client` $\leftrightarrow$ `ngfw_suricata` $\leftrightarrow$ `web_server`). You can optionally select a **premade ruleset** (like `sample_rules.txt`) to compile and load onto the firewall container upon setup.

**On Windows (PowerShell):**
```powershell
# Setup with default baseline rules (ICMP drop + /admin block)
.\start_demo.ps1

# OR: Setup and automatically compile/optimize/inject a premade ruleset
.\start_demo.ps1 -RulesetPath sample_rules.txt
```

**On Linux / macOS:**
```bash
chmod +x start_demo.sh stop_demo.sh
# Setup with baseline rules
./start_demo.sh

# OR: Setup with premade ruleset
./start_demo.sh sample_rules.txt
```

#### Step B: Start the Services
Run the simulated firewall REST API sidecar (representing the NGFW device) and the main compliance engine:

```bash
# 1. Run the Simulated Firewall API (Port 8001)
python -m src.firewall_api

# 2. Run the Main Compliance API Server (Port 8000)
uvicorn src.api:app --host 127.0.0.1 --port 8000
```

#### Step C: Run the Compliance & Optimization Pipeline
Using either the **CLI** or **REST API**, perform intake, Z3-optimization, and deployment:

##### Method 1: Using the CLI
```bash
# 1. Intake: Pull rules from the firewall API, normalize, and save to DB
python -m src.main intake --firewall-url http://127.0.0.1:8001/api/v1/rules

# 2. Deploy: Fetch rules, optimize with Z3 (pruning redundant/shadowed rules), translate to Suricata, and deploy!
python -m src.main deploy --firewall-url http://127.0.0.1:8001/api/v1/rules
```

##### Method 2: Using the REST API
```bash
# 1. Intake Endpoint
curl -X POST http://127.0.0.1:8000/api/v1/firewall/intake \
  -H "Content-Type: application/json" \
  -d '{"firewall_url": "http://127.0.0.1:8001/api/v1/rules"}'

# 2. Deploy & Hot-Reload Endpoint
curl -X POST http://127.0.0.1:8000/api/v1/firewall/deploy \
  -H "Content-Type: application/json" \
  -d '{"firewall_url": "http://127.0.0.1:8001/api/v1/rules"}'
```

#### Step D: Verify Traffic Interception
Validate the firewall's inline blocking capabilities using the client container:

```bash
# 1. Test ICMP Ping (Blocked by rule)
docker exec ext_client ping -c 3 -W 2 10.0.50.10

# 2. Test standard HTTP Web Server access (Allowed)
docker exec ext_client wget -qO- --timeout=3 http://10.0.50.10/

# 3. Test HTTP L7 /admin URI access (Blocked & timed out by Suricata)
docker exec ext_client wget -qO- --timeout=3 http://10.0.50.10/admin
```

#### Step E: Clean Up Teardown
```powershell
# On Windows
.\stop_demo.ps1

# On Linux/macOS
./stop_demo.sh
```

---

### 2. Standalone Command-Line Interface (CLI)
Analyze, hardening, and compile rulesets offline:

```bash
# Parse rules and verify schema
python -m src.main parse --vendor paloalto --file sample_rules.txt

# Run comprehensive Z3 SMT and local LLM (Ollama) analysis
python -m src.main analyze --vendor paloalto --file sample_rules.txt

# Generate a policy hardening plan
python -m src.main recommend --vendor paloalto --file sample_rules.txt --top 5 --threshold 70

# Offline compile/optimize any vendor ruleset directly to Suricata format
python -m src.main compile --vendor paloalto --file sample_rules.txt --output reports/compiled.rules
```

---

### 3. Asynchronous Scanning REST API
For deep, non-blocking compliance scans:

**1. Trigger Scan**
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"vendor":"paloalto","rules":["id:1|name:Allow-HTTP|from:internal|to:external|source:any|destination:any|application:web-browsing|service:tcp/80|action:allow"]}'
```
*Returns a `task_id`.*

**2. Poll Task Status**
```bash
curl http://127.0.0.1:8000/status/<task_id>
```

**3. "What-If" Simulation**
Verify proposed rules before deploying:
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
- `src/api.py`: FastAPI routes, endpoints, and firewall integration mapping (`intake` & `deploy`).
- `src/main.py`: Click-based CLI application featuring standard analysis and `compile` / `intake` / `deploy` commands.
- `src/translator.py`: Engine to compile normalized rules into native Suricata syntax.
- `src/firewall_api.py`: Mock firewall REST API representing the NGFW device to receive rules and interface with Docker.
- `src/analysis.py`: Z3 SMT solver logic handling redundancy, shadowing, correlation, and rule simulation.
- `src/intent.py`: Ollama API integration and LLM prompt engineering for compliance checks.
- `src/database.py`: SQLAlchemy database models tracking tasks, firewall rules, analysis issues, and LLM cache.
- `src/schema.py`: Pydantic data models for validation.
- `src/parsers/`: Extensible parser factory with `BaseFirewallParser` interface and vendor-specific implementations.
- `start_demo.ps1` / `stop_demo.ps1`: Windows PowerShell orchestration scripts for active container testing.
- `start_demo.sh` / `stop_demo.sh`: Linux/macOS bash orchestration scripts.
- `docker-compose.yml`: Multi-container configuration defining the simulated network zones.

## Future Roadmap
- **Phase 7**: UI Dashboard (React/Vue) for visualizing Z3 conflicts.
- **Phase 8**: Automate deployment configuration generation for Palo Alto/Cisco hardware.
- **Phase 9**: Finish Cisco ASA and Check Point regex parsing logic.
