# Firewall Compliance Analysis

LLM-assisted, vendor-agnostic firewall rule compliance analysis framework.

## Project Goals
- Parse vendor firewall rules (Palo Alto initial)
- Normalize to unified schema
- Run formal analysis (SMT) to detect shadowing and conflicts
- Generate risk scores and hardening recommendations
- Provide a CLI and REST API scaffold for integration

## Quick Start

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Run CLI commands:
   ```bash
   python -m src.main parse --vendor paloalto --file sample_rules.txt
   python -m src.main analyze --vendor paloalto --file sample_rules.txt
   python -m src.main recommend --vendor paloalto --file sample_rules.txt --top 5 --threshold 70
  python -m src.main full-scan --vendor paloalto --file sample_rules.txt 
    python -m src.main full-scan --vendor paloalto --file panos-random-100rules.xml 
   ```

3. Run REST API server:
   ```bash
   uvicorn src.api:app --host 127.0.0.1 --port 8000
   ```

4. API usage:
   - Health check:
     ```bash
     curl http://127.0.0.1:8000/health
     ```
   - Analyze rules:
     ```bash
     curl -X POST http://127.0.0.1:8000/analyze -H "Content-Type: application/json" -d "{\"vendor\":\"paloalto\",\"rules\":[\"id:1|name:Allow-HTTP|from:internal|to:external|source:any|destination:any|application:web-browsing|service:tcp/80|action:allow\"]}"
     ```
   - Recommend hardening:
     ```bash
     curl -X POST "http://127.0.0.1:8000/recommend?top_n=5&threshold=70" -H "Content-Type: application/json" -d "{\"vendor\":\"paloalto\",\"rules\":[\"id:1|name:Allow-HTTP|from:internal|to:external|source:any|destination:any|application:web-browsing|service:tcp/80|action:allow\"]}"
     ```

## Project Roadmap (Next Handoff)

1. **Phase 6 - Productionization & integration**
   - Add full vendor parser modules for Check Point, Cisco ASA/FTD, Fortinet
   - Implement persistent storage (SQLite/PostgreSQL) for rules and analysis results
   - Add authentication/authorization for API endpoints
   - Add edge-case handling for rule condition overlaps and ranges

2. **Phase 7 - GUI / Dashboard**
   - Build a simple React/Vue UI to upload rule files and display compliance findings
   - Show interactive risk-scoring dashboards and rule hardening recommendations
   - Add export to PDF/CSV compliance report

3. **Phase 8 - Simulation + deployment automation**
   - Integrate with GNS3 or local simulation environment for generated policy tests
   - Add firewall syntax generation for vendor imports and verify on simulated traffic
   - Add CI pipeline tests for rule parser and analyzer regressions

4. **Phase 9 - LLM-assisted policy suggestions**
   - Add a secured LLM prompt service (OpenAI/Anthropic or local LLM)
   - Provide policy improvement suggestions as natural-language assistant
   - Add feedback loop to refine suggestions with user approvals

5. **Phase 10 - Security & compliance**
   - Add static analysis, logging, monitoring, and security audit integration
   - Add role-based access, data validation and strict schema enforcement
   - Document deployment architecture and runbook for production

## How to Contribute

1. Fork this repository and create a feature branch:
   ```bash
   git checkout -b feature/<your-feature>
   ```
2. Add tests for your changes and run the analyzer commands.
3. Keep changes modular: parser, normalizer, analysis, intent, and API layers.
4. Open a pull request with a short summary + validation steps.
5. Include new CLI commands or API contract docs in `README.md`.

### Local development checklist
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```
- Run CLI smoke tests:
  ```bash
  python -m src.main analyze --vendor paloalto --file sample_rules.txt
  ```
- Run API server and verify endpoints:
  ```bash
  uvicorn src.api:app --host 127.0.0.1 --port 8000
  ```
- Ensure formatting/linting before commit.

