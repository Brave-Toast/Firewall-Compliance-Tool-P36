# Simulated NGFW Simulation & Compliance Optimization: Step-by-Step Testing Guide

This guide explains how to use the Firewall Compliance Analyzer to set up a containerized next-generation firewall simulation, perform mathematical compliance auditing, prune logical policy issues, and push an optimized ruleset back to a live Suricata engine.

---

## 1. Prerequisites

1. **Docker Desktop**: Must be active on your host system.
2. **Python 3.9+**: Ensure Python is available and your virtual environment is active:
   ```powershell
   # Activate virtual environment (PowerShell)
   .\.venv\Scripts\activate
   ```
3. **Pip Dependencies**: Confirm all packages are installed:
   ```powershell
   pip install -r requirements.txt
   ```

---

## 2. Infrastructure Setup (Simulated Network Topology)

The orchestration script spins up a three-tier containerized network boundary:
* **`ext_client` (Alpine)**: External attacker/testing client.
* **`ngfw_suricata` (Suricata)**: The core inline firewall running inside AlmaLinux 9.
* **`web_server` (Nginx)**: Secure HTTP server sitting in the isolated DMZ zone.

### Option A: Run Setup with Custom Ruleset (Recommended)
This compiles and optimizes your Palo Alto rules file (`sample_rules.txt`) into Suricata format and loads it automatically upon startup:
```powershell
.\start_demo.ps1 -RulesetPath sample_rules.txt
```

### Option B: Run Setup with Baseline Ruleset
This sets up the network and injects the baseline ruleset (blocks pings and `/admin` requests) directly:
```powershell
.\start_demo.ps1
```

*Note: The script automatically installs required dependencies inside the container, configures packet routing via `NFQUEUE` redirection, injects bidirectional static routes, and hot-reloads Suricata rules.*

---

## 3. Run the Sidecar REST APIs

To execute the intake and deploy loops, both API servers must be running. Open two separate PowerShell terminal windows (ensure both have `.venv` active):

### Window 1: Start the simulated Firewall REST API
This mimics the management engine of a hardware NGFW device:
```powershell
python -m src.firewall_api
```
*Port: `http://127.0.0.1:8001`*

### Window 2: Start the Compliance Engine REST API
This runs the core Z3 SMT mathematical optimization and framework compliance engine:
```powershell
uvicorn src.api:app --host 127.0.0.1 --port 8000
```
*Port: `http://127.0.0.1:8000`*

---

## 4. Run the Intake and Deploy Loops

Now, in a third terminal window, you can run the automated pipeline via the CLI:

### Step 4.1: The Intake Phase
Connect to the firewall's REST API, pull down the active configuration, normalize it, and save it to the SQLite database:
```powershell
python -m src.main intake --firewall-url http://127.0.0.1:8001/api/v1/rules
```
*Expected Output: `Success! Pulled, normalized, and saved 101 rules from firewall REST API into local database.`*

### Step 4.2: The Optimization & Deployment Phase
Retrieve rules from the database, run the **Z3 SMT Solver** to mathematically check for overlaps, redundancies, shadowing, and collisions, **prune** all logically incorrect rules, and push the optimized ruleset back to Suricata:
```powershell
python -m src.main deploy --firewall-url http://127.0.0.1:8001/api/v1/rules
```
*Expected Output: Original rule list reduces (e.g. from `101` down to `42` optimized rules, pruning `69` redundant/shadowed rules) and pushes successfully.*
```text
Original Rules: 101 | Optimized Rules: 42 | Pruned: 69
Pushing optimized ruleset to firewall at http://127.0.0.1:8001/api/v1/rules ...
Firewall REST API Response:
{
  "status": "success",
  "message": "Rules deployed and Suricata reloaded successfully.",
  "rules_deployed": 42,
  "mode": "live"
}
Success! Optimized ruleset deployed successfully.
```

---

## 5. Traffic Enforcement Verification

To verify that Suricata is actively intercepting and filtering traffic inline, execute these diagnostic commands on the `ext_client` container:

### Test 1: Layer 3 ICMP Ping Block
* **Action**: Ping the DMZ web server from the client:
  ```powershell
  docker exec ext_client ping -c 3 -W 2 10.0.50.10
   ```
* **Expected Result (with Baseline Active)**: **100% packet loss** (intercepted and dropped).
* **Expected Result (with sample_rules.txt)**: Success (allowed, as `sample_rules.txt` does not block pings).

### Test 2: Standard HTTP Web Server access
* **Action**: Curl/wget the web server homepage:
  ```powershell
  docker exec ext_client wget -qO- --timeout=3 http://10.0.50.10/
  ```
* **Expected Result**: **Success** (returns the default welcome page of Nginx, showing normal traffic passes).

### Test 3: Layer 7 Deep Packet URI Block
* **Action**: Attempt to access the restricted `/admin` URI:
  ```powershell
  docker exec ext_client wget -qO- --timeout=3 http://10.0.50.10/admin
  ```
* **Expected Result**: **Connection Timed Out** (Suricata deep packet inspection successfully flags the payload and drops the stream).

---

## 6. Standalone Compliance Auditing (Offline Reporting)

To run a scan offline, mathematically inspect a configuration file, perform **MITRE ATT&CK, NIST, CIS, and ISO 27001** framework mappings, and save a structured JSON report:
```powershell
python -m src.main full-scan --vendor paloalto --file panos-random-100rules.xml
```
Open the generated report under the `reports/` folder (e.g., `reports/scan_report_*.json`) to inspect:
- **`comprehensive_analysis_issues`**: SMT-based zone path violations.
- **`basic_anomaly_issues`**: SMT-computed shadowed, redundant, and conflicting rules.
- **`intent_analysis`**: Vulnerability framework controls mapping and suggestions.
- **`hardening_plan`**: Risk-prioritized rule tuning guides.

---

## 7. Graceful Teardown
To shut down containers, remove network bounds, and destroy static routing tables when testing is complete:
```powershell
.\stop_demo.ps1
```

---

## 8. Fully Automated End-to-End Demonstration (One Command)

We have created an automated demonstration orchestrator script that runs the **entire pipeline lifecycle in a single command**. It will:
1. Tear down any existing container environments and clean up orphan background ports.
2. Generate a new randomized ruleset of 100 rules with 40 active mathematical anomalies (`custom_test_rules.txt`).
3. Boot up the multi-container network simulation and dependency layer.
4. Launch the background API servers on ports `8000` and `8001`, and poll them until fully online.
5. Execute the **Intake** phase (fetching raw policies into the DB).
6. Run the **Z3 SMT Optimization** phase, pruning the 40 logical anomalies, compiling the 60 clean rules, and deploying them to Suricata.
7. Run the inline network diagnostic suite (ICMP Ping, Nginx bypass, `/admin` interception).
8. Run a comprehensive standalone scan, mapping rules against **MITRE ATT&CK, NIST, CIS, and ISO 27001**.
9. Output a master JSON report specifically aggregated for frontend **React/Vue dashboards** to `Test Reports/master_demo_report.json`.
10. Automatically stop background servers and gracefully tear down the Docker environment.

### Run on Windows (PowerShell):
```powershell
.\run_full_demo.ps1
```

### Run on Linux / macOS (Bash):
```bash
chmod +x run_full_demo.sh
./run_full_demo.sh
```

### Generated Dashboard Assets:
After execution, check the **`Test Reports`** directory:
* **`Test Reports/master_demo_report.json`**: Master log containing execution step timestamps, pruned rules lists, original vs. optimized rule metrics, and traffic validation logs.
* **`Test Reports/scan_report_*.json`**: Deep framework mappings (MITRE/NIST/CIS/ISO) and risk score prioritization plans.

