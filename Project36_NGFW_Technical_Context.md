# NGFW Simulation Environment: Technical Context Document

## 1. Architecture Overview
This document outlines the containerized Next-Generation Firewall (NGFW) simulation environment. It is designed to act as a local testing ground for Project 36, allowing the team (including Muhammad, Josh, Qasim, James, Syed Ali, and Junkai) to validate the vendor-agnostic firewall policy normalization and SBOM automation pipeline.

The environment simulates a three-tier network architecture using Docker, routing traffic from an external client through a Suricata-based inline firewall into a DMZ web server.

## 2. Network Topology & Container Specifications

The simulation relies on `docker-compose.yml` to define the network boundaries and container capabilities.

### 2.1 Networks
* **external_net**: Bridge network representing the WAN/External zone. Subnet: `10.0.1.0/24`.
* **dmz_net**: Bridge network representing the isolated DMZ zone. Subnet: `10.0.50.0/24`.

### 2.2 Services (Containers)
1.  **ngfw_suricata** (`jasonish/suricata:latest`):
    * **Role**: The core inline IPS/NGFW.
    * **Capabilities**: Requires `NET_ADMIN`, `SYS_NICE`, `NET_RAW` and runs as root (`user: "0:0"`) to interface with `NFQUEUE` for active packet interception.
    * **Networking**: Attached to both `external_net` and `dmz_net`. Acts as the gateway router between the two. `net.ipv4.ip_forward=1` is enabled.
2.  **web_server** (`nginx:alpine`):
    * **Role**: The target HTTP server in the DMZ.
    * **Networking**: Attached only to `dmz_net`.
3.  **client** (`alpine`):
    * **Role**: The external attacker/tester.
    * **Networking**: Attached only to `external_net`.

## 3. Traffic Interception & IPS Implementation

The firewall operates in inline IPS mode rather than passive IDS mode. This is achieved via `NFQUEUE`.

* **Routing Interception**: The setup scripts execute `iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass` within the `ngfw_suricata` container. This forces all traffic attempting to route *through* the container to be sent to Suricata's inspection engine before being forwarded.
* **Bidirectional Routing**: Because Docker isolates bridge networks, explicit static routes are injected post-deployment. The `client` is taught to reach `10.0.50.0/24` via the firewall's external IP interface, and the `web_server` is taught to reach `10.0.1.0/24` via the firewall's DMZ IP interface.

## 4. Rule Injection Pipeline

Suricata rules are defined locally and injected dynamically at runtime to support rapid testing of the firewall compliance tool's outputs.

### 4.1 Base Ruleset (`local.rules.txt`)
The baseline demonstrates both Layer 3 and Layer 7 deep packet inspection:
* **Layer 3 Drop**: Blocks all ICMP ping traffic from any source to any destination (`sid:1000001`).
* **Layer 7 Drop**: Blocks HTTP requests attempting to access the `/admin` URI path (`sid:1000002`).
* **Default Action**: Traffic not explicitly matching a `drop` rule is passed by default.

### 4.2 Orchestration Automation (`start_demo.ps1`)
The PowerShell script serves as the primary orchestrator for the simulation lifecycle:
1.  **Teardown**: Executes `docker compose down` to ensure a clean state.
2.  **Provisioning**: Brings up the containers in detached mode.
3.  **Dependency Injection**: Installs `iptables` natively inside the Suricata container.
4.  **Rule Compilation**: Takes the ruleset as a PowerShell Here-String, cleans carriage returns (`tr -d ''`), and writes them directly into Suricata's active rule directories (`/var/lib/suricata/rules/suricata.rules` and `/etc/suricata/suricata.rules`).
5.  **Hot Reload**: Executes `suricatasc -c reload-rules` to apply the injected rules without restarting the container.
6.  **Routing Configuration**: Dynamically extracts the assigned Docker IPs via `docker inspect` and maps the static routes for the `client` and `web_server`.

## 5. Teardown Protocol (`stop_demo.ps1`)
Executes a graceful shutdown via `docker compose down` to destroy the network interfaces, routing tables, and containers, ensuring no persistent state interferes with subsequent test runs.

## 6. Antigravity IDE Integration Directives
*For the AI Agent extending this pipeline:*
1.  **Rule Generation Hook**: When generating vendor-agnostic rules, the output formatter must target the Here-String `$SuricataRules` inside `start_demo.ps1` for automated testing.
2.  **SBOM Mapping**: Ensure any dependencies required for translating normalized rules into Suricata syntax are logged in the project's active SBOM pipeline.
3.  **Testing Automation**: Use the validation commands provided at the end of `start_demo.ps1` (e.g., `docker exec -it ext_client wget --timeout=3 -qO- http://$WEB_IP/admin`) as assertions in the test suite to verify rule deployment success.
