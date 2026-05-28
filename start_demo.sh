#!/bin/bash
set -e

RULESET_PATH=""
if [ "$1" != "" ]; then
    RULESET_PATH="$1"
fi

echo "============================================="
echo "   NGFW Suricata Simulation Orchestrator     "
echo "============================================="

# 1. Teardown existing containers
echo "Step 1: Destroying existing simulation containers..."
docker compose down

# 2. Provision new containers
echo "Step 2: Starting new simulation containers..."
docker compose up -d

# Wait for container initialization
echo "Waiting for containers to initialize (5s)..."
sleep 5

# 3. Verify containers are running
CONTAINERS=$(docker ps --format "{{.Names}}")
if [[ ! "$CONTAINERS" =~ "ngfw_suricata" ]] || [[ ! "$CONTAINERS" =~ "ext_client" ]] || [[ ! "$CONTAINERS" =~ "web_server" ]]; then
    echo "Error: Core containers failed to start. Please check 'docker compose ps'."
    exit 1
fi

# 4. Dependency Injection inside Suricata container
echo "Step 3: Installing iptables inside ngfw_suricata container..."
docker exec ngfw_suricata dnf install -y iptables
docker exec ngfw_suricata mkdir -p /var/lib/suricata/rules

# 5. Interception Configuration (NFQUEUE)
echo "Step 4: Injecting inline packet interception (NFQUEUE)..."
docker exec ngfw_suricata iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

# 6. Bidirectional Routing Injection
echo "Step 5: Injecting static routes for zone boundary simulation..."
# Client route to reach DMZ zone (10.0.50.0/24) via NGFW external IP (10.0.1.5)
docker exec ext_client ip route del 10.0.50.0/24 2>/dev/null || true
docker exec ext_client ip route add 10.0.50.0/24 via 10.0.1.5

# Web Server route to reach External zone (10.0.1.0/24) via NGFW DMZ IP (10.0.50.5)
docker exec web_server ip route del 10.0.1.0/24 2>/dev/null || true
docker exec web_server ip route add 10.0.1.0/24 via 10.0.50.5

# 7. Ruleset Injection Pipeline
echo "Step 6: Rule compilation and injection..."
mkdir -p reports

ACTIVE_RULES_PATH="reports/active_suricata.rules"

if [ -n "$RULESET_PATH" ] && [ -f "$RULESET_PATH" ]; then
    echo "Compiling premade ruleset: $RULESET_PATH ..."
    # Use compliance tool CLI to parse, normalize, Z3-optimize, and translate
    python3 -m src.main compile --file "$RULESET_PATH" --output "$ACTIVE_RULES_PATH"
else
    echo "No premade ruleset specified or file not found. Deploying default baseline..."
    # Write default baseline rules
    cat << 'EOF' > "$ACTIVE_RULES_PATH"
drop icmp any any -> any any (msg:"Block ICMP ping"; sid:1000001; rev:1;)
drop tcp any any -> any 80 (msg:"Block HTTP /admin"; content:"/admin"; http_uri; sid:1000002; rev:1;)
EOF
    # Remove carriage returns
    sed -i 's/\r$//' "$ACTIVE_RULES_PATH" || true
fi

# Copy rules into Suricata container
docker cp "$ACTIVE_RULES_PATH" ngfw_suricata:/var/lib/suricata/rules/suricata.rules
docker cp "$ACTIVE_RULES_PATH" ngfw_suricata:/etc/suricata/suricata.rules

# 8. Hot Reload Suricata rules
echo "Step 7: Hot reloading Suricata engine ruleset..."
docker exec ngfw_suricata suricatasc -c reload-rules

echo ""
echo "============================================="
echo "   Simulation Setup Completed Successfully   "
echo "============================================="
echo "Useful Validation Commands:"
echo "1. Test ICMP Ping (should be blocked by default):"
echo "   docker exec ext_client ping -c 3 -W 2 10.0.50.10"
echo "2. Test standard Web HTTP (should succeed):"
echo "   docker exec ext_client wget -qO- --timeout=3 http://10.0.50.10/"
echo "3. Test Web HTTP /admin block (should time out/fail):"
echo "   docker exec ext_client wget -qO- --timeout=3 http://10.0.50.10/admin"
