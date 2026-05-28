#!/bin/bash
echo "============================================="
echo "   NGFW Suricata Simulation Teardown         "
echo "============================================="

echo "Tearing down containerized environment and custom networks..."
docker compose down

echo "Success! Teardown completed cleanly."
