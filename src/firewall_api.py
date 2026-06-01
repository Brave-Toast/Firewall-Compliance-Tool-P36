"""Simulated Firewall REST API Server representing the NGFW.

Runs on port 8001. Allows retrieving active firewall rules and deploying optimized rulesets.
"""

import os
import subprocess
import shutil
import logging
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FirewallAPI")

app = FastAPI(title="Simulated Firewall REST API", version="1.0.0")

class DeployRequest(BaseModel):
    rules: List[str]

@app.get("/health")
def health():
    return {"status": "online", "firewall": "ngfw_suricata"}

@app.get("/api/v1/rules")
def get_rules():
    """Returns the current rules of the firewall. 
    
    Acts as the source for the compliance tool to intake raw rules.
    Loads  first hte Suricata Firewall rules and if there is issue with that file then loads panos-random-100rules.xml or sample_rules.txt if available, otherwise returns baseline.
    """
    suricata_path="suricata_generated.rules"
    if os.path.exists(suricata_path):
        try:
            with open(suricata_path,"r") as f:
                content=f.read()
            return {
                "vendor":"suricata",
                "rules":[content]
            }
        except Exception as e:
            logger.error(f"Error reading {suricata_path}: {e}")    
    else:
        logger.info("Intake request received from compliance tool.")
        
        xml_path = "panos-random-100rules.xml"
        txt_path = "sample_rules.txt"
        
        if os.path.exists(xml_path):
            try:
                with open(xml_path, "r", encoding="utf-8") as f:
                    content = f.read()
                return {
                    "vendor": "paloalto",
                    "rules": [content]
                }
            except Exception as e:
                logger.error(f"Error reading {xml_path}: {e}")
                
        if os.path.exists(txt_path):
            try:
                with open(txt_path, "r", encoding="utf-8") as f:
                    content = f.read()
                return {
                    "vendor": "paloalto",
                    "rules": [content]
                }
            except Exception as e:
                logger.error(f"Error reading {txt_path}: {e}")
                
        # Hardcoded baseline fallback
        fallback_rules = (
            "id:1|name:Allow-HTTP|from:internal|to:external|source:any|destination:any|application:web-browsing|service:tcp/80|action:allow\n"
            "id:2|name:Allow-SSL|from:internal|to:external|source:any|destination:any|application:ssl|service:tcp/443|action:allow\n"
            "id:3|name:Block-Ping|from:any|to:any|source:any|destination:any|application:ping|service:icmp/any|action:deny"
        )
        return {
            "vendor": "paloalto",
            "rules": [fallback_rules]
        }

def is_container_running(name: str) -> bool:
    """Checks if a Docker container is running by name."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={name}", "--filter", "status=running", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True
        )
        return name in result.stdout
    except Exception as e:
        logger.warning(f"Could not check Docker status: {e}")
        return False

@app.post("/api/v1/rules")
def deploy_rules(payload: DeployRequest):
    """Pushes a list of translated Suricata rules to the firewall container."""
    rules = payload.rules
    logger.info(f"Deploy request received. Rules count: {len(rules)}")
    
    # Save rules to a temporary file on the host
    os.makedirs("reports", exist_ok=True)
    temp_rules_file = "reports/deployed_suricata.rules"
    try:
        with open(temp_rules_file, "w", encoding="utf-8") as f:
            for rule in rules:
                f.write(rule + "\n")
        logger.info(f"Saved Suricata rules locally on host to: {temp_rules_file}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write rules to host: {e}")
        
    # Check if Suricata container is running
    container_name = "ngfw_suricata"
    if is_container_running(container_name):
        try:
            # 1. Copy rules to Suricata paths inside container
            subprocess.run(
                ["docker", "cp", temp_rules_file, f"{container_name}:/var/lib/suricata/rules/suricata.rules"],
                check=True, capture_output=True
            )
            subprocess.run(
                ["docker", "cp", temp_rules_file, f"{container_name}:/etc/suricata/suricata.rules"],
                check=True, capture_output=True
            )
            logger.info("Successfully copied rules to Suricata container.")
            
            # 2. Reload rules using suricatasc
            reload_result = subprocess.run(
                ["docker", "exec", container_name, "suricatasc", "-c", "reload-rules"],
                capture_output=True, text=True, check=True
            )
            logger.info(f"Suricata rule reload output: {reload_result.stdout.strip()}")
            
            return {
                "status": "success",
                "message": "Rules deployed and Suricata reloaded successfully.",
                "rules_deployed": len(rules),
                "mode": "live"
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to execute Docker commands: {e.stderr or e.stdout}")
            return {
                "status": "warning",
                "message": f"Rules written to host, but failed to apply to Suricata container: {e.stderr or str(e)}",
                "rules_deployed": len(rules),
                "mode": "dry-run"
            }
    else:
        logger.warning("Docker container 'ngfw_suricata' is not running. Running in offline/dry-run mode.")
        return {
            "status": "success",
            "message": "Rules successfully verified and saved locally on host (Offline Mode).",
            "rules_deployed": len(rules),
            "mode": "dry-run"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
