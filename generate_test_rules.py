#!/usr/bin/env python3
"""Script to generate a synthetic ruleset of 100 firewall rules for the simulated network.

This script generates a file containing 100 rules in the mock Palo Alto text format.
It specifically targets the containerized network topology (External client at 10.0.1.10, 
DMZ Web Server at 10.0.50.10) and injects intentional redundancies, shadowing, and 
collision anomalies to allow thorough testing of the Z3 SMT compliance pipeline.
"""

import os
import uuid
import random

# Target file to output the rules
OUTPUT_FILE = "custom_test_rules.txt"

# Defined zones and networks for this simulated environment
ZONES = ["External", "DMZ", "Internal"]
CLIENT_IP = "10.0.1.10/32"
CLIENT_NET = "10.0.1.0/24"
WEB_SERVER_IP = "10.0.50.10/32"
DMZ_NET = "10.0.50.0/24"
INTERNAL_NET = "192.168.1.0/24"

APPLICATIONS = ["web-browsing", "ssl", "ssh", "ping", "smb", "dns", "rdp", "any"]
SERVICES = {
    "web-browsing": "tcp/80",
    "ssl": "tcp/443",
    "ssh": "tcp/22",
    "ping": "icmp/any",
    "smb": "tcp/445",
    "dns": "udp/53",
    "rdp": "tcp/3389",
    "any": "tcp/any"
}

def generate_random_ip():
    """Generates a random public or internal IP for broad coverage."""
    prefix = random.choice(["192.168.2.", "172.16.5.", "8.8.", "45.67.", "198.51.100."])
    host = random.randint(1, 254)
    mask = random.choice(["/32", "/24"])
    return f"{prefix}{host}{mask}"

def create_rule_line(rule_id, name, from_zone, to_zone, source, destination, app, service, action):
    """Formats attributes into a single line conforming to the parser schema."""
    return f"id:{rule_id}|name:{name}|from:{from_zone}|to:{to_zone}|source:{source}|destination:{destination}|application:{app}|service:{service}|action:{action}"

def main():
    print("=============================================")
    print("   Firewall Rule Generator for Simulation     ")
    print("=============================================")
    
    rules = []
    
    # 1. Generate core standard rules (about 60 rules)
    print("Generating baseline standard rules...")
    for i in range(1, 61):
        rule_id = str(uuid.uuid4())
        name = f"Core-Rule-{i}"
        
        # Select zones
        from_z = random.choice(ZONES)
        to_z = random.choice([z for z in ZONES if z != from_z])
        
        # Tailor IPs based on zone
        if from_z == "External":
            src = random.choice([CLIENT_IP, CLIENT_NET, "any", generate_random_ip()])
        elif from_z == "Internal":
            src = random.choice([INTERNAL_NET, "any", generate_random_ip()])
        else:
            src = random.choice([DMZ_NET, "any"])
            
        if to_z == "DMZ":
            dst = random.choice([WEB_SERVER_IP, DMZ_NET, "any"])
        elif to_z == "Internal":
            dst = random.choice([INTERNAL_NET, "any", generate_random_ip()])
        else:
            dst = random.choice(["any", generate_random_ip()])
            
        app = random.choice(APPLICATIONS)
        svc = SERVICES[app]
        action = random.choice(["allow", "deny"])
        
        rules.append({
            "id": rule_id, "name": name, "from": from_z, "to": to_z, 
            "source": src, "destination": dst, "app": app, "svc": svc, "action": action
        })

    # 2. Inject intentional Redundancies (about 15 rules)
    # Redundancy: A rule placed BELOW another rule that is identical or a broader subset with the same action
    print("Injecting mathematical redundancies...")
    redundancy_count = 0
    while redundancy_count < 15:
        # Choose a target core rule to copy/subset
        parent = random.choice(rules[:50])
        
        rule_id = str(uuid.uuid4())
        name = f"Redundant-Rule-{redundancy_count + 1}-Subset-of-{parent['name']}"
        
        # Make a subset of the source/destination IPs or keep it identical
        if "/24" in parent["source"]:
            # e.g., if parent is 10.0.1.0/24, subset is 10.0.1.10/32
            base_ip = parent["source"].split(".")[0:3]
            src = f"{'.'.join(base_ip)}.10/32"
        else:
            src = parent["source"]
            
        if "/24" in parent["destination"]:
            base_ip = parent["destination"].split(".")[0:3]
            dst = f"{'.'.join(base_ip)}.10/32"
        else:
            dst = parent["destination"]
            
        # Ensure identical actions and parameters
        rules.append({
            "id": rule_id, "name": name, "from": parent["from"], "to": parent["to"], 
            "source": src, "destination": dst, "app": parent["app"], "svc": parent["svc"], "action": parent["action"]
        })
        redundancy_count += 1

    # 3. Inject intentional Shadowing (about 15 rules)
    # Shadowing: A rule placed BELOW a broader rule with a DIFFERENT action (so it can never be reached)
    print("Injecting mathematical shadowing conflicts...")
    shadow_count = 0
    while shadow_count < 15:
        parent = random.choice(rules[:50])
        
        rule_id = str(uuid.uuid4())
        name = f"Shadowed-Rule-{shadow_count + 1}-Blocked-by-{parent['name']}"
        
        # Opposite action to create a conflict
        opp_action = "deny" if parent["action"] == "allow" else "allow"
        
        # Must be a subset so it's fully covered
        if parent["source"] == "any":
            src = random.choice([CLIENT_IP, INTERNAL_NET, generate_random_ip()])
        else:
            src = parent["source"]
            
        if parent["destination"] == "any":
            dst = random.choice([WEB_SERVER_IP, DMZ_NET, generate_random_ip()])
        else:
            dst = parent["destination"]
            
        rules.append({
            "id": rule_id, "name": name, "from": parent["from"], "to": parent["to"], 
            "source": src, "destination": dst, "app": parent["app"], "svc": parent["svc"], "action": opp_action
        })
        shadow_count += 1

    # 4. Inject intentional Collisions (about 10 rules)
    # Collision: Identical match criteria, but opposite actions
    print("Injecting policy collisions...")
    collision_count = 0
    while collision_count < 10:
        parent = random.choice(rules[:50])
        
        rule_id = str(uuid.uuid4())
        name = f"Collision-Rule-{collision_count + 1}-Opposes-{parent['name']}"
        
        opp_action = "deny" if parent["action"] == "allow" else "allow"
        
        rules.append({
            "id": rule_id, "name": name, "from": parent["from"], "to": parent["to"], 
            "source": parent["source"], "destination": parent["destination"], 
            "app": parent["app"], "svc": parent["svc"], "action": opp_action
        })
        collision_count += 1

    # Shuffle the latter half slightly so anomalies are distributed
    anomalies = rules[60:]
    random.shuffle(anomalies)
    final_rules = rules[:60] + anomalies
    
    # Trim to exactly 100 rules if needed (should already be exactly 100)
    final_rules = final_rules[:100]

    # Write rules to output file
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for rule in final_rules:
                rule_str = create_rule_line(
                    rule["id"], rule["name"], rule["from"], rule["to"],
                    rule["source"], rule["destination"], rule["app"], rule["svc"], rule["action"]
                )
                f.write(rule_str + "\n")
                
        print("\n=============================================")
        print("   Ruleset Generation Complete!               ")
        print("=============================================")
        print(f"Successfully generated 100 custom rules in: {OUTPUT_FILE}")
        print("\nBreakdown of rules generated:")
        print("  - Core standard rules: 60")
        print("  - Intentional Z3 Redundancies injected: 15")
        print("  - Intentional Z3 Shadowing conflicts injected: 15")
        print("  - Intentional Policy Collisions injected: 10")
        print("\nTarget Networks Covered:")
        print(f"  - External Client: {CLIENT_IP} on network {CLIENT_NET}")
        print(f"  - DMZ Web Server: {WEB_SERVER_IP} on network {DMZ_NET}")
        print(f"  - Internal Network: {INTERNAL_NET}")
        print("\nHow to test this ruleset:")
        print(f"  1. Start the simulation environment using this ruleset:")
        print(f"     .\\start_demo.ps1 -RulesetPath {OUTPUT_FILE}")
        print("  2. Run the Intake command to parse and upload them:")
        print("     python -m src.main intake")
        print("  3. Run the Deploy command to see Z3 prune the 40 injected anomalies:")
        print("     python -m src.main deploy")
        
    except Exception as e:
        print(f"Error writing to file {OUTPUT_FILE}: {e}")

if __name__ == "__main__":
    main()
