"""Module to translate normalized firewall rules into Suricata rules."""

import hashlib
from typing import List, Dict, Any, Tuple
from .schema import FirewallRule, Action

def generate_sid(rule_id: str) -> int:
    """Generates a stable, unique 7-digit SID for a given rule ID."""
    # Deterministic hashing of the rule ID to produce a stable integer
    hash_obj = hashlib.sha256(rule_id.encode('utf-8'))
    int_hash = int(hash_obj.hexdigest(), 16)
    # Range: 1000100 to 9999999 (avoiding baseline SIDs 1000001 and 1000002)
    return 1000100 + (int_hash % 8999800)

def parse_service_field(service_str: str) -> Tuple[str, str]:
    """Parses a service string like 'tcp/80, 443' or 'udp/53' into (protocol, ports).
    
    Returns (protocol, ports_str). Default is ('ip', 'any').
    """
    if not service_str:
        return "ip", "any"
    
    s = service_str.strip().lower()
    if "/" not in s:
        # Check if it is a port number directly (assume tcp by default)
        if s.isdigit() or "," in s:
            return "tcp", s
        return "ip", "any"
    
    parts = s.split("/", 1)
    proto = parts[0].strip()
    ports = parts[1].strip()
    
    # Standardize protocol
    if proto not in ["tcp", "udp", "icmp", "ip"]:
        proto = "ip"
        
    # Standardize ports
    if not ports or ports == "any":
        ports = "any"
    elif "," in ports:
        # Strip spaces and wrap in brackets
        ports_list = [p.strip() for p in ports.split(",") if p.strip()]
        ports = f"[{','.join(ports_list)}]"
        
    return proto, ports

def infer_protocol_and_ports(rule: FirewallRule) -> Tuple[str, str]:
    """Infers the protocol and destination ports based on the rule's service and application."""
    # 1. Try parsing from the service field
    if rule.service and rule.service.lower() != "any":
        return parse_service_field(rule.service)
    
    # 2. Try parsing from the application field
    app = rule.application.strip().lower() if rule.application else ""
    if not app or app == "any":
        return "ip", "any"
    
    # Map common application names to protocol and ports
    app_mappings = {
        "web-browsing": ("tcp", "[80,443]"),
        "ssl": ("tcp", "443"),
        "web": ("tcp", "80"),
        "ssh": ("tcp", "22"),
        "rdp": ("tcp", "3389"),
        "dns": ("udp", "53"),
        "smb": ("tcp", "445"),
        "ping": ("icmp", "any"),
        "icmp": ("icmp", "any"),
    }
    
    if app in app_mappings:
        return app_mappings[app]
    
    # If the app name is a number, treat it as a port
    if app.isdigit():
        return "tcp", app
        
    return "ip", "any"

def format_addresses(addresses: List[str]) -> str:
    """Formats a list of IP addresses into Suricata syntax."""
    if not addresses:
        return "any"
    
    # Clean addresses
    cleaned = []
    for addr in addresses:
        addr = addr.strip().lower()
        if not addr or addr == "any":
            return "any"
        cleaned.append(addr)
        
    if len(cleaned) == 1:
        return cleaned[0]
    
    return f"[{','.join(cleaned)}]"

def translate_to_suricata(rule: FirewallRule) -> str:
    """Translates a single normalized FirewallRule to a Suricata rule string.
    
    Converts action:
      - allow -> pass
      - deny -> drop
    """
    # 1. Translate action
    action = "pass" if rule.action == Action.allow else "drop"
    
    # 2. Infer protocol and destination ports
    proto, dst_ports = infer_protocol_and_ports(rule)
    
    # 3. Format source and destination addresses
    src_addrs = format_addresses(rule.source_addresses)
    dst_addrs = format_addresses(rule.destination_addresses)
    
    # 4. Generate stable unique SID
    sid = generate_sid(rule.id)
    
    # 5. Extract metadata/options
    msg_name = rule.name if rule.name else rule.id
    options = [f'msg:"{msg_name}"']
    
    # Special Layer 7 check for HTTP URI path targeting "/admin"
    is_admin_rule = False
    if rule.application and "admin" in rule.application.lower():
        is_admin_rule = True
    elif rule.name and "admin" in rule.name.lower():
        is_admin_rule = True
        
    if is_admin_rule and proto == "tcp" and dst_ports in ["80", "443", "[80,443]", "any"]:
        # Inline HTTP inspect rule
        options.append('content:"/admin"')
        options.append('http_uri')
        
    options.append(f"sid:{sid}")
    options.append("rev:1")
    
    options_str = "; ".join(options) + ";"
    
    # Format of Suricata rule:
    # action protocol src_ip src_port -> dst_ip dst_port (options)
    suricata_rule = f"{action} {proto} {src_addrs} any -> {dst_addrs} {dst_ports} ({options_str})"
    return suricata_rule

def translate_ruleset_to_suricata(rules: List[FirewallRule]) -> List[str]:
    """Translates a list of FirewallRule objects to a list of Suricata rules."""
    suricata_rules = []
    for rule in rules:
        if not rule.enabled:
            continue
        try:
            suricata_rule = translate_to_suricata(rule)
            suricata_rules.append(suricata_rule)
        except Exception as e:
            # Silently skip/log malformed translations for robustness
            print(f"Skipping rule {rule.id} translation due to error: {e}")
    return suricata_rules
