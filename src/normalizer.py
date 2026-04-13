from typing import List
from .schema import FirewallRule


def normalize_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    normalized = []
    for r in rules:
        r.source_zones = [zone.strip().lower() for zone in r.source_zones if zone.strip()]
        r.destination_zones = [zone.strip().lower() for zone in r.destination_zones if zone.strip()]
        r.source_addresses = [addr.strip().lower() for addr in r.source_addresses if addr.strip()]
        r.destination_addresses = [addr.strip().lower() for addr in r.destination_addresses if addr.strip()]
        if not r.name:
            r.name = r.id
        normalized.append(r)
    return normalized
