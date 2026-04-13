import xml.etree.cElementTree as ET
from typing import List, Dict, Any
from ..schema import FirewallRule, Action


class PaloAltoParser:
    """Basic parser for simplified Palo Alto rule text and XML."""

    @staticmethod
    def parse_rule_line(line: str) -> FirewallRule:
        parts = [p.strip() for p in line.split("|") if p.strip()]
        fields: Dict[str, Any] = {
            "id": "",
            "vendor": "paloalto",
            "name": None,
            "source_zones": [],
            "destination_zones": [],
            "source_addresses": [],
            "destination_addresses": [],
            "application": None,
            "service": None,
            "action": Action.deny,
            "enabled": True,
            "logging": False,
            "metadata": {},
        }

        for part in parts:
            if part.startswith("name:"):
                fields["name"] = part.split(":", 1)[1]
            elif part.startswith("from:"):
                fields["source_zones"] = [z.strip() for z in part.split(":", 1)[1].split(",")]
            elif part.startswith("to:"):
                fields["destination_zones"] = [z.strip() for z in part.split(":", 1)[1].split(",")]
            elif part.startswith("source:"):
                fields["source_addresses"] = [a.strip() for a in part.split(":", 1)[1].split(",")]
            elif part.startswith("destination:"):
                fields["destination_addresses"] = [a.strip() for a in part.split(":", 1)[1].split(",")]
            elif part.startswith("application:"):
                fields["application"] = part.split(":", 1)[1]
            elif part.startswith("service:"):
                fields["service"] = part.split(":", 1)[1]
            elif part.startswith("action:"):
                fields["action"] = Action(part.split(":", 1)[1].lower())
            elif part.startswith("enabled:"):
                fields["enabled"] = part.split(":", 1)[1].lower() in ["true", "1", "yes", "on"]
            elif part.startswith("logging:"):
                fields["logging"] = part.split(":", 1)[1].lower() in ["true", "1", "yes", "on"]
            elif part.startswith("id:"):
                fields["id"] = part.split(":", 1)[1]

        if not fields["id"]:
            fields["id"] = f"pa-{fields.get('name','unnamed')}-{hash(line) % 10000}"

        return FirewallRule(**fields)

    @staticmethod
    def parse_from_text(text: str) -> List[FirewallRule]:
        rules = []
        for i, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                r = PaloAltoParser.parse_rule_line(line)
                rules.append(r)
            except Exception as e:
                raise ValueError(f"Error parsing line {i+1}: {e}")
        return rules

    @staticmethod
    def parse_from_xml(file_path: str) -> List[FirewallRule]:
        """Parses Palo Alto rules from an XML configuration file."""
        tree = ET.parse(file_path)
        root = tree.getroot()
        rules_reference = root.find(".//rules")
        
        rules = []
        rule_counter = 1
        
        if rules_reference is not None:
            for each_rule in rules_reference:
                name = each_rule.get("name")
                
                # Safe access helpers in case XML tags are empty/missing
                def safe_get_text(element, idx1, idx2=0, default="any"):
                    try:
                        text = element[idx1][idx2].text
                        return text if text else default
                    except (IndexError, TypeError, AttributeError):
                        return default

                source_zone = safe_get_text(each_rule, 0)
                destination_zone = safe_get_text(each_rule, 1)
                source_device = safe_get_text(each_rule, 2)
                destination_device = safe_get_text(each_rule, 3)
                application = safe_get_text(each_rule, 4)
                service = safe_get_text(each_rule, 5) # <-- Added extraction for service at index 5
                
                try:
                    action_text = each_rule[6].text.lower()
                except (IndexError, AttributeError):
                    action_text = "deny"
                
                action = Action.allow if "allow" in action_text else Action.deny

                rule = FirewallRule(
                    id=f"pa-{name}-{rule_counter}",
                    vendor="paloalto",
                    name=name,
                    source_zones=[source_zone],
                    destination_zones=[destination_zone],
                    source_addresses=[source_device],
                    destination_addresses=[destination_device],
                    application=application,
                    service=service,         # <-- Now successfully passing service to Pydantic
                    action=action,
                    enabled=True
                )
                rules.append(rule)
                rule_counter += 1
                
        return rules