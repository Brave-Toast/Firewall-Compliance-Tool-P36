from typing import Type
from .base import BaseFirewallParser
from .paloalto import PaloAltoParser
from .cisco import CiscoASAParser
from .checkpoint import CheckPointParser
from .suricata import SuricataParser


def get_parser(vendor: str) -> Type[BaseFirewallParser]:
    """Factory function to retrieve the appropriate parser by vendor name."""
    v = vendor.lower().replace(" ", "").replace("-", "")
    if v == "paloalto":
        return PaloAltoParser
    elif v in ["cisco", "ciscoasa"]:
        return CiscoASAParser
    elif v == "checkpoint":
        return CheckPointParser
    elif v in ["suricata"]:
        return SuricataParser
    else:
        raise ValueError(f"Unsupported vendor: {vendor}")
