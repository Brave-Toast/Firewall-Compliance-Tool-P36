from typing import List
from ..schema import FirewallRule
from .base import BaseFirewallParser

class CheckPointParser(BaseFirewallParser):
    """Stub parser for CheckPoint configurations."""

    @classmethod
    def parse_from_text(cls, text: str) -> List[FirewallRule]:
        """Parses CheckPoint rules from a raw text configuration."""
        return []

    @classmethod
    def parse_from_xml(cls, file_path: str) -> List[FirewallRule]:
        """Parses CheckPoint rules from an XML configuration file."""
        return []
