from abc import ABC, abstractmethod
from typing import List
from ..schema import FirewallRule

class BaseFirewallParser(ABC):
    """Abstract base class for all firewall vendor parsers."""

    @classmethod
    @abstractmethod
    def parse_from_text(cls, text: str) -> List[FirewallRule]:
        """Parses firewall rules from a raw text configuration."""
        pass

    @classmethod
    @abstractmethod
    def parse_from_xml(cls, file_path: str) -> List[FirewallRule]:
        """Parses firewall rules from an XML configuration file."""
        pass
