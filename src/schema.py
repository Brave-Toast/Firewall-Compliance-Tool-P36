from datetime import datetime
from enum import Enum
from pydantic import BaseModel, IPvAnyAddress
from typing import Optional, List, Dict, Any


class Action(str, Enum):
    allow = "allow"
    deny = "deny"


class Protocol(str, Enum):
    tcp = "tcp"
    udp = "udp"
    icmp = "icmp"
    any = "any"


class FirewallRule(BaseModel):
    id: str
    vendor: str
    name: Optional[str]
    source_zones: List[str]
    destination_zones: List[str]
    source_addresses: List[str]
    destination_addresses: List[str]
    application: Optional[str]
    service: Optional[str]
    action: Action
    enabled: bool = True
    logging: Optional[bool] = False
    metadata: Dict[str, Any] = {}
    created_at: datetime = datetime.utcnow()


class AnalysisIssue(BaseModel):
    severity: str
    rule_id: str
    rule_name: Optional[str]
    description: str
    details: Dict[str, Any] = {}
