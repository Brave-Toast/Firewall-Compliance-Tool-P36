from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
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

class LLMRuleAnalysis(BaseModel):
    rule_id: str = Field(description="The ID of the rule being analyzed")
    intent_summary: str = Field(description="A plain English summary of what the rule allows or denies.")
    mitre_techniques: List[str] = Field(description="Applicable MITRE ATT&CK technique IDs (e.g., T1071.001).")
    nist_controls: List[str] = Field(description="Applicable NIST 800-53 controls (e.g., AC-4).")
    cis_controls: List[str] = Field(description="Applicable CIS Controls (e.g., Control 12).")
    risk_score: int = Field(description="Risk score from 0 to 100 based on exposure and zero trust principles.")
    recommendation: str = Field(description="Specific advice to harden this rule or apply micro-segmentation.")

class BulkAnalysisResponse(BaseModel):
    analyses: List[LLMRuleAnalysis]