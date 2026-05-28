from sqlalchemy import create_engine, Column, String, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
import datetime
import uuid
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./firewall.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL, connect_args=connect_args
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class DBFirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    vendor = Column(String, index=True)
    name = Column(String, nullable=True)
    source_zones = Column(JSON, default=list)
    destination_zones = Column(JSON, default=list)
    source_addresses = Column(JSON, default=list)
    destination_addresses = Column(JSON, default=list)
    application = Column(String, nullable=True)
    service = Column(String, nullable=True)
    action = Column(String)
    enabled = Column(Boolean, default=True)
    logging = Column(Boolean, default=False)
    rule_metadata = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class DBAnalysisIssue(Base):
    __tablename__ = "analysis_issues"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    severity = Column(String, index=True)
    rule_id = Column(String, index=True)
    rule_name = Column(String, nullable=True)
    description = Column(String)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class DBTask(Base):
    """Tracks background tasks for asynchronous processing."""
    __tablename__ = "tasks"

    id = Column(String, primary_key=True, index=True)
    status = Column(String, default="pending")
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class DBLLMCache(Base):
    """Caches LLM analysis JSON based on rule IDs."""
    __tablename__ = "llm_cache"

    rule_id = Column(String, primary_key=True, index=True)
    analysis_json = Column(JSON)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class DBComplianceMapping(Base):
    __tablename__ = "compliance_mappings"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    issue_id = Column(String, ForeignKey("analysis_issues.id"), index=True)
    framework_name = Column(String, index=True)
    control_id = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)
