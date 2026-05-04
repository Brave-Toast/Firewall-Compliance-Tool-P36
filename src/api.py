from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid
from .parsers import get_parser
from .normalizer import normalize_rules
from .analysis import check_rule_anomalies, analyze_firewall_comprehensive, simulate_proposed_rule
from .intent import analyze_rules_intent, generate_policy_hardening_plan
from .database import SessionLocal, init_db, DBFirewallRule, DBAnalysisIssue, DBTask
from .schema import FirewallRule

app = FastAPI(title="Firewall Compliance Analyzer")

init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class RuleUpload(BaseModel):
    vendor: str
    rules: List[str]

class TaskResponse(BaseModel):
    task_id: str

class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    result: Optional[Dict[str, Any]] = None

class SimulateRequest(BaseModel):
    vendor: str
    existing_rules: List[str]
    proposed_rule: FirewallRule


class AnalyzeResponse(BaseModel):
    parsed_count: int
    redundancy_issues: List[dict]
    formal_issues: List[dict]
    intent_issues: List[dict]


class RecommendResponse(BaseModel):
    high_risk_count: int
    plan_items: List[dict]


def _parse_and_normalize_upload(payload: RuleUpload):
    try:
        parser = get_parser(payload.vendor)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    text = "\n".join(payload.rules)
    rules = parser.parse_from_text(text)
    return normalize_rules(rules)


@app.get("/health")
def health():
    return {"status": "ok", "service": "firewall-compliance"}


@app.get("/status/{task_id}", response_model=TaskStatusResponse)
def get_status(task_id: str, db: Session = Depends(get_db)):
    db_task = db.query(DBTask).filter(DBTask.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")
    return TaskStatusResponse(
        task_id=db_task.id,
        status=db_task.status,
        result=db_task.result
    )

def _run_analyze_task(task_id: str, payload: RuleUpload):
    db = SessionLocal()
    try:
        db_task = db.query(DBTask).filter(DBTask.id == task_id).first()
        if not db_task:
            return
        
        db_task.status = "in_progress"
        db.commit()

        rules = _parse_and_normalize_upload(payload)
        
        # Persist rules
        for r in rules:
            db_rule = db.query(DBFirewallRule).filter(DBFirewallRule.id == r.id).first()
            if not db_rule:
                db_rule = DBFirewallRule(id=r.id)
                db.add(db_rule)
            
            db_rule.vendor = r.vendor
            db_rule.name = r.name
            db_rule.source_zones = r.source_zones
            db_rule.destination_zones = r.destination_zones
            db_rule.source_addresses = r.source_addresses
            db_rule.destination_addresses = r.destination_addresses
            db_rule.application = r.application
            db_rule.service = r.service
            db_rule.action = r.action.value if hasattr(r.action, 'value') else r.action
            db_rule.enabled = r.enabled
            db_rule.logging = r.logging
            db_rule.rule_metadata = r.metadata
            db_rule.created_at = r.created_at
        
        db.commit()

        redundancy = check_rule_anomalies(rules)
        formal = analyze_firewall_comprehensive(rules)
        intent = analyze_rules_intent(rules)
        
        # Persist analysis issues
        for issue in redundancy + formal:
            db.add(DBAnalysisIssue(
                severity=issue.severity,
                rule_id=issue.rule_id,
                rule_name=issue.rule_name,
                description=issue.description,
                details=issue.details
            ))
            
        for intent_res in intent:
            db.add(DBAnalysisIssue(
                severity="info",
                rule_id=intent_res.rule_id,
                rule_name=None,
                description=intent_res.intent_summary,
                details={
                    "mitre_techniques": intent_res.mitre_techniques,
                    "nist_controls": intent_res.nist_controls,
                    "cis_controls": intent_res.cis_controls,
                    "risk_score": intent_res.risk_score,
                    "recommendation": intent_res.recommendation
                }
            ))
            
        db.commit()

        response_data = AnalyzeResponse(
            parsed_count=len(rules),
            redundancy_issues=[i.model_dump() for i in redundancy],
            formal_issues=[i.model_dump() for i in formal],
            intent_issues=[i.model_dump() for i in intent],
        )

        db_task.status = "completed"
        db_task.result = response_data.model_dump()
        db.commit()
    except Exception as e:
        db_task.status = "failed"
        db_task.result = {"error": str(e)}
        db.commit()
    finally:
        db.close()

@app.post("/analyze", response_model=TaskResponse)
def analyze(payload: RuleUpload, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    task_id = str(uuid.uuid4())
    db_task = DBTask(id=task_id, status="pending")
    db.add(db_task)
    db.commit()
    background_tasks.add_task(_run_analyze_task, task_id, payload)
    return TaskResponse(task_id=task_id)

def _run_recommend_task(task_id: str, payload: RuleUpload, top_n: int, threshold: int):
    db = SessionLocal()
    try:
        db_task = db.query(DBTask).filter(DBTask.id == task_id).first()
        if not db_task:
            return
            
        db_task.status = "in_progress"
        db.commit()

        rules = _parse_and_normalize_upload(payload)
        
        # Persist rules
        for r in rules:
            db_rule = db.query(DBFirewallRule).filter(DBFirewallRule.id == r.id).first()
            if not db_rule:
                db_rule = DBFirewallRule(id=r.id)
                db.add(db_rule)
            
            db_rule.vendor = r.vendor
            db_rule.name = r.name
            db_rule.source_zones = r.source_zones
            db_rule.destination_zones = r.destination_zones
            db_rule.source_addresses = r.source_addresses
            db_rule.destination_addresses = r.destination_addresses
            db_rule.application = r.application
            db_rule.service = r.service
            db_rule.action = r.action.value if hasattr(r.action, 'value') else r.action
            db_rule.enabled = r.enabled
            db_rule.logging = r.logging
            db_rule.rule_metadata = r.metadata
            db_rule.created_at = r.created_at
            
        db.commit()

        plan = generate_policy_hardening_plan(rules, top_n=top_n, threshold=threshold)
        
        response_data = RecommendResponse(
            high_risk_count=plan["high_risk_count"],
            plan_items=plan["plan_items"],
        )
        
        db_task.status = "completed"
        db_task.result = response_data.model_dump()
        db.commit()
    except Exception as e:
        db_task.status = "failed"
        db_task.result = {"error": str(e)}
        db.commit()
    finally:
        db.close()

@app.post("/recommend", response_model=TaskResponse)
def recommend(payload: RuleUpload, background_tasks: BackgroundTasks, top_n: Optional[int] = 10, threshold: Optional[int] = 70, db: Session = Depends(get_db)):
    task_id = str(uuid.uuid4())
    db_task = DBTask(id=task_id, status="pending")
    db.add(db_task)
    db.commit()
    background_tasks.add_task(_run_recommend_task, task_id, payload, top_n, threshold)
    return TaskResponse(task_id=task_id)

@app.post("/simulate")
def simulate(payload: SimulateRequest):
    """What-if analysis: Checks a proposed rule against existing uploaded rules."""
    # Create a temporary payload to parse existing rules
    temp_payload = RuleUpload(vendor=payload.vendor, rules=payload.existing_rules)
    existing_rules = _parse_and_normalize_upload(temp_payload)
    
    issues = simulate_proposed_rule(existing_rules, payload.proposed_rule)
    return {"conflicts": [i.model_dump() for i in issues]}
