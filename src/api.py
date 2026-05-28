from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid
import os
import urllib.request
import json
from .parsers import get_parser
from .normalizer import normalize_rules
from .analysis import check_rule_anomalies, analyze_firewall_comprehensive, simulate_proposed_rule
from .intent import analyze_rules_intent, generate_policy_hardening_plan
from .database import SessionLocal, init_db, DBFirewallRule, DBAnalysisIssue, DBTask, DBComplianceMapping
from .schema import FirewallRule, RuleUpload, Action
from .translator import translate_ruleset_to_suricata


app = FastAPI(title="Firewall Compliance Analyzer")

init_db()

USE_CELERY = os.getenv("USE_CELERY", "false").lower() == "true"
if USE_CELERY:
    from .worker import analyze_task_celery, recommend_task_celery

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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
        seen_ids = set()
        for r in rules:
            if r.id in seen_ids:
                continue
            seen_ids.add(r.id)
            
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
            db_issue = DBAnalysisIssue(
                severity="info",
                rule_id=intent_res.rule_id,
                rule_name=intent_res.rule_name,
                description=intent_res.description,
                details=intent_res.details
            )
            db.add(db_issue)
            
            # Populate DBComplianceMapping
            intent_details = intent_res.details.get("intent", {})
            for fw, key in [("NIST", "nist"), ("MITRE", "mitre"), ("CIS", "cis"), ("ISO", "iso_27001")]:
                controls = intent_details.get(key, [])
                for control in controls:
                    db.add(DBComplianceMapping(
                        issue_id=db_issue.id,
                        framework_name=fw,
                        control_id=control
                    ))
            
        db.commit()

        response_data = AnalyzeResponse(
            parsed_count=len(rules),
            redundancy_issues=[i.model_dump() for i in redundancy],
            formal_issues=[i.model_dump() for i in formal],
            intent_issues=[i.model_dump() for i in intent],
        )

        db_task.status = "completed"
        result_dict = response_data.model_dump()
        db_task.result = result_dict
        db.commit()
        
        # Save a formatted copy to the reports folder for team testing
        import os
        import json
        from datetime import datetime
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"reports/scan_report_{timestamp}.json"
        with open(report_filename, "w", encoding="utf-8") as f:
            json.dump({
                "task_id": task_id,
                "status": "completed",
                "result": result_dict
            }, f, indent=4)
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
    
    if USE_CELERY:
        analyze_task_celery.delay(task_id, payload.model_dump())
    else:
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
        seen_ids = set()
        for r in rules:
            if r.id in seen_ids:
                continue
            seen_ids.add(r.id)
            
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
    
    if USE_CELERY:
        recommend_task_celery.delay(task_id, payload.model_dump(), top_n, threshold)
    else:
        background_tasks.add_task(_run_recommend_task, task_id, payload, top_n, threshold)
        
    return TaskResponse(task_id=task_id)

@app.get("/recommendations")
def get_recommendations(framework: Optional[str] = None, control_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Filter dashboard recommendations by framework or control ID."""
    query = db.query(DBAnalysisIssue)
    if framework or control_id:
        query = query.join(DBComplianceMapping, DBAnalysisIssue.id == DBComplianceMapping.issue_id)
        if framework:
            query = query.filter(DBComplianceMapping.framework_name == framework)
        if control_id:
            query = query.filter(DBComplianceMapping.control_id == control_id)
            
    issues = query.all()
    return [
        {
            "id": issue.id,
            "rule_id": issue.rule_id,
            "rule_name": issue.rule_name,
            "description": issue.description,
            "severity": issue.severity,
            "details": issue.details
        }
        for issue in issues
    ]

@app.post("/simulate")
def simulate(payload: SimulateRequest):
    """What-if analysis: Checks a proposed rule against existing uploaded rules."""
    # Create a temporary payload to parse existing rules
    temp_payload = RuleUpload(vendor=payload.vendor, rules=payload.existing_rules)
    existing_rules = _parse_and_normalize_upload(temp_payload)
    
    issues = simulate_proposed_rule(existing_rules, payload.proposed_rule)
    return {"conflicts": [i.model_dump() for i in issues]}

class FirewallIntakeRequest(BaseModel):
    firewall_url: str = "http://127.0.0.1:8001/api/v1/rules"

class FirewallDeployRequest(BaseModel):
    firewall_url: str = "http://127.0.0.1:8001/api/v1/rules"

@app.post("/api/v1/firewall/intake")
def firewall_intake(payload: Optional[FirewallIntakeRequest] = None, db: Session = Depends(get_db)):
    """Connects to the firewall REST API, fetches rules, normalizes, and persists them to the local DB."""
    url = payload.firewall_url if payload else "http://127.0.0.1:8001/api/v1/rules"
    
    try:
        # Fetch raw rules from firewall REST API
        with urllib.request.urlopen(url, timeout=5) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        raise HTTPException(
            status_code=502, 
            detail=f"Failed to connect to firewall REST API at {url}: {e}"
        )
        
    vendor = resp_data.get("vendor", "paloalto")
    rules_list = resp_data.get("rules", [])
    
    # Process and parse
    try:
        parser = get_parser(vendor)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    text = "\n".join(rules_list)
    parsed_rules = parser.parse_from_text(text)
    normalized_rules = normalize_rules(parsed_rules)
    
    # Save/update rules in DB
    seen_ids = set()
    for r in normalized_rules:
        if r.id in seen_ids:
            continue
        seen_ids.add(r.id)
        
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
    
    return {
        "status": "success",
        "vendor": vendor,
        "message": f"Successfully pulled, normalized, and saved {len(normalized_rules)} rules from firewall REST API.",
        "parsed_count": len(normalized_rules)
    }

@app.post("/api/v1/firewall/deploy")
def firewall_deploy(payload: Optional[FirewallDeployRequest] = None, db: Session = Depends(get_db)):
    """Retrieves rules from DB, prunes redundant/shadowed rules via SMT analysis, and pushes optimized Suricata ruleset to the firewall."""
    url = payload.firewall_url if payload else "http://127.0.0.1:8001/api/v1/rules"
    
    # Fetch all rules from database
    db_rules = db.query(DBFirewallRule).all()
    if not db_rules:
        raise HTTPException(
            status_code=400,
            detail="No rules found in compliance database. Please run rule intake (/api/v1/firewall/intake) first."
        )
        
    # Map DB models to Pydantic FirewallRule models
    rules = []
    for r in db_rules:
        try:
            act = Action(r.action)
        except ValueError:
            act = Action.deny
            
        rules.append(FirewallRule(
            id=r.id,
            vendor=r.vendor,
            name=r.name,
            source_zones=r.source_zones or [],
            destination_zones=r.destination_zones or [],
            source_addresses=r.source_addresses or [],
            destination_addresses=r.destination_addresses or [],
            application=r.application,
            service=r.service,
            action=act,
            enabled=r.enabled,
            logging=r.logging,
            metadata=r.rule_metadata or {},
            created_at=r.created_at
        ))
        
    # Run Z3 compliance optimization
    comprehensive_issues = analyze_firewall_comprehensive(rules)
    anomaly_issues = check_rule_anomalies(rules)
    
    # Compile list of shadowed and redundant rule IDs
    pruned_ids = set()
    for issue in comprehensive_issues + anomaly_issues:
        is_pruned = False
        desc = issue.description.lower()
        if "redundant" in desc or "redundancy" in desc or "[redundant]" in desc:
            is_pruned = True
        elif "shadowed" in desc or "shadowing" in desc or "[shadow]" in desc:
            is_pruned = True
            
        if is_pruned:
            pruned_ids.add(issue.rule_id)
            
    # Filter rules to build the optimized ruleset (only enabled and non-pruned rules)
    optimized_rules = []
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.id in pruned_ids:
            continue
        optimized_rules.append(rule)
        
    # Translate clean rules to Suricata format
    suricata_rules = translate_ruleset_to_suricata(optimized_rules)
    
    # Push to firewall REST API
    try:
        req_data = json.dumps({"rules": suricata_rules}).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect and push optimized ruleset to firewall REST API at {url}: {e}"
        )
        
    return {
        "status": "success",
        "original_rules_count": len(rules),
        "optimized_rules_count": len(optimized_rules),
        "pruned_rules_count": len(pruned_ids),
        "pruned_rules": list(pruned_ids),
        "firewall_response": resp_data
    }

