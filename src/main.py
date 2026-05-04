import click
import os
import json
from datetime import datetime
from .parsers import get_parser
from .normalizer import normalize_rules
from .analysis import analyze_firewall_comprehensive, check_rule_anomalies
from .intent import analyze_rules_intent, identify_high_risk_rules, generate_policy_hardening_plan
from .database import SessionLocal, init_db, DBFirewallRule, DBAnalysisIssue

@click.group()
def cli():
    pass

def _load_and_normalize(vendor: str, file_path: str):
    try:
        parser = get_parser(vendor)
    except ValueError as e:
        raise click.ClickException(str(e))
        
    if file_path.lower().endswith(".xml"):
        rules = parser.parse_from_xml(file_path)
    else:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
        rules = parser.parse_from_text(text)
        
    normalized = normalize_rules(rules)
    return normalized

def _persist_to_db(rules, anomaly_issues, comprehensive_issues, intent_issues):
    init_db()
    db = SessionLocal()
    try:
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
        
        # Persist analysis issues
        for issue in anomaly_issues + comprehensive_issues:
            db.add(DBAnalysisIssue(
                severity=issue.severity,
                rule_id=issue.rule_id,
                rule_name=issue.rule_name,
                description=issue.description,
                details=issue.details
            ))
            
        for intent_res in intent_issues:
            # handle both Intent response types (Dict vs LLMRuleAnalysis) just in case
            if hasattr(intent_res, "rule_id"):
                rule_id = intent_res.rule_id
                intent_summary = intent_res.intent_summary
                details = {
                    "mitre_techniques": intent_res.mitre_techniques,
                    "nist_controls": intent_res.nist_controls,
                    "cis_controls": intent_res.cis_controls,
                    "risk_score": intent_res.risk_score,
                    "recommendation": intent_res.recommendation
                }
            else:
                rule_id = intent_res.get("rule_id", "unknown")
                intent_summary = intent_res.get("description", "")
                details = intent_res.get("details", {})

            db.add(DBAnalysisIssue(
                severity="info",
                rule_id=rule_id,
                rule_name=None,
                description=intent_summary,
                details=details
            ))
            
        db.commit()
    finally:
        db.close()

@cli.command()
@click.option("--vendor", type=click.Choice(["paloalto"], case_sensitive=False), default="paloalto")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True))
def parse(vendor, file_path):
    normalized = _load_and_normalize(vendor, file_path)
    click.echo(f"Parsed and normalized {len(normalized)} rules")
    click.echo("Normalized rules:")
    for r in normalized:
        click.echo(r.model_dump_json())

@cli.command()
@click.option("--vendor", type=click.Choice(["paloalto"], case_sensitive=False), default="paloalto")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True))
def analyze(vendor, file_path):
    normalized = _load_and_normalize(vendor, file_path)
    
    comprehensive_issues = analyze_firewall_comprehensive(normalized)
    anomaly_issues = check_rule_anomalies(normalized)
    intent_issues = analyze_rules_intent(normalized)

    _persist_to_db(normalized, anomaly_issues, comprehensive_issues, intent_issues)

    click.echo(f"Rule set size: {len(normalized)}")
    
    click.echo("\n--- Comprehensive Analysis Issues (SMT & Path Violations) ---")
    if not comprehensive_issues:
        click.echo("None")
    for i in comprehensive_issues:
        click.echo(i.model_dump_json(indent=2))

    click.echo("\n--- Basic Anomaly Detection (Shadowing, Redundancy, Collision) ---")
    if not anomaly_issues:
        click.echo("None")
    for i in anomaly_issues:
        click.echo(i.model_dump_json(indent=2))

    click.echo("\n--- Intent & risk analysis issues ---")
    if not intent_issues:
        click.echo("None")
    for i in intent_issues:
        click.echo(i.model_dump_json(indent=2))

@cli.command()
@click.option("--vendor", type=click.Choice(["paloalto"], case_sensitive=False), default="paloalto")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True))
@click.option("--top", "top_n", default=10, type=int)
@click.option("--threshold", default=70, type=int)
def recommend(vendor, file_path, top_n, threshold):
    normalized = _load_and_normalize(vendor, file_path)
    high_risk = identify_high_risk_rules(normalized, threshold=threshold)
    plan = generate_policy_hardening_plan(normalized, top_n=top_n, threshold=threshold)

    click.echo(f"High-risk rules (threshold={threshold}): {len(high_risk)}")
    if not high_risk:
        click.echo("No high-risk rules detected.")
    else:
        for item in high_risk:
            click.echo("---")
            click.echo(f"Rule {item['rule_id']} ({item['rule_name']}): risk={item['risk_score']}")
            click.echo(f"Summary: {item['summary']}")
            click.echo(f"Frameworks: MITRE: {item['mitre']} | NIST: {item['nist']} | CIS: {item['cis']}")
            click.echo(f"Recommendation: {item['recommended_action']}")

    click.echo("\nPolicy hardening plan:")
    click.echo(f"Top N: {plan['top_n']}, high risk count: {plan['high_risk_count']}")
    for item in plan['plan_items']:
        click.echo(f"#{item['priority']}: {item['rule_id']} ({item['rule_name']}) risk={item['risk_score']}")
        click.echo(f"  Frameworks: MITRE: {item['mitre']} | NIST: {item['nist']} | CIS: {item['cis']}")
        click.echo(f"  Recommendation: {item['recommendation']}")

@cli.command()
@click.option("--vendor", type=click.Choice(["paloalto"], case_sensitive=False), default="paloalto")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True))
@click.option("--top", "top_n", default=10, type=int)
@click.option("--threshold", default=70, type=int)
@click.option("--output", "output_dir", default="reports", help="Directory to save the generated report")
def full_scan(vendor, file_path, top_n, threshold, output_dir):
    """Parses, analyzes, and generates a structured JSON recommendation report."""
    normalized = _load_and_normalize(vendor, file_path)
    
    # Run all analysis functions 
    analysis_issues = analyze_firewall_comprehensive(normalized)
    anomaly_issues = check_rule_anomalies(normalized)
    intent_issues = analyze_rules_intent(normalized)
    plan = generate_policy_hardening_plan(normalized, top_n=top_n, threshold=threshold)

    _persist_to_db(normalized, anomaly_issues, analysis_issues, intent_issues)

    # Compile the results into a structured dictionary
    report_data = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "target_file": file_path,
            "vendor": vendor,
            "total_rules_parsed": len(normalized)
        },
        "comprehensive_analysis_issues": [issue.model_dump() for issue in analysis_issues],
        "basic_anomaly_issues": [issue.model_dump() for issue in anomaly_issues],
        "intent_analysis": [issue.model_dump() for issue in intent_issues],
        "hardening_plan": plan 
    }

    # Convert the dictionary to a formatted JSON string
    json_output = json.dumps(report_data, indent=2, default=str)

    # Handle Directory Creation and File Saving
    os.makedirs(output_dir, exist_ok=True)
    file_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path = os.path.join(output_dir, file_name)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_output)
        
    click.echo(f"✅ Success! Structured JSON report saved to: {output_path}")
    
    click.echo("\n--- Report Preview ---")
    click.echo(json.dumps(report_data["metadata"], indent=2))

if __name__ == "__main__":
    cli()