import click
import os
import json
import urllib.request
from datetime import datetime
from xml.etree import ElementTree as ET
from xml.dom import minidom
from .parsers import get_parser
from .normalizer import normalize_rules
from .analysis import analyze_firewall_comprehensive, check_rule_anomalies
from .intent import analyze_rules_intent, identify_high_risk_rules, generate_policy_hardening_plan
from .database import SessionLocal, init_db, DBFirewallRule, DBAnalysisIssue
from .schema import FirewallRule, Action
from .translator import translate_ruleset_to_suricata


@click.group()
def cli():
    pass

def rules_to_xml(rules):
    root = ET.Element("rules")
    for rule in rules:
        rule_elem = ET.SubElement(root, "rule")
        rule_dict = rule.model_dump()
        for field, value in rule_dict.items():
            if isinstance(value, list):
                list_elem = ET.SubElement(rule_elem, field)
                for item in value:
                    ET.SubElement(list_elem, "item").text = str(item)
            elif isinstance(value, dict):
                dict_elem = ET.SubElement(rule_elem, field)
                for k, v in value.items():
                    ET.SubElement(dict_elem, k).text = str(v)
            else:
                ET.SubElement(rule_elem, field).text = str(value)
    
    rough_string = ET.tostring(root, encoding='unicode')
    dom = minidom.parseString(rough_string)
    pretty_xml = dom.toprettyxml(indent="  ")
    # Remove extra newlines
    lines = pretty_xml.split('\n')
    non_empty_lines = [line for line in lines if line.strip()]
    return '\n'.join(non_empty_lines)

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
            # handle Intent response types (Dict vs LLMRuleAnalysis vs AnalysisIssue)
            if isinstance(intent_res, dict):
                db.add(DBAnalysisIssue(
                    severity="info",
                    rule_id=intent_res.get("rule_id", "unknown"),
                    rule_name=None,
                    description=intent_res.get("description", ""),
                    details=intent_res.get("details", {})
                ))
            elif hasattr(intent_res, "intent_summary"):
                db.add(DBAnalysisIssue(
                    severity="info",
                    rule_id=intent_res.rule_id,
                    rule_name=None,
                    description=intent_res.intent_summary,
                    details={
                        "mitre_techniques": getattr(intent_res, "mitre_techniques", []),
                        "nist_controls": getattr(intent_res, "nist_controls", []),
                        "cis_controls": getattr(intent_res, "cis_controls", []),
                        "risk_score": getattr(intent_res, "risk_score", 0),
                        "recommendation": getattr(intent_res, "recommendation", "")
                    }
                ))
            else:
                db.add(DBAnalysisIssue(
                    severity=getattr(intent_res, "severity", "info"),
                    rule_id=getattr(intent_res, "rule_id", "unknown"),
                    rule_name=getattr(intent_res, "rule_name", None),
                    description=getattr(intent_res, "description", ""),
                    details=getattr(intent_res, "details", {})
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
        
    click.echo(f"Success! Structured JSON report saved to: {output_path}")
    
    click.echo("\n--- Report Preview ---")
    click.echo(json.dumps(report_data["metadata"], indent=2))

@cli.command()
@click.option("--vendor", type=click.Choice(["paloalto"], case_sensitive=False), default="paloalto")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True))
@click.option("--top", "top_n", default=10, type=int)
@click.option("--threshold", default=70, type=int)
@click.option("--output", "output_dir", default="reports", help="Directory to save the generated report")
def partial_scan(vendor, file_path, top_n, threshold, output_dir):
    """Parses, analyzes (first 20 rules only), and generates a structured JSON recommendation report."""
    normalized = _load_and_normalize(vendor, file_path)
    
    # Limit to first 20 rules
    normalized = normalized[:20]
    
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
            "total_rules_parsed": len(normalized),
            "scan_type": "partial_scan"
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
    file_name = f"partial_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path = os.path.join(output_dir, file_name)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_output)
        
    click.echo(f"Success! Partial scan JSON report saved to: {output_path}")
    
    click.echo("\n--- Report Preview ---")
    click.echo(json.dumps(report_data["metadata"], indent=2))

@cli.command()
@click.option("--vendor", type=click.Choice(["paloalto"], case_sensitive=False), default="paloalto")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True))
@click.option("--output", "output_dir", default="reports", help="Directory to save the XML export")
def validate_schema(vendor, file_path, output_dir):
    """Validate and export firewall rules to XML format conforming to the unified schema."""
    normalized = _load_and_normalize(vendor, file_path)
    xml_output = rules_to_xml(normalized)
    
    # Handle Directory Creation and File Saving
    os.makedirs(output_dir, exist_ok=True)
    file_name = f"schema_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    output_path = os.path.join(output_dir, file_name)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml_output)
        
    click.echo(f"Success! XML schema validation report saved to: {output_path}")
    click.echo(f"Validated {len(normalized)} rules conforming to the unified schema.")

@cli.command()
@click.option("--firewall-url", default="http://127.0.0.1:8001/api/v1/rules", help="The REST API endpoint of the firewall")
def intake(firewall_url):
    """Pull rules from the firewall's REST API, normalize them, and persist to local database."""
    click.echo(f"Connecting to firewall REST API at: {firewall_url} ...")
    try:
        with urllib.request.urlopen(firewall_url, timeout=5) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        raise click.ClickException(f"Failed to connect to firewall REST API at {firewall_url}: {e}")
        
    vendor = resp_data.get("vendor", "paloalto")
    rules_list = resp_data.get("rules", [])
    
    try:
        parser = get_parser(vendor)
    except ValueError as e:
        raise click.ClickException(str(e))
        
    text = "\n".join(rules_list)
    parsed_rules = parser.parse_from_text(text)
    normalized_rules = normalize_rules(parsed_rules)
    
    init_db()
    db = SessionLocal()
    try:
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
        click.echo(f"Success! Pulled, normalized, and saved {len(normalized_rules)} rules from firewall REST API into local database.")
    except Exception as e:
        raise click.ClickException(f"Failed to save rules to database: {e}")
    finally:
        db.close()

@cli.command()
@click.option("--firewall-url", default="http://127.0.0.1:8001/api/v1/rules", help="The REST API endpoint of the firewall")
def deploy(firewall_url):
    """Retrieve rules from local DB, run SMT compliance optimization to prune redundant/shadowed rules, translate, and push to firewall."""
    click.echo("Retrieving rules from database...")
    init_db()
    db = SessionLocal()
    try:
        db_rules = db.query(DBFirewallRule).all()
        if not db_rules:
            raise click.ClickException("No rules found in local compliance database. Please run rule intake first.")
            
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
                click.echo(f"-> Optimization: Pruning redundant/shadowed rule '{rule.name}' ({rule.id})")
                continue
            optimized_rules.append(rule)
            
        click.echo(f"Original Rules: {len(rules)} | Optimized Rules: {len(optimized_rules)} | Pruned: {len(pruned_ids)}")
        
        # Translate to Suricata format
        suricata_rules = translate_ruleset_to_suricata(optimized_rules)
        
        # Push to firewall REST API
        click.echo(f"Pushing optimized ruleset to firewall at {firewall_url} ...")
        req_data = json.dumps({"rules": suricata_rules}).encode('utf-8')
        req = urllib.request.Request(
            firewall_url,
            data=req_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            
        click.echo(f"Firewall REST API Response:")
        click.echo(json.dumps(resp_data, indent=2))
        if resp_data.get("status") == "success":
            click.echo("Success! Optimized ruleset deployed successfully.")
        else:
            click.echo("Warning: Rules pushed but might not be active (see response above).")
            
    except Exception as e:
        raise click.ClickException(f"Deployment failed: {e}")
    finally:
        db.close()

@cli.command()
@click.option("--vendor", type=click.Choice(["paloalto"], case_sensitive=False), default="paloalto")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True))
@click.option("--output", "output_path", required=True)
def compile(vendor, file_path, output_path):
    """Parse, normalize, SMT-optimize, and compile a ruleset directly to Suricata rules."""
    click.echo(f"Compiling ruleset {file_path} ...")
    normalized = _load_and_normalize(vendor, file_path)
    
    # Run Z3 compliance optimization
    comprehensive_issues = analyze_firewall_comprehensive(normalized)
    anomaly_issues = check_rule_anomalies(normalized)
    
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
            
    optimized = [r for r in normalized if r.enabled and r.id not in pruned_ids]
    suricata_rules = translate_ruleset_to_suricata(optimized)
    
    # Create parent directories if they don't exist
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        
    with open(output_path, "w", encoding="utf-8") as f:
        for rule in suricata_rules:
            f.write(rule + "\n")
            
    click.echo(f"Success! Compiled {len(optimized)} optimized Suricata rules (pruned {len(pruned_ids)} redundant/shadowed rules) to {output_path}")

if __name__ == "__main__":
    cli()