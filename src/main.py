import click
import os
import json
from datetime import datetime
from .parsers.paloalto import PaloAltoParser
from .normalizer import normalize_rules
from .analysis import analyze_firewall_comprehensive, check_rule_anomalies
from .intent import analyze_rules_intent, identify_high_risk_rules, generate_policy_hardening_plan

@click.group()
def cli():
    pass

def _load_and_normalize(vendor: str, file_path: str):
    if vendor.lower() == "paloalto":
        if file_path.lower().endswith(".xml"):
            rules = PaloAltoParser.parse_from_xml(file_path)
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                text = f.read()
            rules = PaloAltoParser.parse_from_text(text)
    else:
        raise click.ClickException("Unsupported vendor")
        
    normalized = normalize_rules(rules)
    return normalized

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