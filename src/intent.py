import json
import ollama
from typing import List, Dict
from .schema import FirewallRule, AnalysisIssue, LLMRuleAnalysis, BulkAnalysisResponse

_local_analysis_cache = None

def batch_analyze_rules_local(rules: List[FirewallRule]) -> BulkAnalysisResponse:
    print(f"⚙️ Packaging {len(rules)} rules for local bulk analysis...")
    
    # Strip non-essential data to save LLM context window space
    rules_context = [
        rule.model_dump(exclude={"metadata", "created_at", "name", "logging"}) 
        for rule in rules
    ]
    
    system_prompt = (
        "You are an expert cybersecurity architect specializing in firewall policy analysis. "
        "Analyze the following JSON list of firewall rules in bulk. "
        "For EACH rule, extract semantic intent, map vulnerabilities to MITRE ATT&CK, "
        "NIST 800-53, and CIS controls, and assign a risk score (0-100). "
        "You must return the analysis strictly matching the provided JSON schema."
    )

    print("🧠 Sending payload to local Llama 3.1 model. This may take a moment...")
    
    try:
        # Utilize Ollama's structured output feature
        response = ollama.chat(
            model='llama3.1',
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': json.dumps(rules_context)}
            ],
            format=BulkAnalysisResponse.model_json_schema(),
            options={"temperature": 0.1} # Keep creativity low for consistent audits
        )
        
        # Parse the JSON string back into Pydantic objects
        result_json = response['message']['content']
        return BulkAnalysisResponse.model_validate_json(result_json)
        
    except Exception as e:
        print(f"❌ Local LLM API Error: {e}")
        return BulkAnalysisResponse(analyses=[])

def get_all_llm_analyses(rules: List[FirewallRule]) -> Dict[str, LLMRuleAnalysis]:
    """Helper function to run the batch process with in-memory caching."""
    global _local_analysis_cache
    
    # If we already analyzed this batch during the current run, return the saved results
    if _local_analysis_cache is not None:
        return _local_analysis_cache
        
    bulk_results = batch_analyze_rules_local(rules)
    _local_analysis_cache = {res.rule_id: res for res in bulk_results.analyses}
    return _local_analysis_cache

def analyze_rules_intent(rules: List[FirewallRule]) -> List[AnalysisIssue]:
    result_map = get_all_llm_analyses(rules)
    issues = []
    
    for rule in rules:
        llm_analysis = result_map.get(rule.id)
        if not llm_analysis:
            print(f"⚠️ Rule {rule.id} was missed by the LLM batch process.")
            continue
            
        severity = "high" if llm_analysis.risk_score > 70 else "medium" if llm_analysis.risk_score > 50 else "low"
        
        issues.append(AnalysisIssue(
            severity=severity,
            rule_id=rule.id,
            rule_name=rule.name,
            description=llm_analysis.intent_summary,
            details={
                "intent": {
                    "rule_id": rule.id,
                    "summary": llm_analysis.intent_summary,
                    "mitre": llm_analysis.mitre_techniques,
                    "nist": llm_analysis.nist_controls,
                    "cis": llm_analysis.cis_controls
                },
                "risk_score": llm_analysis.risk_score,
                "suggested_action": llm_analysis.recommendation,
            }
        ))
    return issues

def identify_high_risk_rules(rules: List[FirewallRule], threshold: int = 70) -> List[Dict]:
    result_map = get_all_llm_analyses(rules)
    high_risk = []
    
    for rule in rules:
        llm_analysis = result_map.get(rule.id)
        if not llm_analysis:
            continue
            
        if llm_analysis.risk_score >= threshold:
            high_risk.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "risk_score": llm_analysis.risk_score,
                "summary": llm_analysis.intent_summary,
                "mitre": llm_analysis.mitre_techniques,
                "nist": llm_analysis.nist_controls,
                "cis": llm_analysis.cis_controls,
                "recommended_action": llm_analysis.recommendation,
            })
    return sorted(high_risk, key=lambda x: x["risk_score"], reverse=True)

def generate_policy_hardening_plan(rules: List[FirewallRule], top_n: int = 10, threshold: int = 70) -> Dict:
    high_risk = identify_high_risk_rules(rules, threshold)
    plan_items = []
    
    for idx, item in enumerate(high_risk[:top_n], start=1):
        plan_items.append({
            "priority": idx,
            "rule_id": item["rule_id"],
            "rule_name": item["rule_name"],
            "risk_score": item["risk_score"],
            "mitre": item["mitre"],
            "nist": item["nist"],
            "cis": item["cis"],
            "recommendation": item["recommended_action"],
        })
        
    return {
        "top_n": top_n,
        "threshold": threshold,
        "high_risk_count": len(high_risk),
        "plan_items": plan_items,
    }