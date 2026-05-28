import os
import json
import ollama
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from .schema import FirewallRule, AnalysisIssue, LLMRuleAnalysis, BulkAnalysisResponse
from .database import SessionLocal, DBLLMCache

def batch_analyze_rules_local(rules: List[FirewallRule]) -> BulkAnalysisResponse:
    print(f"Packaging {len(rules)} rules for local bulk analysis...")
    
    system_prompt = (
        "You are an expert cybersecurity architect specializing in firewall policy analysis. "
        "Analyze the following JSON list of firewall rules in bulk. "
        "For EACH rule, extract semantic intent, map vulnerabilities to MITRE ATT&CK, "
        "NIST 800-53, ISO 27001, and CIS controls, and assign a risk score (0-100). "
        "In the 'recommendation' field, you MUST provide explicit, actionable CLI commands (e.g., Palo Alto 'set rulebase...') "
        "to mitigate the risk. You must return the analysis strictly matching the provided JSON schema. "
        "Example mapping: If a rule allows Any to Any on SSH, intent_summary='Permissive SSH', "
        "mitre_techniques=['T1021.004'], nist_controls=['AC-4'], risk_score=85, "
        "recommendation='set rulebase security rules \"Allow-SSH\" source \"10.0.0.0/8\"'."
    )

    model_name = os.getenv("LLM_MODEL", "llama3.1")
    print(f"Sending payload to local {model_name} model. This may take a moment...")
    
    def process_chunk(chunk_index, chunk):
        print(f"Processing chunk {chunk_index + 1} ({len(chunk)} rules)...")
        rules_context = [
            rule.model_dump(exclude={"metadata", "created_at", "name", "logging"}) 
            for rule in chunk
        ]
        try:
            response = ollama.chat(
                model=model_name,
                messages=[
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': json.dumps(rules_context)}
                ],
                format=BulkAnalysisResponse.model_json_schema(),
                options={"temperature": 0.1}
            )
            result_json = response['message']['content']
            chunk_result = BulkAnalysisResponse.model_validate_json(result_json)
            return chunk_result.analyses
        except Exception as e:
            print(f"Local LLM API Error for chunk {chunk_index + 1}: {e}")
            return []

    chunk_size = 5
    chunks = [rules[i:i + chunk_size] for i in range(0, len(rules), chunk_size)]
    all_analyses = []
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(process_chunk, i, chunk): i for i, chunk in enumerate(chunks)}
        for future in as_completed(futures):
            all_analyses.extend(future.result())
            
    return BulkAnalysisResponse(analyses=all_analyses)

import hashlib

def get_rule_hash(rule: FirewallRule) -> str:
    """Generate a deterministic hash of rule attributes for LLM caching."""
    # Ensure lists are sorted so order doesn't change the hash
    data = (
        f"{','.join(sorted(rule.source_zones))}|"
        f"{','.join(sorted(rule.destination_zones))}|"
        f"{','.join(sorted(rule.source_addresses))}|"
        f"{','.join(sorted(rule.destination_addresses))}|"
        f"{rule.application or ''}|"
        f"{rule.service or ''}|"
        f"{rule.action.value if hasattr(rule.action, 'value') else rule.action}"
    )
    return hashlib.md5(data.encode()).hexdigest()

def get_all_llm_analyses(rules: List[FirewallRule]) -> Dict[str, LLMRuleAnalysis]:
    """Helper function to run the batch process with SQLAlchemy caching."""
    db = SessionLocal()
    try:
        results = {}
        uncached_rules = []
        
        cache_key_to_rule = {}
        for rule in rules:
            rule_hash = get_rule_hash(rule)
            cache_key = f"{rule.id}_{rule_hash}"
            cache_key_to_rule[cache_key] = rule
            
        db_caches = db.query(DBLLMCache).filter(DBLLMCache.rule_id.in_(cache_key_to_rule.keys())).all()
        
        cached_keys = set()
        for db_cache in db_caches:
            if db_cache.analysis_json:
                rule = cache_key_to_rule[db_cache.rule_id]
                results[rule.id] = LLMRuleAnalysis.model_validate(db_cache.analysis_json)
                cached_keys.add(db_cache.rule_id)
                
        for cache_key, rule in cache_key_to_rule.items():
            if cache_key not in cached_keys:
                uncached_rules.append(rule)
                
        if uncached_rules:
            bulk_results = batch_analyze_rules_local(uncached_rules)
            for res in bulk_results.analyses:
                results[res.rule_id] = res
                
                # Find the rule that generated this result to get its hash
                rule_obj = next((r for r in uncached_rules if r.id == res.rule_id), None)
                if rule_obj:
                    rule_hash = get_rule_hash(rule_obj)
                    cache_key = f"{rule_obj.id}_{rule_hash}"
                    
                    db_cache = db.query(DBLLMCache).filter(DBLLMCache.rule_id == cache_key).first()
                    if not db_cache:
                        db_cache = DBLLMCache(rule_id=cache_key)
                        db.add(db_cache)
                    db_cache.analysis_json = res.model_dump()
            db.commit()
            
        return results
    finally:
        db.close()

def analyze_rules_intent(rules: List[FirewallRule]) -> List[AnalysisIssue]:
    result_map = get_all_llm_analyses(rules)
    issues = []
    
    for rule in rules:
        llm_analysis = result_map.get(rule.id)
        if not llm_analysis:
            print(f"Rule {rule.id} was missed by the LLM batch process.")
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
                    "iso_27001": llm_analysis.iso_27001_controls,
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