import os
import sqlite3
import hashlib
import asyncio
from typing import List, Dict
from pydantic import BaseModel, Field
from openai import AsyncOpenAI
from dotenv import load_dotenv
from .schema import FirewallRule, AnalysisIssue

# Load environment variables
load_dotenv()

# 1. Database Initialization for Caching
DB_FILE = "llm_cache.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS rule_analysis_cache (
                rule_hash TEXT PRIMARY KEY,
                analysis_result TEXT
            )
        ''')
        conn.commit()

init_db()

# 2. Initialize Async Client
aclient = AsyncOpenAI(
    base_url="https://models.inference.ai.azure.com",
    api_key=os.getenv("GITHUB_TOKEN")
)

# 3. Define the Expected LLM Output Schema
class LLMRuleAnalysis(BaseModel):
    intent_summary: str = Field(description="A plain English summary of what the rule allows or denies.")
    mitre_techniques: List[str] = Field(description="List of applicable MITRE ATT&CK technique IDs (e.g., T1071.001) based on the exposed service/app.")
    risk_score: int = Field(description="Risk score from 0 to 100 based on exposure, privilege level, and zero trust principles.")
    recommendation: str = Field(description="Specific advice to harden this rule, narrow its scope, or apply micro-segmentation.")

def get_rule_hash(rule: FirewallRule) -> str:
    """Creates a unique hash for the rule based on its actual logic, ignoring volatile fields."""
    rule_str = rule.model_dump_json(exclude={"id", "name", "metadata", "created_at"})
    return hashlib.sha256(rule_str.encode('utf-8')).hexdigest()

# 4. The Core Asynchronous Function
async def analyze_rule_with_llm_async(rule: FirewallRule, semaphore: asyncio.Semaphore) -> LLMRuleAnalysis:
    """Analyzes a SINGLE rule via API (Cache checking is now handled before this function)."""
    rule_hash = get_rule_hash(rule)
    rule_context = rule.model_dump_json(exclude={"id", "name", "metadata", "created_at"})
    
    system_prompt = (
        "You are an expert cybersecurity architect specializing in firewall policy analysis. "
        "Your task is to analyze firewall rules, extract their semantic intent, map potential "
        "vulnerabilities to MITRE ATT&CK techniques, and recommend improvements based on "
        "Zero Trust Architecture and micro-segmentation principles."
    )

    async with semaphore:
        max_retries = 5
        base_delay = 5 

        for attempt in range(max_retries):
            try:
                completion = await aclient.beta.chat.completions.parse(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Analyze the following firewall rule: {rule_context}"}
                    ],
                    response_format=LLMRuleAnalysis,
                    temperature=0.2
                )
                result = completion.choices[0].message.parsed
                
                # SAVE TO CACHE FOR NEXT TIME
                with get_db_connection() as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO rule_analysis_cache (rule_hash, analysis_result) VALUES (?, ?)", 
                        (rule_hash, result.model_dump_json())
                    )
                    conn.commit()
                    
                return result
                
            except Exception as e:
                error_details = str(e).lower() + str(type(e)).lower()
                if "429" in error_details or "ratelimit" in error_details or "too many requests" in error_details:
                    if attempt < max_retries - 1:
                        wait_time = base_delay * (2 ** attempt)
                        print(f"⚠️ Rate limit hit for rule {rule.id}. Pausing for {wait_time}s before retry...")
                        await asyncio.sleep(wait_time)
                        continue 
                
                print(f"❌ LLM API Error for rule {rule.id}: {e}")
                return LLMRuleAnalysis(
                    intent_summary=f"{rule.action.value.upper()} traffic",
                    mitre_techniques=[],
                    risk_score=50,
                    recommendation="Manual review required due to LLM analysis failure."
                )

async def batch_process_rules(rules: List[FirewallRule]) -> Dict[str, LLMRuleAnalysis]:
    """Smartly pre-filters cached rules before hitting the slow API chunks."""
    results_dict = {}
    uncached_rules = []

    # STEP 1: PRE-CHECK THE CACHE FOR EVERYTHING
    with get_db_connection() as conn:
        for rule in rules:
            rule_hash = get_rule_hash(rule)
            row = conn.execute("SELECT analysis_result FROM rule_analysis_cache WHERE rule_hash = ?", (rule_hash,)).fetchone()
            if row:
                # Cache Hit! Instantly save to our results dictionary.
                results_dict[rule.id] = LLMRuleAnalysis.model_validate_json(row["analysis_result"])
            else:
                # Cache Miss! Queue it for the API.
                uncached_rules.append(rule)

    # STEP 2: ONLY PROCESS THE RULES WE ACTUALLY NEED TO
    if uncached_rules:
        print(f"\n🔍 Found {len(uncached_rules)} new rules to analyze. {len(rules) - len(uncached_rules)} loaded from cache.")
        semaphore = asyncio.Semaphore(2) 
        chunk_size = 2         
        cooldown_seconds = 12  

        for i in range(0, len(uncached_rules), chunk_size):
            chunk = uncached_rules[i:i + chunk_size]
            print(f"⚙️ Analyzing chunk {i//chunk_size + 1} (Rules {i+1} to {min(i+chunk_size, len(uncached_rules))}) via API...")
            
            tasks = [analyze_rule_with_llm_async(r, semaphore) for r in chunk]
            chunk_results = await asyncio.gather(*tasks)
            
            # Merge the new API results into our main dictionary
            for r, res in zip(chunk, chunk_results):
                results_dict[r.id] = res
            
            if i + chunk_size < len(uncached_rules):
                print(f"⏳ Cooldown for {cooldown_seconds} seconds to respect API limits...")
                await asyncio.sleep(cooldown_seconds)
    else:
        # If all rules were cached, let the user know!
        print(f"\n⚡ All {len(rules)} rules loaded instantly from cache!")

    return results_dict

def get_all_llm_analyses(rules: List[FirewallRule]) -> Dict[str, LLMRuleAnalysis]:
    return asyncio.run(batch_process_rules(rules))

# 5. Output Generators
def analyze_rules_intent(rules: List[FirewallRule]) -> List[AnalysisIssue]:
    llm_results = get_all_llm_analyses(rules)
    issues = []
    
    for rule in rules:
        llm_analysis = llm_results[rule.id]
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
                    "mitre": llm_analysis.mitre_techniques
                },
                "risk_score": llm_analysis.risk_score,
                "suggested_action": llm_analysis.recommendation,
            }
        ))
    return issues

def identify_high_risk_rules(rules: List[FirewallRule], threshold: int = 70) -> List[Dict]:
    llm_results = get_all_llm_analyses(rules)
    high_risk = []
    
    for rule in rules:
        llm_analysis = llm_results[rule.id]
        if llm_analysis.risk_score >= threshold:
            high_risk.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "risk_score": llm_analysis.risk_score,
                "summary": llm_analysis.intent_summary,
                "mitre": llm_analysis.mitre_techniques,
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
            "recommendation": item["recommended_action"],
        })
        
    return {
        "top_n": top_n,
        "threshold": threshold,
        "high_risk_count": len(high_risk),
        "plan_items": plan_items,
    }