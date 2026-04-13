from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from .parsers.paloalto import PaloAltoParser
from .normalizer import normalize_rules
from .analysis import find_shadowing_and_redundancy, verify_rules_with_z3
from .intent import analyze_rules_intent, generate_policy_hardening_plan

app = FastAPI(title="Firewall Compliance Analyzer")


class RuleUpload(BaseModel):
    vendor: str
    rules: List[str]


class AnalyzeResponse(BaseModel):
    parsed_count: int
    redundancy_issues: List[dict]
    formal_issues: List[dict]
    intent_issues: List[dict]


class RecommendResponse(BaseModel):
    high_risk_count: int
    plan_items: List[dict]


def _parse_and_normalize_upload(payload: RuleUpload):
    if payload.vendor.lower() != "paloalto":
        raise HTTPException(status_code=400, detail="Only paloalto vendor supported in minimal API")
    text = "\n".join(payload.rules)
    rules = PaloAltoParser.parse_from_text(text)
    return normalize_rules(rules)


@app.get("/health")
def health():
    return {"status": "ok", "service": "firewall-compliance"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: RuleUpload):
    rules = _parse_and_normalize_upload(payload)
    redundancy = find_shadowing_and_redundancy(rules)
    formal = verify_rules_with_z3(rules)
    intent = analyze_rules_intent(rules)
    return AnalyzeResponse(
        parsed_count=len(rules),
        redundancy_issues=[i.model_dump() for i in redundancy],
        formal_issues=[i.model_dump() for i in formal],
        intent_issues=[i.model_dump() for i in intent],
    )


@app.post("/recommend", response_model=RecommendResponse)
def recommend(payload: RuleUpload, top_n: Optional[int] = 10, threshold: Optional[int] = 70):
    rules = _parse_and_normalize_upload(payload)
    plan = generate_policy_hardening_plan(rules, top_n=top_n, threshold=threshold)
    return RecommendResponse(
        high_risk_count=plan["high_risk_count"],
        plan_items=plan["plan_items"],
    )
