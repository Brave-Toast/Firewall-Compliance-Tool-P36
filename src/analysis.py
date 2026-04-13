from typing import List, Dict
from .schema import FirewallRule, AnalysisIssue
from z3 import Solver, String, And, Or, Not, sat, unsat

def _make_overlap_constraint(symbol, values):
    """Converts rule attributes into Z3 logical expressions."""
    if not values:
        return True
    normalized = [v.strip().lower() for v in values if v.strip()]
    if not normalized or "any" in normalized:
        return True
    return Or(*[symbol == v for v in normalized])

def analyze_firewall_comprehensive(rules: List[FirewallRule], forbidden_paths: List[Dict[str, str]] = None) -> List[AnalysisIssue]:
    issues = []
    
    # Symbolic packet headers for Z3
    src_z = String("src_zone")
    dst_z = String("dst_zone")
    app = String("app")
    svc = String("svc")

    for i in range(len(rules)):
        r1 = rules[i]
        
        # 1. Path Violation Detection (Single Rule Analysis)
        if forbidden_paths and r1.action.value == "allow":
            for path in forbidden_paths:
                s = Solver()
                s.add(_make_overlap_constraint(src_z, r1.source_zones))
                s.add(_make_overlap_constraint(dst_z, r1.destination_zones))
                s.add(src_z == path["from"].lower())
                s.add(dst_z == path["to"].lower())
                
                if s.check() == sat:
                    issues.append(AnalysisIssue(
                        severity="critical",
                        rule_id=r1.id,
                        rule_name=r1.name,
                        description=f"Security Path Violation: Rule allows forbidden path {path['from']} -> {path['to']}",
                        details={"forbidden_path": path}
                    ))

        for j in range(i + 1, len(rules)):
            r2 = rules[j]
            
            # Define logical constraints for both rules
            r1_con = And(
                _make_overlap_constraint(src_z, r1.source_zones),
                _make_overlap_constraint(dst_z, r1.destination_zones),
                _make_overlap_constraint(app, [r1.application] if r1.application else []),
                _make_overlap_constraint(svc, [r1.service] if r1.service else [])
            )
            r2_con = And(
                _make_overlap_constraint(src_z, r2.source_zones),
                _make_overlap_constraint(dst_z, r2.destination_zones),
                _make_overlap_constraint(app, [r2.application] if r2.application else []),
                _make_overlap_constraint(svc, [r2.service] if r2.service else [])
            )

            s = Solver()
            s.add(And(r1_con, r2_con))
            
            # Check if rules intersect at all
            if s.check() == sat:
                # Case A: Same Action -> Redundancy Check
                if r1.action == r2.action:
                    # R2 is redundant if it is a subset of R1
                    # Logic: Is there any traffic in R2 that is NOT in R1?
                    s_subset = Solver()
                    s_subset.add(And(r2_con, Not(r1_con)))
                    if s_subset.check() == unsat:
                        issues.append(AnalysisIssue(
                            severity="medium",
                            rule_id=r2.id,
                            rule_name=r2.name,
                            description=f"Redundancy: Rule {r2.id} is fully covered by earlier rule {r1.id}",
                            details={"covered_by": r1.id}
                        ))

                # Case B: Different Actions -> Shadowing or Correlation
                else:
                    s_r1_only = Solver()
                    s_r1_only.add(And(r1_con, Not(r2_con)))
                    
                    s_r2_only = Solver()
                    s_r2_only.add(And(r2_con, Not(r1_con)))
                    
                    # If both rules have unique traffic, it's Correlation
                    if s_r1_only.check() == sat and s_r2_only.check() == sat:
                        issue_type = "Correlation Conflict"
                        sev = "medium"
                    else:
                        # If R2 is a subset of R1 but actions differ, it's Shadowing
                        issue_type = "Shadowing Conflict"
                        sev = "high"

                    issues.append(AnalysisIssue(
                        severity=sev,
                        rule_id=f"{r1.id}-{r2.id}",
                        rule_name=f"{r1.name}<->{r2.name}",
                        description=f"SMT {issue_type} detected between {r1.id} and {r2.id}",
                        details={"conflict_type": issue_type}
                    ))

    return issues


def check_rule_anomalies(rules: List[FirewallRule]) -> List[AnalysisIssue]:
    """Basic anomaly detection ported from PAN-OS standalone script."""
    issues = []
    redundant_rules = set()
    shadowed_rules = set()
    collision_rules = set()

    def match_exact(l1, l2):
        return sorted(l1) == sorted(l2)
        
    def match_any(l1, l2):
        return match_exact(l1, l2) or "any" in l1 or "any" in l2

    for i in range(len(rules)):
        rule1 = rules[i]
        for j in range(i + 1, len(rules)):
            rule2 = rules[j]
            
            # Exact matches
            exact_sz = match_exact(rule1.source_zones, rule2.source_zones)
            exact_dz = match_exact(rule1.destination_zones, rule2.destination_zones)
            exact_sa = match_exact(rule1.source_addresses, rule2.source_addresses)
            exact_da = match_exact(rule1.destination_addresses, rule2.destination_addresses)
            exact_app = (rule1.application == rule2.application)
            exact_action = (rule1.action == rule2.action)

            # Any matches (for shadowing)
            any_sz = match_any(rule1.source_zones, rule2.source_zones)
            any_dz = match_any(rule1.destination_zones, rule2.destination_zones)
            any_sa = match_any(rule1.source_addresses, rule2.source_addresses)
            any_da = match_any(rule1.destination_addresses, rule2.destination_addresses)
            any_app = exact_app or (rule1.application in ["any", None]) or (rule2.application in ["any", None])

            # 1. Redundancy Check
            if exact_sz and exact_dz and exact_sa and exact_da and exact_app and exact_action:
                if rule2.id not in redundant_rules:
                    issues.append(AnalysisIssue(
                        severity="low",
                        rule_id=rule2.id,
                        rule_name=rule2.name,
                        description=f"[REDUNDANT] Rule adds no value. Identical to earlier rule {rule1.name}",
                        details={"type": "redundant", "covered_by": rule1.id}
                    ))
                    redundant_rules.add(rule2.id)

            # 2. Shadowed Check
            if any_sz and any_dz and any_sa and any_da and any_app:
                if rule2.id not in shadowed_rules:
                    issues.append(AnalysisIssue(
                        severity="medium",
                        rule_id=rule2.id,
                        rule_name=rule2.name,
                        description=f"[SHADOW] Rule will never be reached. Shadowed by earlier rule {rule1.name}",
                        details={"type": "shadowed", "shadowed_by": rule1.id}
                    ))
                    shadowed_rules.add(rule2.id)

            # 3. Collision Check
            if exact_sz and exact_dz and exact_sa and exact_da and exact_app and not exact_action:
                if rule2.id not in collision_rules:
                    issues.append(AnalysisIssue(
                        severity="high",
                        rule_id=rule2.id,
                        rule_name=rule2.name,
                        description=f"[COLLISION] Conflicting action for identical traffic as earlier rule {rule1.name}",
                        details={"type": "collision", "conflicts_with": rule1.id}
                    ))
                    collision_rules.add(rule2.id)

    return issues