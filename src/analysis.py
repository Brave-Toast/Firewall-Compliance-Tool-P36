"""Utilities to analyse firewall rule sets and detect issues.

This module provides functions that perform both fast heuristics and
SMT-based checks (via Z3) to find redundancies, shadowing, collisions,
and forbidden path violations among firewall rules.
"""

import ipaddress
from typing import List, Dict, Set

from z3 import (
    Solver,
    String,
    And,
    Or,
    Not,
    sat,
    unsat,
    BitVec,
    BitVecVal,
    UGE,
    ULE,
)
from intervaltree import IntervalTree

from .schema import FirewallRule, AnalysisIssue


def _make_overlap_constraint(symbol, values):
    """Converts rule attributes into Z3 logical expressions."""
    if not values:
        return True
    normalized = [v.strip().lower() for v in values if v.strip()]
    if not normalized or "any" in normalized:
        return True
    return Or(*[symbol == v for v in normalized])


def _make_ip_constraint(symbol, values):
    """Converts a list of IP/CIDR strings into Z3 BitVec constraints."""
    if not values:
        return True
    normalized = [v.strip().lower() for v in values if v.strip()]
    if not normalized or "any" in normalized:
        return True

    constraints = []
    for val in normalized:
        try:
            net = ipaddress.ip_network(val, strict=False)
            start_ip = int(net.network_address)
            end_ip = int(net.broadcast_address)
            low = BitVecVal(start_ip, 32)
            high = BitVecVal(end_ip, 32)
            constraints.append(And(UGE(symbol, low), ULE(symbol, high)))
        except ValueError:
            # Ignore invalid CIDR/address values
            pass

    if not constraints:
        return True
    return Or(*constraints)


def _check_fast_overlap(r1: FirewallRule, r2: FirewallRule) -> bool:
    """Fast Python-based check to see if two rules might overlap before using Z3."""

    def match_overlap(l1, l2):
        if not l1 or not l2:
            return True
        l1_norm = [v.strip().lower() for v in l1 if v.strip()]
        l2_norm = [v.strip().lower() for v in l2 if v.strip()]
        if not l1_norm or "any" in l1_norm or not l2_norm or "any" in l2_norm:
            return True
        return bool(set(l1_norm) & set(l2_norm))

    if not match_overlap(r1.source_zones, r2.source_zones):
        return False
    if not match_overlap(r1.destination_zones, r2.destination_zones):
        return False
    if not match_overlap(
        [r1.application] if r1.application else [],
        [r2.application] if r2.application else [],
    ):
        return False
    if not match_overlap(
        [r1.service] if r1.service else [],
        [r2.service] if r2.service else [],
    ):
        return False

    def ip_overlap(l1, l2):
        if not l1 or not l2:
            return True
        l1_norm = [v.strip().lower() for v in l1 if v.strip()]
        l2_norm = [v.strip().lower() for v in l2 if v.strip()]
        if not l1_norm or "any" in l1_norm or not l2_norm or "any" in l2_norm:
            return True
        for ip1 in l1_norm:
            try:
                n1 = ipaddress.ip_network(ip1, strict=False)
            except ValueError:
                continue
            for ip2 in l2_norm:
                try:
                    n2 = ipaddress.ip_network(ip2, strict=False)
                    if n1.overlaps(n2):
                        return True
                except ValueError:
                    continue
        return False

    if not ip_overlap(r1.source_addresses, r2.source_addresses):
        return False
    if not ip_overlap(r1.destination_addresses, r2.destination_addresses):
        return False

    return True


def _build_ip_tree(rules: List[FirewallRule], is_source: bool) -> IntervalTree:
    tree = IntervalTree()
    for idx, rule in enumerate(rules):
        ips = rule.source_addresses if is_source else rule.destination_addresses

        if not ips or "any" in [v.strip().lower() for v in ips if v.strip()]:
            # Covers entire IPv4 space
            tree.addi(0, 4294967295 + 1, idx)
        else:
            for ip_str in ips:
                try:
                    net = ipaddress.ip_network(ip_str.strip().lower(), strict=False)
                    start = int(net.network_address)
                    end = int(net.broadcast_address)
                    tree.addi(start, end + 1, idx)
                except ValueError:
                    pass
    return tree


def _get_overlapping_indices(tree: IntervalTree, ips: List[str], total_rules: int) -> Set[int]:
    if not ips or "any" in [v.strip().lower() for v in ips if v.strip()]:
        return set(range(total_rules))

    indices = set()
    for ip_str in ips:
        try:
            net = ipaddress.ip_network(ip_str.strip().lower(), strict=False)
            start = int(net.network_address)
            end = int(net.broadcast_address)
            indices.update(interval.data for interval in tree.overlap(start, end + 1))
        except ValueError:
            pass
    return indices


def analyze_firewall_comprehensive(rules: List[FirewallRule], forbidden_paths: List[Dict[str, str]] = None) -> List[AnalysisIssue]:
    """Perform comprehensive analysis of firewall `rules`.

    This runs fast heuristic checks and (when needed) SMT-based checks
    to detect redundancies, shadowing, collisions, and forbidden-path
    violations. `forbidden_paths` can be provided to flag single-rule
    path violations.

    Args:
        rules: List of `FirewallRule` objects to analyze.
        forbidden_paths: Optional list of dicts with keys "from" and "to"
            representing disallowed zone-to-zone paths.

    Returns:
        A list of `AnalysisIssue` instances describing detected problems.
    """
    issues = []

    total_rules = len(rules)
    src_tree = _build_ip_tree(rules, True)
    dst_tree = _build_ip_tree(rules, False)

    # Symbolic packet headers for Z3
    src_z = String("src_zone")
    dst_z = String("dst_zone")
    app = String("app")
    svc = String("svc")
    src_ip = BitVec("src_ip", 32)
    dst_ip = BitVec("dst_ip", 32)

    for i, r1 in enumerate(rules):

        # 1. Path Violation Detection (Single Rule Analysis)
        if forbidden_paths and r1.action.value == "allow":
            for path in forbidden_paths:
                s = Solver()
                s.add(_make_overlap_constraint(src_z, r1.source_zones))
                s.add(_make_overlap_constraint(dst_z, r1.destination_zones))
                s.add(_make_ip_constraint(src_ip, r1.source_addresses))
                s.add(_make_ip_constraint(dst_ip, r1.destination_addresses))
                s.add(src_z == path["from"].lower())
                s.add(dst_z == path["to"].lower())

                if s.check() == sat:
                    issues.append(
                        AnalysisIssue(
                            severity="critical",
                            rule_id=r1.id,
                            rule_name=r1.name,
                            description=(
                                "Security Path Violation: Rule allows forbidden path "
                                + f"{path['from']} -> {path['to']}"
                            ),
                            details={"forbidden_path": path},
                        )
                    )

        src_overlaps = _get_overlapping_indices(src_tree, r1.source_addresses, total_rules)
        dst_overlaps = _get_overlapping_indices(dst_tree, r1.destination_addresses, total_rules)
        potential_overlaps = src_overlaps.intersection(dst_overlaps)

        for j in potential_overlaps:
            if j <= i:
                continue

            r2 = rules[j]

            # Fast Python pre-filter to bypass expensive SMT solvers if completely disjoint
            if not _check_fast_overlap(r1, r2):
                continue

            # Define logical constraints for both rules
            r1_con = And(
                _make_overlap_constraint(src_z, r1.source_zones),
                _make_overlap_constraint(dst_z, r1.destination_zones),
                _make_ip_constraint(src_ip, r1.source_addresses),
                _make_ip_constraint(dst_ip, r1.destination_addresses),
                _make_overlap_constraint(app, [r1.application] if r1.application else []),
                _make_overlap_constraint(svc, [r1.service] if r1.service else []),
            )
            r2_con = And(
                _make_overlap_constraint(src_z, r2.source_zones),
                _make_overlap_constraint(dst_z, r2.destination_zones),
                _make_ip_constraint(src_ip, r2.source_addresses),
                _make_ip_constraint(dst_ip, r2.destination_addresses),
                _make_overlap_constraint(app, [r2.application] if r2.application else []),
                _make_overlap_constraint(svc, [r2.service] if r2.service else []),
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
                        issues.append(
                            AnalysisIssue(
                                severity="medium",
                                rule_id=r2.id,
                                rule_name=r2.name,
                                description=(
                                    "Redundancy: Rule "
                                    + f"{r2.id} is fully covered by earlier rule {r1.id}"
                                ),
                                details={"covered_by": r1.id},
                            )
                        )

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

                    issues.append(
                        AnalysisIssue(
                            severity=sev,
                            rule_id=f"{r1.id}-{r2.id}",
                            rule_name=f"{r1.name}<->{r2.name}",
                            description=(
                                "SMT " + issue_type + " detected between " + f"{r1.id} and {r2.id}"
                            ),
                            details={"conflict_type": issue_type},
                        )
                    )

    return issues


def check_rule_anomalies(rules: List[FirewallRule]) -> List[AnalysisIssue]:
    """Basic anomaly detection ported from PAN-OS standalone script."""
    issues = []
    redundant_rules = set()
    shadowed_rules = set()
    collision_rules = set()

    def match_exact(l1, l2):
        """Return True when two lists match exactly (order-insensitive)."""
        return sorted(l1) == sorted(l2)

    def is_subset_list(l1, l2):
        """Return True when `l2` is a subset of `l1` by value comparison.

        Treat an empty or 'any' in `l1` as a universal match.
        """
        if not l1 or "any" in [v.lower() for v in l1]:
            return True
        if not l2 or "any" in [v.lower() for v in l2]:
            return False
        return set(l2).issubset(set(l1))

    def is_subset_ip(l1, l2):
        # Is l2 a subset of l1?
        if not l1 or "any" in [v.lower() for v in l1]:
            return True
        if not l2 or "any" in [v.lower() for v in l2]:
            return False

        for ip2_str in l2:
            try:
                n2 = ipaddress.ip_network(ip2_str.strip().lower(), strict=False)
            except ValueError:
                continue

            subset_found = False
            for ip1_str in l1:
                try:
                    n1 = ipaddress.ip_network(ip1_str.strip().lower(), strict=False)
                    if n2.subnet_of(n1):
                        subset_found = True
                        break
                except ValueError:
                    continue
            if not subset_found:
                return False
        return True

    for i, rule1 in enumerate(rules):
        for rule2 in rules[i + 1 :]:

            # Exact matches
            exact_sz = match_exact(rule1.source_zones, rule2.source_zones)
            exact_dz = match_exact(rule1.destination_zones, rule2.destination_zones)
            exact_sa = match_exact(rule1.source_addresses, rule2.source_addresses)
            exact_da = match_exact(rule1.destination_addresses, rule2.destination_addresses)
            exact_app = rule1.application == rule2.application
            exact_action = rule1.action == rule2.action

            # Subset matches (for shadowing where rule2 is subset of rule1)
            subset_sz = is_subset_list(rule1.source_zones, rule2.source_zones)
            subset_dz = is_subset_list(rule1.destination_zones, rule2.destination_zones)
            subset_sa = is_subset_ip(rule1.source_addresses, rule2.source_addresses)
            subset_da = is_subset_ip(rule1.destination_addresses, rule2.destination_addresses)
            if not rule1.application:
                subset_app = True
            else:
                subset_app = exact_app or str(rule1.application).lower() == "any"

            # 1. Redundancy Check
            if (
                exact_sz
                and exact_dz
                and exact_sa
                and exact_da
                and exact_app
                and exact_action
            ):
                if rule2.id not in redundant_rules:
                    issues.append(AnalysisIssue(
                        severity="low",
                        rule_id=rule2.id,
                        rule_name=rule2.name,
                        description=f"[REDUNDANT] Rule adds no value. Identical to earlier rule {rule1.name}",
                        details={"type": "redundant", "covered_by": rule1.id},
                    ))
                    redundant_rules.add(rule2.id)

            # 2. Shadowed Check
            if (
                subset_sz
                and subset_dz
                and subset_sa
                and subset_da
                and subset_app
            ):
                if rule2.id not in shadowed_rules:
                    issues.append(AnalysisIssue(
                        severity="medium",
                        rule_id=rule2.id,
                        rule_name=rule2.name,
                        description=f"[SHADOW] Rule will never be reached. Shadowed by earlier rule {rule1.name}",
                        details={"type": "shadowed", "shadowed_by": rule1.id},
                    ))
                    shadowed_rules.add(rule2.id)

            # 3. Collision Check
            if (
                exact_sz
                and exact_dz
                and exact_sa
                and exact_da
                and exact_app
                and not exact_action
            ):
                if rule2.id not in collision_rules:
                    issues.append(AnalysisIssue(
                        severity="high",
                        rule_id=rule2.id,
                        rule_name=rule2.name,
                        description=f"[COLLISION] Conflicting action for identical traffic as earlier rule {rule1.name}",
                        details={"type": "collision", "conflicts_with": rule1.id},
                    ))
                    collision_rules.add(rule2.id)
    return issues


def simulate_proposed_rule(rules: List[FirewallRule], proposed_rule: FirewallRule) -> List[AnalysisIssue]:
    """Tests a proposed rule against existing rules using Z3 solver."""
    issues = []

    src_z = String("src_zone")
    dst_z = String("dst_zone")
    app = String("app")
    svc = String("svc")
    src_ip = BitVec("src_ip", 32)
    dst_ip = BitVec("dst_ip", 32)

    r2 = proposed_rule
    r2_con = And(
        _make_overlap_constraint(src_z, r2.source_zones),
        _make_overlap_constraint(dst_z, r2.destination_zones),
        _make_ip_constraint(src_ip, r2.source_addresses),
        _make_ip_constraint(dst_ip, r2.destination_addresses),
        _make_overlap_constraint(app, [r2.application] if r2.application else []),
        _make_overlap_constraint(svc, [r2.service] if r2.service else []),
    )

    for r1 in rules:
        if not _check_fast_overlap(r1, r2):
            continue

        r1_con = And(
            _make_overlap_constraint(src_z, r1.source_zones),
            _make_overlap_constraint(dst_z, r1.destination_zones),
            _make_ip_constraint(src_ip, r1.source_addresses),
            _make_ip_constraint(dst_ip, r1.destination_addresses),
            _make_overlap_constraint(app, [r1.application] if r1.application else []),
            _make_overlap_constraint(svc, [r1.service] if r1.service else []),
        )

        s = Solver()
        s.add(And(r1_con, r2_con))

        if s.check() == sat:
            if r1.action == r2.action:
                s_subset = Solver()
                s_subset.add(And(r2_con, Not(r1_con)))
                if s_subset.check() == unsat:
                    issues.append(AnalysisIssue(
                        severity="medium",
                        rule_id=r2.id,
                        rule_name=r2.name,
                        description=f"Redundancy: Proposed rule is fully covered by existing rule {r1.id}",
                        details={"covered_by": r1.id},
                    ))
            else:
                s_r1_only = Solver()
                s_r1_only.add(And(r1_con, Not(r2_con)))
                s_r2_only = Solver()
                s_r2_only.add(And(r2_con, Not(r1_con)))

                if s_r1_only.check() == sat and s_r2_only.check() == sat:
                    issue_type = "Correlation Conflict"
                    sev = "medium"
                else:
                    issue_type = "Shadowing Conflict"
                    sev = "high"

                issues.append(AnalysisIssue(
                    severity=sev,
                    rule_id=f"{r1.id}-{r2.id}",
                    rule_name=f"{r1.name}<->{r2.name}",
                    description=f"SMT {issue_type} detected between existing rule {r1.id} and proposed rule",
                    details={"conflict_type": issue_type},
                ))

    return issues
