"""
OWASP Top 10 for LLM Applications Compliance Matrix Evaluator.
"""

from __future__ import annotations
from typing import List, Dict, Any
from orvyen.core.models import Finding


OWASP_LLM_ITEMS = {
    "LLM01": {
        "title": "Prompt Injection",
        "description": "Manipulating LLM behavior through crafted inputs in prompts.",
        "rules": ["OAG-002"],
    },
    "LLM02": {
        "title": "Sensitive Information Disclosure",
        "description": "Exposing confidential data, hardcoded secrets, or PII via outputs/logs.",
        "rules": ["OAG-003", "OAG-004", "OAG-012"],
    },
    "LLM06": {
        "title": "Excessive Agency",
        "description": "Granting agents over-permissioned tools, unbounded execution, or unaudited actions.",
        "rules": ["OAG-001", "OAG-006", "OAG-008", "OAG-010", "OAG-011"],
    },
    "LLM09": {
        "title": "Misinformation / Insecure Plugin Design",
        "description": "Insecure MCP/plugin transport exposing tool calls to interception.",
        "rules": ["OAG-009"],
    },
    "LLM10": {
        "title": "Unbounded Consumption",
        "description": "Resource exhaustion and financial loss from unconstrained loops and missing budgets.",
        "rules": ["OAG-005", "OAG-007"],
    },
}


class OWASPComplianceEvaluator:
    """Evaluates scan findings against OWASP Top 10 for LLM Applications."""

    @staticmethod
    def evaluate(findings: List[Finding]) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        tracked_items = len(OWASP_LLM_ITEMS)
        passed_items = 0

        findings_by_rule: Dict[str, List[Finding]] = {}
        for f in findings:
            findings_by_rule.setdefault(f.rule_id, []).append(f)

        for owasp_id, info in OWASP_LLM_ITEMS.items():
            violations = []
            for r_id in info["rules"]:
                if r_id in findings_by_rule:
                    violations.extend(findings_by_rule[r_id])

            is_pass = len(violations) == 0
            if is_pass:
                passed_items += 1

            results[owasp_id] = {
                "title": info["title"],
                "description": info["description"],
                "status": "PASS" if is_pass else "FAIL",
                "is_pass": is_pass,
                "violation_count": len(violations),
                "mapped_rules": info["rules"],
            }

        score_pct = int((passed_items / tracked_items) * 100) if tracked_items else 100

        return {
            "score_percentage": score_pct,
            "overall_status": "PASS" if score_pct == 100 else ("WARN" if score_pct >= 50 else "FAIL"),
            "items": results,
            "standard": "OWASP Top 10 for LLM Applications",
        }
