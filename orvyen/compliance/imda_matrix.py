"""
Singapore IMDA Model AI Governance Framework for Agentic AI (v1.5 / May 2026) Scorecard.
"""

from __future__ import annotations
from typing import List, Dict, Any
from orvyen.core.models import Finding


IMDA_PILLARS = {
    "Pillar 1": {
        "name": "Assess and Bound Risk Upfront",
        "description": "Establish operational boundaries, maximum recursion limits, and failure fallback modes.",
        "rules": ["OAG-002", "OAG-005", "OAG-011"],
    },
    "Pillar 2": {
        "name": "Make Humans Meaningfully Accountable",
        "description": "Ensure clear tool ownership, avoid orphaned components, and record comprehensive audit logs.",
        "rules": ["OAG-006", "OAG-008", "OAG-010"],
    },
    "Pillar 3": {
        "name": "Implement Technical Controls",
        "description": "Enforce principle of least privilege on tools, secure secret storage, PII redaction, and rate limiting.",
        "rules": ["OAG-001", "OAG-003", "OAG-004", "OAG-007", "OAG-009", "OAG-012"],
    },
    "Pillar 4": {
        "name": "Enable End-User Responsibility",
        "description": "Provide transparent capability disclosures, structured AIBOM manifests, and verifiable trails.",
        "rules": [],
    },
}


class IMDAComplianceEvaluator:
    """Evaluates scan findings against Singapore's IMDA Agentic AI 4-Pillar framework."""

    @staticmethod
    def evaluate(findings: List[Finding]) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        total_pillars = len(IMDA_PILLARS)
        compliant_pillars = 0

        findings_by_rule: Dict[str, List[Finding]] = {}
        for f in findings:
            findings_by_rule.setdefault(f.rule_id, []).append(f)

        for pillar_id, info in IMDA_PILLARS.items():
            violations = []
            for r_id in info["rules"]:
                if r_id in findings_by_rule:
                    violations.extend(findings_by_rule[r_id])

            is_compliant = len(violations) == 0
            if is_compliant:
                compliant_pillars += 1

            status = "COMPLIANT" if is_compliant else "NON-COMPLIANT"
            severity_counts = {
                "critical": sum(1 for v in violations if v.severity.value == "CRITICAL"),
                "high": sum(1 for v in violations if v.severity.value == "HIGH"),
                "medium": sum(1 for v in violations if v.severity.value == "MEDIUM"),
                "low": sum(1 for v in violations if v.severity.value == "LOW"),
            }

            results[pillar_id] = {
                "name": info["name"],
                "description": info["description"],
                "status": status,
                "is_compliant": is_compliant,
                "violation_count": len(violations),
                "severities": severity_counts,
                "governance_guidelines": "MAS AI Risk Management Guidelines / IMDA Agentic AI v1.5",
            }

        score_pct = int((compliant_pillars / total_pillars) * 100)
        return {
            "score_percentage": score_pct,
            "overall_status": "COMPLIANT" if score_pct == 100 else ("NEEDS_ATTENTION" if score_pct >= 50 else "FAILED"),
            "pillars": results,
            "framework_version": "IMDA Model AI Governance Framework for Agentic AI (May 2026)",
            "jurisdiction": "Singapore (IMDA / MAS)",
        }
