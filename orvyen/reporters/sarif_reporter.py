"""
SARIF 2.1.0 reporter for GitHub Advanced Security and CI/CD code scanning integration.
Produces Oasis SARIF standard JSON output with rule definitions, severity mapping,
and physical source region locations.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from orvyen.core.models import Finding, ScanResult, Severity
from orvyen.rules.base import RuleRegistry


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map Orvyen Severity to SARIF 2.1.0 result level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _normalize_path(path_str: str) -> str:
    """Normalize file path to forward slashes for cross-platform SARIF URIs."""
    return path_str.replace("\\", "/")


class SARIFReporter:
    """Generates SARIF 2.1.0 output for GitHub Code Scanning and security dashboards."""

    @classmethod
    def generate(cls, result: ScanResult, scanner_version: str = "0.3.0") -> str:
        data = cls.generate_dict(result, scanner_version=scanner_version)
        return json.dumps(data, indent=2)

    @classmethod
    def generate_dict(cls, result: ScanResult, scanner_version: str = "0.3.0") -> Dict[str, Any]:
        # Collect distinct rules referenced by findings and registered in catalog
        all_rules = RuleRegistry.get_all_rules()
        rule_registry_map = {r.metadata.id: r.metadata for r in all_rules}

        # Build list of SARIF rule definitions
        sarif_rules: List[Dict[str, Any]] = []
        rule_id_to_index: Dict[str, int] = {}

        sorted_rule_ids = sorted(rule_registry_map.keys())
        for idx, rid in enumerate(sorted_rule_ids):
            meta = rule_registry_map[rid]
            rule_id_to_index[rid] = idx
            sarif_rules.append({
                "id": meta.id,
                "name": meta.title.replace(" ", ""),
                "shortDescription": {
                    "text": meta.title,
                },
                "fullDescription": {
                    "text": meta.description,
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(meta.severity),
                },
                "help": {
                    "text": meta.remediation,
                    "markdown": (
                        f"**Remediation:** {meta.remediation}\n\n"
                        f"- **OWASP LLM:** {meta.owasp_id or 'N/A'}\n"
                        f"- **IMDA Pillar:** {meta.imda_pillar or 'N/A'}"
                    ),
                },
                "properties": {
                    "precision": "very-high",
                    "problem.severity": _severity_to_sarif_level(meta.severity),
                    "tags": [
                        "security",
                        "ai-agent",
                        meta.owasp_id or "OWASP-LLM",
                        meta.imda_pillar or "IMDA",
                    ],
                    "owasp_id": meta.owasp_id,
                    "imda_pillar": meta.imda_pillar,
                },
            })

        # Build SARIF results
        sarif_results: List[Dict[str, Any]] = []
        for f in result.findings:
            norm_path = _normalize_path(f.file_path)
            line = max(1, f.line_number or 1)
            col = max(1, f.column or 1)

            sarif_result: Dict[str, Any] = {
                "ruleId": f.rule_id,
                "ruleIndex": rule_id_to_index.get(f.rule_id, 0),
                "level": _severity_to_sarif_level(f.severity),
                "message": {
                    "text": f.message,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": norm_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": line,
                                "startColumn": col,
                                "snippet": {
                                    "text": f.code_snippet or f.message,
                                },
                            },
                        },
                    }
                ],
                "properties": {
                    "severity": f.severity.name,
                    "owasp_id": f.owasp_id,
                    "imda_pillar": f.imda_pillar,
                    "remediation": f.remediation,
                },
            }
            sarif_results.append(sarif_result)

        now_utc = datetime.now(timezone.utc).isoformat()

        sarif_doc: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Orvyen Agentic",
                            "version": scanner_version,
                            "semanticVersion": scanner_version,
                            "informationUri": "https://github.com/algorzen/orvyen-agentic",
                            "rules": sarif_rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": now_utc,
                        }
                    ],
                    "results": sarif_results,
                }
            ],
        }

        return sarif_doc

    @classmethod
    def write_to_file(cls, result: ScanResult, output_path: Path, scanner_version: str = "0.3.0") -> Path:
        content = cls.generate(result, scanner_version=scanner_version)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path
