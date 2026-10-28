"""
JSON reporter for CI/CD automation and machine-readable vulnerability ingestion.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional

from orvyen.core.models import ScanResult
from orvyen.compliance.aibom import AIBOMCompiler


class JSONReporter:
    """Generates JSON payloads for CI/CD pipelines and API consumers."""

    @classmethod
    def generate(cls, result: ScanResult) -> str:
        data = result.to_dict()
        if not data.get("aibom"):
            data["aibom"] = AIBOMCompiler.compile(result)
        return json.dumps(data, indent=2)

    @classmethod
    def write_to_file(cls, result: ScanResult, output_path: Path) -> Path:
        content = cls.generate(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path
