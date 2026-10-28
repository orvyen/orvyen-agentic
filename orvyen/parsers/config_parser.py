"""
Parser and secret scanner for configuration, environment (.env), and YAML files.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any


SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9_-]{20,}", "OpenAI / Generic Secret Key"),
    (r"sk-ant-[a-zA-Z0-9_-]{20,}", "Anthropic Secret Key"),
    (r"ghp_[a-zA-Z0-9]{30,}", "GitHub Personal Access Token"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,}", "Slack Token"),
    (r"AIza[0-9A-Za-z-_]{35}", "Google Cloud / Gemini API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Private Cryptographic Key"),
    (
        r"(?:api[_-]?key|secret[_-]?key|auth[_-]?token|password)\s*[:=]\s*['\"]([a-zA-Z0-9_!@#$%^&*()\-+=]{8,})['\"]",
        "Assigned Secret Variable",
    ),
]


class ConfigFileScanner:
    """Scans config and environment files for committed credentials."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Dict[str, Any]] = []

    def scan(self) -> List[Dict[str, Any]]:
        try:
            content = self.file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except Exception:
            return []

        for lineno, line in enumerate(lines, start=1):
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue

            for pattern, desc in SECRET_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Redact matched portion in snippet
                    secret_val = match.group(0)
                    redacted = secret_val[:4] + "*" * (max(4, len(secret_val) - 6)) + secret_val[-2:]
                    safe_snippet = line.replace(secret_val, redacted)

                    self.findings.append({
                        "file_path": str(self.file_path),
                        "line_number": lineno,
                        "column": match.start() + 1,
                        "description": desc,
                        "snippet": safe_snippet,
                        "message": f"Hardcoded credential detected ({desc}) in configuration.",
                    })
                    break

        return self.findings
