"""
Rule OAG-012: Sensitive Data Exfiltration via External Sink.

Detects tools that simultaneously hold a reference to an external network
sink (HTTP POST/PUT/webhook) AND accept PII-named parameters, creating a
direct exfiltration path with no evidence of redaction.
"""

from typing import List, Set
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


_PII_PARAM_KEYWORDS: Set[str] = {
    "email", "phone", "ssn", "nric", "credit_card", "card_number",
    "passport", "dob", "address", "national_id", "tax_id", "iban",
    "bank_account", "social_security", "date_of_birth",
}

_EXTERNAL_SINK_KEYWORDS = (
    "post", "put", "patch", "webhook", "requests", "httpx",
    "aiohttp", "urllib", "send", "upload", "export", "transfer",
    "sendmail", "smtp", "publish",
)

_REDACTION_KEYWORDS = (
    "mask", "redact", "anonymize", "hash", "encrypt", "sanitize",
    "clean", "scrub", "tokenize",
)


@RuleRegistry.register
class OAG012SensitiveDataExfiltration(BaseRule):
    metadata = RuleMetadata(
        id="OAG-012",
        title="Sensitive Data Exfiltration via External Network Sink",
        description=(
            "Identifies tools that accept PII-named parameters (email, SSN, credit_card, etc.) "
            "and contain external network mutation sinks (HTTP POST/PUT, webhook, SMTP) without "
            "evidence of redaction or anonymization. This creates a direct PII exfiltration path "
            "controllable by agent reasoning."
        ),
        severity=Severity.CRITICAL,
        owasp_id="LLM02:2025",
        owasp_title="Sensitive Information Disclosure",
        imda_pillar="Pillar 3: Implement Technical Controls",
        remediation=(
            "Apply PII redaction/tokenization before any external network call. Remove PII "
            "parameters from tool signatures entirely; pass opaque references (user_id) instead. "
            "Add data loss prevention (DLP) middleware at the agent output boundary."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # Build a map from (file_path, tool_name) -> full function source text
        # by extracting lines from the visitor between the tool's start line
        # and the next top-level definition.
        full_sources: dict = {}
        for file_path, visitor in ctx.python_visitors.items():
            lines = visitor.lines
            for tool in visitor.tools:
                start = tool.line_number - 1  # 0-indexed
                # Gather lines until the next top-level def/class or EOF
                body_lines = []
                for i in range(start, len(lines)):
                    body_lines.append(lines[i])
                    if i > start and lines[i] and not lines[i][0].isspace() and lines[i].strip():
                        # Reached the next top-level statement
                        break
                full_sources[(file_path, tool.name)] = "\n".join(body_lines).lower()

        for tool in ctx.tools:
            if tool.framework == "mcp":
                continue

            # Check tool parameters for PII names
            pii_params = [
                p for p in tool.parameters
                if any(kw in p.lower() for kw in _PII_PARAM_KEYWORDS)
            ]
            if not pii_params:
                continue

            # Get the full function source text for sink/redaction analysis
            full_src = full_sources.get((tool.file_path, tool.name), "")
            if not full_src and tool.raw_code:
                full_src = tool.raw_code.lower()

            # Check for external network sinks anywhere in the function body
            has_external_sink = any(
                kw in sink.lower()
                for sink in tool.dangerous_sinks
                for kw in _EXTERNAL_SINK_KEYWORDS
            ) or any(kw in full_src for kw in _EXTERNAL_SINK_KEYWORDS)

            if not has_external_sink:
                continue

            # Check for redaction routines in the executable function body (ignoring comments/docstrings)
            clean_lines = []
            in_doc = False
            delim = None
            for line in full_sources.get((tool.file_path, tool.name), "").splitlines():
                stripped = line.strip()
                if in_doc:
                    if delim and delim in stripped:
                        in_doc = False
                    continue
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    delim = stripped[:3]
                    if stripped.count(delim) < 2:
                        in_doc = True
                    continue
                if stripped.startswith("#"):
                    continue
                code_segment = line.split("#", 1)[0]
                if code_segment.strip():
                    clean_lines.append(code_segment)

            clean_code = "\n".join(clean_lines)
            has_redaction = any(kw in clean_code for kw in _REDACTION_KEYWORDS)
            if has_redaction:
                continue

            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_title=self.metadata.title,
                    severity=self.metadata.severity,
                    file_path=tool.file_path,
                    line_number=tool.line_number,
                    column=1,
                    code_snippet=tool.raw_code or f"def {tool.name}(...)",
                    message=(
                        f"Tool '{tool.name}' accepts PII parameter(s) "
                        f"({', '.join(pii_params)}) and contains an external network "
                        "sink without PII redaction. This is a direct exfiltration path."
                    ),
                    remediation=self.metadata.remediation,
                    owasp_id=self.metadata.owasp_id,
                    imda_pillar=self.metadata.imda_pillar,
                )
            )

        return findings
