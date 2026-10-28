"""
Core data models for Orvyen Agentic scanner.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def level(self) -> int:
        levels = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
        return levels.get(self.value, 0)

    def __ge__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level >= other.level

    def __gt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level > other.level

    def __le__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level <= other.level

    def __lt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level < other.level


class ToolPrivilege(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    ADMIN = "ADMIN"


@dataclass
class ToolDefinition:
    name: str
    framework: str  # "langchain", "crewai", "langgraph", "mcp", "custom"
    privilege: ToolPrivilege
    file_path: str
    line_number: int
    dangerous_sinks: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    docstring: Optional[str] = None
    is_audited: bool = False
    is_bound: bool = False  # Track whether bound to an agent executor/graph
    raw_code: Optional[str] = None


@dataclass
class AgentNode:
    name: str
    framework: str  # "langgraph", "crewai", "langchain", "raw"
    file_path: str
    line_number: int
    model_name: Optional[str] = None
    bound_tools: List[str] = field(default_factory=list)
    system_prompt_expr: Optional[str] = None
    is_fstring_prompt: bool = False
    recursion_limit: Optional[int] = None
    step_limit: Optional[int] = None
    has_audit_logging: bool = False


@dataclass
class MCPServer:
    name: str
    command: str
    args: List[str] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)
    tools: List[str] = field(default_factory=list)
    file_path: str = ""
    line_number: int = 1


@dataclass
class GraphEdge:
    source: str
    target: str
    condition: Optional[str] = None
    file_path: str = ""
    line_number: int = 1


@dataclass
class RuleMetadata:
    id: str
    title: str
    description: str
    severity: Severity
    owasp_id: str
    owasp_title: str
    imda_pillar: str
    remediation: str


@dataclass
class Finding:
    rule_id: str
    rule_title: str
    severity: Severity
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    message: str
    remediation: str
    owasp_id: str
    imda_pillar: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "message": self.message,
            "remediation": self.remediation,
            "owasp_id": self.owasp_id,
            "imda_pillar": self.imda_pillar,
        }


@dataclass
class ScanResult:
    target_path: str
    files_scanned: int
    duration_ms: float
    findings: List[Finding] = field(default_factory=list)
    tools: List[ToolDefinition] = field(default_factory=list)
    agents: List[AgentNode] = field(default_factory=list)
    mcp_servers: List[MCPServer] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    aibom: Optional[Dict[str, Any]] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def security_score(self) -> int:
        """Calculate a 0-100 security score based on weighted deductions."""
        score = 100
        score -= self.critical_count * 25
        score -= self.high_count * 12
        score -= self.medium_count * 5
        score -= self.low_count * 2
        return max(0, min(100, score))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "files_scanned": self.files_scanned,
            "duration_ms": round(self.duration_ms, 2),
            "summary": {
                "security_score": self.security_score,
                "total_findings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "tools": [
                {
                    "name": t.name,
                    "framework": t.framework,
                    "privilege": t.privilege.value,
                    "file_path": t.file_path,
                    "line_number": t.line_number,
                    "dangerous_sinks": t.dangerous_sinks,
                    "is_audited": t.is_audited,
                    "is_bound": t.is_bound,
                }
                for t in self.tools
            ],
            "agents": [
                {
                    "name": a.name,
                    "framework": a.framework,
                    "file_path": a.file_path,
                    "line_number": a.line_number,
                    "model_name": a.model_name,
                    "bound_tools": a.bound_tools,
                    "recursion_limit": a.recursion_limit,
                    "step_limit": a.step_limit,
                    "has_audit_logging": a.has_audit_logging,
                }
                for a in self.agents
            ],
            "mcp_servers": [
                {
                    "name": s.name,
                    "command": s.command,
                    "args": s.args,
                    "tools": s.tools,
                    "file_path": s.file_path,
                }
                for s in self.mcp_servers
            ],
            "aibom": self.aibom,
        }
