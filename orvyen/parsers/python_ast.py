"""
AST-based static analyzer for Python agent code (LangChain, LangGraph, CrewAI).
"""

from __future__ import annotations
import ast
import re
from pathlib import Path
from typing import List, Dict, Set, Any, Optional, Tuple

from orvyen.core.models import (
    ToolDefinition,
    ToolPrivilege,
    AgentNode,
    GraphEdge,
)
from orvyen.parsers.config_parser import SECRET_PATTERNS

SECRET_KEYWORDS = (
    "api_key",
    "apikey",
    "secret_key",
    "secretkey",
    "auth_token",
    "authtoken",
    "access_token",
    "accesstoken",
    "private_key",
    "privkey",
    "client_secret",
    "password",
    "passwd",
    "db_pass",
    "db_password",
    "app_secret",
)


def _is_secret_identifier(name: str) -> bool:
    name_lower = name.lower()
    if any(k in name_lower for k in SECRET_KEYWORDS):
        return True
    if name_lower in ("secret", "token", "password", "api_key", "apikey"):
        return True
    return False


def _is_placeholder_secret(val: str) -> bool:
    v = val.strip().lower()
    if len(v) < 8:
        return True
    if v.startswith(("$", "{", "%")) or v.endswith(("}", "%")):
        return True
    placeholders = {
        "your-api-key",
        "your_api_key",
        "your-api-key-here",
        "your_api_key_here",
        "your-token-here",
        "your_token_here",
        "enter_api_key",
        "placeholder",
        "changeme",
        "dummy",
        "redacted",
        "todo",
        "sample",
        "example",
    }
    if v in placeholders:
        return True
    if any(p in v for p in ("your-api-key", "your_api_key", "your-key", "insert_key", "<your-")):
        return True
    if v.startswith("<") and v.endswith(">"):
        return True
    return False


class PythonAgentASTVisitor(ast.NodeVisitor):
    """
    Traverses Python AST to identify tools, agent graphs, prompt templates,
    PII references, dangerous sinks, and recursion bounds.
    """

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.splitlines()

        self.tools: List[ToolDefinition] = []
        self.agents: List[AgentNode] = []
        self.edges: List[GraphEdge] = []
        self.bound_tool_names: Set[str] = set()

        # AST Raw Findings & Signals
        self.system_prompt_injections: List[Dict[str, Any]] = []
        self.hardcoded_secrets: List[Dict[str, Any]] = []
        self.pii_exposures: List[Dict[str, Any]] = []
        self.dangerous_sinks_found: List[Dict[str, Any]] = []
        self.unaudited_mutations: List[Dict[str, Any]] = []
        self.unbounded_loops: List[Dict[str, Any]] = []

        # Tracking state during traversal
        self.current_function: Optional[ast.FunctionDef] = None
        self.declared_tool_names: Set[str] = set()
        self.state_graphs: Dict[str, Dict[str, Any]] = {}
        self._seen_secrets: Set[Tuple[int, str]] = set()

    def _record_secret(
        self,
        lineno: int,
        col_offset: int,
        secret_val: str,
        desc: str,
        custom_message: Optional[str] = None,
    ) -> None:
        key = (lineno, secret_val)
        if key in self._seen_secrets:
            return
        self._seen_secrets.add(key)

        line_str = self.lines[lineno - 1] if 1 <= lineno <= len(self.lines) else ""
        if secret_val in line_str:
            redacted = secret_val[:4] + "*" * (max(4, len(secret_val) - 6)) + secret_val[-2:]
            safe_snippet = line_str.replace(secret_val, redacted)
        else:
            redacted = secret_val[:4] + "*" * (max(4, len(secret_val) - 6)) + secret_val[-2:]
            safe_snippet = f'"{redacted}"'

        message = custom_message or f"Hardcoded credential detected ({desc}) in Python source code."
        self.hardcoded_secrets.append({
            "file_path": self.file_path,
            "line_number": lineno,
            "column": col_offset + 1,
            "col_offset": col_offset,
            "description": desc,
            "snippet": safe_snippet,
            "message": message,
        })

    def _scan_comments_for_secrets(self) -> None:
        """Scan line comments for exposed credential tokens."""
        for lineno, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            if "#" in stripped:
                comment_part = stripped[stripped.index("#"):]
                for pattern, desc in SECRET_PATTERNS[:9]:
                    match = re.search(pattern, comment_part)
                    if match:
                        matched_val = match.group(0)
                        col = stripped.index(matched_val)
                        self._record_secret(
                            lineno,
                            col,
                            matched_val,
                            desc,
                            f"Hardcoded credential detected ({desc}) in Python source comment.",
                        )
                        break

    def visit_Assign(self, node: ast.Assign) -> None:
        self._inspect_assign_secrets(node)
        self.generic_visit(node)

    def _inspect_assign_secrets(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val_str = node.value.value
            for target in node.targets:
                target_name = self._get_call_name(target)
                if _is_secret_identifier(target_name) and not _is_placeholder_secret(val_str):
                    matched_desc = "Assigned Secret Variable"
                    for pattern, token_desc in SECRET_PATTERNS[:9]:
                        if re.search(pattern, val_str):
                            matched_desc = token_desc
                            break
                    self._record_secret(node.lineno, node.col_offset, val_str, matched_desc)
                    break

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val_str = node.value.value
            target_name = self._get_call_name(node.target)
            if _is_secret_identifier(target_name) and not _is_placeholder_secret(val_str):
                matched_desc = "Assigned Secret Variable"
                for pattern, token_desc in SECRET_PATTERNS[:9]:
                    if re.search(pattern, val_str):
                        matched_desc = token_desc
                        break
                self._record_secret(node.lineno, node.col_offset, val_str, matched_desc)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for k, v in zip(node.keys, node.values):
            if k and isinstance(k, ast.Constant) and isinstance(k.value, str):
                if _is_secret_identifier(k.value):
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        val_str = v.value
                        if not _is_placeholder_secret(val_str):
                            matched_desc = "Dictionary Secret Value"
                            for pattern, token_desc in SECRET_PATTERNS[:9]:
                                if re.search(pattern, val_str):
                                    matched_desc = token_desc
                                    break
                            lineno = getattr(v, "lineno", node.lineno)
                            col = getattr(v, "col_offset", node.col_offset)
                            self._record_secret(lineno, col, val_str, matched_desc)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) >= 16:
            for pattern, desc in SECRET_PATTERNS[:9]:
                match = re.search(pattern, node.value)
                if match:
                    matched_val = match.group(0)
                    self._record_secret(
                        node.lineno,
                        node.col_offset,
                        matched_val,
                        desc,
                    )
                    break
        self.generic_visit(node)

    def get_code_snippet(self, lineno: int, context_lines: int = 1) -> str:
        """Return lines of code around lineno (1-indexed)."""
        if not (1 <= lineno <= len(self.lines)):
            return ""
        start = max(0, lineno - 1 - context_lines)
        end = min(len(self.lines), lineno + context_lines)
        return "\n".join(self.lines[start:end])

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev_func = self.current_function
        self.current_function = node

        # 1. Check if decorated with @tool or @tool(...)
        is_tool = False
        tool_framework = "custom"
        for dec in node.decorator_list:
            dec_id = ""
            if isinstance(dec, ast.Name):
                dec_id = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_id = dec.attr
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    dec_id = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    dec_id = dec.func.attr

            if dec_id in ("tool", "structured_tool"):
                is_tool = True
                tool_framework = "langchain"
                break

        # Sinks and privileges
        sinks, privilege, has_audit = self._analyze_function_body(node)

        if is_tool:
            self.declared_tool_names.add(node.name)
            docstring = ast.get_docstring(node)
            params = [a.arg for a in node.args.args if a.arg != "self"]
            tool_def = ToolDefinition(
                name=node.name,
                framework=tool_framework,
                privilege=privilege,
                file_path=self.file_path,
                line_number=node.lineno,
                dangerous_sinks=sinks,
                parameters=params,
                docstring=docstring,
                is_audited=has_audit,
                raw_code=self.get_code_snippet(node.lineno, context_lines=2),
            )
            self.tools.append(tool_def)

        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        # Treat async functions the same as sync functions for tool analysis
        self.visit_FunctionDef(node)  # type: ignore

    def _analyze_function_body(self, func_node: ast.FunctionDef) -> Tuple[List[str], ToolPrivilege, bool]:
        """Inspect calls inside function for dangerous sinks, audit logs, and privilege."""
        sinks = []
        privilege = ToolPrivilege.READ
        has_audit = False

        for subnode in ast.walk(func_node):
            if isinstance(subnode, ast.Call):
                call_name = self._get_call_name(subnode.func)
                call_lower = call_name.lower()

                # Audit detection
                if any(k in call_lower for k in ("log", "logger", "audit", "trace", "callback")):
                    has_audit = True

                # Dangerous OS / Shell sinks
                if any(shell in call_lower for shell in (
                    "system", "popen", "subprocess", "spawn", "exec", "eval", "bashprocess"
                )):
                    sinks.append(f"ShellExecution: {call_name}")
                    privilege = ToolPrivilege.EXECUTE

                # Destructive DB operations
                if "execute" in call_lower or "cursor" in call_lower or "query" in call_lower:
                    # Check string arguments for destructive SQL
                    for arg in subnode.args:
                        sql_text = self._extract_string_literal(arg)
                        if sql_text:
                            upper_sql = sql_text.upper()
                            if any(w in upper_sql for w in ("DROP", "TRUNCATE", "ALTER", "DELETE FROM", "GRANT")):
                                sinks.append(f"DestructiveSQL: {upper_sql[:40]}")
                                privilege = ToolPrivilege.ADMIN
                            elif any(w in upper_sql for w in ("INSERT", "UPDATE", "CREATE")):
                                sinks.append(f"MutatingSQL: {upper_sql[:40]}")
                                if privilege != ToolPrivilege.ADMIN:
                                    privilege = ToolPrivilege.WRITE

                # Filesystem write/delete
                if call_name in ("open",) and len(subnode.args) >= 2:
                    mode = self._extract_string_literal(subnode.args[1])
                    if mode and any(m in mode for m in ("w", "a", "+")):
                        sinks.append(f"FileWrite: mode='{mode}'")
                        if privilege not in (ToolPrivilege.ADMIN, ToolPrivilege.EXECUTE):
                            privilege = ToolPrivilege.WRITE

                if any(fs in call_lower for fs in ("remove", "unlink", "rmdir", "rmtree")):
                    sinks.append(f"FileDeletion: {call_name}")
                    privilege = ToolPrivilege.ADMIN

                # External network mutation
                if any(net in call_lower for net in ("post", "delete", "put", "patch", "sendmail")):
                    sinks.append(f"ExternalNetworkMutation: {call_name}")
                    if privilege not in (ToolPrivilege.ADMIN, ToolPrivilege.EXECUTE):
                        privilege = ToolPrivilege.WRITE

        return sinks, privilege, has_audit

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node.func)

        # 2. Framework Agent / Graph detection
        # LangGraph: StateGraph(...)
        if "StateGraph" in call_name:
            # Found StateGraph initialization
            pass

        # LangGraph: workflow.add_node("node_name", func)
        if call_name.endswith(".add_node"):
            if len(node.args) >= 1:
                node_name = self._extract_string_literal(node.args[0])
                if node_name:
                    self.agents.append(AgentNode(
                        name=node_name,
                        framework="langgraph",
                        file_path=self.file_path,
                        line_number=node.lineno,
                    ))

        # LangGraph: workflow.add_edge("from", "to")
        if call_name.endswith(".add_edge"):
            if len(node.args) >= 2:
                src = self._extract_string_literal(node.args[0]) or ""
                dst = self._extract_string_literal(node.args[1]) or ""
                if src and dst:
                    self.edges.append(GraphEdge(
                        source=src,
                        target=dst,
                        file_path=self.file_path,
                        line_number=node.lineno,
                    ))

        # LangGraph: workflow.add_conditional_edges("from", router_func, {...})
        if call_name.endswith(".add_conditional_edges"):
            if len(node.args) >= 3 and isinstance(node.args[2], ast.Dict):
                src = self._extract_string_literal(node.args[0]) or ""
                for target_expr in node.args[2].values:
                    dst = self._extract_string_literal(target_expr) or ""
                    if src and dst:
                        self.edges.append(GraphEdge(
                            source=src,
                            target=dst,
                            condition="conditional",
                            file_path=self.file_path,
                            line_number=node.lineno,
                        ))

        # LangGraph: workflow.compile(...)
        is_langgraph_file = any(lg in self.source_code for lg in ("langgraph", "StateGraph", "MessageGraph"))
        is_non_langgraph_call = call_name.startswith(("re.", "regex.", "AIBOMCompiler.", "Compiler.", "compiler.", "Pattern."))
        if is_langgraph_file and call_name.endswith(".compile") and not is_non_langgraph_call:
            # Check for recursion_limit or checkpointer
            has_recursion_limit = False
            limit_val = None
            for kw in node.keywords:
                if kw.arg in ("recursion_limit", "max_iterations"):
                    has_recursion_limit = True
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                        limit_val = kw.value.value

            if has_recursion_limit:
                # Propagate this recursion limit to all LangGraph nodes in this file
                for a in self.agents:
                    if a.framework == "langgraph" and a.recursion_limit is None:
                        a.recursion_limit = limit_val
            else:
                self.unbounded_loops.append({
                    "framework": "langgraph",
                    "line_number": node.lineno,
                    "col_offset": node.col_offset,
                    "snippet": self.get_code_snippet(node.lineno),
                    "message": "LangGraph compilation missing explicit 'recursion_limit' safeguard.",
                })

        # CrewAI: Agent(role=..., goal=..., tools=[...], max_iter=...)
        if call_name == "Agent" or call_name.endswith(".Agent"):
            bound_tools: List[str] = []
            has_max_iter = False
            max_iter_val = None
            role_name = "CrewAIAgent"

            for kw in node.keywords:
                if kw.arg == "role" and isinstance(kw.value, ast.Constant):
                    role_name = str(kw.value.value)
                elif kw.arg == "tools" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        t_name = self._get_call_name(elt)
                        if t_name:
                            bound_tools.append(t_name)
                            self.bound_tool_names.add(t_name)
                elif kw.arg == "max_iter":
                    has_max_iter = True
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                        max_iter_val = kw.value.value

            if not has_max_iter:
                self.unbounded_loops.append({
                    "framework": "crewai",
                    "line_number": node.lineno,
                    "col_offset": node.col_offset,
                    "snippet": self.get_code_snippet(node.lineno),
                    "message": f"CrewAI Agent '{role_name}' configured without 'max_iter' circuit breaker.",
                })

            self.agents.append(AgentNode(
                name=role_name,
                framework="crewai",
                file_path=self.file_path,
                line_number=node.lineno,
                bound_tools=bound_tools,
                step_limit=max_iter_val,
            ))

        # LangChain: AgentExecutor(tools=[...], max_iterations=...)
        if "AgentExecutor" in call_name:
            has_max_iter = False
            bound_tools = []
            for kw in node.keywords:
                if kw.arg == "max_iterations":
                    has_max_iter = True
                elif kw.arg == "tools" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        t_name = self._get_call_name(elt)
                        if t_name:
                            bound_tools.append(t_name)
                            self.bound_tool_names.add(t_name)

            if not has_max_iter:
                self.unbounded_loops.append({
                    "framework": "langchain",
                    "line_number": node.lineno,
                    "col_offset": node.col_offset,
                    "snippet": self.get_code_snippet(node.lineno),
                    "message": "LangChain AgentExecutor instantiated without 'max_iterations' ceiling.",
                })

        # LangChain tool binding: llm.bind_tools([tool1, tool2])
        if call_name.endswith(".bind_tools"):
            if len(node.args) >= 1 and isinstance(node.args[0], ast.List):
                for elt in node.args[0].elts:
                    t_name = self._get_call_name(elt)
                    if t_name:
                        self.bound_tool_names.add(t_name)

        # 3. System Prompt & Prompt Injection Detection
        self._inspect_prompt_construction(node, call_name)

        # 4. PII flow detection in call arguments
        self._inspect_pii_in_call(node, call_name)

        # 5. Call keyword argument credentials inspection
        for kw in node.keywords:
            if kw.arg and _is_secret_identifier(kw.arg):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    val_str = kw.value.value
                    if not _is_placeholder_secret(val_str):
                        matched_desc = "Call Keyword Secret Argument"
                        for pattern, token_desc in SECRET_PATTERNS[:9]:
                            if re.search(pattern, val_str):
                                matched_desc = token_desc
                                break
                        lineno = getattr(kw.value, "lineno", getattr(kw, "lineno", node.lineno))
                        col = getattr(kw.value, "col_offset", getattr(kw, "col_offset", node.col_offset))
                        self._record_secret(lineno, col, val_str, matched_desc)

        self.generic_visit(node)

    def _inspect_prompt_construction(self, node: ast.Call, call_name: str) -> None:
        """Detect raw concatenation or f-strings injecting user variables into SystemMessage/prompts."""
        is_system_prompt_target = any(k in call_name for k in (
            "SystemMessage", "SystemMessagePromptTemplate", "ChatPromptTemplate"
        ))

        # Check keyword content in SystemMessage(content=...)
        if is_system_prompt_target:
            for kw in node.keywords:
                if kw.arg in ("content", "system", "template"):
                    if isinstance(kw.value, ast.JoinedStr):  # f-string!
                        self.system_prompt_injections.append({
                            "line_number": node.lineno,
                            "col_offset": node.col_offset,
                            "snippet": self.get_code_snippet(node.lineno),
                            "message": "Unsanitized f-string variable interpolation inside system prompt instruction.",
                        })
                    elif isinstance(kw.value, ast.BinOp) and isinstance(kw.value.op, ast.Add):
                        self.system_prompt_injections.append({
                            "line_number": node.lineno,
                            "col_offset": node.col_offset,
                            "snippet": self.get_code_snippet(node.lineno),
                            "message": "Unescaped string concatenation ('+') directly into system prompt instruction.",
                        })

        # Also check tuple patterns like ("system", f"You are... {user_input}")
        for arg in node.args:
            if isinstance(arg, (ast.List, ast.Tuple)):
                for elt in arg.elts:
                    if isinstance(elt, (ast.List, ast.Tuple)) and len(elt.elts) == 2:
                        role_literal = self._extract_string_literal(elt.elts[0])
                        if role_literal and role_literal.lower() == "system":
                            val_node = elt.elts[1]
                            if isinstance(val_node, ast.JoinedStr):
                                self.system_prompt_injections.append({
                                    "line_number": elt.lineno,
                                    "col_offset": elt.col_offset,
                                    "snippet": self.get_code_snippet(elt.lineno),
                                    "message": "Dynamic f-string passed as ('system', ...) message in prompt tuple.",
                                })
                            elif isinstance(val_node, ast.BinOp) and isinstance(val_node.op, ast.Add):
                                self.system_prompt_injections.append({
                                    "line_number": elt.lineno,
                                    "col_offset": elt.col_offset,
                                    "snippet": self.get_code_snippet(elt.lineno),
                                    "message": "String concatenation '+' inside ('system', ...) message tuple.",
                                })

    def _inspect_pii_in_call(self, node: ast.Call, call_name: str) -> None:
        """Detect variables or dictionary keys containing PII sent directly to external tools or LLM calls."""
        import re
        pii_keywords = {"email", "phone", "ssn", "nric", "credit_card", "card_number", "passport", "dob", "address"}

        # Inspect all arguments passed to this function call
        for arg in node.args:
            # Constant literals (e.g. byte strings like b'\nendobj\n') are not customer PII variables
            if isinstance(arg, ast.Constant):
                continue

            arg_name = self._get_call_name(arg).lower()
            tokens = set(re.findall(r"[a-z0-9]+", arg_name))
            has_pii = False
            for p in pii_keywords:
                if "_" in p:
                    if p in arg_name:
                        has_pii = True
                        break
                elif p in tokens:
                    if p == "address" and any(net in arg_name for net in ("ip_", "server_", "socket_", "host_", "mac_")):
                        continue
                    has_pii = True
                    break

            if has_pii:
                # Ensure it's not wrapped in a mask/redact/anonymize call
                if not any(sanitizer in call_name.lower() for sanitizer in ("mask", "redact", "anonymize", "hash", "clean")):
                    self.pii_exposures.append({
                        "line_number": node.lineno,
                        "col_offset": node.col_offset,
                        "snippet": self.get_code_snippet(node.lineno),
                        "variable": arg_name,
                        "sink": call_name,
                        "message": f"Sensitive PII field '{arg_name}' passed into '{call_name}' without redaction.",
                    })

    def _get_call_name(self, node: ast.AST) -> str:
        """Extract a readable dotted name from an AST expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_call_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        elif isinstance(node, ast.Call):
            return self._get_call_name(node.func)
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return ""

    def _extract_string_literal(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None


def parse_python_agent_file(file_path: Path) -> PythonAgentASTVisitor:
    """Parse a single Python file and return the completed visitor."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
        visitor = PythonAgentASTVisitor(str(file_path), source)
        visitor.visit(tree)
        visitor._scan_comments_for_secrets()
        return visitor
    except Exception as e:
        # Fallback if syntax error in target file
        visitor = PythonAgentASTVisitor(str(file_path), "")
        visitor._scan_comments_for_secrets()
        return visitor
