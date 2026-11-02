# Orvyen Agentic CLI — Breaking Points, Vulnerabilities & Edge-Case Report

**Date**: November 2026  
**Version Tested**: `orvyen-agentic v0.3.0`  
**Target Architecture**: Python 3.10+ / Node.js 18+  
**Scope**: CLI Argument Parsing, Static AST Analysis Engine, MCP Manifest Parsers, Reporting Subsystems, Execution Lifecycle  

---

## Executive Summary

A comprehensive edge-case, fault-injection, and boundary analysis was conducted on the **Orvyen Agentic** CLI and static analysis engine. 

While the engine achieves impressive scan performance (sub-10ms execution on standard codebases) and features a rich terminal interface, several critical breaking points were identified across four main categories:

1. **Fatal Unhandled Crashes (`Traceback`)**: Valid and slightly malformed MCP JSON configuration structures (`mcp.json`, `claude_desktop_config.json`) cause uncaught exceptions (`AttributeError`, `TypeError`), immediately crashing the scanner.
2. **Analysis Engine False Positives**: Broad AST patterns flag standard Python constructs (such as `re.compile()` or standard keyword arguments `content=f"..."`) as high-severity agent security vulnerabilities.
3. **UI Display & Ingestion Integrity**: The terminal header displays hardcoded fallbacks (`3 Tools • 1 MCP Gateways`) when scanning targets with 0 tools, and syntax-errored Python files are silently accepted as 100% healthy.
4. **Packaging & Automation Quirks**: Interactive mode engages by default on standard TTY terminals, which can freeze CI/CD pipelines and headless scripts if `--no-interactive` is omitted.

---

## Quick Reference: Severity & Impact Matrix

| Ref ID | Category | Severity | Issue Description | Impact |
| :--- | :--- | :--- | :--- | :--- |
| **BP-01** | Crashes / Uncaught | **CRITICAL** | `mcp.json` with null `env`, `args`, or `tools` | Scanner crashes with unhandled `AttributeError` / `TypeError` |
| **BP-02** | Crashes / Uncaught | **CRITICAL** | Root array or non-dict `mcpServers` in MCP JSON | Scanner crashes with `AttributeError` |
| **BP-03** | Crashes / Uncaught | **HIGH** | `-o` / `--output-dir` targeting an existing file path | Uncaught `FileExistsError` crash |
| **BP-04** | Crashes / Uncaught | **HIGH** | Output directory without write permissions | Uncaught `PermissionError` crash |
| **BP-05** | Logic / False Positive | **HIGH** | Standard `re.compile()` flagged as OAG-005 | Every Python file using regex fails security scan |
| **BP-06** | Logic / False Positive | **HIGH** | Any function call with `content=f"..."` flagged as OAG-002 | Unscoped check treats non-prompt arguments as prompt injection |
| **BP-07** | Logic / False Positive | **MEDIUM** | Network socket / host addresses flagged as OAG-004 PII | `socket.connect(server_address)` flagged as sensitive PII leak |
| **BP-08** | Logic / Accuracy | **MEDIUM** | Tool count conflated with execution depth in OAG-011 | Having >5 tools in toolbox flagged as "Chain Depth >5" |
| **BP-09** | Reporting / Display | **MEDIUM** | Hardcoded banner values (`3 Tools • 1 MCP Gateways`) | Misleading asset counts on clean/empty targets |
| **BP-10** | Analysis / Integrity | **MEDIUM** | Python `SyntaxError` silently swallowed | Corrupted files are reported as 100% Healthy |
| **BP-11** | Logic / Security Gate | **MEDIUM** | OAG-010 human approval gate trivially bypassed by comments | Incidental word "review" in any line bypasses approval gate |
| **BP-12** | Automation / Runtime | **LOW** | TTY interactive prompt hangs non-CI automations | Terminal blocks waiting for keypress unless `--no-interactive` passed |

---

## Detailed Findings & Breaking Points

### 1. Unhandled Fatal Crashes (CLI Termination)

#### BP-01: MCP Configuration Crashes on Null / Empty Fields
- **Location**: `orvyen/parsers/mcp_parser.py`, Lines 41–44
- **Root Cause**:
  ```python
  args = [str(a) for a in server_cfg.get("args", [])]
  env_vars = {str(k): str(v) for k, v in server_cfg.get("env", {}).items()}
  ```
  In standard JSON configs, `"env": null` or `"args": null` is common. In Python dicts, `server_cfg.get("env", {})` returns `None` (not `{}`) if the key exists with value `null`.
- **Resulting Exception**:
  ```text
  AttributeError: 'NoneType' object has no attribute 'items'
  TypeError: 'NoneType' object is not iterable
  ```
- **Reproduction**:
  ```bash
  mkdir -p /tmp/bad_mcp
  echo '{"mcpServers": {"test": {"command": "node", "env": null}}}' > /tmp/bad_mcp/mcp.json
  python3 -m orvyen.cli scan /tmp/bad_mcp --no-interactive
  ```

---

#### BP-02: Non-Dictionary Root or `mcpServers` in MCP Manifest
- **Location**: `orvyen/parsers/mcp_parser.py`, Lines 30–37
- **Root Cause**:
  ```python
  servers_dict = self.raw_data.get("mcpServers", {})
  ...
  for server_name, server_cfg in servers_dict.items():
  ```
  If `mcp.json` has a root JSON array (e.g., `["server1", "server2"]`) or `"mcpServers": "some_string"`, `self.raw_data.get` or `servers_dict.items` raises an unhandled `AttributeError`.
- **Reproduction**:
  ```bash
  mkdir -p /tmp/bad_mcp_arr
  echo '["server_a", "server_b"]' > /tmp/bad_mcp_arr/mcp.json
  python3 -m orvyen.cli scan /tmp/bad_mcp_arr --no-interactive
  ```

---

#### BP-03: Output Directory Collision with Existing File
- **Location**: `orvyen/reporters/json_reporter.py` (and related reporters), Line 27
- **Root Cause**:
  ```python
  output_path.parent.mkdir(parents=True, exist_ok=True)
  ```
  When the user passes `--output-dir` or `-o` pointing to an existing file rather than a directory, `mkdir` attempts to create parent directories across a file node, causing Python to terminate with an unhandled `FileExistsError`.
- **Reproduction**:
  ```bash
  touch /tmp/existing_report_file
  python3 -m orvyen.cli scan tests/fixtures/secure_agent -f json -o /tmp/existing_report_file --no-interactive
  ```

---

#### BP-04: Unhandled `PermissionError` on Read-Only Output Directories
- **Location**: `orvyen/reporters/json_reporter.py`, `html_reporter.py`, `sarif_reporter.py`
- **Root Cause**: File write and directory creation calls lack clean error boundaries catching `PermissionError` or `OSError`. Instead of a user-friendly CLI error (e.g. `Error: Unable to write to directory: Permission denied`), a full Python traceback is dumped to stderr with exit code 1.
- **Reproduction**:
  ```bash
  mkdir -p /tmp/readonly_dir && chmod 555 /tmp/readonly_dir
  python3 -m orvyen.cli scan tests/fixtures/secure_agent -f json -o /tmp/readonly_dir/sub --no-interactive
  ```

---

### 2. Core Static Analysis Engine False Positives & Logic Bugs

#### BP-05: False Positive on Standard `re.compile()` (OAG-005)
- **Location**: `orvyen/parsers/python_ast.py`, Line 213
- **Root Cause**:
  ```python
  # LangGraph: workflow.compile(...)
  if call_name.endswith(".compile"):
      # Flags missing recursion_limit
  ```
  The parser matches *any* method call in Python ending in `.compile`. This includes Python's standard library `re.compile(pattern)` or custom builders (`AIBOMCompiler.compile(...)`).
- **Impact**: Any Python codebase using standard regular expressions will receive a **HIGH severity security violation** (`OAG-005: LangGraph compilation missing explicit 'recursion_limit' safeguard`) and fail CI/CD build gates.
- **Reproduction**:
  ```bash
  mkdir -p /tmp/test_regex
  echo 'import re; pattern = re.compile("^[a-z]+$")' > /tmp/test_regex/regex_helper.py
  python3 -m orvyen.cli scan /tmp/test_regex --compact --fail-on NONE --no-interactive
  ```

---

#### BP-06: Unscoped Prompt Injection Flagging on `content=f"..."` (OAG-002)
- **Location**: `orvyen/parsers/python_ast.py`, Lines 317–324
- **Root Cause**:
  ```python
  is_system_prompt_target = any(k in call_name for k in (
      "SystemMessage", "SystemMessagePromptTemplate", "ChatPromptTemplate"
  ))

  # Check keyword content in SystemMessage(content=...)
  for kw in node.keywords:
      if kw.arg in ("content", "system", "template"):
          if isinstance(kw.value, ast.JoinedStr):
  ```
  Notice that `is_system_prompt_target` is calculated on line 317, but **never checked** in the `for kw in node.keywords:` loop.
- **Impact**: Any normal Python function invocation containing a `content=...` or `template=...` f-string (e.g., `requests.post(url, content=f"id={user_id}")`, `logger.info(content=f"...")`) is flagged as a prompt injection vulnerability.
- **Reproduction**:
  ```bash
  mkdir -p /tmp/test_content
  echo 'def send_payload(data): client.post("/api", content=f"data: {data}")' > /tmp/test_content/service.py
  python3 -m orvyen.cli scan /tmp/test_content --compact --fail-on NONE --no-interactive
  ```

---

#### BP-07: Network Socket / Host Addresses Flagged as Sensitive PII (OAG-004)
- **Location**: `orvyen/parsers/python_ast.py`, Lines 364–379
- **Root Cause**:
  The keyword list contains `"address"` without boundary context.
  ```python
  pii_keywords = {"email", "phone", "ssn", "nric", "credit_card", "card_number", "passport", "dob", "address"}
  ```
- **Impact**: Standard network programming constructs such as `s.connect(server_address)`, `bind(ip_address)`, or memory pointers (`memory.get_address(ptr)`) trigger **HIGH severity OAG-004 PII exposure violations**.
- **Reproduction**:
  ```bash
  mkdir -p /tmp/test_net
  echo 'def connect(server_address): socket.connect(server_address)' > /tmp/test_net/net.py
  python3 -m orvyen.cli scan /tmp/test_net --compact --fail-on NONE --no-interactive
  ```

---

#### BP-08: Conflation of Toolset Size with Tool Chain Depth (OAG-011)
- **Location**: `orvyen/rules/oag011_excessive_tool_chaining.py`, Lines 42–44
- **Root Cause**:
  ```python
  for agent in ctx.agents:
      tool_count = len(agent.bound_tools)
      if tool_count > _CHAIN_DEPTH_LIMIT:
  ```
  The rule documentation states it detects sequential multi-hop execution (`chain depth > 5`). However, the implementation merely evaluates `len(agent.bound_tools) > 5`.
- **Impact**: An agent equipped with 6 independent, single-purpose read-only tools (e.g., `calc`, `search_docs`, `get_weather`, `get_stock`, `get_date`, `translate`) is falsely reported for "Excessive Tool Chaining (>5 hops)".

---

#### BP-09: Trivial Human Approval Gate Bypass via Incidental Text (OAG-010)
- **Location**: `orvyen/rules/oag010_missing_human_in_loop.py`, Lines 47–65
- **Root Cause**:
  ```python
  visitor = ctx.python_visitors.get(tool.file_path)
  if visitor:
      for (fpath, lno) in approval_lines:
          if fpath == tool.file_path:
              has_approval = True
              break
  ```
  Rather than verifying that high-privilege tools are wrapped with `interrupt()` or `human_input=True`, any line anywhere in the source file containing words like `"review"`, `"confirm"`, or `"checkpoint"` satisfies the requirement.
- **Impact**: A comment such as `# Code review done by Bob` or a function `def review_summary()` anywhere in the file silently disables OAG-010 enforcement for all dangerous tools in that file.

---

### 3. UI, Reporting & Ingestion Integrity

#### BP-10: Hardcoded Fallback Counts in Console Header Banner
- **Location**: `orvyen/reporters/console.py`, Lines 284–286
- **Root Cause**:
  ```python
  tools_count = len(result.tools) if result and result.tools else 3
  exec_count = sum(...) if result and result.tools else 0
  mcp_count = len(result.mcp_servers) if result and result.mcp_servers else 1
  ```
  Because an empty list evaluates to `False` in Python (`bool([]) == False`), empty tool and MCP lists trigger the fallback constants (`3` tools, `1` MCP gateway).
- **Impact**: Scanning an empty folder or simple script prints:
  `↑ 12 checks • AIBOM + OWASP + IMDA • 0.0ms scan • 3 Tools (0 High-Privilege) • 1 MCP Gateways`
  at the top, while the bottom summary box correctly reports `0 Tools • 0 MCP Gateways`.

---

#### BP-11: Silent Swallowing of Python Syntax Errors
- **Location**: `orvyen/parsers/python_ast.py`, Lines 408–411
- **Root Cause**:
  ```python
  except Exception as e:
      # Fallback if syntax error in target file
      visitor = PythonAgentASTVisitor(str(file_path), "")
      return visitor
  ```
- **Impact**: If a codebase contains unparseable syntax or corrupted files, the AST visitor returns an empty code buffer. The scanner reports the file as scanned and declares the project **100/100 HEALTHY** with zero warnings or errors.

---

### 4. Packaging, Portability & Automation Lifecycle

#### BP-12: Unintended Interactive Mode Blocking in Terminal Scripts
- **Location**: `orvyen/cli.py`, Lines 302–309
- **Root Cause**:
  ```python
  is_interactive = (
      sys.stdin.isatty()
      and sys.stdout.isatty()
      and not args.quiet
      and args.format == "terminal"
      and not os.environ.get("CI")
      and not os.environ.get("ORVYEN_NO_INTERACTIVE")
  )
  ```
- **Impact**: If a developer invokes `orvyen-agentic scan .` inside an interactive shell script, dev container, or wrapper script without passing `--no-interactive` or setting `CI=1`, the scan completes and immediately halts at an interactive command prompt waiting for keypresses (`Ctrl+C` or `exit`).

---

## Actionable Recommendations & Fix Plan

### 1. Hardening MCP Parsing (`mcp_parser.py`)
Replace direct attribute and dict accesses with safe type validation:
```python
if not isinstance(self.raw_data, dict):
    return

servers_dict = self.raw_data.get("mcpServers")
if not isinstance(servers_dict, dict):
    servers_dict = {}

raw_env = server_cfg.get("env")
env_vars = {str(k): str(v) for k, v in raw_env.items()} if isinstance(raw_env, dict) else {}

raw_args = server_cfg.get("args")
args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
```

### 2. Fixing AST Prompt Injection (`python_ast.py`)
Ensure `is_system_prompt_target` guards keyword parameter inspections:
```python
if is_system_prompt_target:
    for kw in node.keywords:
        if kw.arg in ("content", "system", "template"):
            ...
```

### 3. Disambiguating `re.compile` from LangGraph (`python_ast.py`)
Ensure `.compile` checks verify the caller object is not standard `re` / `regex`:
```python
if call_name.endswith(".compile") and not call_name.startswith(("re.", "regex.")):
    # Check that the caller is a StateGraph or MessageGraph instance
```

### 4. Correcting Console Header Counts (`console.py`)
Remove hardcoded integer fallbacks for empty collections:
```python
tools_count = len(result.tools) if result and result.tools is not None else 0
exec_count = sum(1 for t in result.tools if t.privilege.value in ("EXECUTE", "ADMIN")) if result and result.tools else 0
mcp_count = len(result.mcp_servers) if result and result.mcp_servers is not None else 0
```

### 5. Proper CLI Error Handling on Output Paths (`cli.py`)
Wrap report generation in structured OS error handling:
```python
try:
    out_dir.mkdir(parents=True, exist_ok=True)
except (FileExistsError, PermissionError) as e:
    print(f"Error: Unable to prepare output directory '{out_dir}': {e}", file=sys.stderr)
    return 2
```

