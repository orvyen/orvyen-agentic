# Orvyen Agentic

> **Static Security & Compliance Scanning for AI Agents**  
> *LangChain &bull; LangGraph &bull; CrewAI &bull; Model Context Protocol (MCP)*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PyPI version](https://img.shields.io/pypi/v/orvyen-agentic.svg?color=blue)](https://pypi.org/project/orvyen-agentic/)
[![npm version](https://img.shields.io/npm/v/orvyen-agentic.svg?color=red)](https://www.npmjs.com/package/orvyen-agentic)
[![tests](https://img.shields.io/badge/tests-22%2F22-brightgreen.svg)](https://github.com/orvyen/orvyen-agentic)
[![time](https://img.shields.io/badge/time-7.1ms-success.svg)](https://github.com/orvyen/orvyen-agentic)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM_Top_10-orange)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![IMDA Governance](https://img.shields.io/badge/Singapore-IMDA_Agentic_AI_(May_2026)-green)](https://www.imda.gov.sg/)

**Orvyen Agentic** is a pre-deployment static analysis security and compliance scanner purpose-built for modern AI agent architectures. While 76% of existing AI security solutions operate at runtime (inspecting prompts downstream after deployment), Orvyen Agentic operates **pre-deployment in CI/CD and local development** — finding security flaws in agent code, prompt templates, tool privileges, and MCP server manifests before code ever merges.

---

## Key Features

- **Agent-Aware AST Parsing**: Deep inspection of Python agent graphs and orchestrations across **LangChain**, **LangGraph**, and **CrewAI**.
- **Model Context Protocol (MCP) Scanning**: Static inspection of `claude_desktop_config.json` and `mcp.json` server configurations, detecting shell capabilities, plaintext credentials, and orphaned gateways.
- **Sub-100ms Performance**: Zero external runtime dependencies; executes blazing-fast static checks in milliseconds using Python's standard library.
- **Agent Bill of Materials (AIBOM)**: Auto-compiles an auditable inventory of every tool, privilege tier, model, and external data flow.
- **Regulatory & Governance Scorecards**:
  - **Singapore IMDA**: Model AI Governance Framework for Agentic AI (May 2026 v1.5 - 4 Pillars).
  - **MAS Guidelines**: Monetary Authority of Singapore AI Risk Management Guidelines.
  - **OWASP LLM Top 10**: Direct vulnerability mapping to the official standard.
- **Multi-Format Reporting**: Colorized terminal output with code snippets, machine-readable JSON for CI/CD, and interactive self-contained HTML dashboards.

---

## The Initial 8-Rule Security Pack

| Rule ID | Rule Name | Severity | OWASP Mapping | Singapore IMDA Pillar |
| :--- | :--- | :--- | :--- | :--- |
| **`OAG-001`** | **Tool Over-Permissioning** | `CRITICAL` / `HIGH` | LLM06: Excessive Agency | Pillar 3: Technical Controls |
| **`OAG-002`** | **Prompt Injection Surface** | `HIGH` | LLM01: Prompt Injection | Pillar 1: Assess & Bound Risk |
| **`OAG-003`** | **Hardcoded Secrets & Keys** | `CRITICAL` | LLM02: Sensitive Information | Pillar 3: Technical Controls |
| **`OAG-004`** | **Unfiltered PII Flow** | `HIGH` | LLM02: Sensitive Information | Pillar 3: Technical Controls |
| **`OAG-005`** | **Unbounded Recursion Cycles**| `HIGH` | LLM10: Unbounded Consumption| Pillar 1: Assess & Bound Risk |
| **`OAG-006`** | **Orphaned Tools & MCPs** | `MEDIUM` / `LOW` | LLM06: Excessive Agency | Pillar 2: Human Accountability |
| **`OAG-007`** | **Missing Rate / Step Limits**| `MEDIUM` | LLM10: Unbounded Consumption| Pillar 3: Technical Controls |
| **`OAG-008`** | **Unaudited State Mutations** | `HIGH` | LLM06: Excessive Agency | Pillar 2: Human Accountability |

---

## Quickstart

### Installation

```bash
# Clone the repository
git clone https://github.com/orvyen/orvyen-agentic.git
cd orvyen-agentic

# Install locally via pip
pip install -e .
```

*Note: Orvyen Agentic has zero mandatory third-party dependencies and runs natively on Python 3.10+.*

---

## CLI Usage

### Basic Scan

Scan the current working directory:

```bash
orvyen-agentic scan .
```

Or run directly via Python module:

```bash
python -m orvyen.cli scan ./my-agent-repo
```

### Output Formats

```bash
# Generate Terminal, JSON, and HTML reports simultaneously
orvyen-agentic scan ./my-agent-repo --format all --output-dir ./scan_results

# Compact view: single-line output (ideal for fast developer loops & IDE terminals)
orvyen-agentic scan ./my-agent-repo --compact

# Export only the Agent Bill of Materials (AIBOM)
orvyen-agentic scan ./my-agent-repo --format aibom --output-dir ./audit_package

# Print AIBOM Markdown directly to stdout
orvyen-agentic scan ./my-agent-repo --aibom-only
```

### CI/CD Failure Gates

Enforce build failure if any vulnerability of a specified severity is discovered:

```bash
# Exit code 1 if any HIGH or CRITICAL vulnerability is found
orvyen-agentic scan . --fail-on HIGH

# Strict mode: fail on any finding (LOW, MEDIUM, HIGH, CRITICAL)
orvyen-agentic scan . --fail-on LOW
```

---

## Agent Bill of Materials (AIBOM)

Every scan generates an **Agent Bill of Materials (AIBOM)** detailing:
1. **Agent Metadata & Frameworks**: Framework versions detected (LangChain, LangGraph, CrewAI, MCP).
2. **Tool Capability Matrix**: Tool name, framework, privilege tier (`READ`, `WRITE`, `EXECUTE`, `ADMIN`), dangerous sink identification, bound status, and audit logging status.
3. **Model Context Protocol (MCP) Manifest**: Connected servers, CLI binaries, execution arguments, and environment configurations.
4. **Governance Scorecards**: Complete status breakdowns for Singapore IMDA 4-Pillars and OWASP LLM Top 10.

---

## CI/CD Pipeline Integration

### GitHub Actions Workflow

Add `.github/workflows/orvyen_agentic.yml`:

```yaml
name: Orvyen Agentic Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  agent-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Orvyen Agentic
        run: pip install orvyen-agentic

      - name: Run Static Security & Compliance Scan
        run: |
          orvyen-agentic scan . \
            --format all \
            --output-dir ./reports \
            --fail-on HIGH

      - name: Upload Security Report & AIBOM
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-security-reports
          path: ./reports/
```

---

## Architecture

```
                    Target Agent Codebase & Manifests
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │                      Parser Layer                       │
       │  • PythonAgentASTVisitor (Tools, Prompts, Cycles)       │
       │  • MCPManifestParser (Servers, Capabilities, Secrets)   │
       │  • ConfigFileScanner (.env, YAML, JSON token detector)  │
       └────────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │                       Rule Engine                       │
       │  • Evaluates OAG-001 to OAG-008 across intermediate IR  │
       │  • Categorizes findings by severity & framework         │
       └────────────────────────────┬────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
       ┌─────────────────────────┐     ┌─────────────────────────┐
       │   Developer Reporters   │     │    Compliance Engine    │
       │ • Rich Terminal Console │     │ • AIBOM Compiler        │
       │ • Machine-readable JSON │     │ • Singapore IMDA Matrix │
       │ • Interactive HTML Dash │     │ • OWASP LLM Top 10      │
       └─────────────────────────┘     └─────────────────────────┘
```

---

## Running the Test Suite

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## License & Attribution

Developed by **Orvyen**.  
Licensed under the Apache-2.0 License.
