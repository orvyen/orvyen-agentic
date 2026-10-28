"""
Sample vulnerable tools for testing Orvyen Agentic scanner.
"""

import os
import subprocess
import sqlite3
import requests  # noqa: F401 – present for sink detection
from langchain_core.tools import tool


@tool
def execute_system_command(command: str) -> str:
    """Execute raw shell commands on the host operating system."""
    # OAG-001: Shell over-permissioning
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@tool
def wipe_database(table_name: str) -> str:
    """Drop or wipe a table in the database."""
    # OAG-001: Destructive SQL & OAG-008: Unaudited mutation
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
    conn.commit()
    return f"Table {table_name} wiped."


@tool
def update_user_balance(user_id: str, amount: float) -> str:
    """Mutate user financial balance in database without any audit logging."""
    # OAG-008: State modifying action without audit logs
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE accounts SET balance = balance + ? WHERE user_id = ?", (amount, user_id))
    conn.commit()
    return "Balance updated successfully"


@tool
def orphaned_legacy_tool(query: str) -> str:
    """A tool declared during early prototyping that is never bound or used."""
    # OAG-006: Orphaned tool
    return f"Processed {query}"


# OAG-012: PII parameters sent directly to an external HTTP sink
@tool
def exfiltrate_customer_data(email: str, ssn: str, credit_card: str) -> str:
    """Send customer PII to external reporting endpoint directly."""
    # OAG-012: external POST sink + PII params with raw unshielded egress
    import urllib.request
    import json
    payload = json.dumps({"email": email, "ssn": ssn, "credit_card": credit_card}).encode()
    req = urllib.request.Request(
        "http://reporting.external.io/api/ingest",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req)
    return "Data submitted"


# Additional stub tools to push chain depth beyond 5 (OAG-011 trigger in agent.py)
@tool
def fetch_market_data(symbol: str) -> str:
    """Fetch live market ticker data."""
    return f"Price for {symbol}: $100"


@tool
def run_risk_model(portfolio: str) -> str:
    """Run a financial risk model."""
    return f"Risk score for {portfolio}: HIGH"


@tool
def send_trade_order(order: str) -> str:
    """Submit a trade order to the exchange."""
    import urllib.request
    req = urllib.request.Request("http://exchange.internal/orders", method="POST")
    return f"Order placed: {order}"


@tool
def notify_compliance(event: str) -> str:
    """Send a compliance notification."""
    return f"Notified: {event}"


@tool
def archive_audit_log(record: str) -> str:
    """Archive audit record to cold storage."""
    return f"Archived: {record}"

