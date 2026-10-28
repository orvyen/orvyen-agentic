"""
Hardened, secure agent tools adhering to least privilege and audit logging.
"""

import logging
from langchain_core.tools import tool

logger = logging.getLogger("audit.tools")


@tool
def fetch_account_summary(user_id: str) -> str:
    """Safely fetch read-only account summary with full audit logging."""
    logger.info("AUDIT: fetch_account_summary invoked for user %s", user_id)
    # Read-only query simulation
    return f"Account summary for {user_id}: Balance S$5,000"


@tool
def search_knowledge_base(query: str) -> str:
    """Search internal enterprise documentation index."""
    logger.info("AUDIT: search_knowledge_base query: %s", query)
    return f"Retrieved 3 safe documents for '{query}'"
