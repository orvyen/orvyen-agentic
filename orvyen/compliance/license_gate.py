"""
License gate for Orvyen Agentic compliance features.

Free tier:  terminal console, JSON report, HTML dashboard, AIBOM JSON.
Paid tier:  AIBOM Markdown with IMDA/OWASP clause annotations, PDF export.

License keys are validated offline via a simple HMAC-SHA256 checksum against
a hard-coded public salt so that validation requires no network call and
preserves the <100 ms scan constraint.

Key format (base64url, no padding):
  <prefix>.<hmac_hex>
  prefix  = "OAG-PRO"
  payload = sha256(prefix + SALT)[:16]

To generate a valid key (for internal tooling only):
  import hashlib, hmac, base64
  SALT = b"orvyen-license-v1"
  h = hmac.new(SALT, b"OAG-PRO", hashlib.sha256).hexdigest()[:16]
  key = f"OAG-PRO.{h}"
"""

from __future__ import annotations
import hashlib
import hmac

_SALT = b"orvyen-license-v1"
_PRO_PREFIX = "OAG-PRO"


def is_valid_license(key: str | None) -> bool:
    """
    Return True when *key* is a structurally valid Orvyen Pro license token.
    Validation is a pure offline HMAC comparison — no network call.
    """
    if not key:
        return False
    key = key.strip()
    parts = key.split(".", 1)
    if len(parts) != 2:
        return False
    prefix, provided_digest = parts
    if prefix != _PRO_PREFIX:
        return False
    expected = hmac.new(_SALT, prefix.encode(), hashlib.sha256).hexdigest()[:16]
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected, provided_digest.lower())


UPGRADE_PROMPT = (
    "\033[33m[Orvyen] This feature requires a Pro license. "
    "Get yours at: https://orvyen.com/pricing\033[0m"
)
