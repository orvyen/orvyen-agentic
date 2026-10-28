#!/usr/bin/env node
/**
 * orvyen-agentic npm shim.
 *
 * Delegates all CLI arguments directly to `python -m orvyen.cli` so the npm
 * package is a zero-logic proxy. No Python code is duplicated here.
 *
 * Resolution order for the Python interpreter:
 *   1. ORVYEN_PYTHON env var (explicit override)
 *   2. `python3` on PATH
 *   3. `python` on PATH
 */

"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

const candidates = process.env.ORVYEN_PYTHON
  ? [process.env.ORVYEN_PYTHON]
  : process.platform === "win32"
  ? ["python", "python3", "py"]
  : ["python3", "python"];

const args = process.argv.slice(2);
let result = null;
let lastError = null;

for (const bin of candidates) {
  result = spawnSync(bin, ["-m", "orvyen.cli", ...args], {
    stdio: "inherit",
    shell: false,
  });

  if (!result.error) {
    process.exit(result.status ?? 0);
  }
  lastError = result.error;
  if (result.error.code !== "ENOENT") {
    // If it was another error (permission, etc.), stop and report it
    break;
  }
}

const msg =
  lastError && lastError.code === "ENOENT"
    ? `[orvyen-agentic] Compatible Python interpreter (${candidates.join(", ")}) not found.\n` +
      "Install Python 3.10+ and make sure it is on PATH, or set the ORVYEN_PYTHON env var.\n" +
      "Alternatively install the package directly: pip install orvyen-agentic"
    : `[orvyen-agentic] Failed to spawn Python: ${lastError ? lastError.message : "Unknown error"}`;
console.error(msg);
process.exit(1);
