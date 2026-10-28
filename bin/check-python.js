#!/usr/bin/env node
/**
 * Postinstall check: verifies that a compatible Python 3.10+ interpreter is
 * available. Emits a warning only — does not fail the install.
 */

"use strict";

const { spawnSync } = require("child_process");

const candidates = process.env.ORVYEN_PYTHON
  ? [process.env.ORVYEN_PYTHON]
  : process.platform === "win32"
  ? ["python", "python3", "py"]
  : ["python3", "python"];

let found = false;
let matchedBin = "";

for (const bin of candidates) {
  const result = spawnSync(
    bin,
    ["-c", "import sys; assert sys.version_info >= (3, 10)"],
    { stdio: "pipe" }
  );
  if (result.status === 0 && !result.error) {
    found = true;
    matchedBin = bin;
    break;
  }
}

if (!found) {
  console.warn(
    `[orvyen-agentic] WARNING: Python 3.10+ not detected via (${candidates.join(", ")}).\n` +
    "Install Python 3.10+ and ensure it is on PATH before using orvyen-agentic.\n" +
    "You can override the interpreter with: ORVYEN_PYTHON=/path/to/python3"
  );
} else {
  console.log(`[orvyen-agentic] Python interpreter check passed (${matchedBin}).`);
}
