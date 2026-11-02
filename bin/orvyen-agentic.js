#!/usr/bin/env node
/**
 * orvyen-agentic npm CLI shim.
 *
 * Delegates arguments directly to `python -m orvyen.cli`.
 * Injects package root into PYTHONPATH so the bundled orvyen package is always resolved.
 */

"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

function getCandidates() {
  if (process.env.ORVYEN_PYTHON) {
    return [process.env.ORVYEN_PYTHON];
  }
  return process.platform === "win32"
    ? ["python3", "python", "py"]
    : ["python3", "python"];
}

function getCheckArgs(bin) {
  return bin === "py"
    ? ["-3", "-c", "import sys; assert sys.version_info >= (3, 10)"]
    : ["-c", "import sys; assert sys.version_info >= (3, 10)"];
}

function getSpawnArgs(bin, cliArgs) {
  return bin === "py"
    ? ["-3", "-m", "orvyen.cli", ...cliArgs]
    : ["-m", "orvyen.cli", ...cliArgs];
}

function findPython(candidates) {
  for (const bin of candidates) {
    try {
      const res = spawnSync(bin, getCheckArgs(bin), {
        stdio: "ignore",
        windowsHide: true,
      });
      if (!res.error && res.status === 0) {
        return bin;
      }
    } catch (_) {}
  }
  return null;
}

const candidates = getCandidates();
let selectedPython = findPython(candidates);

// If explicit ORVYEN_PYTHON was provided but failed version check, still attempt invocation
if (!selectedPython && process.env.ORVYEN_PYTHON) {
  selectedPython = process.env.ORVYEN_PYTHON;
}

if (!selectedPython) {
  console.error(
    `[orvyen-agentic] Error: A compatible Python 3.10+ interpreter was not found.\n` +
    `Checked candidate binaries: ${candidates.join(", ")}\n\n` +
    `Please ensure Python 3.10+ is installed and available on your PATH.\n` +
    `You can also set the ORVYEN_PYTHON environment variable to your Python binary:\n` +
    `  export ORVYEN_PYTHON=/usr/bin/python3`
  );
  process.exit(1);
}

const pkgRoot = path.resolve(__dirname, "..");
const pythonPath = process.env.PYTHONPATH
  ? `${pkgRoot}${path.delimiter}${process.env.PYTHONPATH}`
  : pkgRoot;

const env = {
  ...process.env,
  PYTHONPATH: pythonPath,
};

const args = process.argv.slice(2);
const spawnArgs = getSpawnArgs(selectedPython, args);

const result = spawnSync(selectedPython, spawnArgs, {
  stdio: "inherit",
  shell: false,
  windowsHide: true,
  env,
});

if (result.error) {
  console.error(`[orvyen-agentic] Failed to execute Python (${selectedPython}): ${result.error.message}`);
  process.exit(1);
}

if (result.status !== null) {
  process.exit(result.status);
} else if (result.signal) {
  const sigMap = { SIGINT: 130, SIGTERM: 143, SIGHUP: 129, SIGQUIT: 131 };
  process.exit(sigMap[result.signal] || 1);
} else {
  process.exit(0);
}
