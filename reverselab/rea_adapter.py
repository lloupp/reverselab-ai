"""Opt-in adapter to the external REA CLI (https://github.com/morluto/rea).

No package installation, network request or target execution is performed by this module.
REA itself may require external tools; use only on trusted targets in an isolated host.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


class REAError(RuntimeError):
    """REA is unavailable, failed, or returned an invalid result."""


def status() -> dict:
    """Report whether an installed REA executable is discoverable."""
    binary = shutil.which("rea")
    return {
        "available": binary is not None,
        "executable": binary,
        "install": "npm install --global rea-agents",
        "setup": "rea setup",
        "node_required": "22.19+ / 24.11+ / 26+",
        "native_provider_required": "Ghidra, Hopper or IDA",
    }


def analyze(path: str | os.PathLike, *, mode: str = "javascript", timeout: int = 120) -> dict:
    """Run read-only REA static inspection on a local file/directory.

    javascript: analyze-javascript-application (directory or ASAR)
    native: analyze (requires a configured native provider)

    REA is not invoked on behalf of untrusted HTTP requests by default; this
    function is an explicit local opt-in for CLI/workflow integrations.
    """
    if mode not in ("javascript", "native"):
        raise ValueError("mode must be 'javascript' or 'native'")
    if not 1 <= timeout <= 600:
        raise ValueError("timeout must be between 1 and 600 seconds")
    target = Path(path).expanduser().resolve(strict=True)
    if not (target.is_file() or target.is_dir()):
        raise REAError("Target must be a regular file or directory")
    binary = shutil.which("rea")
    if not binary:
        raise REAError("REA CLI not installed. Run: npm install --global rea-agents")
    command = [binary, "analyze-javascript-application" if mode == "javascript" else "analyze", str(target), "--json"]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            check=False, shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise REAError(f"REA exceeded the {timeout}s deadline") from exc
    except OSError as exc:
        raise REAError(f"Unable to launch REA: {exc}") from exc
    if completed.returncode:
        raise REAError(f"REA failed (exit {completed.returncode}): {completed.stderr[-2000:]}")
    try:
        evidence = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise REAError("REA did not return valid JSON") from exc
    return {"engine": "rea", "mode": mode, "target": str(target), "evidence": evidence}
