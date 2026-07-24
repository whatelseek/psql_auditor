"""Discover and irreversibly redact passwords/tokens for anonymized exports.

TruffleHog (optional CLI) finds high-entropy / detector-matched secrets in an
evidence tree. Inventory credential fields are always included. Values are
replaced with ``***REDACTED***`` and must **never** enter the reversible
anonymization mapping.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

REDACTED = "***REDACTED***"

_SECRET_KEY_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "access_key",
)

# Avoid wiping short / noisy false positives from scanners.
_MIN_SECRET_LEN = 6


def inventory_secrets(creds: dict[str, Any] | None) -> set[str]:
    """Collect password/token-like values from inventory credential env map."""
    out: set[str] = set()
    if not creds:
        return out
    for key, value in creds.items():
        text = str(value or "").strip()
        if not text or len(text) < _MIN_SECRET_LEN:
            continue
        low = str(key).lower()
        if any(hint in low for hint in _SECRET_KEY_HINTS):
            # Private key *paths* are not secret material to scrub from reports.
            if "path" in low and "password" not in low:
                continue
            out.add(text)
    return out


def _extract_raw_from_finding(obj: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("Raw", "RawV2", "raw", "raw_v2"):
        raw = obj.get(key)
        if isinstance(raw, str) and raw.strip():
            values.append(raw.strip())
    # Some detectors put parts under ExtraData / SecretParts.
    for nest_key in ("ExtraData", "SecretParts", "extra_data", "secret_parts"):
        nested = obj.get(nest_key)
        if isinstance(nested, dict):
            for value in nested.values():
                if isinstance(value, str) and value.strip():
                    values.append(value.strip())
    return values


def parse_trufflehog_jsonl(stdout: str) -> set[str]:
    """Parse TruffleHog ``--json`` NDJSON stdout into raw secret strings."""
    found: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        for raw in _extract_raw_from_finding(obj):
            if len(raw) >= _MIN_SECRET_LEN:
                found.add(raw)
    return found


def discover_secrets_with_trufflehog(
    root: Path,
    *,
    binary: str = "trufflehog",
    timeout_sec: float = 120.0,
    enabled: bool = True,
) -> set[str]:
    """Run ``trufflehog filesystem`` when available; return discovered Raw values.

    Uses ``--no-verification`` so secrets are not sent to external verifiers
    during anonymization. Missing binary or scan errors yield an empty set.
    """
    if not enabled:
        return set()
    root = Path(root)
    if not root.is_dir():
        return set()
    exe = shutil.which(binary) if os.path.sep not in binary else (
        binary if Path(binary).is_file() else None
    )
    if not exe:
        logger.info("TruffleHog not found (%s); skipping secret discovery", binary)
        return set()
    cmd = [
        exe,
        "filesystem",
        str(root),
        "--json",
        "--no-verification",
        "--no-update",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("TruffleHog scan failed: %s", exc)
        return set()
    found = parse_trufflehog_jsonl(proc.stdout or "")
    if proc.returncode not in (0, 183):
        # TruffleHog may use non-zero when findings exist; still parse stdout.
        logger.debug(
            "TruffleHog exit=%s stderr=%s",
            proc.returncode,
            (proc.stderr or "")[:500],
        )
    return found


def collect_secrets_for_redaction(
    *,
    evidence_root: Path,
    inventory_creds: dict[str, Any] | None = None,
    trufflehog_enabled: bool = True,
    trufflehog_bin: str = "trufflehog",
    trufflehog_timeout_sec: float = 120.0,
) -> set[str]:
    """Union of inventory secrets and optional TruffleHog discoveries."""
    secrets = inventory_secrets(inventory_creds)
    if trufflehog_enabled:
        secrets |= discover_secrets_with_trufflehog(
            evidence_root,
            binary=trufflehog_bin,
            timeout_sec=trufflehog_timeout_sec,
            enabled=True,
        )
    return {s for s in secrets if s and len(s) >= _MIN_SECRET_LEN}


def redact_secrets_in_text(text: str, secrets: Iterable[str]) -> str:
    """Irreversibly replace known secret strings with ``***REDACTED***``."""
    masked = text
    # Longest first so nested / overlapping values redact cleanly.
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        if len(secret) < _MIN_SECRET_LEN:
            continue
        if secret in masked:
            masked = masked.replace(secret, REDACTED)
        # Also try regex-escaped for safety with identical result.
        else:
            masked = re.sub(re.escape(secret), REDACTED, masked)
    return masked
