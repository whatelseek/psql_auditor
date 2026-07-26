"""Sanitized discovery evidence persistence and secret scanning."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

COLLECTOR_VERSION = "1.0.0"

# Defense-in-depth patterns — never persist secrets or secret references.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(ssh_password|winrm_password|pg_password)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)vault://\S+"),
    re.compile(r"(?i)secret_ref\s*[:=]\s*\S+"),
    re.compile(r"(?i)(postgresql|postgres|mysql)://[^\s]+"),
)


class EvidenceSecretError(ValueError):
    """Raised when discovery evidence contains a secret canary or pattern."""

    def __init__(self, message: str, *, code: str = "secret_in_evidence") -> None:
        super().__init__(message)
        self.code = code


@dataclass(slots=True)
class CommandEvidence:
    """One sanitized remote command result."""

    command: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    collected_at: str = ""
    transport: str = ""
    error: str = ""


@dataclass(slots=True)
class HostDiscoveryEvidence:
    """Sanitized discovery evidence for one host."""

    host_id: str
    transport: str
    collector: str
    collector_version: str = COLLECTOR_VERSION
    collected_at: str = ""
    facts: dict[str, Any] = field(default_factory=dict)
    commands: list[CommandEvidence] = field(default_factory=list)
    error_code: str = ""
    error: str = ""
    limitations: list[str] = field(default_factory=list)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sanitize_text(text: str, *, known_secrets: Iterable[str] = ()) -> str:
    """Redact known secrets and obvious secret-shaped substrings."""
    out = text or ""
    for secret in known_secrets:
        value = (secret or "").strip()
        if value and len(value) >= 4:
            out = out.replace(value, "***REDACTED***")
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("***REDACTED***", out)
    return out


def scan_for_secrets(text: str, *, known_secrets: Iterable[str] = ()) -> list[str]:
    """Return human-readable reasons when secret material is detected."""
    hits: list[str] = []
    blob = text or ""
    for secret in known_secrets:
        value = (secret or "").strip()
        if value and len(value) >= 4 and value in blob:
            hits.append("known_secret_value")
    for pattern in _SECRET_PATTERNS:
        if pattern.search(blob):
            hits.append(f"pattern:{pattern.pattern[:48]}")
    return hits


def assert_no_secrets(payload: Any, *, known_secrets: Iterable[str] = ()) -> None:
    """Raise :class:`EvidenceSecretError` when secret material is present."""
    blob = json.dumps(payload, default=str, sort_keys=True)
    hits = scan_for_secrets(blob, known_secrets=known_secrets)
    # Also reject literal password-bearing keys except provenance markers.
    lowered = blob.lower()
    for banned in (
        '"password":',
        '"ssh_password":',
        '"winrm_password":',
        '"pg_password":',
        '"token":',
        '"private_key":',
        '"private_key_path":',
        '"secret_ref":',
    ):
        if banned in lowered and "password_encryption" not in lowered:
            # secret_ref must never appear in evidence (runtime-only).
            hits.append(f"key:{banned.strip(':').strip(chr(34))}")
    if hits:
        detail = ", ".join(sorted(set(hits)))
        raise EvidenceSecretError(
            f"discovery evidence rejected: secret material detected ({detail})"
        )


def evidence_dir_for(
    artifacts_root: Path | str,
    *,
    client_slug: str,
    inventory_version_id: str,
    host_id: str,
) -> Path:
    """Return ``artifacts/<client_slug>/preflight/<inventory_version_id>/<host_id>/``."""
    return Path(artifacts_root) / client_slug / "preflight" / inventory_version_id / host_id


def persist_host_evidence(
    evidence: HostDiscoveryEvidence,
    *,
    artifacts_root: Path | str,
    client_slug: str,
    inventory_version_id: str,
    known_secrets: Iterable[str] = (),
) -> Path:
    """Persist sanitized ``discovery.json`` and ``commands.json`` for one host.

    Secret scanning runs on the raw evidence first (defense in depth). Sanitized
    payloads are scanned again before write.
    """
    root = evidence_dir_for(
        artifacts_root,
        client_slug=client_slug,
        inventory_version_id=inventory_version_id,
        host_id=evidence.host_id,
    )
    root.mkdir(parents=True, exist_ok=True)

    # Reject before redaction so canaries cannot be silently persisted.
    raw_commands = [
        {
            "command": c.command,
            "exit_code": c.exit_code,
            "stdout": c.stdout,
            "stderr": c.stderr,
            "collected_at": c.collected_at,
            "transport": c.transport,
            "error": c.error,
        }
        for c in evidence.commands
    ]
    raw_discovery = {
        "host_id": evidence.host_id,
        "transport": evidence.transport,
        "collector": evidence.collector,
        "collector_version": evidence.collector_version,
        "collected_at": evidence.collected_at or utc_now(),
        "facts": evidence.facts,
        "error_code": evidence.error_code,
        "error": evidence.error,
        "limitations": list(evidence.limitations),
    }
    assert_no_secrets(raw_discovery, known_secrets=known_secrets)
    assert_no_secrets(raw_commands, known_secrets=known_secrets)

    commands_payload = [
        {
            "command": sanitize_text(c.command, known_secrets=known_secrets),
            "exit_code": c.exit_code,
            "stdout": sanitize_text(c.stdout, known_secrets=known_secrets),
            "stderr": sanitize_text(c.stderr, known_secrets=known_secrets),
            "collected_at": c.collected_at,
            "transport": c.transport,
            "error": sanitize_text(c.error, known_secrets=known_secrets),
        }
        for c in evidence.commands
    ]
    discovery_payload = {
        "host_id": evidence.host_id,
        "transport": evidence.transport,
        "collector": evidence.collector,
        "collector_version": evidence.collector_version,
        "collected_at": evidence.collected_at or utc_now(),
        "facts": evidence.facts,
        "error_code": evidence.error_code,
        "error": sanitize_text(evidence.error, known_secrets=known_secrets),
        "limitations": list(evidence.limitations),
    }
    assert_no_secrets(discovery_payload, known_secrets=known_secrets)
    assert_no_secrets(commands_payload, known_secrets=known_secrets)

    (root / "discovery.json").write_text(
        json.dumps(discovery_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "commands.json").write_text(
        json.dumps(commands_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return root


def evidence_to_dict(evidence: HostDiscoveryEvidence) -> dict[str, Any]:
    """Serialize evidence for hashing (excludes volatile timestamps when needed)."""
    data = asdict(evidence)
    return data
