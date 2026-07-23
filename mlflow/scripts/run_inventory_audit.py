#!/usr/bin/env python3
"""Drive intake + full inventory audit via the agent OpenAI-compatible API.

Walks the pre-audit questionnaire for a client that already has
``inventory/<client>/INVENTORY.md``, confirms the proposed host→framework
plan, then waits for the assessment to finish.

Usage::

    python mlflow/scripts/run_inventory_audit.py \\
        --client TestCompany \\
        --base-url http://127.0.0.1:8001 \\
        --api-key sk-auditor-local
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from http.client import RemoteDisconnected
from pathlib import Path
from typing import Any

INTAKE_RE = re.compile(r"\[AUDIT_INTAKE:(?P<thread>[A-Za-z0-9._:-]+)\]")
HITL_RE = re.compile(r"\[AUDIT_HITL:(?P<thread>[A-Za-z0-9._:-]+)\]")


def _chat(
    base_url: str,
    api_key: str,
    messages: list[dict[str, str]],
    *,
    timeout: float,
    retries: int = 2,
) -> str:
    """POST /v1/chat/completions and return assistant content."""
    url = base_url.rstrip("/") + "/v1/chat/completions"
    payload = {
        "model": "auditor",
        "stream": False,
        "messages": messages,
    }
    data = json.dumps(payload).encode("utf-8")
    last_exc: Exception | None = None
    for attempt in range(1, retries + 2):
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            choices = body.get("choices") or []
            if not choices:
                raise RuntimeError(f"empty choices: {body!r}")
            return str(choices[0].get("message", {}).get("content") or "")
        except (urllib.error.URLError, TimeoutError, RemoteDisconnected, ConnectionResetError) as exc:
            last_exc = exc
            print(
                f"(chat attempt {attempt} failed: {type(exc).__name__}: {exc}; retrying)",
                flush=True,
            )
            time.sleep(min(5 * attempt, 20))
    assert last_exc is not None
    raise last_exc


def _step_kind(content: str) -> str:
    """Return intake / hitl / done based on assistant markers."""
    if INTAKE_RE.search(content):
        return "intake"
    if HITL_RE.search(content):
        return "hitl"
    return "done"


def _reply_for_intake(content: str, client: str) -> str:
    """Choose the next intake answer from the assistant prompt.

    Step markers (``1/4`` … ``4/4``) win over keywords — later steps often
    echo earlier answers (e.g. NetBox unreachable text inside step 3).
    """
    lower = content.lower()
    if "1/4" in lower or (
        "client name" in lower and "2/4" not in lower and "3/4" not in lower
    ):
        return client
    if "4/4" in lower or (
        ("confirm" in lower or "exclude" in lower)
        and "1/4" not in lower
        and "2/4" not in lower
        and "3/4" not in lower
    ):
        return "confirm"
    if "3/4" in lower or (
        "access to servers" in lower or "access to servers and services" in lower
    ):
        return "yes"
    if "2/4" in lower or (
        ("cmdb" in lower or "netbox" in lower)
        and "3/4" not in lower
        and "4/4" not in lower
    ):
        return "no"
    if "yes" in lower and "no" in lower:
        return "yes"
    return "confirm"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", default="TestCompany")
    parser.add_argument("--base-url", default="http://127.0.0.1:8001")
    parser.add_argument("--api-key", default="sk-auditor-local")
    parser.add_argument(
        "--intake-timeout",
        type=float,
        default=180.0,
        help="Timeout seconds for simple intake turns",
    )
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=600.0,
        help="Timeout seconds for access=yes probe turn",
    )
    parser.add_argument(
        "--audit-timeout",
        type=float,
        default=14400.0,
        help="Timeout seconds for the final confirm/assess turn",
    )
    parser.add_argument(
        "--max-intake-turns",
        type=int,
        default=8,
    )
    args = parser.parse_args()

    messages: list[dict[str, str]] = [
        {
            "role": "user",
            "content": (
                f"Start a full IT and cybersecurity audit for {args.client}. "
                "Use inventory credentials. Audit every proposed host and "
                "framework from agents/."
            ),
        }
    ]

    print(f"==> starting intake for {args.client} @ {args.base_url}", flush=True)
    try:
        content = _chat(
            args.base_url,
            args.api_key,
            messages,
            timeout=args.intake_timeout,
        )
    except urllib.error.URLError as exc:
        print(f"ERROR contacting agent: {exc}", file=sys.stderr)
        return 1

    messages.append({"role": "assistant", "content": content})
    print("--- assistant ---\n" + content[:2000] + ("\n...\n" if len(content) > 2000 else "\n"), flush=True)

    for turn in range(1, args.max_intake_turns + 1):
        kind = _step_kind(content)
        if kind == "done":
            print("==> audit finished (no further intake)", flush=True)
            break
        if kind == "hitl":
            reply = "skip all"
            print(f"==> HITL pause → {reply!r}", flush=True)
        else:
            reply = _reply_for_intake(content, args.client)
            print(f"==> intake turn {turn} → {reply!r}", flush=True)

        messages.append({"role": "user", "content": reply})
        # Access probe and final confirm are the long turns.
        if reply in {"confirm", "skip all", "retry all"}:
            timeout = args.audit_timeout
        elif reply == "yes":
            timeout = args.probe_timeout
        else:
            timeout = args.intake_timeout
        t0 = time.time()
        try:
            content = _chat(
                args.base_url,
                args.api_key,
                messages,
                timeout=timeout,
            )
        except (urllib.error.URLError, TimeoutError, RemoteDisconnected, ConnectionResetError) as exc:
            print(f"ERROR during turn {turn}: {exc}", file=sys.stderr)
            return 1
        elapsed = time.time() - t0
        messages.append({"role": "assistant", "content": content})
        print(
            f"--- assistant ({elapsed:.0f}s) ---\n"
            + content[:3000]
            + ("\n...\n" if len(content) > 3000 else "\n"),
            flush=True,
        )
        if _step_kind(content) == "done" and reply == "confirm":
            print("==> assessment complete", flush=True)
            break
    else:
        print("ERROR: exceeded intake turns without completion", file=sys.stderr)
        return 1

    summary: dict[str, Any] = {
        "client": args.client,
        "messages": len(messages),
        "final_preview": content[:500],
    }
    try:
        out = Path(__file__).resolve().parents[1] / "data" / "last_inventory_audit.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"==> wrote {out}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"(summary write skipped: {exc})", flush=True)

    print("==> done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
