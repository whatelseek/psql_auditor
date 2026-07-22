#!/usr/bin/env python3
"""OWUI: gather more evidence for a REQ, refill cells, update report."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path("/home/ekachurov/psql_auditor")
ENV = dict(
    l.split("=", 1)
    for l in (ROOT / ".env").read_text().splitlines()
    if "=" in l and not l.startswith("#")
)
OWUI = (
    ENV.get("OPEN_WEBUI_PUBLIC_URL", "http://127.0.0.1:3001").rstrip("/")
    + "/api/chat/completions"
)
TOKEN = ENV.get("OPEN_WEBUI_API_KEY") or ENV.get("API_KEY") or ""
MODEL = "auditor"
CLIENT = "AlphaCo"
REQ = "REQ-001"
FRAMEWORK = "it_audit"
ARTIFACTS = ROOT / "artifacts" / CLIENT / FRAMEWORK / REQ
LOG = ROOT / "artifacts" / "owui_req_followup_test.log"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    line = f"[{utc_now()}] {msg}"
    print(line, flush=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def chat(messages: list[dict], user_text: str, *, timeout: float = 600.0) -> str:
    messages.append({"role": "user", "content": user_text})
    body = json.dumps(
        {"model": MODEL, "messages": messages, "stream": False},
        ensure_ascii=False,
    ).encode("utf-8")
    req = Request(
        OWUI,
        data=body,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    content = (
        ((payload.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    )
    messages.append({"role": "assistant", "content": content})
    return content


def list_evidence_files() -> list[str]:
    if not ARTIFACTS.is_dir():
        return []
    return sorted(p.name for p in ARTIFACTS.iterdir() if p.is_file())


def main() -> int:
    LOG.write_text("", encoding="utf-8")
    before = set(list_evidence_files())
    log(f"Evidence before: {sorted(before)}")

    messages: list[dict] = []

    # Step 1 — gather (append tools only)
    gather = (
        f"Gather evidence for {REQ} on {FRAMEWORK} for {CLIENT}. "
        "Use SSH: hostname -f; hostname -I; ip -4 addr show | head -40"
    )
    log(f"STEP1 {gather}")
    t0 = time.monotonic()
    r1 = chat(messages, gather, timeout=600)
    log(f"STEP1 ({time.monotonic() - t0:.1f}s) preview: {r1[:500]}")
    after_gather = set(list_evidence_files())
    new_files = sorted(after_gather - before)
    log(f"NEW evidence files after gather: {new_files}")
    if "AlphaCo" not in r1 and "BetaCo" in r1:
        log("FAIL: resolved BetaCo instead of AlphaCo")
        return 1
    if "SSH_HOST is not configured" in r1:
        log("FAIL: SSH still not bound from inventory")
        return 1
    if not new_files:
        log("WARN: no new evidence files (may still have useful tool output)")

    # Step 2 — refill finding cells
    refill = f"Prepare new observation and recommendation for {REQ} for {CLIENT}"
    log(f"STEP2 {refill}")
    t1 = time.monotonic()
    r2 = chat(messages, refill, timeout=600)
    log(f"STEP2 ({time.monotonic() - t1:.1f}s) preview: {r2[:700]}")
    finding = ARTIFACTS / "finding.json"
    if finding.is_file():
        data = json.loads(finding.read_text(encoding="utf-8"))
        log(
            "Finding after refill: "
            f"status={data.get('status')} "
            f"obs_len={len(str(data.get('evidence') or ''))} "
            f"rem_len={len(str(data.get('remediation') or ''))}"
        )
        if "NameError" in str(data.get("evidence") or ""):
            log("FAIL: NameError still in finding")
            return 1
    else:
        log("FAIL: finding.json missing")
        return 1

    # Step 3 — rebuild report
    update = f"Update the report for {CLIENT}"
    log(f"STEP3 {update}")
    t2 = time.monotonic()
    r3 = chat(messages, update, timeout=600)
    log(f"STEP3 ({time.monotonic() - t2:.1f}s) preview: {r3[:500]}")
    report = ARTIFACTS.parent.parent / "report.md"
    log(f"Report exists={report.is_file()} size={report.stat().st_size if report.is_file() else 0}")

    ok = ("AlphaCo" in r1 or "resolved via" in r1.lower()) and "NameError" not in r2
    log("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
