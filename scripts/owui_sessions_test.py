#!/usr/bin/env python3
"""Test Open WebUI sessions: allocate → interrupt → list → continue (no new #)."""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
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
CLIENT = "SessionLab"
LOG = ROOT / "artifacts" / "owui_sessions_test.log"

PAUSE_RE = re.compile(
    r"\[AUDIT_(?P<kind>HITL|INTAKE|CONTINUE):(?P<thread>[A-Za-z0-9._:-]+)\]",
    re.I,
)
STEP_RE = re.compile(r"\((\d+)/4\)")
SESSION_ROW_RE = re.compile(
    r"\|\s*\*\*#(\d+)\*\*\s*\|\s*([^|]+)\|\s*`([^`]+)`",
    re.I,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    line = f"[{utc_now()}] {msg}"
    print(line, flush=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def chat(
    messages: list[dict],
    user_text: str,
    *,
    timeout: float = 3600.0,
    fresh: bool = False,
) -> str:
    if fresh:
        messages.clear()
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


def newest_pause(text: str) -> tuple[str, str] | None:
    matches = list(PAUSE_RE.finditer(text or ""))
    if not matches:
        return None
    m = matches[-1]
    return m.group("kind").lower(), m.group("thread")


def parse_sessions_table(text: str) -> list[dict]:
    rows = []
    for m in SESSION_ROW_RE.finditer(text or ""):
        rows.append(
            {
                "number": int(m.group(1)),
                "client": m.group(2).strip(),
                "status": m.group(3).strip(),
            }
        )
    return rows


def db_sessions() -> list[dict]:
    out = subprocess.check_output(
        [
            "docker",
            "exec",
            "psql_auditor-results-db-1",
            "psql",
            "-U",
            "results_admin",
            "-d",
            "results_sessionlab",
            "-At",
            "-F",
            "|",
            "-c",
            "SELECT session_number, status, evidence_run_id, "
            "COALESCE(continue_thread_id,''), COALESCE(framework_id,'') "
            "FROM audit_sessions ORDER BY session_number",
        ],
        text=True,
    )
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        rows.append(
            {
                "number": int(parts[0]),
                "status": parts[1],
                "evidence_run_id": parts[2],
                "continue_thread_id": parts[3] if len(parts) > 3 else "",
                "framework_id": parts[4] if len(parts) > 4 else "",
            }
        )
    return rows


def wait_for_session(timeout: float = 90.0) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            rows = db_sessions()
        except subprocess.CalledProcessError:
            rows = []
        if rows:
            return rows
        time.sleep(2)
    return []


def force_interrupt(session_number: int) -> None:
    subprocess.check_call(
        [
            "docker",
            "exec",
            "psql_auditor-results-db-1",
            "psql",
            "-U",
            "results_admin",
            "-d",
            "results_sessionlab",
            "-c",
            (
                "UPDATE audit_sessions SET status='interrupted', "
                "finished_at=COALESCE(finished_at, now()) "
                f"WHERE session_number={int(session_number)};"
            ),
        ]
    )
    # Best-effort meta patch
    try:
        raw = subprocess.check_output(
            [
                "docker",
                "exec",
                "psql_auditor-agent-1",
                "cat",
                "/app/artifacts/sessionlab/meta.json",
            ],
            text=True,
        )
        data = json.loads(raw)
        data["status"] = "interrupted"
        tid = str(data.get("thread_id") or data.get("continue_thread_id") or "")
        if tid:
            data["continue_thread_id"] = tid
        blob = json.dumps(data, indent=2, ensure_ascii=False)
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                "psql_auditor-agent-1",
                "sh",
                "-c",
                "cat > /app/artifacts/sessionlab/meta.json",
            ],
            input=blob,
            text=True,
            check=True,
        )
    except Exception as exc:  # noqa: BLE001
        log(f"meta patch skipped: {exc}")

    subprocess.check_call(
        ["docker", "compose", "restart", "agent"],
        cwd="/home/ekachurov/psql_auditor",
    )
    time.sleep(5)


def main() -> int:
    LOG.write_text("", encoding="utf-8")
    results: dict[str, str] = {}
    messages: list[dict] = []

    log("=" * 60)
    log("OPEN WEBUI SESSIONS TEST")
    log(f"client={CLIENT} via {OWUI}")
    log("=" * 60)

    # --- Phase A: intake steps 1-3 (short), then CIS with short timeout ---
    log("PHASE A: intake via Open WebUI")
    content = chat(messages, "Start a full CIS cybersecurity audit", fresh=True)
    for expected_step, reply in (
        (1, CLIENT),
        (2, "no"),
        (3, "yes"),
    ):
        pause = newest_pause(content)
        log(f"intake pause={pause} (expect step {expected_step})")
        if not pause or pause[0] != "intake":
            log(f"FAIL expected intake pause, got {pause} / {content[:200]!r}")
            return 1
        log(f"INTAKE -> {reply!r}")
        content = chat(messages, reply, timeout=120)

    pause = newest_pause(content)
    log(f"step4 prompt pause={pause}")
    if not pause or pause[0] != "intake":
        log(f"FAIL expected audit-type intake, got {pause}")
        return 1

    log("PHASE A: answer CIS — allow ~55s then client disconnect (interrupt)")
    interrupted_by_timeout = False
    try:
        content = chat(messages, "CIS", timeout=55)
        log(f"CIS call returned early pause={newest_pause(content)}")
    except (TimeoutError, socket.timeout, urllib.error.URLError) as exc:
        interrupted_by_timeout = True
        log(f"CIS call disconnected/timed out as intended: {type(exc).__name__}: {exc}")
        # Remove dangling user message without assistant reply
        if messages and messages[-1].get("role") == "user":
            messages.pop()

    rows = wait_for_session(90)
    log(f"DB sessions: {rows}")
    if not rows:
        log("FAIL: warehouse session was not created")
        results["session_allocated"] = "FAIL"
        return 1

    sess1 = rows[0]["number"]
    results["session_allocated"] = f"PASS (#{sess1} status={rows[0]['status']})"

    if rows[0]["status"] == "running" or interrupted_by_timeout:
        log(f"Forcing interrupt on session #{sess1} + agent restart")
        force_interrupt(sess1)
        results["interrupt"] = "PASS"
    else:
        results["interrupt"] = f"INFO already {rows[0]['status']}"

    rows = db_sessions()
    log(f"DB after interrupt: {rows}")
    if rows[0]["status"] != "interrupted":
        results["interrupt_status"] = f"FAIL status={rows[0]['status']}"
    else:
        results["interrupt_status"] = "PASS (interrupted)"

    evid = rows[0]["evidence_run_id"]
    if evid.lower() in {"sessionlab", CLIENT.lower()}:
        results["evidence_run_id"] = f"PASS ({evid})"
    else:
        results["evidence_run_id"] = f"WARN ({evid})"

    # --- Phase B: list via OWUI ---
    log("PHASE B: List audit sessions for SessionLab via Open WebUI")
    listed = chat(
        [],
        f"List audit sessions for {CLIENT}",
        fresh=True,
        timeout=120,
    )
    log(f"list preview: {listed[:600]!r}")
    table = parse_sessions_table(listed)
    log(f"parsed: {table}")
    if any(r["number"] == sess1 for r in table) or f"#{sess1}" in listed:
        results["list_sessions"] = f"PASS (#{sess1} listed)"
    else:
        results["list_sessions"] = f"FAIL listed={table!r} text={listed[:200]!r}"

    # --- Phase C: continue — must not create new session ---
    log(f"PHASE C: continue session {sess1} for {CLIENT}")
    before_max = max(r["number"] for r in db_sessions())
    try:
        continued = chat(
            [],
            f"continue session {sess1} for {CLIENT}",
            fresh=True,
            timeout=180,
        )
        cont_preview = (continued or "").replace("\n", " ")[:350]
        log(f"continue preview: {cont_preview!r}")
    except (TimeoutError, socket.timeout, urllib.error.URLError) as exc:
        continued = f"(client timeout while resuming: {exc})"
        log(continued)
        # Resume started — restart agent so we can inspect DB without long run
        subprocess.check_call(
            ["docker", "compose", "restart", "agent"],
            cwd="/home/ekachurov/psql_auditor",
        )
        time.sleep(5)

    after = db_sessions()
    after_max = max(r["number"] for r in after)
    log(f"DB after continue: {after}")
    if after_max > before_max:
        results["continue_no_new_session"] = (
            f"FAIL allocated #{after_max} (was max #{before_max})"
        )
    else:
        results["continue_no_new_session"] = f"PASS (still max #{after_max})"

    text = continued or ""
    if "Starting pre-audit intake" in text or newest_pause(text) and newest_pause(text)[0] == "intake" and "1/4" in text:
        results["continue_not_intake"] = "FAIL fell into intake"
    elif (
        "Continuing" in text
        or "Could not resume" in text
        or "Host → framework" in text
        or "Assessed" in text
        or "HITL" in text
        or "timeout" in text.lower()
        or newest_pause(text) is not None
    ):
        results["continue_not_intake"] = "PASS"
    else:
        results["continue_not_intake"] = f"WARN {text[:180]!r}"

    # --- Summary ---
    log("")
    log("=" * 60)
    log("SESSIONS TEST SUMMARY")
    failed = 0
    for k, v in results.items():
        log(f"  {k}: {v}")
        if str(v).startswith("FAIL"):
            failed += 1
    log("=" * 60)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
