#!/usr/bin/env python3
"""Multi-client Open WebUI sessions test: switch clients/sessions + evidence on #2."""

from __future__ import annotations

import json
import re
import subprocess
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
CLIENT_A = "AlphaCo"
CLIENT_B = "BetaCo"
LOG = ROOT / "artifacts" / "owui_multi_client_sessions_test.log"

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


def chat(messages: list[dict], user_text: str, *, timeout: float = 3600.0) -> str:
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


def client_slug(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", name.strip()).strip("_").lower() or "client"


def db_sessions(client: str) -> list[dict]:
    db = f"results_{client_slug(client)}"
    out = subprocess.check_output(
        [
            "docker",
            "exec",
            "psql_auditor-results-db-1",
            "psql",
            "-U",
            "results_admin",
            "-d",
            db,
            "-At",
            "-F",
            "|",
            "-c",
            "SELECT session_number, status, evidence_run_id, "
            "COALESCE(framework_id,''), "
            "(SELECT count(*) FROM requirement_results rr "
            " WHERE rr.session_number = s.session_number) AS req_rows "
            "FROM audit_sessions s ORDER BY session_number",
        ],
        text=True,
    )
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        num, status, evid, fw, reqs = line.split("|", 4)
        rows.append(
            {
                "number": int(num),
                "status": status,
                "evidence_run_id": evid,
                "framework_id": fw,
                "req_rows": int(reqs or 0),
            }
        )
    return rows


def db_session_req_count(client: str, session_number: int) -> int:
    db = f"results_{client_slug(client)}"
    out = subprocess.check_output(
        [
            "docker",
            "exec",
            "psql_auditor-results-db-1",
            "psql",
            "-U",
            "results_admin",
            "-d",
            db,
            "-At",
            "-c",
            f"SELECT count(*) FROM requirement_results "
            f"WHERE session_number={int(session_number)};",
        ],
        text=True,
    ).strip()
    return int(out or 0)


def disk_finding_count(client: str) -> int:
    root = Path("/home/ekachurov/psql_auditor/artifacts") / client_slug(client)
    if not root.is_dir():
        # Case variants
        for p in Path("/home/ekachurov/psql_auditor/artifacts").iterdir():
            if p.is_dir() and p.name.lower() == client_slug(client):
                root = p
                break
    if not root.is_dir():
        return 0
    return sum(1 for _ in root.rglob("finding.json"))


def run_it_audit(client: str, *, label: str) -> str:
    """Full IT audit via OWUI for one client; auto skip-all on HITL."""
    log(f"--- {label}: IT audit for {client} ---")
    messages: list[dict] = []
    content = chat(messages, "Start an IT audit", timeout=120)
    for step, reply in (
        (1, client),
        (2, "no"),
        (3, "yes"),
        (4, "IT"),
    ):
        pause = newest_pause(content)
        log(f"{label} intake step~{step} pause={pause}")
        if not pause or pause[0] != "intake":
            # May already be past intake on last answer
            if step == 4 and pause and pause[0] == "hitl":
                break
            if step == 4 and pause is None:
                break
            raise RuntimeError(f"{label}: expected intake, got {pause} / {content[:200]!r}")
        log(f"{label} INTAKE -> {reply!r}")
        # Step 4 (IT) starts assessment — allow long timeout
        timeout = 900 if step == 4 else 120
        content = chat(messages, reply, timeout=timeout)

    # HITL loop
    for i in range(20):
        pause = newest_pause(content)
        if pause is None:
            break
        if pause[0] == "hitl":
            log(f"{label} HITL -> skip all")
            content = chat(messages, "skip all", timeout=900)
            continue
        if pause[0] == "intake":
            raise RuntimeError(f"{label}: unexpected intake after assess: {content[:200]!r}")
        if pause[0] == "continue":
            content = chat(messages, "continue", timeout=900)
            continue
        break

    preview = (content or "").replace("\n", " ")[:220]
    log(f"{label} done preview={preview!r}")
    return content


def list_sessions(client: str | None = None) -> tuple[str, list[dict]]:
    messages: list[dict] = []
    msg = (
        f"List audit sessions for {client}"
        if client
        else "List audit sessions"
    )
    text = chat(messages, msg, timeout=120)
    return text, parse_sessions_table(text)


def continue_session(client: str, session_number: int, *, timeout: float = 180) -> str:
    messages: list[dict] = []
    return chat(
        messages,
        f"continue session {session_number} for {client}",
        timeout=timeout,
    )


def main() -> int:
    LOG.write_text("", encoding="utf-8")
    results: dict[str, str] = {}

    log("=" * 60)
    log("MULTI-CLIENT SESSIONS TEST (Open WebUI)")
    log(f"clients: {CLIENT_A}, {CLIENT_B}")
    log("=" * 60)

    # Fresh DBs for these clients
    for c in (CLIENT_A, CLIENT_B):
        db = f"results_{client_slug(c)}"
        subprocess.call(
            [
                "docker",
                "exec",
                "psql_auditor-results-db-1",
                "psql",
                "-U",
                "results_admin",
                "-d",
                "postgres",
                "-c",
                f"DROP DATABASE IF EXISTS {db};",
            ]
        )

    # 1) Alpha session #1 — complete IT with evidence
    try:
        run_it_audit(CLIENT_A, label="A1")
    except Exception as exc:  # noqa: BLE001
        log(f"FAIL A1: {exc}")
        return 1
    a_rows = db_sessions(CLIENT_A)
    log(f"Alpha DB: {a_rows}")
    if not a_rows or a_rows[0]["number"] != 1:
        results["alpha_s1_alloc"] = f"FAIL {a_rows!r}"
        return 1
    a1_reqs = db_session_req_count(CLIENT_A, 1)
    a1_disk = disk_finding_count(CLIENT_A)
    results["alpha_s1_alloc"] = "PASS (#1)"
    results["alpha_s1_evidence"] = (
        f"PASS (db_reqs={a1_reqs}, disk_findings={a1_disk})"
        if a1_reqs > 0 or a1_disk > 0
        else "FAIL no evidence"
    )

    # 2) Beta session #1 — switch client, complete IT
    try:
        run_it_audit(CLIENT_B, label="B1")
    except Exception as exc:  # noqa: BLE001
        log(f"FAIL B1: {exc}")
        return 1
    b_rows = db_sessions(CLIENT_B)
    log(f"Beta DB: {b_rows}")
    b1_reqs = db_session_req_count(CLIENT_B, 1)
    results["beta_s1_alloc"] = "PASS (#1)" if b_rows and b_rows[0]["number"] == 1 else f"FAIL {b_rows!r}"
    results["beta_s1_evidence"] = (
        f"PASS (db_reqs={b1_reqs})" if b1_reqs > 0 else f"WARN db_reqs={b1_reqs} disk={disk_finding_count(CLIENT_B)}"
    )

    # 3) Alpha session #2 — same client, new session + gather evidence
    try:
        run_it_audit(CLIENT_A, label="A2")
    except Exception as exc:  # noqa: BLE001
        log(f"FAIL A2: {exc}")
        return 1
    a_rows = db_sessions(CLIENT_A)
    log(f"Alpha DB after #2: {a_rows}")
    a2 = next((r for r in a_rows if r["number"] == 2), None)
    a2_reqs = db_session_req_count(CLIENT_A, 2)
    results["alpha_s2_alloc"] = "PASS (#2)" if a2 else f"FAIL {a_rows!r}"
    results["alpha_s2_evidence"] = (
        f"PASS (db_reqs={a2_reqs})"
        if a2_reqs > 0
        else f"FAIL db_reqs={a2_reqs} (need warehouse cells for session 2)"
    )

    # 4) List / switch visibility
    log("PHASE: list sessions (all / Alpha / Beta)")
    alpha_text, alpha_table = list_sessions(CLIENT_A)
    beta_text, beta_table = list_sessions(CLIENT_B)
    _all_text, all_table = list_sessions(None)
    log(f"Alpha list: {alpha_table}")
    log(f"Beta list: {beta_table}")
    log(f"All list: {all_table}")
    log(f"Alpha list preview: {alpha_text[:400]!r}")
    log(f"Beta list preview: {beta_text[:400]!r}")

    alpha_nums = {r["number"] for r in alpha_table}
    beta_nums = {r["number"] for r in beta_table}
    if 1 in alpha_nums and 2 in alpha_nums:
        results["list_alpha_both_sessions"] = "PASS (#1 and #2)"
    else:
        results["list_alpha_both_sessions"] = f"FAIL {alpha_table!r}"

    if any(CLIENT_B.lower() in r["client"].lower() or r["number"] == 1 for r in beta_table) or "#1" in beta_text:
        results["list_beta"] = "PASS"
    else:
        results["list_beta"] = f"FAIL {beta_table!r}"

    # Cross-client isolation: Alpha list should not show BetaCo rows
    if any(CLIENT_B.lower() in r["client"].lower() for r in alpha_table):
        results["list_isolation"] = "FAIL Alpha list includes Beta"
    else:
        results["list_isolation"] = "PASS"

    # 5) Switch: continue Beta #1 then Alpha #2
    log("PHASE: switch continue Beta#1 → Alpha#2")
    try:
        cont_b = continue_session(CLIENT_B, 1, timeout=120)
        log(f"continue Beta#1 preview: {cont_b[:250]!r}")
        # Completed session continue may say cannot resume / already done — OK
        if "intake (1/4)" in cont_b.lower() or "Starting pre-audit intake" in cont_b:
            results["switch_to_beta"] = "FAIL fell into intake"
        else:
            results["switch_to_beta"] = "PASS"
    except Exception as exc:  # noqa: BLE001
        results["switch_to_beta"] = f"WARN {exc}"

    before_a_max = max(r["number"] for r in db_sessions(CLIENT_A))
    try:
        cont_a2 = continue_session(CLIENT_A, 2, timeout=300)
        log(f"continue Alpha#2 preview: {cont_a2[:250]!r}")
        after_a = db_sessions(CLIENT_A)
        after_max = max(r["number"] for r in after_a)
        if after_max > before_a_max:
            results["switch_to_alpha_s2"] = f"FAIL new session #{after_max}"
        elif "Starting pre-audit intake" in cont_a2 or (
            newest_pause(cont_a2)
            and newest_pause(cont_a2)[0] == "intake"
            and "1/4" in cont_a2
        ):
            results["switch_to_alpha_s2"] = "FAIL fell into intake"
        else:
            results["switch_to_alpha_s2"] = "PASS (same client session #2)"
    except Exception as exc:  # noqa: BLE001
        results["switch_to_alpha_s2"] = f"WARN {exc}"

    # Final evidence check for Alpha session 2
    a2_reqs = db_session_req_count(CLIENT_A, 2)
    a2_host = subprocess.check_output(
        [
            "docker",
            "exec",
            "psql_auditor-results-db-1",
            "psql",
            "-U",
            "results_admin",
            "-d",
            f"results_{client_slug(CLIENT_A)}",
            "-At",
            "-c",
            "SELECT count(*) FROM host_results WHERE session_number=2;",
        ],
        text=True,
    ).strip()
    results["alpha_s2_host_results"] = (
        f"PASS (host_results={a2_host}, reqs={a2_reqs})"
        if int(a2_host or 0) > 0 and a2_reqs > 0
        else f"FAIL host_results={a2_host} reqs={a2_reqs}"
    )

    log("")
    log("=" * 60)
    log("MULTI-CLIENT SESSIONS SUMMARY")
    failed = 0
    for k, v in results.items():
        log(f"  {k}: {v}")
        if str(v).startswith("FAIL"):
            failed += 1
    log("=" * 60)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
