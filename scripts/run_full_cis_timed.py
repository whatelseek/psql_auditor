#!/usr/bin/env python3
"""Drive a full CIS audit via /v1/chat/completions and print wall-clock timing."""

from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path("/home/ekachurov/psql_auditor")
ENV = dict(
    l.split("=", 1)
    for l in (ROOT / ".env").read_text().splitlines()
    if "=" in l and not l.startswith("#")
)
API = (
    f"http://127.0.0.1:{ENV.get('AGENT_HOST_PORT', '8001')}/v1/chat/completions"
)
API_KEY = ENV.get("API_KEY") or "sk-auditor-local"
MODEL = "auditor"
LOG = ROOT / "artifacts" / "full_cis_timing.log"

PAUSE_RE = re.compile(
    r"\[AUDIT_(?P<kind>HITL|INTAKE|CONTINUE):(?P<thread>[A-Za-z0-9._:-]+)\]",
    re.I,
)
STEP_RE = re.compile(r"\((\d+)/4\)")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    line = f"[{utc_now()}] {msg}"
    print(line, flush=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def chat(messages: list[dict], user_text: str, *, timeout: int = 10800) -> str:
    messages.append({"role": "user", "content": user_text})
    body = json.dumps(
        {"model": MODEL, "messages": messages, "stream": False},
        ensure_ascii=False,
    ).encode("utf-8")
    req = Request(
        API,
        data=body,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    content = payload["choices"][0]["message"]["content"] or ""
    messages.append({"role": "assistant", "content": content})
    return content


def newest_pause(text: str) -> tuple[str, str] | None:
    matches = list(PAUSE_RE.finditer(text or ""))
    if not matches:
        return None
    m = matches[-1]
    return m.group("kind").lower(), m.group("thread")


def intake_answer(assistant_text: str, step_idx: int) -> str:
    m = STEP_RE.search(assistant_text or "")
    step = int(m.group(1)) if m else step_idx + 1
    answers = {
        1: "TestCompany",
        2: "no",
        3: "yes",
        4: "CIS",
    }
    return answers.get(step, "CIS")


def format_duration(seconds: float) -> str:
    total = int(round(seconds))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s ({seconds:.1f}s)"
    if m:
        return f"{m}m {s}s ({seconds:.1f}s)"
    return f"{s}s ({seconds:.1f}s)"


def main() -> int:
    LOG.write_text("", encoding="utf-8")
    messages: list[dict] = []
    start = time.perf_counter()
    start_iso = utc_now()
    log(f"START full CIS audit at {start_iso}")

    try:
        content = chat(messages, "Start a full CIS cybersecurity audit")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        log(f"FATAL on start: {exc}")
        return 1

    intake_steps = 0
    hitl_steps = 0
    continue_steps = 0
    max_turns = 40

    for turn in range(1, max_turns + 1):
        pause = newest_pause(content)
        preview = (content or "").replace("\n", " ")[:220]
        log(f"turn={turn} pause={pause} preview={preview!r}")

        if pause is None:
            break

        kind, _thread = pause
        if kind == "intake":
            reply = intake_answer(content, intake_steps)
            intake_steps += 1
            log(f"INTAKE reply -> {reply!r}")
        elif kind == "hitl":
            reply = "skip all"
            hitl_steps += 1
            log("HITL reply -> 'skip all'")
        else:
            reply = "continue"
            continue_steps += 1
            log("CONTINUE reply -> 'continue'")

        step_started = time.perf_counter()
        try:
            content = chat(messages, reply)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            elapsed = time.perf_counter() - start
            log(f"FATAL during resume: {exc}")
            log(f"ELAPSED before failure: {format_duration(elapsed)}")
            return 1
        log(
            f"resume completed in {format_duration(time.perf_counter() - step_started)}"
        )
    else:
        elapsed = time.perf_counter() - start
        log(f"FATAL: exceeded max turns ({max_turns})")
        log(f"ELAPSED: {format_duration(elapsed)}")
        return 1

    end = time.perf_counter()
    end_iso = utc_now()
    elapsed = end - start

    report_path = Path("/home/ekachurov/psql_auditor/artifacts/testcompany/report.md")
    zip_path = Path("/home/ekachurov/psql_auditor/artifacts/testcompany_audit.zip")
    report_exists = report_path.exists()
    zip_exists = zip_path.exists()

    summary = [
        "",
        "=" * 60,
        "FULL CIS AUDIT TIMING RESULT",
        "=" * 60,
        f"start_utc:          {start_iso}",
        f"end_utc:            {end_iso}",
        f"elapsed:            {format_duration(elapsed)}",
        f"elapsed_seconds:    {elapsed:.3f}",
        f"intake_answers:      {intake_steps}",
        f"hitl_skip_all:      {hitl_steps}",
        f"continue_resumes:   {continue_steps}",
        f"report.md present:  {report_exists}",
        f"audit.zip present:  {zip_exists}",
        f"final_chars:        {len(content or '')}",
        "=" * 60,
    ]
    for line in summary:
        log(line)

    # Keep a small tail of the final assistant message for verification.
    tail = (content or "")[-1200:]
    log("FINAL_REPORT_TAIL_BEGIN")
    log(tail)
    log("FINAL_REPORT_TAIL_END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
