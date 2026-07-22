#!/usr/bin/env python3
"""Drive an IT audit through Open WebUI API and report timing."""

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
OWUI = (
    ENV.get("OPEN_WEBUI_PUBLIC_URL", "http://127.0.0.1:3001").rstrip("/")
    + "/api/chat/completions"
)
TOKEN = ENV.get("OPEN_WEBUI_API_KEY") or ENV.get("API_KEY") or ""
MODEL = "auditor"
LOG = ROOT / "artifacts" / "owui_it_audit_test.log"

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


def chat(messages: list[dict], user_text: str, *, timeout: int = 3600) -> str:
    messages.append({"role": "user", "content": user_text})
    body = json.dumps(
        {
            "model": MODEL,
            "messages": messages,
            "stream": False,
        },
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
        ((payload.get("choices") or [{}])[0].get("message") or {}).get("content")
        or payload.get("content")
        or ""
    )
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
    return {1: "TestCompany", 2: "no", 3: "yes", 4: "IT"}.get(step, "IT")


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
    log(f"START Open WebUI IT audit test at {start_iso}")
    log(f"endpoint={OWUI} model={MODEL}")

    try:
        content = chat(messages, "Start an IT audit")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        log(f"FATAL on start: {exc}")
        return 1

    intake_steps = 0
    hitl_steps = 0
    for turn in range(1, 30):
        pause = newest_pause(content)
        preview = (content or "").replace("\n", " ")[:220]
        log(f"turn={turn} pause={pause} preview={preview!r}")
        if pause is None:
            break
        kind, _ = pause
        if kind == "intake":
            reply = intake_answer(content, intake_steps)
            intake_steps += 1
            log(f"INTAKE -> {reply!r}")
        elif kind == "hitl":
            reply = "skip all"
            hitl_steps += 1
            log("HITL -> skip all")
        else:
            reply = "continue"
            log("CONTINUE -> continue")
        step_t0 = time.perf_counter()
        try:
            content = chat(messages, reply)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            log(f"FATAL: {exc}")
            log(f"ELAPSED: {format_duration(time.perf_counter() - start)}")
            return 1
        log(f"resume in {format_duration(time.perf_counter() - step_t0)}")
    else:
        log("FATAL: max turns")
        return 1

    elapsed = time.perf_counter() - start
    end_iso = utc_now()
    report = Path("/home/ekachurov/psql_auditor/artifacts/testcompany/report.md")
    zip_path = Path("/home/ekachurov/psql_auditor/artifacts/testcompany_audit.zip")
    for line in [
        "",
        "=" * 60,
        "OPEN WEBUI IT AUDIT TEST RESULT",
        "=" * 60,
        f"start_utc:       {start_iso}",
        f"end_utc:         {end_iso}",
        f"elapsed:         {format_duration(elapsed)}",
        f"intake_answers:   {intake_steps}",
        f"hitl_skip_all:   {hitl_steps}",
        f"report.md:       {report.exists()}",
        f"audit.zip:       {zip_path.exists()}",
        f"final_chars:     {len(content or '')}",
        "=" * 60,
    ]:
        log(line)
    log("FINAL_TAIL_BEGIN")
    log((content or "")[-900:])
    log("FINAL_TAIL_END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
