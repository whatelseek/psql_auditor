#!/usr/bin/env python3
"""Smoke-test Inline Visualizer v2 via Open WebUI (tool-loop + dashboard)."""

from __future__ import annotations

import json
import re
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
OWUI = ENV.get("OPEN_WEBUI_PUBLIC_URL", "http://127.0.0.1:3001").rstrip("/")
EMAIL = ENV["OPEN_WEBUI_EMAIL"]
PASSWORD = ENV["OPEN_WEBUI_PASSWORD"]
MODEL = "visualizer"
LOG = ROOT / "artifacts" / "owui_inline_visualizer_test.log"

VIZ_RE = re.compile(r"@@@VIZ-START\s*(.*?)\s*@@@VIZ-END", re.S | re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    line = f"[{utc_now()}] {msg}"
    print(line, flush=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def http(
    method: str,
    path: str,
    token: str | None,
    payload: dict | None = None,
    *,
    timeout: float = 420.0,
) -> object:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(
        f"{OWUI}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else {}


def signin() -> str:
    data = http(
        "POST",
        "/api/v1/auths/signin",
        None,
        {"email": EMAIL, "password": PASSWORD},
        timeout=60,
    )
    assert isinstance(data, dict)
    return str(data["token"])


def resolve_tool_result(token: str, name: str, arguments: str) -> str:
    """Execute / stub tool results for the OpenAI-compat tool loop."""
    try:
        args = json.loads(arguments or "{}")
    except json.JSONDecodeError:
        args = {}

    if name in {"view_skill", "builtin_view_skill"} or name.endswith("view_skill"):
        skill_id = (
            args.get("id")
            or args.get("skill")
            or args.get("name")
            or "visualize"
        )
        skill = http("GET", f"/api/v1/skills/id/{skill_id}", token, timeout=60)
        if isinstance(skill, dict) and skill.get("content"):
            return str(skill["content"])
        return json.dumps({"error": f"skill {skill_id} not found"})

    if name in {"visualize", "inline_visualizer_visualize"} or name.endswith(
        "visualize"
    ):
        title = args.get("title") or "Visualization"
        return (
            f'Visualization wrapper "{title}" is mounted and waiting for content. '
            "Now emit the HTML/SVG in your NEXT text response wrapped in the "
            "TEXT delimiters @@@VIZ-START and @@@VIZ-END, each on their own line."
        )

    return json.dumps(
        {"error": f"unsupported tool in smoke test: {name}", "args": args}
    )


def chat_once(token: str, messages: list[dict], *, timeout: float = 420.0) -> dict:
    data = http(
        "POST",
        "/api/chat/completions",
        token,
        {
            "model": MODEL,
            "messages": messages,
            "stream": False,
            "tool_ids": ["inline_visualizer"],
            "skill_ids": ["visualize"],
        },
        timeout=timeout,
    )
    assert isinstance(data, dict)
    choice = (data.get("choices") or [{}])[0]
    return choice.get("message") or {}


def run_tool_loop(token: str, user_text: str, *, max_turns: int = 8) -> str:
    messages: list[dict] = [{"role": "user", "content": user_text}]
    final = ""
    for turn in range(1, max_turns + 1):
        msg = chat_once(token, messages)
        tool_calls = msg.get("tool_calls") or []
        content = msg.get("content") or ""
        if content:
            final = content
            log(f"turn {turn}: content_len={len(content)}")
        if tool_calls:
            names = [(tc.get("function") or {}).get("name") for tc in tool_calls]
            log(f"turn {turn}: tool_calls={names}")
            messages.append(
                {
                    "role": "assistant",
                    "content": content or None,
                    "tool_calls": tool_calls,
                }
            )
            for tc in tool_calls:
                fn = tc.get("function") or {}
                name = fn.get("name") or ""
                result = resolve_tool_result(
                    token, name, fn.get("arguments") or "{}"
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.get("id") or name,
                        "name": name,
                        "content": result[:120000],
                    }
                )
            continue
        return final or content
    return final


def verify_install(token: str) -> None:
    tools = http("GET", "/api/v1/tools/", token, timeout=60)
    ids = [t.get("id") for t in tools] if isinstance(tools, list) else []
    skills = http("GET", "/api/v1/skills/", token, timeout=60)
    if isinstance(skills, dict):
        skill_items = skills.get("items") or []
    else:
        skill_items = skills if isinstance(skills, list) else []
    skill_ids = [s.get("id") for s in skill_items]
    log(f"tools={ids}")
    log(f"skills={skill_ids}")
    if "inline_visualizer" not in ids:
        raise SystemExit("inline_visualizer tool missing")
    if "visualize" not in skill_ids:
        raise SystemExit("visualize skill missing")
    model = http("GET", f"/api/v1/models/model?id={MODEL}", token, timeout=60)
    assert isinstance(model, dict)
    meta = model.get("meta") or {}
    log(f"model meta toolIds={meta.get('toolIds')} skillIds={meta.get('skillIds')}")


def main() -> int:
    LOG.write_text("", encoding="utf-8")
    token = signin()
    log(f"signed in; testing model={MODEL}")
    verify_install(token)

    prompt = (
        "Create a small interactive dashboard visualization for AlphaCo IT audit "
        "follow-up. Include three KPI cards (REQ-001 pass, REQ-002 error, overall "
        "risk High) and a simple SVG bar chart of pass/fail/error counts "
        "(pass=4, fail=1, error=2). Use the visualize tool and skill protocol."
    )
    log(f"PROMPT: {prompt[:160]}…")
    t0 = time.monotonic()
    try:
        content = run_tool_loop(token, prompt)
    except Exception as exc:
        log(f"FAIL chat: {type(exc).__name__}: {exc}")
        return 1
    elapsed = time.monotonic() - t0
    log(f"done in {elapsed:.1f}s, len={len(content or '')}")
    log(f"preview: {(content or '')[:900]}")

    m = VIZ_RE.search(content or "")
    if not m:
        if "@@@VIZ-START" in (content or "") and "@@@VIZ-END" in (content or ""):
            log("PASS: markers present")
            return 0
        log("FAIL: missing @@@VIZ-START / @@@VIZ-END markers")
        return 1

    fragment = m.group(1)
    has_visual = any(
        tag in fragment.lower() for tag in ("<svg", "<div", "<canvas", "<table")
    )
    log(f"viz fragment bytes={len(fragment)} has_visual={has_visual}")
    if not has_visual:
        log("FAIL: viz block empty or non-visual")
        return 1
    log("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
