#!/usr/bin/env python3
"""Install auditor slash-command Prompts into Open WebUI Workspace.

Creates / updates Workspace → Prompts entries so operators can type e.g.
``/list-sessions`` in chat (model **auditor**). Content must match agent
intent phrases in ``auditor.intent``.

Usage (repo root, Open WebUI up)::

    python3 openwebui/install_owui_prompts.py

Operator docs: ``docs/owui-slash-commands.md``.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"

# command (no leading /) → name, content, tags
PROMPTS: list[dict[str, object]] = [
    {
        "command": "list-sessions",
        "name": "List audit sessions",
        "content": "List audit sessions",
        "tags": ["auditor", "sessions"],
    },
    {
        "command": "sessions-continue",
        "name": "Sessions that need continue",
        "content": "Which sessions need continue?",
        "tags": ["auditor", "sessions"],
    },
    {
        "command": "list-sessions-client",
        "name": "List sessions for client",
        "content": "Show me audit sessions for {{client | text:required}}",
        "tags": ["auditor", "sessions"],
    },
    {
        "command": "list-results",
        "name": "List warehouse results for session",
        "content": (
            "List results for {{client | text:required}} session "
            "{{n | number:required}}"
        ),
        "tags": ["auditor", "sessions", "results"],
    },
    {
        "command": "continue",
        "name": "Continue latest interrupted",
        "content": "continue",
        "tags": ["auditor", "sessions"],
    },
    {
        "command": "continue-session",
        "name": "Continue session N for client",
        "content": (
            "continue session {{n | number:required}} for {{client | text:required}}"
        ),
        "tags": ["auditor", "sessions"],
    },
    {
        "command": "update-report",
        "name": "Update report for client",
        "content": "Update the report for {{client | text:required}}",
        "tags": ["auditor", "report"],
    },
    {
        "command": "gather-req",
        "name": "Gather evidence for REQ",
        "content": (
            "Gather evidence for {{req | text:required}} on "
            "{{framework | text:default=\"it_audit\"}} for {{client | text:required}}. "
            "{{hint | textarea:placeholder=\"Optional SSH/SQL hint\"}}"
        ),
        "tags": ["auditor", "followup"],
    },
    {
        "command": "refill-req",
        "name": "Prepare observation for REQ",
        "content": (
            "Prepare new observation and recommendation for "
            "{{req | text:required}} for {{client | text:required}}"
        ),
        "tags": ["auditor", "followup"],
    },
    {
        "command": "revise-req",
        "name": "Revise REQ (gather + refill)",
        "content": (
            "Revise {{req | text:required}} on "
            "{{framework | text:default=\"it_audit\"}} for {{client | text:required}}"
        ),
        "tags": ["auditor", "followup"],
    },
    {
        "command": "start-it-audit",
        "name": "Start IT audit",
        "content": "Start an IT audit",
        "tags": ["auditor", "audit"],
    },
    {
        "command": "run-command",
        "name": "Run ad-hoc SSH command",
        "content": "Run this command: `{{command | text:required}}`",
        "tags": ["auditor", "adhoc"],
    },
    {
        "command": "run-sql",
        "name": "Execute ad-hoc SQL",
        "content": "Execute SQL: {{sql | textarea:required}}",
        "tags": ["auditor", "adhoc"],
    },
    {
        "command": "dashboard",
        "name": "Ask Visualizer for a dashboard",
        "content": (
            "Create an interactive dashboard visualization for "
            "{{client | text:default=\"AlphaCo\"}} audit results. "
            "Include KPI cards and a status breakdown chart. "
            "{{notes | textarea:placeholder=\"Optional counts or findings to include\"}}"
        ),
        "tags": ["visualizer", "dashboard"],
    },
]

PUBLIC_READ = [
    {
        "principal_type": "public",
        "principal_id": "*",
        "permission": "read",
    }
]


def _load_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _request(
    method: str,
    url: str,
    token: str | None,
    payload: dict | None = None,
) -> tuple[int, object]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    def _parse(body: str) -> object:
        if not body:
            return {}
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, _parse(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, _parse(exc.read().decode("utf-8", errors="replace"))


def signin(base: str, email: str, password: str) -> str:
    code, data = _request(
        "POST",
        f"{base}/api/v1/auths/signin",
        None,
        {"email": email, "password": password},
    )
    if code != 200 or not isinstance(data, dict) or not data.get("token"):
        raise SystemExit(f"signin failed ({code}): {data}")
    return str(data["token"])


def list_prompts(base: str, token: str) -> dict[str, dict]:
    code, data = _request("GET", f"{base}/api/v1/prompts/", token)
    if code != 200 or not isinstance(data, list):
        raise SystemExit(f"list prompts failed ({code}): {data}")
    return {str(p.get("command")): p for p in data if isinstance(p, dict)}


def upsert_prompt(base: str, token: str, spec: dict[str, object]) -> None:
    command = str(spec["command"]).lstrip("/")
    existing = list_prompts(base, token)
    payload = {
        "command": command,
        "name": spec["name"],
        "content": spec["content"],
        "tags": spec.get("tags") or ["auditor"],
        "access_grants": PUBLIC_READ,
        "is_production": True,
        "commit_message": "auditor workspace prompts",
    }
    if command in existing:
        pid = existing[command]["id"]
        code, data = _request(
            "POST", f"{base}/api/v1/prompts/id/{pid}/update", token, payload
        )
        action = "updated"
    else:
        code, data = _request(
            "POST", f"{base}/api/v1/prompts/create", token, payload
        )
        action = "created"
        if code in (200, 201) and isinstance(data, dict) and data.get("id"):
            pid = data["id"]
            _request(
                "POST",
                f"{base}/api/v1/prompts/id/{pid}/access/update",
                token,
                {"access_grants": PUBLIC_READ},
            )
    if code not in (200, 201):
        raise SystemExit(f"prompt {command} {action} failed ({code}): {data}")
    # Ensure public read on update path too
    if action == "updated" and isinstance(data, dict) and data.get("id"):
        _request(
            "POST",
            f"{base}/api/v1/prompts/id/{data['id']}/access/update",
            token,
            {"access_grants": PUBLIC_READ},
        )
    print(f"prompt {action}: /{command}")


def main() -> int:
    env = _load_env(ENV_PATH)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        default=env.get("OPEN_WEBUI_PUBLIC_URL", "http://127.0.0.1:3001"),
    )
    parser.add_argument("--email", default=env.get("OPEN_WEBUI_EMAIL", ""))
    parser.add_argument("--password", default=env.get("OPEN_WEBUI_PASSWORD", ""))
    args = parser.parse_args()
    if not args.email or not args.password:
        raise SystemExit("OPEN_WEBUI_EMAIL / OPEN_WEBUI_PASSWORD required")

    base = args.base.rstrip("/")
    token = signin(base, args.email, args.password)
    for spec in PROMPTS:
        upsert_prompt(base, token, spec)

    code, data = _request("GET", f"{base}/api/v1/prompts/", token)
    cmds = sorted(
        f"/{p.get('command')}"
        for p in (data if isinstance(data, list) else [])
        if isinstance(p, dict)
    )
    print(f"done ({len(cmds)} prompts): {', '.join(cmds)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
