#!/usr/bin/env python3
"""Install Inline Visualizer v2 (tool + skill) into Open WebUI via API.

Also optionally:
  * adds a LiteLLM OpenAI connection (for a general chat model)
  * creates workspace model ``visualizer`` with tool/skill attached
  * enables ``iframeSandboxAllowSameOrigin`` for the admin user

Run on the host (needs Open WebUI reachable). Defaults match this lab stack.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "openwebui" / "inline-visualizer-v2" / "tool.py"
SKILL_PATH = ROOT / "openwebui" / "inline-visualizer-v2" / "SKILL.md"
ENV_PATH = ROOT / ".env"

TOOL_ID = "inline_visualizer"
SKILL_ID = "visualize"
MODEL_ID = "visualizer"


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
    token: str,
    payload: dict | None = None,
    *,
    insecure: bool = False,
) -> tuple[int, object]:
    data = None
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = ssl._create_unverified_context() if insecure else None
    def _parse(body: str) -> object:
        if not body:
            return {}
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
            return resp.status, _parse(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, _parse(body)


def signin(base: str, email: str, password: str) -> str:
    code, data = _request(
        "POST",
        f"{base}/api/v1/auths/signin",
        "",
        {"email": email, "password": password},
    )
    if code != 200 or not isinstance(data, dict) or not data.get("token"):
        raise SystemExit(f"signin failed ({code}): {data}")
    return str(data["token"])


def parse_skill_md(text: str) -> tuple[str, str, str]:
    """Return (name, description, content) from SKILL.md with YAML frontmatter."""
    m = re.match(r"^---\n(.*?)\n---\n(.*)\Z", text, re.S)
    if not m:
        return "visualize", "Inline visualizer skill", text
    fm, body = m.group(1), m.group(2).lstrip("\n")
    name, desc = "visualize", ""
    for line in fm.splitlines():
        if line.startswith("name:"):
            name = line.split(":", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("description:"):
            desc = line.split(":", 1)[1].strip().strip('"').strip("'")
    return name, desc, body


def upsert_tool(base: str, token: str, content: str) -> None:
    meta = {
        "description": (
            "Renders interactive HTML/SVG visualizations inline in chat "
            "(@@@VIZ-START / @@@VIZ-END streaming)."
        ),
        "manifest": {},
    }
    payload = {
        "id": TOOL_ID,
        "name": "Inline Visualizer",
        "content": content,
        "meta": meta,
        "access_grants": [],
    }
    code, data = _request("GET", f"{base}/api/v1/tools/id/{TOOL_ID}", token)
    if code == 200:
        code, data = _request(
            "POST", f"{base}/api/v1/tools/id/{TOOL_ID}/update", token, payload
        )
        action = "updated"
    else:
        code, data = _request("POST", f"{base}/api/v1/tools/create", token, payload)
        action = "created"
    if code not in (200, 201):
        raise SystemExit(f"tool {action} failed ({code}): {data}")
    print(f"tool {action}: {TOOL_ID}")


def upsert_skill(base: str, token: str, skill_text: str) -> None:
    name, desc, body = parse_skill_md(skill_text)
    payload = {
        "id": SKILL_ID,
        "name": name,
        "description": desc
        or "Render rich interactive visuals inline via visualize().",
        "content": body,
        "meta": {"tags": ["visualizer", "dashboard"]},
        "is_active": True,
        "access_grants": [],
    }
    code, _ = _request("GET", f"{base}/api/v1/skills/id/{SKILL_ID}", token)
    if code == 200:
        code, data = _request(
            "POST", f"{base}/api/v1/skills/id/{SKILL_ID}/update", token, payload
        )
        action = "updated"
    else:
        code, data = _request("POST", f"{base}/api/v1/skills/create", token, payload)
        action = "created"
    if code not in (200, 201):
        raise SystemExit(f"skill {action} failed ({code}): {data}")
    print(f"skill {action}: {SKILL_ID} (name={name})")


def ensure_litellm_connection(
    base: str,
    token: str,
    litellm_base: str,
    litellm_key: str,
) -> None:
    code, cfg = _request("GET", f"{base}/openai/config", token)
    if code != 200 or not isinstance(cfg, dict):
        print(f"warn: could not read openai config ({code}); skip litellm wire-up")
        return

    urls = list(cfg.get("OPENAI_API_BASE_URLS") or [])
    keys = list(cfg.get("OPENAI_API_KEYS") or [])
    configs = dict(cfg.get("OPENAI_API_CONFIGS") or {})

    litellm_url = litellm_base.rstrip("/")
    if not litellm_url.endswith("/v1"):
        litellm_url = litellm_url + "/v1"

    if litellm_url in urls:
        idx = urls.index(litellm_url)
        keys[idx] = litellm_key
        print(f"litellm connection already present at index {idx}")
    else:
        urls.append(litellm_url)
        keys.append(litellm_key)
        idx = len(urls) - 1
        print(f"added litellm connection at index {idx}: {litellm_url}")

    # Keep agent connection scoped; litellm gets chat completions.
    configs.setdefault(
        "0",
        {
            "enable": True,
            "tags": [],
            "prefix_id": "",
            "model_ids": ["auditor"],
            "connection_type": "external",
            "auth_type": "bearer",
            "api_type": "openai",
        },
    )
    configs["0"]["model_ids"] = ["auditor"]
    configs["0"]["api_type"] = configs["0"].get("api_type") or "openai"
    configs[str(idx)] = {
        "enable": True,
        "tags": ["litellm"],
        "prefix_id": "",
        "model_ids": [],
        "connection_type": "external",
        "auth_type": "bearer",
        "api_type": "openai",
    }

    payload = {
        "ENABLE_OPENAI_API": True,
        "OPENAI_API_BASE_URLS": urls,
        "OPENAI_API_KEYS": keys,
        "OPENAI_API_CONFIGS": configs,
    }
    code, data = _request("POST", f"{base}/openai/config/update", token, payload)
    if code in (200, 201):
        print("openai config updated")
        return
    print(f"warn: openai config update failed ({code}): {data}")


def upsert_visualizer_model(base: str, token: str, base_model_id: str) -> None:
    payload = {
        "id": MODEL_ID,
        "base_model_id": base_model_id,
        "name": "Visualizer",
        "meta": {
            "description": (
                "General chat model with Inline Visualizer v2 "
                "(dashboards / charts / diagrams)."
            ),
            "toolIds": [TOOL_ID],
            "skillIds": [SKILL_ID],
            "capabilities": {
                "vision": False,
                "file_upload": False,
                "web_search": False,
                "image_generation": False,
                "code_interpreter": False,
                "citations": False,
            },
        },
        "params": {"function_calling": "native"},
        "access_grants": [],
        "is_active": True,
    }
    code, existing = _request(
        "GET", f"{base}/api/v1/models/model?id={MODEL_ID}", token
    )
    if code == 200 and isinstance(existing, dict) and existing.get("id"):
        code, data = _request(
            "POST", f"{base}/api/v1/models/model/update", token, payload
        )
        if code not in (200, 201):
            raise SystemExit(f"model update failed ({code}): {data}")
        print(f"model updated: {MODEL_ID} -> {base_model_id}")
        return
    code, data = _request("POST", f"{base}/api/v1/models/create", token, payload)
    if code not in (200, 201):
        raise SystemExit(f"model create failed ({code}): {data}")
    print(f"model created: {MODEL_ID} -> {base_model_id}")


def enable_iframe_same_origin(base: str, token: str) -> None:
    code, settings = _request("GET", f"{base}/api/v1/users/user/settings", token)
    if code != 200 or not isinstance(settings, dict):
        print(f"warn: could not read user settings ({code})")
        return
    ui = dict(settings.get("ui") or {})
    ui["iframeSandboxAllowSameOrigin"] = True
    settings["ui"] = ui
    code, data = _request(
        "POST", f"{base}/api/v1/users/user/settings/update", token, settings
    )
    if code in (200, 201):
        print("enabled ui.iframeSandboxAllowSameOrigin")
    else:
        print(f"warn: settings update failed ({code}): {data}")


def main() -> int:
    env = _load_env(ENV_PATH)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        default=env.get("OPEN_WEBUI_PUBLIC_URL", "http://127.0.0.1:3001"),
    )
    parser.add_argument("--email", default=env.get("OPEN_WEBUI_EMAIL", ""))
    parser.add_argument("--password", default=env.get("OPEN_WEBUI_PASSWORD", ""))
    parser.add_argument(
        "--litellm-base",
        default=env.get("LITELLM_BASE_URL", ""),
    )
    parser.add_argument(
        "--litellm-key",
        default=env.get("LITELLM_API_KEY", ""),
    )
    parser.add_argument(
        "--base-model",
        default=env.get("LITELLM_MODEL", "openai/gpt-oss-120b"),
    )
    parser.add_argument(
        "--skip-model",
        action="store_true",
        help="Only install tool+skill (no LiteLLM / workspace model).",
    )
    args = parser.parse_args()
    if not args.email or not args.password:
        raise SystemExit("OPEN_WEBUI_EMAIL / OPEN_WEBUI_PASSWORD required")
    if not TOOL_PATH.is_file() or not SKILL_PATH.is_file():
        raise SystemExit(f"missing {TOOL_PATH} or {SKILL_PATH}")

    base = args.base.rstrip("/")
    token = signin(base, args.email, args.password)
    upsert_tool(base, token, TOOL_PATH.read_text(encoding="utf-8"))
    upsert_skill(base, token, SKILL_PATH.read_text(encoding="utf-8"))
    enable_iframe_same_origin(base, token)

    if not args.skip_model:
        if not args.litellm_base or not args.litellm_key:
            print("warn: LITELLM_* not set; skipping model wire-up")
        else:
            ensure_litellm_connection(
                base, token, args.litellm_base, args.litellm_key
            )
            upsert_visualizer_model(base, token, args.base_model)

    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
