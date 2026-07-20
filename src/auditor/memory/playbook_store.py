"""Long-term procedural memory for audit verify commands.

Implements LangGraph long-term memory as a **procedural playbook collection**:

* Namespace: ``(\"playbooks\", <framework_id>)``
* Key: requirement id (``REQ-001``) or ``_framework`` for general tips
* Value: tools to prefer, notes, source (``seed`` / ``learned``)

Seed YAML files under ``agents/playbooks/<framework_id>.yaml`` are loaded at
startup into an ``InMemoryStore``. Successful tool calls can be written back
(hot-path learning) and flushed to ``MEMORY_DIR`` so they survive restarts.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from langgraph.store.memory import InMemoryStore

from auditor.config import Settings, get_settings

logger = logging.getLogger(__name__)

MAX_LEARNED_TOOLS_PER_REQ = 6


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ns(framework_id: str) -> tuple[str, ...]:
    return ("playbooks", framework_id)


class PlaybookMemory:
    """Procedural long-term memory backed by LangGraph ``InMemoryStore`` + disk."""

    def __init__(
        self,
        *,
        playbooks_dir: Path | str,
        memory_dir: Path | str,
        learn: bool = True,
    ) -> None:
        self.playbooks_dir = Path(playbooks_dir)
        self.memory_dir = Path(memory_dir)
        self.learn = learn
        self._store = InMemoryStore()
        self._lock = threading.Lock()
        self._dirty = False
        self.reload()

    @property
    def store(self) -> InMemoryStore:
        return self._store

    def reload(self) -> None:
        """Load seed YAML then overlay learned JSON from ``memory_dir``."""
        with self._lock:
            self._store = InMemoryStore()
            self._load_seeds()
            self._load_learned()
            self._dirty = False

    def _load_seeds(self) -> None:
        if not self.playbooks_dir.is_dir():
            return
        for path in sorted(self.playbooks_dir.glob("*.yaml")):
            self._ingest_yaml_file(path, source="seed")
        for path in sorted(self.playbooks_dir.glob("*.yml")):
            self._ingest_yaml_file(path, source="seed")

    def _ingest_yaml_file(self, path: Path, *, source: str) -> None:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            logger.warning("Skipping playbook %s: %s", path, exc)
            return
        if not isinstance(data, dict):
            return
        framework_id = str(data.get("framework_id") or path.stem)
        tips = data.get("framework_tips") or data.get("tips") or []
        if tips:
            self._store.put(
                _ns(framework_id),
                "_framework",
                {
                    "framework_id": framework_id,
                    "tips": list(tips) if isinstance(tips, list) else [str(tips)],
                    "source": source,
                    "updated_at": _utc_now(),
                },
            )
        requirements = data.get("requirements") or {}
        if not isinstance(requirements, dict):
            return
        for req_id, body in requirements.items():
            if not isinstance(body, dict):
                continue
            self._store.put(
                _ns(framework_id),
                str(req_id),
                {
                    "framework_id": framework_id,
                    "requirement_id": str(req_id),
                    "tools": list(body.get("tools") or []),
                    "notes": str(body.get("notes") or ""),
                    "source": source,
                    "updated_at": _utc_now(),
                },
            )

    def _load_learned(self) -> None:
        path = self.memory_dir / "learned_playbooks.json"
        if not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not load learned memory %s: %s", path, exc)
            return
        frameworks = payload.get("frameworks") or {}
        if not isinstance(frameworks, dict):
            return
        for framework_id, entries in frameworks.items():
            if not isinstance(entries, dict):
                continue
            for key, value in entries.items():
                if not isinstance(value, dict):
                    continue
                value = {**value, "source": value.get("source") or "learned"}
                self._store.put(_ns(str(framework_id)), str(key), value)

    def persist(self) -> Path | None:
        """Flush learned entries to ``MEMORY_DIR/learned_playbooks.json``."""
        with self._lock:
            if not self._dirty and not self.learn:
                return None
            frameworks: dict[str, dict[str, Any]] = {}
            # InMemoryStore has no public list-all; track via search per known ns
            # by reading seed file stems + any keys already in learned file.
            framework_ids = self._known_framework_ids()
            for fw in framework_ids:
                items = self._store.search(_ns(fw), limit=200)
                learned: dict[str, Any] = {}
                for item in items:
                    value = dict(item.value or {})
                    if value.get("source") != "learned":
                        continue
                    learned[item.key] = value
                if learned:
                    frameworks[fw] = learned
            self.memory_dir.mkdir(parents=True, exist_ok=True)
            path = self.memory_dir / "learned_playbooks.json"
            path.write_text(
                json.dumps(
                    {"updated_at": _utc_now(), "frameworks": frameworks},
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            self._dirty = False
            return path

    def _known_framework_ids(self) -> set[str]:
        ids: set[str] = set()
        if self.playbooks_dir.is_dir():
            for path in self.playbooks_dir.glob("*.y*ml"):
                ids.add(path.stem)
        learned = self.memory_dir / "learned_playbooks.json"
        if learned.is_file():
            try:
                payload = json.loads(learned.read_text(encoding="utf-8"))
                ids.update((payload.get("frameworks") or {}).keys())
            except (OSError, json.JSONDecodeError):
                pass
        return ids

    def get_entry(self, framework_id: str, req_id: str) -> dict[str, Any] | None:
        item = self._store.get(_ns(framework_id), req_id)
        if item is None:
            return None
        return dict(item.value or {})

    def get_framework_tips(self, framework_id: str) -> list[str]:
        item = self._store.get(_ns(framework_id), "_framework")
        if item is None:
            return []
        tips = (item.value or {}).get("tips") or []
        return [str(t) for t in tips]

    def format_prompt_block(self, framework_id: str, req_id: str) -> str:
        """Render procedural memory for injection into the evidence prompt."""
        lines: list[str] = [
            "### Long-term playbook memory (prefer these tools/commands)",
        ]
        tips = self.get_framework_tips(framework_id)
        if tips:
            lines.append("Framework tips:")
            for tip in tips[:8]:
                lines.append(f"- {tip}")
        entry = self.get_entry(framework_id, req_id)
        if not entry:
            lines.append(
                f"No stored playbook for `{framework_id}` / `{req_id}` yet. "
                "Use checklist How-to-verify; successful tool calls will be remembered."
            )
            return "\n".join(lines)

        notes = (entry.get("notes") or "").strip()
        if notes:
            lines.append(f"Notes: {notes}")
        tools = entry.get("tools") or []
        if tools:
            lines.append("Preferred tool calls (run these first when applicable):")
            for idx, tool in enumerate(tools, start=1):
                if not isinstance(tool, dict):
                    continue
                name = tool.get("name") or tool.get("tool") or "tool"
                args = tool.get("arguments") or tool.get("args") or {}
                lines.append(f"{idx}. `{name}` args={json.dumps(args, ensure_ascii=False)}")
        else:
            lines.append("No concrete tool recipes stored for this requirement.")
        source = entry.get("source") or "seed"
        lines.append(f"(memory source: {source})")
        return "\n".join(lines)

    def remember_tool(
        self,
        framework_id: str,
        req_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
        *,
        success: bool,
    ) -> None:
        """Hot-path learning: remember a successful tool recipe for this REQ."""
        if not self.learn or not success or not framework_id or not req_id:
            return
        if not tool_name or tool_name.startswith("mcp_list"):
            return
        args = dict(arguments or {})
        # Avoid storing huge SQL dumps / file bodies as "memory".
        for key in list(args.keys()):
            val = args[key]
            if isinstance(val, str) and len(val) > 2000:
                args[key] = val[:2000] + "…"

        with self._lock:
            item = self._store.get(_ns(framework_id), req_id)
            existing = dict(item.value or {}) if item else {
                "framework_id": framework_id,
                "requirement_id": req_id,
                "tools": [],
                "notes": "",
            }
            tools = list(existing.get("tools") or [])
            recipe = {"name": tool_name, "arguments": args}
            # Deduplicate by name+args JSON
            sig = json.dumps(recipe, sort_keys=True, ensure_ascii=False)
            tools = [
                t
                for t in tools
                if json.dumps(
                    {
                        "name": t.get("name"),
                        "arguments": t.get("arguments") or t.get("args") or {},
                    },
                    sort_keys=True,
                    ensure_ascii=False,
                )
                != sig
            ]
            tools.insert(0, recipe)
            tools = tools[:MAX_LEARNED_TOOLS_PER_REQ]
            existing.update(
                {
                    "tools": tools,
                    "source": "learned",
                    "updated_at": _utc_now(),
                }
            )
            self._store.put(_ns(framework_id), req_id, existing)
            self._dirty = True

        # Persist outside the lock (persist() acquires the same lock).
        try:
            self.persist()
        except OSError as exc:
            logger.warning("Failed to persist learned playbooks: %s", exc)


@lru_cache
def get_playbook_memory() -> PlaybookMemory:
    """Process-wide playbook memory (seed + learned overlay)."""
    settings = get_settings()
    return PlaybookMemory(
        playbooks_dir=settings.playbooks_dir,
        memory_dir=settings.memory_dir,
        learn=settings.memory_learn,
    )


def reset_playbook_memory_cache() -> None:
    """Test helper: clear the cached singleton."""
    get_playbook_memory.cache_clear()
