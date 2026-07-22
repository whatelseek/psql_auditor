"""Long-term procedural memory for audit verify commands.

Implements LangGraph long-term memory as a **procedural playbook collection**:

* Namespace: ``(\"playbooks\", <framework_id>)``
* Key: requirement id (``REQ-001``) or ``_framework`` for general tips
* Value: tools to prefer, notes, source (``seed`` / ``learned``)

Pipeline role:
    Injected into evidence prompts via ``format_prompt_block`` and updated
    after successful tool calls in ``remember_tool``. Learned recipes persist to
    the **results warehouse Postgres** (``playbook_memory`` table) when
    ``RESULTS_DB_ENABLED``; otherwise to ``MEMORY_DIR/learned_playbooks.json``.
    Hot-path reads use an in-process ``InMemoryStore`` cache.

Key entry point:
    ``PlaybookMemory`` — YAML seeds + Postgres/JSON learned overlay + RAM cache.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from langgraph.store.memory import InMemoryStore

from auditor.config import Settings

logger = logging.getLogger(__name__)

MAX_LEARNED_TOOLS_PER_REQ = 6


def _utc_now() -> str:
    """Return current UTC time as ISO-8601 string for playbook timestamps."""
    return datetime.now(timezone.utc).isoformat()


def _memory_framework_id(framework_id: str) -> str:
    """Bare checklist id safe for LangGraph store namespaces.

    Evidence keys may be ``host/fw`` (e.g. ``10.200.29.78/ubuntu_cis``). LangGraph
    rejects namespace labels that contain ``.``, so strip the host prefix and
    neutralize remaining dots.
    """
    parts = [p for p in str(framework_id or "").replace("\\", "/").split("/") if p]
    bare = parts[-1] if parts else "unknown"
    return bare.replace(".", "_") or "unknown"


def _ns(framework_id: str) -> tuple[str, ...]:
    """Build LangGraph store namespace tuple for a framework id.

    Args:
        framework_id: Checklist or evidence key (may include host prefix).

    Returns:
        ``("playbooks", <sanitized_framework_id>)``.
    """
    return ("playbooks", _memory_framework_id(framework_id))


def _run_coro_sync(coro: Any, *, timeout: float = 30.0) -> Any:
    """Run an async coroutine from sync code (thread + dedicated event loop)."""

    def _runner() -> Any:
        return asyncio.run(coro)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_runner).result(timeout=timeout)


class PlaybookMemory:
    """Procedural long-term memory backed by LangGraph ``InMemoryStore`` + Postgres.

    Loads seed YAML from ``playbooks_dir``, overlays learned entries from the
    results warehouse (or JSON fallback), and persists new recipes after
    successful tool calls. Reads stay in RAM for speed.
    """

    def __init__(
        self,
        *,
        playbooks_dir: Path | str,
        memory_dir: Path | str,
        learn: bool = True,
        settings: Settings | None = None,
    ) -> None:
        """Create memory and load seeds + learned entries.

        Args:
            playbooks_dir: Directory of ``*.yaml`` / ``*.yml`` seed playbooks.
            memory_dir: Writable directory for JSON fallback
                (``learned_playbooks.json`` when Postgres is off).
            learn: When ``False``, skip hot-path learning and persistence.
            settings: Optional settings (results DB URL / flags).
        """
        self.playbooks_dir = Path(playbooks_dir)
        self.memory_dir = Path(memory_dir)
        self.learn = learn
        self.settings = settings
        self._store = InMemoryStore()
        self._lock = threading.Lock()
        self._dirty = False
        self._pg_framework_ids: set[str] = set()
        self.reload()

    @property
    def store(self) -> InMemoryStore:
        """Underlying LangGraph in-memory key-value store (hot-path cache)."""
        return self._store

    def _results_store(self):
        """Return enabled ResultsStore when settings configure the warehouse."""
        if self.settings is None:
            return None
        from auditor.results_store import get_results_store

        return get_results_store(self.settings)

    def reload(self) -> None:
        """Load seed YAML then overlay learned entries from Postgres or JSON.

        Replaces the in-memory store and clears the dirty flag.
        """
        with self._lock:
            self._store = InMemoryStore()
            self._load_seeds()
            self._load_learned()
            self._dirty = False

    def _load_seeds(self) -> None:
        """Ingest all ``*.yaml`` / ``*.yml`` files from ``playbooks_dir``."""
        if not self.playbooks_dir.is_dir():
            return
        for path in sorted(self.playbooks_dir.glob("*.yaml")):
            self._ingest_yaml_file(path, source="seed")
        for path in sorted(self.playbooks_dir.glob("*.yml")):
            self._ingest_yaml_file(path, source="seed")

    def _ingest_yaml_file(self, path: Path, *, source: str) -> None:
        """Parse one playbook YAML file into store entries.

        Args:
            path: Seed playbook file path.
            source: Provenance label (typically ``seed``).
        """
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

    def _apply_learned_frameworks(self, frameworks: dict[str, dict[str, Any]]) -> None:
        """Overlay learned framework→entry maps onto the in-memory store."""
        for framework_id, entries in frameworks.items():
            if not isinstance(entries, dict):
                continue
            self._pg_framework_ids.add(_memory_framework_id(str(framework_id)))
            for key, value in entries.items():
                if not isinstance(value, dict):
                    continue
                value = {**value, "source": value.get("source") or "learned"}
                self._store.put(_ns(str(framework_id)), str(key), value)

    def _load_learned_from_json(self) -> dict[str, dict[str, Any]]:
        """Read ``memory_dir/learned_playbooks.json`` if present."""
        path = self.memory_dir / "learned_playbooks.json"
        if not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not load learned memory %s: %s", path, exc)
            return {}
        frameworks = payload.get("frameworks") or {}
        return frameworks if isinstance(frameworks, dict) else {}

    def _load_learned(self) -> None:
        """Overlay learned recipes from Postgres (preferred) or JSON fallback."""
        self._pg_framework_ids = set()
        store = self._results_store()
        frameworks: dict[str, dict[str, Any]] = {}
        if store is not None:
            try:
                frameworks = _run_coro_sync(store.load_learned_playbooks()) or {}
            except Exception as exc:  # noqa: BLE001
                logger.warning("Postgres playbook load failed: %s", exc)
                frameworks = {}
        if not frameworks:
            frameworks = self._load_learned_from_json()
            # One-time migrate JSON → Postgres when warehouse is on and empty.
            if frameworks and store is not None:
                try:
                    n = _run_coro_sync(store.save_learned_playbooks(frameworks))
                    if n:
                        logger.info(
                            "Migrated %s learned playbook entries from JSON to Postgres",
                            n,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("JSON→Postgres playbook migrate failed: %s", exc)
        self._apply_learned_frameworks(frameworks)

    def _collect_learned(self) -> dict[str, dict[str, Any]]:
        """Snapshot learned entries currently in the RAM store."""
        frameworks: dict[str, dict[str, Any]] = {}
        for fw in self._known_framework_ids():
            items = self._store.search(_ns(fw), limit=200)
            learned: dict[str, Any] = {}
            for item in items:
                value = dict(item.value or {})
                if value.get("source") != "learned":
                    continue
                learned[item.key] = value
            if learned:
                frameworks[fw] = learned
        return frameworks

    def persist(self) -> Path | None:
        """Flush learned entries to Postgres (preferred) or JSON fallback.

        Returns:
            JSON path when written to disk, or ``None`` when persisted only to
            Postgres / nothing to write / learning off.
        """
        with self._lock:
            if not self._dirty:
                return None
            frameworks = self._collect_learned()
            store = self._results_store()
            wrote_pg = False
            if store is not None:
                try:
                    _run_coro_sync(store.save_learned_playbooks(frameworks))
                    wrote_pg = True
                    self._dirty = False
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Postgres playbook persist failed: %s", exc)
            if wrote_pg:
                return None
            # Fallback: JSON file (warehouse off or PG write failed).
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
        """Collect framework ids from seed filenames + learned overlays."""
        ids: set[str] = set(self._pg_framework_ids)
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
        """Return the stored playbook dict for one requirement, if any.

        Args:
            framework_id: Framework or host/framework key.
            req_id: Requirement id (e.g. ``REQ-001``).

        Returns:
            Value dict with ``tools``, ``notes``, ``source``, etc., or ``None``.
        """
        item = self._store.get(_ns(framework_id), req_id)
        if item is None:
            return None
        return dict(item.value or {})

    def get_framework_tips(self, framework_id: str) -> list[str]:
        """Return framework-level tips from the ``_framework`` store key.

        Args:
            framework_id: Framework id.

        Returns:
            List of tip strings (may be empty).
        """
        item = self._store.get(_ns(framework_id), "_framework")
        if item is None:
            return []
        tips = (item.value or {}).get("tips") or []
        return [str(t) for t in tips]

    def format_prompt_block(self, framework_id: str, req_id: str) -> str:
        """Render procedural memory for injection into the evidence prompt.

        Args:
            framework_id: Active checklist framework id.
            req_id: Requirement being assessed.

        Returns:
            Markdown block with tips, notes, and preferred tool recipes.
        """
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
        """Hot-path learning: remember a successful tool recipe for this REQ.

        Skips when learning is disabled, the call failed, or the tool is a
        diagnostic list (``mcp_list*``). Arguments are redacted and truncated
        before storage; duplicates are deduplicated by name+args signature.

        Args:
            framework_id: Framework id for namespace.
            req_id: Requirement id.
            tool_name: LangChain tool name.
            arguments: Tool arguments (secrets redacted).
            success: Only successful calls are remembered.
        """
        if not self.learn or not success or not framework_id or not req_id:
            return
        if not tool_name or tool_name.startswith("mcp_list"):
            return
        from auditor.tools.secrets import redact_secrets

        args = redact_secrets(dict(arguments or {}))
        for key in list(args.keys()):
            val = args[key]
            if isinstance(val, str) and len(val) > 2000:
                args[key] = val[:2000] + "…"

        with self._lock:
            item = self._store.get(_ns(framework_id), req_id)
            existing = dict(item.value or {}) if item else {
                "framework_id": _memory_framework_id(framework_id),
                "requirement_id": req_id,
                "tools": [],
                "notes": "",
            }
            tools = list(existing.get("tools") or [])
            recipe = {"name": tool_name, "arguments": args}
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
                    "framework_id": _memory_framework_id(framework_id),
                    "requirement_id": req_id,
                    "tools": tools,
                    "source": "learned",
                    "updated_at": _utc_now(),
                }
            )
            self._store.put(_ns(framework_id), req_id, existing)
            self._pg_framework_ids.add(_memory_framework_id(framework_id))
            self._dirty = True

        try:
            self.persist()
        except OSError as exc:
            logger.warning("Failed to persist learned playbooks: %s", exc)
