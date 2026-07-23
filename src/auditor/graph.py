"""LangGraph cyclic auditor: route → assess → reconnect / HITL → finalize.

Drop-in frameworks live in ``agents/*.md``. The operator request selects one
or more checklists; evidence is gathered via SSH and MCP tools, then cells are
filled and a fixed-format report is produced.

Pipeline role:
    Central orchestration layer between the HTTP API and tool adapters.
    Compiles the main audit ``StateGraph``, optional intake subgraph, and
    exposes async entry points (``arun``, ``aresume``, ``acontinue``).

Control flow::

    START
      → route_framework → load_framework → collect_host_facts → assess_parallel
      → route_after_assess
           ├─ recoverable errors & retries left → reconnect_session ─┐
           │                                                         │
           │◄────────────────────────────────────────────────────────┘
           ├─ failed REQs (HITL) → human_gate  (LangGraph interrupt)
           │         ├─ retry → assess_parallel
           │         ├─ more failures → human_gate
           │         └─ done → finalize → END
           └─ else → finalize → END

Key entry points:
    ``AuditorGraph``, ``get_auditor_graph``, ``get_auditor_graph_ready``.

``human_gate`` asks the operator to **skip** or **retry** via Open WebUI chat.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Iterator, Literal

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from langgraph.types import Command, interrupt

from auditor.access_probe import (
    probe_access_endpoints,
    probe_access_services,
)
from auditor.adhoc import run_adhoc_commands
from auditor.checklist import Requirement
from auditor.compliance import format_compliance_markdown
from auditor.config import Settings, get_settings
from auditor.context import (
    compact_findings_for_summary,
    count_tool_rounds,
    truncate_text,
)
from auditor.followup import (
    followup_footer,
    run_refill_finding,
    run_revise_req,
    run_update_report,
)
from auditor.evidence_store import (
    EvidenceStore,
    bind_host_segment,
    client_artifacts_id,
    new_run_id,
)
from auditor.frameworks import (
    frameworks_catalog_text,
    frameworks_detect_catalog_text,
    get_framework,
    list_frameworks,
    load_framework_checklist,
    route_framework,
    route_frameworks,
    select_frameworks_for_host,
)
from auditor.host_facts import (
    HostFacts,
    format_host_facts_markdown,
    merge_facts_from_raw,
    parse_host_facts_json,
    resolve_client_inventory,
    upsert_inventory_md,
    write_host_facts_json,
)
from auditor.hitl import (
    HitlDecision,
    build_hitl_prompt,
    format_continue_assistant_message,
    format_hitl_assistant_message,
    interpret_hitl_decision,
    interrupt_payload_to_prompt,
)
from auditor.progress import (
    emit_phase,
    emit_req_status,
    emit_tool_call,
    emit_tool_result,
)
from auditor.session_store import (
    drop_multi_session,
    find_interrupted_run,
    load_all_multi_sessions,
    save_multi_session,
    write_run_status,
)
from auditor.intake import (
    client_slug,
    domains_for_audit_type,
    enrich_facts_from_access_rows,
    extract_management_summary,
    format_host_access_list_markdown,
    format_intake_assistant_message,
    format_proposed_jobs_markdown,
    frameworks_for_audit_type,
    intake_clarification_from_payload,
    intake_interrupt_payload,
    parse_client_name,
    prompts_for_language,
    resolve_audit_type,
    resolve_scope_decision,
    resolve_yes_no,
)
from auditor.language import (
    ReportLanguage,
    detect_report_language,
    language_instruction,
    language_name,
)
from auditor.memory.playbook_store import PlaybookMemory
from auditor.report_archive import package_and_publish_archive
from auditor.mlflow_store import (
    end_mlflow_run_safe,
    ensure_mlflow_run_safe,
    log_mlflow_finalize_safe,
)
from auditor.results_store import (
    record_requirement_result_safe,
    record_results_safe,
    snapshot_checklist_safe,
    start_session_safe,
    sync_session_status_from_run_meta,
)
from auditor.llm import build_chat_model
from auditor.prompts import (
    EVIDENCE_FORCE_PROMPT,
    EVIDENCE_PROMPT,
    EVIDENCE_SYSTEM_PROMPT,
    FILL_CELL_PROMPT,
    FILL_SYSTEM_PROMPT,
    FINALIZE_PROMPT,
    HOST_FACTS_FILL_PROMPT,
    HOST_FACTS_FILL_SYSTEM_PROMPT,
    HOST_FACTS_FORCE_PROMPT,
    HOST_FACTS_PROMPT,
    HOST_FACTS_SYSTEM_PROMPT,
    SOFTWARE_FRAMEWORK_ROUTE_PROMPT,
    SOFTWARE_FRAMEWORK_ROUTE_SYSTEM,
    INTAKE_INTERPRET_AUDIT_TYPE_PROMPT,
    INTAKE_INTERPRET_AUDIT_TYPE_SYSTEM,
    INTAKE_INTERPRET_SCOPE_PROMPT,
    INTAKE_INTERPRET_SCOPE_SYSTEM,
    INTAKE_INTERPRET_YES_NO_PROMPT,
    INTAKE_INTERPRET_YES_NO_SYSTEM,
)
from auditor.secrets_file import (
    InventorySshTarget,
    bind_host_target,
    list_client_access_endpoints,
    list_client_ssh_targets,
    read_client_credentials,
)
from auditor.runtime_target import (
    bind_runtime_credentials,
    effective_settings,
)
from auditor.state import AuditorState, Finding, render_report
from auditor.tools.mcp_client import get_mcp_tools, reconnect_mcp_session
from auditor.tools.ssh import get_ssh_tools
from auditor.tools.winrm import get_winrm_tools

# Tight markers only — bare "session" / "timeout" / "eof" caused false reconnects.
_RECOVERABLE_MARKERS = (
    "mcp error",
    "mcp reconnect failed",
    "ssh error",
    "winrm error",
    "connection refused",
    "connection reset",
    "broken pipe",
    "not connected",
    "closed resource",
    "connection closed",
)


def _all_tools() -> list:
    """Collect LangChain tools for evidence gathering.

    Returns:
        SSH, WinRM, and Postgres MCP tools.
    """
    return [*get_ssh_tools(), *get_winrm_tools(), *get_mcp_tools()]


def _host_tools() -> list:
    """Remote host tools (SSH + WinRM) for discovery / host_facts."""
    return [*get_ssh_tools(), *get_winrm_tools()]


def _extract_json(text: str) -> dict[str, Any] | None:
    """Parse a JSON object from model output (raw or embedded in prose).

    Args:
        text: LLM response text.

    Returns:
        First dict parsed from the string or a ``{…}`` regex match, or ``None``.
    """
    text = text.strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def _normalize_status(value: str | None) -> str:
    """Map arbitrary status text to a allowed finding status literal.

    Args:
        value: Raw status from model JSON.

    Returns:
        One of ``pass``, ``fail``, ``partial``, ``error``, ``skipped``;
        defaults to ``error`` for unknown values.
    """
    allowed = {"pass", "fail", "partial", "error", "skipped"}
    status = (value or "error").strip().lower()
    return status if status in allowed else "error"


def _is_recoverable_finding(finding: Finding) -> bool:
    """True when a finding looks like a dead session / transport failure."""
    if finding.status != "error":
        return False
    blob = f"{finding.evidence} {finding.notes}".lower()
    return any(marker in blob for marker in _RECOVERABLE_MARKERS)


def _as_finding(value: Finding | dict[str, Any]) -> Finding:
    """Coerce graph state finding values to a ``Finding`` model.

    Args:
        value: ``Finding`` instance or dict from checkpoint/state.

    Returns:
        Validated ``Finding``.
    """
    return value if isinstance(value, Finding) else Finding.model_validate(value)


def _hitl_candidates(state: AuditorState) -> list[str]:
    """Requirement ids with ``status=error`` not yet skipped by the operator."""
    findings = state.get("findings") or {}
    skipped = set(state.get("hitl_skipped") or [])
    out: list[str] = []
    for req_id, raw in findings.items():
        finding = _as_finding(raw)
        if finding.status == "error" and req_id not in skipped:
            out.append(req_id)
    return sorted(out)


def _tool_result_looks_failed(text: str) -> bool:
    """True when a tool result string indicates transport/auth failure."""
    lower = (text or "").lower()
    return any(
        marker in lower
        for marker in (
            "ssh error",
            "mcp error",
            "tool error",
            "connection refused",
            "permission denied",
        )
    )


class AuditorGraph:
    """Compile and run the cyclic multi-framework audit StateGraph.

    Owns tool-bound LLMs, evidence stores per run, procedural playbooks,
    intake and main compiled graphs, and multi-framework session bookkeeping
    across HITL pauses.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """Wire settings, models, tools, memory, and compile LangGraph workflows.

        Args:
            settings: Application settings; defaults to ``get_settings()``.
        """
        self.settings = settings or get_settings()
        self.tools = _all_tools()
        self.tools_by_name = {t.name: t for t in self.tools}
        # Evidence stores keyed by run_id (safe for parallel multi-framework).
        self._evidence_by_run: dict[str, EvidenceStore] = {}
        # Multi-framework orchestration while a HITL pause is active.
        self._multi_sessions: dict[str, dict[str, Any]] = {}
        self._checkpointer = MemorySaver()
        self._checkpoint_conn = None
        self._async_cp_ready = False
        # Orphaned runs still executing after client disconnect (thread_id → task).
        self._orphan_tasks: dict[str, asyncio.Task[Any]] = {}
        # Long-term procedural memory (framework command playbooks).
        self.playbooks = (
            PlaybookMemory(
                playbooks_dir=self.settings.playbooks_dir,
                memory_dir=self.settings.memory_dir,
                learn=self.settings.memory_learn,
                settings=self.settings,
            )
            if self.settings.memory_enabled
            else None
        )
        self.evidence_model = build_chat_model(self.settings).bind_tools(self.tools)
        self.evidence_model_ssh = build_chat_model(self.settings).bind_tools(
            _host_tools()
        )
        self.fill_model = build_chat_model(self.settings)
        self.graph = self._build()
        self.intake_graph = self._build_intake()

    @contextmanager
    def _target_scope(
        self,
        *,
        client_slug: str | None = None,
        ssh_target: InventorySshTarget | None = None,
        intake: dict[str, Any] | None = None,
    ) -> Iterator[None]:
        """Bind run-scoped SSH/PG credentials for the duration of a graph call.

        Prefers ``client_slug``, else ``intake["client_slug"]``. Nested SSH host
        binds override SSH fields without clearing PostgreSQL overlays.
        """
        slug = (client_slug or "").strip()
        if not slug and intake:
            slug = str(intake.get("client_slug") or "").strip()
        with ExitStack() as stack:
            if slug:
                try:
                    creds = read_client_credentials(self.settings.inventory_dir, slug)
                except (OSError, ValueError, FileNotFoundError):
                    creds = {}
                if creds:
                    stack.enter_context(bind_runtime_credentials(creds))
            if ssh_target is not None:
                stack.enter_context(bind_host_target(ssh_target))
            yield

    def _client_slug_from_values(self, values: dict[str, Any] | None) -> str | None:
        """Extract client slug from checkpoint/intake state when present."""
        if not values:
            return None
        intake = values.get("intake") if isinstance(values.get("intake"), dict) else {}
        slug = str(
            values.get("client_slug")
            or (intake or {}).get("client_slug")
            or ""
        ).strip()
        return slug or None

    async def ensure_async_checkpointer(self) -> None:
        """Upgrade to AsyncSqliteSaver (required for ``ainvoke`` durability)."""
        if self._async_cp_ready and self._checkpoint_conn is not None:
            # Detect a closed aiosqlite connection (common after redeploy / WAL churn).
            try:
                conn = self._checkpoint_conn
                closed = bool(getattr(conn, "_connection", None) is None) or bool(
                    getattr(conn, "_closed", False)
                )
                if not closed:
                    return
            except Exception:  # noqa: BLE001
                pass
            self._async_cp_ready = False
        if self._async_cp_ready:
            return
        try:
            from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

            path = Path(self.settings.checkpoint_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Keep the async context manager open for the process lifetime.
            if getattr(self, "_sqlite_cm", None) is not None:
                try:
                    await self._sqlite_cm.__aexit__(None, None, None)
                except Exception:  # noqa: BLE001
                    pass
                self._sqlite_cm = None
            self._sqlite_cm = AsyncSqliteSaver.from_conn_string(str(path))
            self._checkpointer = await self._sqlite_cm.__aenter__()
            self._checkpoint_conn = getattr(self._checkpointer, "conn", None)
            self.graph = self._build()
            self.intake_graph = self._build_intake()
            self._async_cp_ready = True
        except Exception:  # noqa: BLE001
            # Keep MemorySaver — process-local resume only.
            self._checkpointer = MemorySaver()
            self.graph = self._build()
            self.intake_graph = self._build_intake()
            self._async_cp_ready = True
            self._checkpoint_conn = None

    def _remember_multi_session(self, thread_id: str, session: dict[str, Any]) -> None:
        """Store multi-framework orchestration state in memory and on disk.

        Args:
            thread_id: LangGraph checkpoint thread id for the active job.
            session: Remaining jobs, completed reports, intake state, etc.
        """
        self._multi_sessions[thread_id] = session
        run_id = str(session.get("run_id") or "")
        if run_id:
            try:
                save_multi_session(
                    self.settings.evidence_dir, run_id, thread_id, session
                )
            except OSError:
                pass

    def _forget_multi_session(self, thread_id: str) -> dict[str, Any] | None:
        """Remove multi-session state for ``thread_id`` and delete disk copy.

        Args:
            thread_id: Thread whose session record should be dropped.

        Returns:
            The removed session dict, or ``None`` if not tracked.
        """
        session = self._multi_sessions.pop(thread_id, None)
        if session is None:
            return None
        run_id = str(session.get("run_id") or "")
        if run_id:
            try:
                drop_multi_session(self.settings.evidence_dir, run_id, thread_id)
            except OSError:
                pass
        return session

    def _reload_multi_sessions(self, run_id: str) -> None:
        """Load persisted multi-session records for ``run_id`` into memory.

        Args:
            run_id: Evidence run id shared across parallel framework threads.
        """
        if not run_id:
            return
        try:
            loaded = load_all_multi_sessions(self.settings.evidence_dir, run_id)
        except OSError:
            return
        for tid, sess in loaded.items():
            if tid not in self._multi_sessions:
                self._multi_sessions[tid] = sess

    def _evidence_llm(self):
        """Return the inventory-only evidence model bound to SSH + MCP tools."""
        return self.evidence_model

    def _build(self):
        """Compile the main audit StateGraph with reconnect and HITL cycles.

        Returns:
            Compiled graph: route → load → host facts → assess → finalize.
        """
        graph = StateGraph(AuditorState)
        graph.add_node("route_framework", self.route_framework_node)
        graph.add_node("load_framework", self.load_framework)
        graph.add_node("collect_host_facts", self.collect_host_facts)
        graph.add_node("assess_parallel", self.assess_parallel)
        graph.add_node("reconnect_session", self.reconnect_session)
        graph.add_node("human_gate", self.human_gate)
        graph.add_node("finalize", self.finalize)

        graph.add_edge(START, "route_framework")
        graph.add_edge("route_framework", "load_framework")
        graph.add_edge("load_framework", "collect_host_facts")
        graph.add_edge("collect_host_facts", "assess_parallel")
        graph.add_conditional_edges(
            "assess_parallel",
            self.route_after_assess,
            {
                "reconnect_session": "reconnect_session",
                "human_gate": "human_gate",
                "finalize": "finalize",
            },
        )
        # Cycle: after reconnect, re-run assess on remaining pending_ids only.
        graph.add_edge("reconnect_session", "assess_parallel")
        graph.add_conditional_edges(
            "human_gate",
            self.route_after_hitl,
            {
                "assess_parallel": "assess_parallel",
                "human_gate": "human_gate",
                "finalize": "finalize",
            },
        )
        graph.add_edge("finalize", END)
        return graph.compile(checkpointer=self._checkpointer)

    def _build_intake(self):
        """Compile the pre-audit intake questionnaire subgraph.

        Returns:
            Single-node graph ending at ``intake_gate`` (may interrupt).
        """
        graph = StateGraph(AuditorState)
        graph.add_node("intake_gate", self.intake_gate)
        graph.add_edge(START, "intake_gate")
        graph.add_edge("intake_gate", END)
        return graph.compile(checkpointer=self._checkpointer)

    async def _intake_llm_json(
        self, system: str, user: str
    ) -> dict[str, Any] | None:
        """Один вызов fill_model для интерпретации ответа intake."""
        try:
            response = await self.fill_model.ainvoke(
                [
                    SystemMessage(content=system),
                    HumanMessage(content=user),
                ]
            )
            return _extract_json(str(response.content or ""))
        except Exception:  # noqa: BLE001
            return None

    async def _intake_resolve_yes_no(
        self, raw: str, *, question_hint: str
    ) -> tuple[str, str]:
        """Интерпретировать да/нет intake через LLM; вернуть ответ + уточнение.

        Args:
            raw: Текст ответа оператора.
            question_hint: Контекст для промпта классификатора.

        Returns:
            ``(yes|no|unknown, clarification)``. Clarification заполняется,
            когда оператор спросил смысл шага (например «что это?»).
        """
        payload = await self._intake_llm_json(
            INTAKE_INTERPRET_YES_NO_SYSTEM,
            INTAKE_INTERPRET_YES_NO_PROMPT.format(
                question_hint=question_hint,
                reply=str(raw or "").strip() or "(empty)",
            ),
        )
        answer = resolve_yes_no(str(raw or ""), payload)
        clarification = ""
        if answer == "unknown":
            clarification = intake_clarification_from_payload(payload)
        return answer, clarification

    def _intake_resolve_client_name(self, raw: str) -> str:
        """Extract client name deterministically (intake step 1 — no LLM).

        Args:
            raw: Operator reply naming the audit client.

        Returns:
            Resolved client display name, or empty when unparseable.
        """
        return parse_client_name(str(raw or ""))

    async def _intake_resolve_audit_type(self, raw: str) -> str | None:
        """Сопоставить ответ intake с типом аудита только через JSON LLM (шаг 4).

        Args:
            raw: Ответ оператора о желаемой области аудита.

        Returns:
            Каноническая строка типа аудита или ``None``, если неясно.
        """
        payload = await self._intake_llm_json(
            INTAKE_INTERPRET_AUDIT_TYPE_SYSTEM,
            INTAKE_INTERPRET_AUDIT_TYPE_PROMPT.format(
                reply=str(raw or "").strip() or "(empty)",
            ),
        )
        return resolve_audit_type(str(raw or ""), payload)

    def _persist_intake_progress(
        self,
        state: AuditorState,
        intake: dict[str, Any],
        *,
        thread_id: str = "",
    ) -> None:
        """Сохранить промежуточные ответы intake в evidence meta для resume.

        LangGraph при каждом resume заново выполняет весь узел ``intake_gate``;
        без записи на диск при access=yes снова шёл бы rediscovery хостов.
        Мержит в существующий dict ``intake``, чтобы частичная запись не стёрла
        ранние ключи (например совместимые поля inventory-only).
        """
        store = self._store_from_state(state)
        if store is None:
            return
        tid = thread_id or str(state.get("thread_id") or "")
        try:
            existing = store.read_run_meta().get("intake")
            merged = dict(existing) if isinstance(existing, dict) else {}
            merged.update(intake)
            store.write_run_meta(
                intake=merged,
                intake_checkpoint_thread=tid,
                intake_complete=False,
            )
        except OSError:
            pass

    def _load_intake_progress(
        self,
        state: AuditorState,
        *,
        thread_id: str = "",
    ) -> dict[str, Any]:
        """Reload discovery/plan fields only (never yes/no answers).

        LangGraph restarts ``intake_gate`` on every resume and assigns
        ``Command(resume=…)`` by interrupt call order. Restoring
        yes/no answers from disk and skipping earlier ``interrupt()`` calls
        mis-assigns replayed answers between intake steps.
        Questionnaire answers must come from interrupt replay; disk is only
        for expensive discovery so SSH is not repeated.
        """
        intake: dict[str, Any] = dict(state.get("intake") or {})
        store = self._store_from_state(state)
        if store is None:
            return intake
        meta = store.read_run_meta()
        if meta.get("intake_complete"):
            return intake
        tid = thread_id or str(state.get("thread_id") or "")
        saved_tid = str(meta.get("intake_checkpoint_thread") or "")
        if tid and saved_tid and saved_tid != tid:
            return intake
        saved = meta.get("intake")
        if not isinstance(saved, dict):
            return intake
        # Discovery / plan outputs only — not client/access/scope answers.
        keep_keys = (
            "artifacts_run_id",
            "discovery_complete",
            "proposed_jobs",
            "host_access_rows",
            "access_probe",
            "discovery_error",
            "access_list_error",
            "highlight_packages",
        )
        for key in keep_keys:
            if key in saved and key not in intake:
                intake[key] = saved[key]
        return intake

    async def intake_gate(self, state: AuditorState) -> dict[str, Any]:
        """Многошаговый предварительный опрос через последовательные interrupt."""
        if not self.settings.intake_enabled or state.get("intake_complete"):
            return {"intake_complete": True}

        lang = self._report_language(state)
        prompts = prompts_for_language(lang.code)
        thread_hint = str(state.get("thread_id") or "")
        intake: dict[str, Any] = self._load_intake_progress(
            state, thread_id=thread_hint
        )

        # 1) Название клиента (детерминированно — без LLM)
        while not intake.get("client_name"):
            raw = interrupt(
                intake_interrupt_payload(step="client_name", prompt=prompts.client)
            )
            name = self._intake_resolve_client_name(str(raw or ""))
            if name:
                intake["client_name"] = name
                intake["client_slug"] = client_slug(name)
                from auditor.host_facts import resolve_client_dir

                client_dir = resolve_client_dir(
                    Path(self.settings.inventory_dir),
                    intake["client_slug"],
                    display_name=name,
                )
                # Artifacts folder = inventory client folder name (e.g. TestCompany).
                if not client_dir.is_dir():
                    client_dir = (
                        Path(self.settings.inventory_dir) / client_artifacts_id(name)
                    )
                client_dir.mkdir(parents=True, exist_ok=True)
                artifacts_id = client_dir.name
                store = self._store_from_state(state)
                if store is not None:
                    old_id = store.run_id
                    store.rebind_run_id(artifacts_id)
                    self._evidence_by_run.pop(old_id, None)
                    self._evidence_by_run[store.run_id] = store
                    # Временный id как алиас, пока state intake не переписан.
                    self._evidence_by_run[old_id] = store
                    for sess in self._multi_sessions.values():
                        if sess.get("run_id") == old_id:
                            sess["run_id"] = store.run_id
                    intake["artifacts_run_id"] = store.run_id
                    # Обновить live-ключи state на оставшуюся часть узла.
                    state["evidence_run_id"] = store.run_id  # type: ignore[typeddict-item]
                    state["evidence_run_dir"] = str(store.root)  # type: ignore[typeddict-item]

                applied = read_client_credentials(
                    self.settings.inventory_dir,
                    intake["client_slug"],
                )
                intake["credentials_loaded"] = sorted(applied.keys())
                # Учётные данные — run-scoped через ContextVar на invoke/resume;
                # не мутировать process os.environ (параллельные аудиты).
                self._persist_intake_progress(
                    state, intake, thread_id=thread_hint
                )
                break
            prompts = prompts_for_language(lang.code)
            prompts = type(prompts)(
                client=prompts.client
                + (
                    "\n\n_Please reply with a non-empty client name._"
                    if lang.code == "en"
                    else "\n\n_Укажите непустое название клиента._"
                ),
                cmdb="",
                access=prompts.access,
                scope=prompts.scope,
                audit_type=prompts.audit_type,
            )

        # 2) Доступ — спросить да/нет, затем список достижимости хостов/сервисов (один раз).
        inv_path, scope, found = resolve_client_inventory(
            Path(self.settings.inventory_dir),
            str(intake.get("client_slug") or ""),
        )
        intake["has_cmdb"] = False
        intake["cmdb_probe"] = {}
        intake["inventory_scope"] = scope
        intake["inventory_found"] = found
        intake["inventory_path"] = str(inv_path) if inv_path else ""
        self._persist_intake_progress(state, intake, thread_id=thread_hint)

        cred_keys = intake.get("credentials_loaded") or []
        if lang.code.startswith("ru"):
            cred_line = (
                f"**Учётные данные загружены из inventory** ({len(cred_keys)} ключей): "
                + (", ".join(cred_keys) if cred_keys else "нет — добавьте таблицу Credentials в INVENTORY.md")
            )
        else:
            cred_line = (
                f"**Credentials loaded from inventory** ({len(cred_keys)} keys): "
                + (", ".join(cred_keys) if cred_keys else "none — add a Credentials table to INVENTORY.md")
            )
        inv_found = bool(intake.get("inventory_found"))
        inv_display_path = intake.get("inventory_path") or ""
        if lang.code.startswith("ru"):
            status = (
                f"**Инвентарь найден:** `{inv_display_path}`"
                if inv_found
                else f"**Инвентарь не найден** по пути `{inv_display_path}`"
            )
        else:
            status = (
                f"**Inventory found:** `{inv_display_path}`"
                if inv_found
                else f"**Inventory not found** at `{inv_display_path}`"
            )
        # Keep this short — a full inventory dump in the prompt confused yes/no.
        scope_block = f"\n\n### Client inventory check\n\n{status}\n\n{cred_line}\n"
        access_prompt = f"{prompts.access}{scope_block}"
        while "has_access" not in intake:
            raw = interrupt(
                intake_interrupt_payload(step="access", prompt=access_prompt)
            )
            yn, clarification = await self._intake_resolve_yes_no(
                str(raw or ""),
                question_hint=(
                    "Can the AUDIT AGENT reach servers/services to probe "
                    "(SSH/DB)? Not whether the human operator personally can."
                ),
            )
            if yn == "unknown":
                if clarification:
                    clarify_block = (
                        f"\n\n### Пояснение\n\n{clarification}\n"
                        if lang.code.startswith("ru")
                        else f"\n\n### Clarification\n\n{clarification}\n"
                    )
                    hint = (
                        "\n\n_После пояснения опишите доступ своими словами._"
                        if lang.code.startswith("ru")
                        else "\n\n_After this clarification, describe access in "
                        "your own words._"
                    )
                    access_prompt = (
                        f"{prompts.access}{scope_block}{clarify_block}{hint}"
                    )
                else:
                    hint = (
                        "\n\n_Could not interpret that. Please describe whether "
                        "live SSH/DB access is available, in your own words._"
                        if lang.code == "en"
                        else "\n\n_Не понял ответ. Опишите своими словами, "
                        "есть ли доступ по SSH/БД._"
                    )
                    access_prompt = (
                        f"{prompts.access}{scope_block}{hint}"
                    )
                continue
            intake["access_raw"] = str(raw or "").strip()
            intake["has_access"] = yn == "yes"
            # On later resumes access is replayed; do not wipe discovery.
            if yn == "yes" and not intake.get("discovery_complete"):
                intake.pop("proposed_jobs", None)
                intake.pop("host_access_rows", None)
            self._persist_intake_progress(state, intake, thread_id=thread_hint)

        # 2b) Probe endpoints + discover hosts once (skipped on exclude resume).
        if intake.get("has_access") and not intake.get("discovery_complete"):
            slug = str(intake.get("client_slug") or "").strip()
            try:
                creds = (
                    read_client_credentials(self.settings.inventory_dir, slug)
                    if slug
                    else {}
                )
            except (OSError, ValueError, FileNotFoundError):
                creds = {}
            if creds:
                with bind_runtime_credentials(creds):
                    access = await probe_access_services(effective_settings())
            else:
                access = await probe_access_services(effective_settings())
            intake["access_probe"] = access

            endpoints = (
                list_client_access_endpoints(self.settings.inventory_dir, slug)
                if slug
                else []
            )
            try:
                host_access_rows = await probe_access_endpoints(endpoints)
            except Exception as exc:  # noqa: BLE001
                host_access_rows = []
                intake["access_list_error"] = f"{type(exc).__name__}: {exc}"
            intake["host_access_rows"] = host_access_rows

            store = self._store_from_state(state)
            if store is not None:
                try:
                    discovered = await self._discover_inventory_hosts(
                        intake=intake, store=store
                    )
                except Exception as exc:  # noqa: BLE001
                    discovered = []
                    intake["discovery_error"] = f"{type(exc).__name__}: {exc}"
                proposed: list[dict[str, Any]] = []
                for target, facts in discovered:
                    llm_ids = [
                        x.strip()
                        for x in str(
                            (facts.raw or {}).get("_llm_framework_ids") or ""
                        ).split(",")
                        if x.strip()
                    ]
                    hl_pkgs = [
                        x
                        for x in str(
                            (facts.raw or {}).get("_llm_highlight_packages") or ""
                        ).splitlines()
                        if x.strip()
                    ]
                    notes = str(
                        (facts.raw or {}).get("_llm_software_notes") or ""
                    ).strip()
                    # Inventory access probe is authoritative for open ports
                    # (e.g. PG :5432) when checklist-filled facts missed them.
                    enrich_facts_from_access_rows(
                        facts, target.host, host_access_rows
                    )
                    if facts.error:
                        matched_ids: list[str] = []
                        it_fw = get_framework(
                            "it_audit", self.settings.agents_dir
                        )
                        if it_fw is not None:
                            matched_ids = [it_fw.id]
                        for fid in llm_ids:
                            if fid not in matched_ids and get_framework(
                                fid, self.settings.agents_dir
                            ):
                                matched_ids.append(fid)
                        # Still match detect rules from enriched ports/binaries.
                        for fw in select_frameworks_for_host(
                            facts,
                            domains=["it", "cybersecurity"],
                            agents_dir=self.settings.agents_dir,
                        ):
                            if fw.id not in matched_ids:
                                matched_ids.append(fw.id)
                        proposed.append(
                            {
                                "host_id": target.slug,
                                "hostname": facts.hostname or "",
                                "ssh_host": target.host,
                                "frameworks": matched_ids,
                                "error": facts.error,
                                "os_id": facts.os_id or "",
                                "os_pretty_name": facts.os_pretty_name or "",
                                "binaries": list(facts.binaries or []),
                                "packages": list(facts.packages or []),
                                "key_files": list(facts.key_files or []),
                                "highlight_packages": hl_pkgs,
                                "software_notes": notes,
                            }
                        )
                    else:
                        matched = select_frameworks_for_host(
                            facts,
                            domains=["it", "cybersecurity"],
                            agents_dir=self.settings.agents_dir,
                        )
                        matched_ids = [fw.id for fw in matched]
                        for fid in llm_ids:
                            if fid not in matched_ids and get_framework(
                                fid, self.settings.agents_dir
                            ):
                                matched_ids.append(fid)
                        proposed.append(
                            {
                                "host_id": target.slug,
                                "hostname": facts.hostname or "",
                                "ssh_host": target.host,
                                "frameworks": matched_ids,
                                "error": "",
                                "os_id": facts.os_id or "",
                                "os_pretty_name": facts.os_pretty_name or "",
                                "binaries": list(facts.binaries or []),
                                "packages": list(facts.packages or []),
                                "key_files": list(facts.key_files or []),
                                "highlight_packages": hl_pkgs,
                                "software_notes": notes,
                            }
                        )
                    # Prefer live hostname on matching SSH access rows; attach frameworks.
                    for row in host_access_rows:
                        if str(row.get("host") or "") != target.host:
                            continue
                        if facts.hostname and str(row.get("kind") or "") != "pg":
                            row["service"] = facts.hostname
                        row["frameworks"] = list(matched_ids)
                intake["proposed_jobs"] = proposed
                intake["host_access_rows"] = host_access_rows
            else:
                intake["proposed_jobs"] = []
            intake["discovery_complete"] = True
            self._persist_intake_progress(state, intake, thread_id=thread_hint)
        elif not intake.get("has_access") and not intake.get("discovery_complete"):
            intake["access_probe"] = {
                "services": [],
                "any_ok": False,
                "skipped": True,
            }
            intake["proposed_jobs"] = []
            intake["host_access_rows"] = []
            intake["discovery_complete"] = True
            self._persist_intake_progress(state, intake, thread_id=thread_hint)

        proposed_jobs = list(intake.get("proposed_jobs") or [])
        has_plan = bool(
            proposed_jobs
            and any((row.get("frameworks") or []) for row in proposed_jobs)
        )
        host_access_md = format_host_access_list_markdown(
            list(intake.get("host_access_rows") or []),
            language=lang.code,
            proposed_jobs=proposed_jobs,
        )

        # 2c) Reachability + applicable frameworks (no full package dump).
        if intake.get("has_access") and "access_list_acked" not in intake:
            if lang.code.startswith("ru"):
                access_list_prompt = (
                    "## План предаудита — доступность и фреймворки\n\n"
                    f"{host_access_md}\n"
                    "Ответьте **продолжить** / **ok**, чтобы подтвердить или "
                    "исключить фреймворки на следующем шаге."
                )
            else:
                access_list_prompt = (
                    "## Pre-audit plan — reachability & frameworks\n\n"
                    f"{host_access_md}\n"
                    "Reply **continue** / **ok** to confirm or exclude frameworks "
                    "in the next step."
                )
            while "access_list_acked" not in intake:
                interrupt(
                    intake_interrupt_payload(
                        step="access_list", prompt=access_list_prompt
                    )
                )
                intake["access_list_acked"] = True
                self._persist_intake_progress(
                    state, intake, thread_id=thread_hint
                )

        # 3) Scope: confirm / exclude / include; after trim, re-show plan and require confirm.
        if has_plan:
            working_jobs = [dict(r) for r in proposed_jobs]
            original_jobs = [dict(r) for r in proposed_jobs]
            plan_md = format_proposed_jobs_markdown(working_jobs)
            scope_prompt = f"{prompts.scope}\n\n{host_access_md}\n\n{plan_md}"
            while "selected_jobs" not in intake:
                raw = interrupt(
                    intake_interrupt_payload(step="scope", prompt=scope_prompt)
                )
                payload = await self._intake_llm_json(
                    INTAKE_INTERPRET_SCOPE_SYSTEM,
                    INTAKE_INTERPRET_SCOPE_PROMPT.format(
                        reply=str(raw or "").strip() or "(empty)",
                        plan=plan_md,
                    ),
                )
                action = str((payload or {}).get("action") or "").strip().lower()
                selected = resolve_scope_decision(
                    str(raw or ""), working_jobs, payload
                )
                if selected is None:
                    hint = (
                        "\n\n_Could not parse that. Reply **confirm**, or describe "
                        "what to **exclude** / keep **only**._"
                        if lang.code == "en"
                        else "\n\n_Не удалось разобрать ответ. Напишите "
                        "**подтвердить**, или что **исключить** / оставить **только**._"
                    )
                    scope_prompt = (
                        f"{prompts.scope}{hint}\n\n{host_access_md}\n\n{plan_md}"
                    )
                    continue
                if not selected:
                    hint = (
                        "\n\n_Nothing left to run after that change. "
                        "Confirm the previous plan or exclude/include fewer items._"
                        if lang.code == "en"
                        else "\n\n_После изменения нечего запускать. "
                        "Подтвердите предыдущий план или измените меньше._"
                    )
                    scope_prompt = (
                        f"{prompts.scope}{hint}\n\n{host_access_md}\n\n{plan_md}"
                    )
                    continue

                if action in {"confirm", "all", "run_all", "accept"}:
                    intake["selected_jobs"] = selected
                    proposed_pairs = {
                        (str(r.get("host_id") or ""), str(fw))
                        for r in original_jobs
                        for fw in (r.get("frameworks") or [])
                    }
                    selected_pairs = {
                        (str(r.get("host_id") or ""), str(fw))
                        for r in selected
                        for fw in (r.get("frameworks") or [])
                    }
                    intake["excluded_pairs"] = sorted(
                        f"{h}/{fw}" for h, fw in (proposed_pairs - selected_pairs)
                    )
                    intake["excluded_frameworks"] = sorted(
                        {fw for _h, fw in (proposed_pairs - selected_pairs)}
                    )
                    intake["proposed_jobs"] = original_jobs
                    intake["audit_types"] = "both"
                    break

                # exclude / include → update working plan and ask for confirm
                working_jobs = selected
                intake["proposed_jobs"] = working_jobs
                plan_md = format_proposed_jobs_markdown(working_jobs)
                if lang.code.startswith("ru"):
                    confirm_block = (
                        "\n\n### Обновлённый план\n\n"
                        "План изменён. Ответьте **подтвердить**, чтобы запустить "
                        "**этот** план, или снова опишите exclude/include.\n"
                    )
                else:
                    confirm_block = (
                        "\n\n### Updated plan\n\n"
                        "Plan updated. Reply **confirm** to run **this** plan, "
                        "or describe more exclusions/inclusions.\n"
                    )
                scope_prompt = (
                    f"{prompts.scope}{confirm_block}\n{host_access_md}\n\n{plan_md}"
                )
                self._persist_intake_progress(
                    state, intake, thread_id=thread_hint
                )
                continue
        else:
            audit_prompt = f"{prompts.audit_type}\n\n{host_access_md}"
            while not intake.get("audit_types"):
                raw = interrupt(
                    intake_interrupt_payload(
                        step="audit_type", prompt=audit_prompt
                    )
                )
                atype = await self._intake_resolve_audit_type(str(raw or ""))
                if atype:
                    intake["audit_types"] = atype
                    break

        store = self._store_from_state(state)
        if store is not None:
            store.write_run_meta(
                intake_complete=True,
                intake=intake,
                client_name=intake.get("client_name"),
                has_cmdb=intake.get("has_cmdb"),
                has_access=intake.get("has_access"),
                audit_types=intake.get("audit_types"),
                proposed_jobs=intake.get("proposed_jobs"),
                selected_jobs=intake.get("selected_jobs"),
            )

        client_note = ""
        if intake.get("selected_jobs"):
            n_jobs = sum(
                len(r.get("frameworks") or [])
                for r in (intake.get("selected_jobs") or [])
            )
            client_note = (
                f" Selected **{n_jobs}** host/framework job(s) from the preaudit plan."
                if lang.code == "en"
                else f" Выбрано **{n_jobs}** задач хост/фреймворк по плану предаудита."
            )

        out: dict[str, Any] = {
            "intake_complete": True,
            "intake": intake,
            "client_name": str(intake.get("client_name") or ""),
            "has_cmdb": bool(intake.get("has_cmdb")),
            "has_access": bool(intake.get("has_access")),
            "audit_types": str(intake.get("audit_types") or "both"),
            "messages": [
                AIMessage(
                    content=(
                        f"Intake complete for **{intake.get('client_name')}**. "
                        f"Audit type: `{intake.get('audit_types')}`.{client_note} "
                        f"Starting assessment…"
                    ),
                    name="auditor",
                )
            ],
        }
        if store is not None and store.run_id != state.get("evidence_run_id"):
            out["evidence_run_id"] = store.run_id
            out["evidence_run_dir"] = str(store.root)
        return out

    async def _collect_host_facts(
        self,
        *,
        store: EvidenceStore | None = None,
        host_id: str = "",
        user_request: str = "",
        extra_binaries: list[str] | None = None,
    ) -> HostFacts:
        """Run ``agents/host_facts.md`` (fallback: compact SSH discovery)."""
        del extra_binaries  # routing hints stay in framework detect / LLM tools
        return await self._collect_host_facts_llm(
            store=store,
            host_id=host_id,
            user_request=user_request,
        )

    async def _facts_from_host_facts_evidence(
        self,
        *,
        evidence: str,
        raw: dict[str, str],
        ssh_host: str,
        source: str,
    ) -> HostFacts:
        """JSON-fill ``HostFacts`` from checklist / tool evidence."""
        fill_messages = [
            SystemMessage(content=HOST_FACTS_FILL_SYSTEM_PROMPT),
            HumanMessage(
                content=HOST_FACTS_FILL_PROMPT.format(
                    ssh_host=ssh_host or "(unknown)",
                    evidence=evidence or "(no evidence collected)",
                )
            ),
        ]
        try:
            fill_response = await self.fill_model.ainvoke(fill_messages)
            payload = _extract_json(str(fill_response.content or ""))
        except Exception as exc:  # noqa: BLE001
            payload = {"error": f"{type(exc).__name__}: {exc}"}

        facts = parse_host_facts_json(payload, ssh_host=ssh_host, raw=raw)
        facts = merge_facts_from_raw(facts, raw)
        if not facts.ssh_host:
            facts.ssh_host = ssh_host
        if not facts.collected_at:
            from datetime import datetime, timezone

            facts.collected_at = datetime.now(timezone.utc).isoformat()
        facts.raw["host_facts_source"] = source
        return facts

    async def _collect_host_facts_compact(
        self,
        *,
        store: EvidenceStore | None = None,
        host_id: str = "",
        user_request: str = "",
    ) -> HostFacts:
        """SSH-only tool loop + JSON fill (used when host_facts.md is missing)."""
        ssh_host = str(effective_settings(self.settings).ssh_host or "")
        evidence_fw = "host_facts"
        evidence_req = "discover"
        if store is not None and host_id:
            store.host_segment = host_id

        messages: list = [
            SystemMessage(content=HOST_FACTS_SYSTEM_PROMPT),
            HumanMessage(
                content=HOST_FACTS_PROMPT.format(
                    user_request=truncate_text(
                        user_request or "Discover host inventory for audit routing.",
                        self.settings.max_user_request_chars,
                        "user_request",
                    ),
                    ssh_host=ssh_host or "(unknown)",
                )
            ),
        ]
        chunks: list[str] = []
        raw: dict[str, str] = {}
        max_rounds = self.settings.max_tool_rounds_per_item
        tool_idx = 0

        for _ in range(max_rounds + 1):
            rounds = count_tool_rounds(messages)
            if rounds >= max_rounds:
                messages.append(HumanMessage(content=HOST_FACTS_FORCE_PROMPT))
                response = await self.fill_model.ainvoke(messages)
                chunks.append(str(response.content or ""))
                break

            response = await self.evidence_model_ssh.ainvoke(messages)
            messages.append(response)
            tool_calls = getattr(response, "tool_calls", None) or []
            if not tool_calls:
                chunks.append(str(response.content or ""))
                break

            tool_messages = await self._execute_tool_calls(
                tool_calls,
                framework_id=evidence_fw,
                req_id=evidence_req,
                store=store,
            )
            messages.extend(tool_messages)
            for tm in tool_messages:
                tool_idx += 1
                text = str(tm.content or "")
                raw[f"tool_{tool_idx}_{tm.name or 'ssh'}"] = text
                chunks.append(f"[{tm.name}] {text}")

        evidence = "\n---\n".join(c.strip() for c in chunks if c and c.strip())
        evidence = truncate_text(
            evidence,
            self.settings.max_tool_output_chars * 2,
            "host_facts_evidence",
        )
        return await self._facts_from_host_facts_evidence(
            evidence=evidence,
            raw=raw,
            ssh_host=ssh_host,
            source="llm",
        )

    async def _collect_host_facts_llm(
        self,
        *,
        store: EvidenceStore | None = None,
        host_id: str = "",
        user_request: str = "",
    ) -> HostFacts:
        """Assess ``agents/host_facts.md`` then fill ``HostFacts`` for routing.

        Intake step 2 (access=yes) uses this path so discovery follows the same
        checklist REQs as a normal host_facts audit. Falls back to compact SSH
        discovery when the framework file is missing.
        """
        ssh_host = str(effective_settings(self.settings).ssh_host or "")
        if store is not None and host_id:
            store.host_segment = host_id

        fw = get_framework("host_facts", self.settings.agents_dir)
        if fw is None:
            return await self._collect_host_facts_compact(
                store=store,
                host_id=host_id,
                user_request=user_request,
            )

        checklist = load_framework_checklist(fw)
        req_map = checklist.by_id()
        pending = list(checklist.ids())
        if not pending:
            return await self._collect_host_facts_compact(
                store=store,
                host_id=host_id,
                user_request=user_request,
            )

        user_req = truncate_text(
            user_request or "Discover host inventory for audit routing.",
            self.settings.max_user_request_chars,
            "user_request",
        )
        limit = max(1, self.settings.max_parallel_assessments)
        sem = asyncio.Semaphore(limit)
        emit_phase(
            f"Discovery: assessing {len(pending)} `host_facts` requirement(s) "
            f"(concurrency={limit})…",
            framework_id="host_facts",
        )

        async def _worker(req_id: str) -> Finding:
            async with sem:
                emit_req_status(
                    req_id,
                    "started",
                    framework_id="host_facts",
                    text=f"Discovery `{req_id}`…",
                )
                try:
                    finding = await self._fill_requirement_cells(
                        req_id=req_id,
                        requirement=req_map[req_id],
                        user_request=user_req,
                        framework_id="host_facts",
                        store=store,
                        ssh_only=True,
                    )
                except Exception as exc:  # noqa: BLE001
                    finding = Finding(
                        requirement_id=req_id,
                        title=req_map[req_id].title,
                        status="error",
                        severity=req_map[req_id].severity,
                        category=req_map[req_id].category,
                        evidence=f"{type(exc).__name__}: {exc}",
                        remediation="",
                        pass_criteria=req_map[req_id].pass_criteria,
                    )
                    if store is not None:
                        store.write_finding(
                            "host_facts", req_id, finding.model_dump()
                        )
                emit_req_status(
                    req_id,
                    finding.status,
                    framework_id="host_facts",
                )
                return finding

        findings = await asyncio.gather(*(_worker(rid) for rid in pending))
        chunks: list[str] = []
        raw: dict[str, str] = {}
        for finding in findings:
            rid = finding.requirement_id
            if store is not None:
                tool_text = store.load_evidence_text(
                    "host_facts",
                    rid,
                    max_chars=self.settings.max_tool_output_chars,
                )
                if tool_text:
                    raw[f"req_{rid}"] = tool_text
                    chunks.append(f"[{rid} tools]\n{tool_text}")
            obs = str(finding.evidence or "").strip()
            if obs:
                chunks.append(
                    f"[{rid} {finding.status}] {finding.title}: {obs}"
                )

        evidence = "\n---\n".join(c.strip() for c in chunks if c and c.strip())
        evidence = truncate_text(
            evidence,
            self.settings.max_tool_output_chars * 2,
            "host_facts_evidence",
        )
        facts = await self._facts_from_host_facts_evidence(
            evidence=evidence,
            raw=raw,
            ssh_host=ssh_host,
            source="checklist",
        )
        if not facts.error and any(f.status == "error" for f in findings):
            # Surface SSH/tool failures for routing when fill did not set error.
            err_bits = [
                f"{f.requirement_id}: {f.evidence}"
                for f in findings
                if f.status == "error" and f.evidence
            ]
            if err_bits and "ssh error" in " ".join(err_bits).lower():
                facts.error = err_bits[0][:500]
        return facts

    async def collect_host_facts(self, state: AuditorState) -> dict[str, Any]:
        """Gather hostname/OS/software/disk/RAM/CPU and refresh INVENTORY.md."""
        if state.get("error") and not (state.get("requirements") or {}):
            return {}

        intake = dict(state.get("intake") or {})
        has_access = bool(state.get("has_access") or intake.get("has_access"))
        client_name = str(
            state.get("client_name") or intake.get("client_name") or "client"
        )
        host_id = str(state.get("evidence_host_id") or "").strip()
        lang = self._report_language(state)
        facts_md = ""
        drift_md = ""
        drift_items = []
        facts = None

        if has_access and effective_settings(self.settings).ssh_host:
            store = self._store_from_state(state)
            # Reuse intake discovery artifacts (avoid re-running host_facts.md).
            if store is not None:
                if host_id:
                    store.host_segment = host_id
                facts_path = store.host_root(host_id or None) / "host_facts.json"
                if facts_path.is_file():
                    try:
                        payload = json.loads(facts_path.read_text(encoding="utf-8"))
                        facts = parse_host_facts_json(
                            payload.get("facts") or payload,
                            ssh_host=str(
                                effective_settings(self.settings).ssh_host or ""
                            ),
                        )
                        # Retry only when prior discovery failed with no identity.
                        if facts.error and not (facts.hostname or facts.os_id):
                            facts = None
                        elif facts is not None:
                            facts.raw["host_facts_source"] = str(
                                (facts.raw or {}).get("host_facts_source")
                                or "reuse"
                            )
                    except Exception:  # noqa: BLE001
                        facts = None
            if facts is None:
                facts = await self._collect_host_facts(
                    store=store,
                    host_id=host_id,
                    user_request=str(state.get("user_request") or ""),
                )
            facts_md = format_host_facts_markdown(
                facts, None, language=lang.code
            )

            if store is not None and facts is not None:
                if host_id:
                    store.host_segment = host_id
                facts_base = store.host_root(host_id or None)
                write_host_facts_json(
                    facts_base / "host_facts.json", facts, drift_items
                )
                (facts_base / "host_facts.md").write_text(facts_md, encoding="utf-8")

            if facts is not None:
                inv_path = (
                    Path(self.settings.inventory_dir)
                    / client_slug(client_name)
                    / "INVENTORY.md"
                )
                upsert_inventory_md(
                    inv_path,
                    client_name=client_name,
                    facts=facts,
                    scope_text=str(intake.get("inventory_scope") or ""),
                    reachable_services=(intake.get("access_probe") or {}).get(
                        "services"
                    ),
                )
                if store is not None:
                    dest = store.root / "INVENTORY.md"
                    dest.write_text(inv_path.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            # Still materialize inventory from scope when no live access
            inv_path = (
                Path(self.settings.inventory_dir)
                / client_slug(client_name)
                / "INVENTORY.md"
            )
            upsert_inventory_md(
                inv_path,
                client_name=client_name,
                facts=None,
                scope_text=str(intake.get("inventory_scope") or ""),
                reachable_services=(intake.get("access_probe") or {}).get("services"),
            )
            store = self._store_from_state(state)
            if store is not None and inv_path.is_file():
                (store.root / "INVENTORY.md").write_text(
                    inv_path.read_text(encoding="utf-8"), encoding="utf-8"
                )

        return {
            "host_facts_md": facts_md,
            "cmdb_drift_md": drift_md,
            "messages": [
                AIMessage(
                    content=facts_md or "Host facts: skipped (no SSH access).",
                    name="auditor",
                )
            ],
        }

    async def route_framework_node(self, state: AuditorState) -> dict[str, Any]:
        """Node: choose ``agents/<framework>.md`` (honors pinned ``framework_id``)."""
        user_request = state.get("user_request") or ""
        if not user_request:
            for msg in reversed(state.get("messages") or []):
                if isinstance(msg, HumanMessage):
                    user_request = str(msg.content)
                    break
        user_request = truncate_text(
            user_request,
            self.settings.max_user_request_chars,
            "user_request",
        )
        report_lang = detect_report_language(user_request)

        pinned = state.get("framework_id") or ""
        try:
            if pinned:
                fw = get_framework(pinned, self.settings.agents_dir)
                if fw is None:
                    raise FileNotFoundError(
                        f"Pinned framework `{pinned}` not found in agents/"
                    )
            else:
                fw = route_framework(user_request, self.settings.agents_dir)
        except FileNotFoundError as exc:
            return {
                "user_request": user_request,
                "report_language": report_lang.code,
                "error": str(exc),
                "framework_id": "",
                "framework_title": "",
                "pending_ids": [],
                "requirements": {},
                "messages": [
                    RemoveMessage(id=REMOVE_ALL_MESSAGES),
                    AIMessage(content=str(exc)),
                ],
            }

        catalog = frameworks_catalog_text(self.settings.agents_dir)
        return {
            "user_request": user_request,
            "report_language": report_lang.code,
            "framework_id": fw.id,
            "framework_title": fw.title,
            "retry_count": 0,
            "error": None,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                SystemMessage(
                    content=(
                        f"Selected framework `{fw.id}` ({fw.title}) from agents/.\n"
                        f"Report language: {report_lang.name} (`{report_lang.code}`).\n"
                        f"{catalog}"
                    )
                ),
            ],
        }

    async def load_framework(self, state: AuditorState) -> dict[str, Any]:
        """Node: load the drop-in Markdown checklist for the selected framework."""
        if state.get("error") and not state.get("framework_id"):
            return {"pending_ids": [], "requirements": {}}

        selected = get_framework(
            state.get("framework_id") or "",
            self.settings.agents_dir,
        )
        if selected is None:
            # Fallback: route again from user text.
            selected = route_framework(
                state.get("user_request") or "",
                self.settings.agents_dir,
            )
        checklist = load_framework_checklist(selected)
        req_map = checklist.by_id()
        store = self._store_from_state(state)
        host_id = str(state.get("evidence_host_id") or "").strip()
        if store is not None and host_id:
            store.host_segment = host_id

        # Reuse findings already written (e.g. host_facts.md during intake discovery).
        existing: dict[str, Finding] = {}
        pending: list[str] = []
        for rid in checklist.ids():
            raw = store.load_finding(selected.id, rid) if store is not None else None
            if raw:
                try:
                    existing[rid] = _as_finding(raw)
                    continue
                except Exception:  # noqa: BLE001
                    pass
            pending.append(rid)

        reused = len(existing)
        msg = (
            f"Loaded {len(req_map)} requirements from {selected.path}"
            + (f" ({reused} already assessed)." if reused else ".")
        )
        return {
            "framework_id": selected.id,
            "framework_title": selected.title,
            "checklist_title": checklist.title,
            "requirements": req_map,
            "pending_ids": pending,
            "findings": existing,
            "report": "",
            "messages": [
                AIMessage(
                    content=msg,
                    name="auditor",
                )
            ],
        }

    async def assess_parallel(self, state: AuditorState) -> dict[str, Any]:
        """Node: fill report cells for pending requirements (parallel)."""
        requirements = state.get("requirements") or {}
        pending = list(state.get("pending_ids") or [])
        if not pending:
            return {
                "pending_ids": [],
                "messages": [
                    AIMessage(content="No pending requirements to assess.", name="auditor")
                ],
            }

        user_request = state.get("user_request") or "(none)"
        framework_id = state.get("framework_id") or ""
        report_lang = self._report_language(state, user_request)
        store = self._store_from_state(state)
        host_id = str(state.get("evidence_host_id") or "").strip()
        if store is not None and host_id:
            store.host_segment = host_id
        limit = max(1, self.settings.max_parallel_assessments)
        sem = asyncio.Semaphore(limit)
        thread_hint = str(state.get("thread_id") or "")
        emit_phase(
            f"Assessing {len(pending)} requirement(s) for `{framework_id}` "
            f"(concurrency={limit})…",
            framework_id=framework_id,
        )
        if requirements:
            evidence_rel = ""
            hostname = None
            ssh_host = None
            if store is not None:
                try:
                    evidence_rel = str(
                        store.root.relative_to(
                            Path(self.settings.evidence_dir).resolve()
                        )
                    )
                except ValueError:
                    evidence_rel = str(store.root)
                facts_path = store.host_root(host_id) / "host_facts.json" if host_id else None
                if facts_path is None:
                    facts_path = store.root / "host_facts.json"
                if facts_path.is_file():
                    try:
                        import json as _json

                        raw_facts = _json.loads(facts_path.read_text(encoding="utf-8"))
                        hostname = str(raw_facts.get("hostname") or "") or None
                        ssh_host = str(raw_facts.get("ssh_host") or "") or None
                    except Exception:  # noqa: BLE001
                        pass
            await snapshot_checklist_safe(
                self.settings,
                client_name=str(state.get("client_name") or "")
                or (store.run_id if store else ""),
                evidence_run_id=str(
                    state.get("evidence_run_id") or (store.run_id if store else "")
                ),
                framework_id=framework_id or "framework",
                requirements=requirements,
                evidence_host_id=host_id or None,
                session_number=self._results_session_number(state, store),
                hostname=hostname,
                ssh_host=ssh_host or host_id or None,
                evidence_relpath=evidence_rel,
            )

        async def _worker(req_id: str) -> Finding:
            """Assess one requirement under the concurrency semaphore."""
            async with sem:
                emit_req_status(
                    req_id, "started", framework_id=framework_id, text=f"Assessing `{req_id}`…"
                )
                try:
                    special = self._deterministic_it_audit_finding(
                        req_id=req_id,
                        requirement=requirements[req_id],
                        framework_id=framework_id,
                        state=state,
                        store=store,
                    )
                    if special is not None:
                        if store is not None:
                            store.write_requirement(
                                framework_id,
                                req_id,
                                {
                                    "id": requirements[req_id].id,
                                    "title": requirements[req_id].title,
                                    "category": requirements[req_id].category,
                                    "severity": requirements[req_id].severity,
                                    "how_to_verify": requirements[req_id].how_to_verify,
                                    "pass_criteria": requirements[req_id].pass_criteria,
                                },
                            )
                            store.write_finding(
                                framework_id, req_id, special.model_dump()
                            )
                        await self._warehouse_live_upsert(
                            state,
                            framework_id=framework_id,
                            finding=special,
                            requirement=requirements.get(req_id),
                            store=store,
                        )
                        emit_req_status(
                            req_id,
                            special.status,
                            framework_id=framework_id,
                        )
                        return special
                    finding = await self._fill_requirement_cells(
                        req_id=req_id,
                        requirement=requirements[req_id],
                        user_request=user_request,
                        framework_id=framework_id,
                        store=store,
                        report_language=report_lang,
                    )
                    await self._warehouse_live_upsert(
                        state,
                        framework_id=framework_id,
                        finding=finding,
                        requirement=requirements.get(req_id),
                        store=store,
                    )
                    emit_req_status(
                        req_id,
                        finding.status,
                        framework_id=framework_id,
                    )
                    return finding
                except asyncio.CancelledError:
                    if store is not None and thread_hint:
                        remaining = [
                            rid
                            for rid in pending
                            if rid not in (state.get("findings") or {})
                        ]
                        write_run_status(
                            self.settings.evidence_dir,
                            store.run_id,
                            status="interrupted",
                            thread_id=thread_hint,
                            pending_ids=remaining,
                            framework_id=framework_id,
                        )
                        await sync_session_status_from_run_meta(
                            self.settings,
                            run_id=store.run_id,
                            status="interrupted",
                            thread_id=thread_hint,
                            pending_ids=remaining,
                            framework_id=framework_id,
                        )
                    raise
                except Exception as exc:  # noqa: BLE001
                    req = requirements.get(req_id)
                    finding = Finding(
                        requirement_id=req_id,
                        title=req.title if req else "",
                        status="error",
                        severity=req.severity if req else "",
                        category=req.category if req else "",
                        pass_criteria=req.pass_criteria if req else "",
                        evidence=f"Cell fill failed: {type(exc).__name__}: {exc}",
                        remediation="Retry after restoring SSH/MCP session",
                    )
                    if store is not None:
                        store.write_finding(
                            framework_id,
                            req_id,
                            finding.model_dump(),
                        )
                    await self._warehouse_live_upsert(
                        state,
                        framework_id=framework_id,
                        finding=finding,
                        requirement=req,
                        store=store,
                    )
                    emit_req_status(
                        req_id, "error", framework_id=framework_id, text=str(exc)[:200]
                    )
                    return finding

        work_ids = [rid for rid in pending if rid in requirements]
        # Finish as completed so disk findings survive mid-run cancel.
        tasks = {asyncio.create_task(_worker(rid)): rid for rid in work_ids}
        findings_list: list[Finding] = []
        try:
            for coro in asyncio.as_completed(tasks):
                findings_list.append(await coro)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if store is not None:
                done_ids = {f.requirement_id for f in findings_list}
                # Also pick up any findings already on disk from cancelled workers.
                for rid in work_ids:
                    if rid in done_ids:
                        continue
                    raw = store.load_finding(framework_id, rid)
                    if raw:
                        done_ids.add(rid)
                remaining = [rid for rid in work_ids if rid not in done_ids]
                write_run_status(
                    self.settings.evidence_dir,
                    store.run_id,
                    status="interrupted",
                    thread_id=thread_hint,
                    pending_ids=remaining,
                    framework_id=framework_id,
                )
                await sync_session_status_from_run_meta(
                    self.settings,
                    run_id=store.run_id,
                    status="interrupted",
                    thread_id=thread_hint or "",
                    pending_ids=remaining,
                    framework_id=framework_id,
                )
            raise

        new_findings = {f.requirement_id: f for f in findings_list}

        # Keep recoverable failures in pending_ids for the reconnect cycle.
        retryable = [f.requirement_id for f in findings_list if _is_recoverable_finding(f)]
        return {
            "findings": new_findings,
            "pending_ids": retryable,
            "current_id": None,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                AIMessage(
                    content=(
                        f"Assessed {len(new_findings)} rows for `{framework_id}` "
                        f"(concurrency={limit}); "
                        f"recoverable failures queued={len(retryable)}."
                    ),
                    name="auditor",
                ),
            ],
        }

    def route_after_assess(
        self, state: AuditorState
    ) -> Literal["reconnect_session", "human_gate", "finalize"]:
        """Reconnect on transport errors; otherwise ask the human about failures."""
        pending = state.get("pending_ids") or []
        retry_count = int(state.get("retry_count") or 0)
        max_retries = self.settings.max_session_retries
        if pending and retry_count < max_retries:
            return "reconnect_session"
        if self.settings.hitl_enabled and _hitl_candidates(state):
            return "human_gate"
        return "finalize"

    def route_after_hitl(
        self, state: AuditorState
    ) -> Literal["assess_parallel", "human_gate", "finalize"]:
        """After skip/retry: reassess, ask about the next failure, or finalize."""
        pending = state.get("pending_ids") or []
        if pending:
            return "assess_parallel"
        if self.settings.hitl_enabled and _hitl_candidates(state):
            return "human_gate"
        return "finalize"

    async def reconnect_session(self, state: AuditorState) -> dict[str, Any]:
        """Node: restore MCP sessions and bump retry counter (graph cycle)."""
        status = await reconnect_mcp_session()
        retry_count = int(state.get("retry_count") or 0) + 1
        pending = state.get("pending_ids") or []
        return {
            "retry_count": retry_count,
            "messages": [
                AIMessage(
                    content=(
                        f"Reconnect attempt #{retry_count}: {status}. "
                        f"Re-queueing {len(pending)} requirements."
                    ),
                    name="auditor",
                )
            ],
        }

    async def human_gate(self, state: AuditorState) -> dict[str, Any]:
        """Pause for the operator when a requirement could not be audited.

        Uses LangGraph ``interrupt()``. The OpenAI-compatible API resumes with
        ``Command(resume=user_text)`` when the user replies skip/retry.
        """
        candidates = _hitl_candidates(state)
        if not candidates:
            return {"awaiting_hitl": False, "pending_ids": []}

        requirements = state.get("requirements") or {}
        findings = state.get("findings") or {}
        framework_id = state.get("framework_id") or ""
        store = self._store_from_state(state)

        req_id = candidates[0]
        finding = _as_finding(findings[req_id])
        requirement = requirements.get(req_id) or Requirement(
            id=req_id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            pass_criteria=finding.pass_criteria,
        )
        evidence_dir = None
        if store is not None:
            evidence_dir = str(store.requirement_dir(framework_id, req_id))

        prompt = build_hitl_prompt(
            framework_id=framework_id,
            requirement=requirement,
            finding=finding,
            evidence_dir=evidence_dir,
        )
        payload: dict[str, Any] = {
            "type": "skip_or_retry",
            "requirement_id": req_id,
            "framework_id": framework_id,
            "candidates": candidates,
            "prompt": prompt,
        }

        raw_reply = interrupt(payload)
        decision = await interpret_hitl_decision(
            raw_reply,
            llm=self.fill_model,
            requirement_id=req_id,
            requirement_title=requirement.title,
            why=finding.evidence or finding.notes or "",
            candidates=candidates,
        )
        if decision.action == "unknown":
            retry_prompt = (
                "I didn't understand that reply "
                "(and the model could not classify it).\n\n"
                "Please answer with **skip**, **retry**, **skip all**, or **retry all**.\n\n"
                f"{prompt}"
            )
            raw_reply = interrupt({**payload, "prompt": retry_prompt})
            decision = await interpret_hitl_decision(
                raw_reply,
                llm=self.fill_model,
                requirement_id=req_id,
                requirement_title=requirement.title,
                why=finding.evidence or finding.notes or "",
                candidates=candidates,
            )
        if decision.action == "unknown":
            # Last resort: continue the audit rather than deadlocking the chat.
            decision = HitlDecision(
                action="skip_all", raw=decision.raw, source="llm"
            )

        skipped = list(state.get("hitl_skipped") or [])
        via = (
            " (LLM interpreted reply)"
            if decision.source == "llm"
            else ""
        )

        if decision.action == "skip_all":
            updates: dict[str, Finding] = {}
            for rid in candidates:
                updates[rid] = self._skipped_finding(
                    _as_finding(findings[rid]),
                    reason="Skipped by operator (skip all).",
                )
                if rid not in skipped:
                    skipped.append(rid)
            return {
                "findings": updates,
                "hitl_skipped": skipped,
                "pending_ids": [],
                "awaiting_hitl": False,
                "messages": [
                    AIMessage(
                        content=(
                            f"Operator skipped {len(candidates)} failed "
                            f"requirement(s){via}."
                        ),
                        name="auditor",
                    )
                ],
            }

        if decision.action == "retry_all":
            return {
                "pending_ids": list(candidates),
                "retry_count": 0,
                "awaiting_hitl": False,
                "messages": [
                    AIMessage(
                        content=(
                            f"Operator requested retry for {len(candidates)} "
                            f"failed requirement(s){via}."
                        ),
                        name="auditor",
                    )
                ],
            }

        if decision.action == "skip":
            if req_id not in skipped:
                skipped.append(req_id)
            return {
                "findings": {
                    req_id: self._skipped_finding(
                        finding,
                        reason="Skipped by operator after failed assessment.",
                    )
                },
                "hitl_skipped": skipped,
                "pending_ids": [],
                "awaiting_hitl": False,
                "messages": [
                    AIMessage(
                        content=f"Operator skipped `{req_id}`{via}.",
                        name="auditor",
                    )
                ],
            }

        # retry single — reset session retry budget so reconnect can run again
        return {
            "pending_ids": [req_id],
            "retry_count": 0,
            "awaiting_hitl": False,
            "messages": [
                AIMessage(
                    content=f"Operator requested retry for `{req_id}`{via}.",
                    name="auditor",
                )
            ],
        }

    def _deterministic_it_audit_finding(
        self,
        *,
        req_id: str,
        requirement: Requirement,
        framework_id: str,
        state: AuditorState,
        store: EvidenceStore | None,
    ) -> Finding | None:
        """Resolve IT-audit REQs that should not HITL-loop.

        REQ-006: pass/fail on ``INVENTORY.md`` (never ``error``).
        REQ-007: summarize intake access probe (never call placeholder SSH).
        """
        if framework_id != "it_audit":
            return None

        intake = state.get("intake") or {}

        if req_id == "REQ-006":
            inv_path = store.root / "INVENTORY.md" if store is not None else None
            if inv_path is not None and inv_path.is_file():
                return Finding(
                    requirement_id=req_id,
                    title=requirement.title,
                    status="pass",
                    severity=requirement.severity,
                    category=requirement.category,
                    pass_criteria=requirement.pass_criteria,
                    evidence=(
                        f"Inventory-only assessment: INVENTORY.md is present at `{inv_path}`."
                    ),
                    remediation="",
                    notes="Deterministic inventory file check.",
                )
            return Finding(
                requirement_id=req_id,
                title=requirement.title,
                status="fail",
                severity=requirement.severity,
                category=requirement.category,
                pass_criteria=requirement.pass_criteria,
                evidence=(
                    "Inventory-only assessment: INVENTORY.md is missing from "
                    "the evidence run directory."
                ),
                remediation=(
                    "Ensure intake wrote inventory/<client>/INVENTORY.md and "
                    "copied it into the artifacts run folder."
                ),
                notes="Deterministic inventory file check.",
            )

        if req_id == "REQ-007":
            probe = intake.get("access_probe") or {}
            services = list(probe.get("services") or [])
            if not services:
                return Finding(
                    requirement_id=req_id,
                    title=requirement.title,
                    status="fail",
                    severity=requirement.severity,
                    category=requirement.category,
                    pass_criteria=requirement.pass_criteria,
                    evidence="No intake access_probe results were stored.",
                    remediation="Re-run intake with access=yes so SSH/PG are probed.",
                )
            lines = [
                f"- **{s.get('name')}**: `{s.get('status')}` — {s.get('detail') or '—'}"
                for s in services
            ]
            any_ok = bool(probe.get("any_ok"))
            return Finding(
                requirement_id=req_id,
                title=requirement.title,
                status="pass" if any_ok else "fail",
                severity=requirement.severity,
                category=requirement.category,
                pass_criteria=requirement.pass_criteria,
                evidence="Intake access probe summary:\n" + "\n".join(lines),
                remediation=""
                if any_ok
                else "Fix SSH/Postgres credentials in inventory and re-probe.",
                notes="Deterministic from intake access_probe.",
            )

        return None

    @staticmethod
    def _skipped_finding(finding: Finding, *, reason: str) -> Finding:
        """Mark a failed finding as skipped while preserving the failure why."""
        notes = finding.notes or ""
        if reason not in notes:
            notes = f"{notes}\n{reason}".strip()
        return finding.model_copy(
            update={
                "status": "skipped",
                "notes": notes,
                "remediation": finding.remediation
                or "Operator skipped this check; re-run later if needed.",
            }
        )

    def _store_from_state(self, state: AuditorState) -> EvidenceStore | None:
        """Resolve the evidence store for this graph run (if configured)."""
        run_id = state.get("evidence_run_id") or ""
        run_dir = state.get("evidence_run_dir") or ""
        if not run_id and not run_dir:
            return None
        if not run_id and run_dir:
            run_id = Path(run_dir).name
        if run_id in self._evidence_by_run:
            return self._evidence_by_run[run_id]
        store = EvidenceStore(self.settings.evidence_dir, run_id=run_id)
        if run_dir:
            path = Path(run_dir)
            if path.is_dir():
                store.root = path
                store.run_id = path.name
        self._evidence_by_run[store.run_id] = store
        return store

    def _results_session_number(
        self,
        state: AuditorState,
        store: EvidenceStore | None,
    ) -> int | None:
        """Resolve warehouse session number from state or disk meta."""
        if store is not None:
            raw = store.read_run_meta().get("results_session_number")
            if raw is not None:
                try:
                    return int(raw)
                except (TypeError, ValueError):
                    pass
        if state.get("results_session_number") is not None:
            try:
                return int(state["results_session_number"])  # type: ignore[index]
            except (TypeError, ValueError):
                return None
        return None

    async def _warehouse_live_upsert(
        self,
        state: AuditorState,
        *,
        framework_id: str,
        finding: Finding,
        requirement: Requirement | None,
        store: EvidenceStore | None,
        source: str = "live",
    ) -> None:
        """Best-effort dual-write of one filled REQ to the results warehouse."""
        evidence_rel = ""
        hostname = None
        ssh_host = None
        host_id = str(state.get("evidence_host_id") or "").strip()
        if store is not None:
            try:
                evidence_rel = str(
                    store.root.relative_to(Path(self.settings.evidence_dir).resolve())
                )
            except ValueError:
                evidence_rel = str(store.root)
            facts_path = (
                store.host_root(host_id) / "host_facts.json"
                if host_id
                else store.root / "host_facts.json"
            )
            if facts_path.is_file():
                try:
                    import json as _json

                    raw_facts = _json.loads(facts_path.read_text(encoding="utf-8"))
                    hostname = str(raw_facts.get("hostname") or "") or None
                    ssh_host = str(raw_facts.get("ssh_host") or "") or None
                except Exception:  # noqa: BLE001
                    pass
        await record_requirement_result_safe(
            self.settings,
            client_name=str(state.get("client_name") or "")
            or (store.run_id if store else ""),
            evidence_run_id=str(
                state.get("evidence_run_id") or (store.run_id if store else "")
            ),
            framework_id=framework_id or "framework",
            evidence_host_id=host_id or None,
            finding=finding,
            requirement=requirement,
            evidence_relpath=evidence_rel,
            source=source,
            session_number=self._results_session_number(state, store),
            hostname=hostname,
            ssh_host=ssh_host or host_id or None,
        )

    async def _fill_requirement_cells(
        self,
        req_id: str,
        requirement: Requirement,
        user_request: str,
        framework_id: str,
        store: EvidenceStore | None = None,
        report_language: ReportLanguage | None = None,
        *,
        ssh_only: bool = False,
    ) -> Finding:
        """Run evidence gathering + fill model for one requirement cell.

        Writes requirement metadata and finding JSON to the evidence store
        when ``store`` is provided.

        Args:
            req_id: Requirement id.
            requirement: Parsed checklist requirement.
            user_request: Original operator request (context).
            framework_id: Active framework id.
            store: Optional evidence store for disk artifacts.
            report_language: Language for fill prompts.
            ssh_only: When True, bind only SSH tools (host_facts discovery).

        Returns:
            Completed ``Finding`` for the requirement.
        """
        if store is not None:
            store.write_requirement(
                framework_id,
                req_id,
                {
                    "id": requirement.id,
                    "title": requirement.title,
                    "category": requirement.category,
                    "severity": requirement.severity,
                    "how_to_verify": requirement.how_to_verify,
                    "pass_criteria": requirement.pass_criteria,
                },
            )
        evidence = await self._gather_evidence(
            req_id,
            requirement,
            user_request,
            framework_id,
            store=store,
            ssh_only=ssh_only,
        )
        evidence = truncate_text(
            evidence,
            self.settings.max_tool_output_chars,
            "evidence",
        )
        report_lang = report_language or self._report_language_from_request(
            user_request
        )
        lang_instr = language_instruction(report_lang)
        fill_messages = [
            SystemMessage(
                content=FILL_SYSTEM_PROMPT.format(language_instruction=lang_instr)
            ),
            HumanMessage(
                content=FILL_CELL_PROMPT.format(
                    report_language=report_lang.name,
                    language_instruction=lang_instr,
                    req_id=req_id,
                    title=requirement.title,
                    category=requirement.category,
                    severity=requirement.severity,
                    pass_criteria=requirement.pass_criteria,
                    how_to_verify=requirement.how_to_verify,
                    evidence=evidence or "(no evidence collected)",
                )
            ),
        ]
        response = await self.fill_model.ainvoke(fill_messages)
        finding = self._cells_to_finding(req_id, requirement, response, evidence)
        if store is not None:
            store.write_finding(framework_id, req_id, finding.model_dump())
        return finding

    async def _gather_evidence(
        self,
        req_id: str,
        requirement: Requirement,
        user_request: str,
        framework_id: str,
        store: EvidenceStore | None = None,
        *,
        ssh_only: bool = False,
    ) -> str:
        """Tool-calling loop: gather raw evidence text for one requirement.

        Injects playbook memory, runs the evidence LLM with SSH/MCP tools,
        and concatenates tool outputs and final narrative.

        Args:
            req_id: Requirement id (for progress and playbook lookup).
            requirement: Checklist requirement being verified.
            user_request: Original operator request.
            framework_id: Active framework id.
            store: Optional evidence store for tool call logging.
            ssh_only: When True, bind only SSH tools.

        Returns:
            Combined evidence string for the fill model.
        """
        playbook_block = ""
        if self.playbooks is not None and self.settings.memory_enabled:
            playbook_block = self.playbooks.format_prompt_block(framework_id, req_id)
        if ssh_only:
            tool_note = "Use ONLY ssh_run / ssh_read_file for this inventory check."
        else:
            tool_note = (
                "Use inventory plus SSH/Postgres MCP tools appropriate for this framework."
            )
        messages: list = [
            SystemMessage(
                content=(
                    f"{EVIDENCE_SYSTEM_PROMPT}\n\n"
                    f"Active framework: `{framework_id}`. "
                    f"{tool_note}"
                )
            ),
            HumanMessage(
                content=EVIDENCE_PROMPT.format(
                    user_request=user_request,
                    requirement_block=requirement.to_prompt_block(),
                    playbook_block=playbook_block
                    or "(no playbook memory for this requirement)",
                )
            ),
        ]
        chunks: list[str] = []
        max_rounds = self.settings.max_tool_rounds_per_item
        evidence_llm = (
            self.evidence_model_ssh
            if ssh_only
            else self._evidence_llm()
        )

        for _ in range(max_rounds + 1):
            rounds = count_tool_rounds(messages)
            if rounds >= max_rounds:
                messages.append(HumanMessage(content=EVIDENCE_FORCE_PROMPT))
                response = await self.fill_model.ainvoke(messages)
                chunks.append(str(response.content or ""))
                break

            response = await evidence_llm.ainvoke(messages)
            messages.append(response)
            tool_calls = getattr(response, "tool_calls", None) or []
            if not tool_calls:
                chunks.append(str(response.content or ""))
                break

            tool_messages = await self._execute_tool_calls(
                tool_calls,
                framework_id=framework_id,
                req_id=req_id,
                store=store,
            )
            messages.extend(tool_messages)
            for tm in tool_messages:
                chunks.append(f"[{tm.name}] {tm.content}")

        return "\n---\n".join(c.strip() for c in chunks if c and c.strip())

    async def _execute_tool_calls(
        self,
        tool_calls: list[dict[str, Any]],
        *,
        framework_id: str = "",
        req_id: str = "",
        store: EvidenceStore | None = None,
    ) -> list[ToolMessage]:
        """Execute parallel tool calls from the evidence model response.

        Emits progress events, logs to the evidence store, and updates playbook
        memory on success.

        Args:
            tool_calls: LangChain tool call dicts from the model.
            framework_id: Framework id for logging and memory.
            req_id: Requirement id for logging and memory.
            store: Optional evidence store.

        Returns:
            ``ToolMessage`` list in call order for appending to chat history.
        """
        async def _one(tc: dict[str, Any]) -> ToolMessage:
            """Invoke a single tool call and return its ``ToolMessage``."""
            name = tc.get("name") or ""
            args = tc.get("args") or {}
            call_id = tc.get("id") or name
            emit_tool_call(
                name,
                args,
                call_id=str(call_id),
                requirement_id=req_id,
                framework_id=framework_id,
            )
            error: str | None = None
            full_result = ""
            tool = self.tools_by_name.get(name)
            if tool is None:
                full_result = f"Tool error: unknown tool '{name}'"
                error = full_result
                content = full_result
            else:
                try:
                    raw = await tool.ainvoke(args)
                    full_result = str(raw)
                    content = truncate_text(
                        full_result,
                        self.settings.max_tool_output_chars,
                        "tool",
                    )
                except Exception as exc:  # noqa: BLE001
                    full_result = f"Tool error: {type(exc).__name__}: {exc}"
                    error = full_result
                    content = full_result
            emit_tool_result(
                name,
                full_result,
                call_id=str(call_id),
                requirement_id=req_id,
                framework_id=framework_id,
                error=error,
            )
            if store is not None and req_id:
                store.write_tool_result(
                    framework_id,
                    req_id,
                    name,
                    args if isinstance(args, dict) else {"value": args},
                    full_result,
                    error=error,
                )
            # Long-term memory: remember successful recipes (hot path).
            if (
                self.playbooks is not None
                and self.settings.memory_learn
                and req_id
                and not error
                and not _tool_result_looks_failed(full_result)
            ):
                self.playbooks.remember_tool(
                    framework_id,
                    req_id,
                    name,
                    args if isinstance(args, dict) else {"value": args},
                    success=True,
                )
            return ToolMessage(content=content, tool_call_id=call_id, name=name)

        return list(await asyncio.gather(*[_one(tc) for tc in tool_calls]))

    def _cells_to_finding(
        self,
        req_id: str,
        req: Requirement,
        ai: AIMessage,
        fallback_evidence: str,
    ) -> Finding:
        """Parse fill-model JSON into a ``Finding`` with status normalization.

        Forces ``error`` status when evidence looks like a transport failure
        even if the model returned pass/fail.

        Args:
            req_id: Requirement id.
            req: Checklist requirement metadata.
            ai: Fill model response message.
            fallback_evidence: Raw evidence when JSON omits observation.

        Returns:
            Truncated ``Finding`` ready for state and disk.
        """
        data = _extract_json(str(ai.content or "")) or {}
        observation = str(
            data.get("observation")
            or data.get("evidence")
            or fallback_evidence
            or ai.content
            or ""
        )
        recommendation = str(
            data.get("recommendation") or data.get("remediation") or ""
        )
        # If observation still looks like a transport failure, force error status
        # so the cyclic reconnect path can pick it up.
        status = _normalize_status(data.get("status"))
        tmp = Finding(
            requirement_id=req_id,
            title=req.title,
            status=status,  # type: ignore[arg-type]
            severity=req.severity,
            category=req.category,
            pass_criteria=req.pass_criteria,
            evidence=observation,
            remediation=recommendation,
            notes=str(data.get("notes") or ""),
        )
        # Transport failures must stay status=error so reconnect / HITL can fire,
        # even when the model incorrectly marks the cell as pass/fail/partial.
        if status != "error" and _is_recoverable_finding(
            Finding(
                requirement_id=req_id,
                status="error",
                evidence=observation,
                notes=str(data.get("notes") or ""),
            )
        ):
            tmp.status = "error"
        tmp.evidence = truncate_text(
            tmp.evidence or "",
            self.settings.max_finding_evidence_chars,
            "observation",
        )
        tmp.remediation = truncate_text(
            tmp.remediation or "",
            min(self.settings.max_finding_evidence_chars, 1200),
            "recommendation",
        )
        return tmp

    def _report_language(
        self, state: AuditorState | None = None, user_request: str = ""
    ) -> ReportLanguage:
        """Resolve report language from state or user request text.

        Args:
            state: Optional graph state with ``report_language`` code.
            user_request: Fallback text for ``detect_report_language``.

        Returns:
            ``ReportLanguage`` with code and display name.
        """
        if state:
            code = str(state.get("report_language") or "").strip()
        if code:
            return ReportLanguage(code=code, name=language_name(code))
        text = user_request or (state.get("user_request") if state else "") or ""
        return detect_report_language(text)

    def _report_language_from_request(self, user_request: str) -> ReportLanguage:
        """Detect report language from the operator request string only."""
        return detect_report_language(user_request)

    async def finalize(self, state: AuditorState) -> dict[str, Any]:
        """Assemble fixed report + short executive summary."""
        if state.get("error") and not (state.get("requirements") or {}):
            msg = state.get("error") or "No framework available."
            return {
                "report": msg,
                "messages": [
                    RemoveMessage(id=REMOVE_ALL_MESSAGES),
                    AIMessage(content=msg),
                ],
            }

        findings = state.get("findings") or {}
        requirements = state.get("requirements") or {}
        title = (
            state.get("checklist_title")
            or state.get("framework_title")
            or "Security Audit"
        )
        report_lang = self._report_language(state)
        lang_instr = language_instruction(report_lang)
        full_report = render_report(
            title, findings, requirements, language=report_lang
        )
        digest = compact_findings_for_summary(
            findings,
            evidence_chars=self.settings.max_finalize_evidence_chars,
        )
        try:
            response = await self.fill_model.ainvoke(
                [
                    SystemMessage(
                        content=(
                            "You write short executive summaries for fixed-format "
                            "security audit reports across OS/DB frameworks. "
                            f"{lang_instr}"
                        )
                    ),
                    HumanMessage(
                        content=FINALIZE_PROMPT.format(
                            report=digest,
                            report_language=report_lang.name,
                            language_instruction=lang_instr,
                        )
                    ),
                ]
            )
            summary = str(response.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            summary = f"(Summary generation failed: {exc})"

        fw = state.get("framework_id") or ""
        retries = int(state.get("retry_count") or 0)
        store = self._store_from_state(state)
        evidence_note = ""
        report_for_mlflow: Path | None = None
        if store is not None:
            host_id = str(state.get("evidence_host_id") or "").strip()
            if host_id:
                store.host_segment = host_id
            report_for_mlflow = store.write_report(
                fw or "framework", f"{summary}\n\n---\n\n{full_report}"
            )
            evidence_note = f" | evidence: `{store.root}`"

        if findings or requirements:
            evidence_rel = ""
            if store is not None:
                try:
                    evidence_rel = str(
                        store.root.relative_to(
                            Path(self.settings.evidence_dir).resolve()
                        )
                    )
                except ValueError:
                    evidence_rel = str(store.root)
            session_number = None
            if store is not None:
                raw_sess = store.read_run_meta().get("results_session_number")
                if raw_sess is not None:
                    try:
                        session_number = int(raw_sess)
                    except (TypeError, ValueError):
                        session_number = None
            if session_number is None and state.get("results_session_number") is not None:
                try:
                    session_number = int(state["results_session_number"])  # type: ignore[index]
                except (TypeError, ValueError):
                    session_number = None
            await record_results_safe(
                self.settings,
                client_name=str(state.get("client_name") or "")
                or (store.run_id if store else ""),
                evidence_run_id=str(
                    state.get("evidence_run_id") or (store.run_id if store else "")
                ),
                framework_id=fw or "framework",
                evidence_host_id=str(state.get("evidence_host_id") or "") or None,
                findings=findings,
                requirements=requirements,
                evidence_relpath=evidence_rel,
                source="finalize",
                report_language=report_lang.code if report_lang else None,
                session_number=session_number,
            )
        else:
            session_number = None

        # Optional MLflow side channel (no-op when MLFLOW_ENABLED=false).
        mlflow_run_id = str(
            state.get("evidence_run_id") or (store.run_id if store else "") or ""
        )
        log_mlflow_finalize_safe(
            self.settings,
            run_id=mlflow_run_id,
            framework_id=fw or "framework",
            findings=findings or None,
            client_name=str(state.get("client_name") or ""),
            evidence_host_id=str(state.get("evidence_host_id") or ""),
            retry_count=retries,
            session_number=session_number,
            report_path=report_for_mlflow,
        )

        header = (
            f"Framework: `{fw}` | session reconnects: {retries}{evidence_note}\n\n"
        )
        client = state.get("client_name") or ""
        if client:
            header = f"Client: **{client}** | {header}"
        preamble_parts: list[str] = []
        if state.get("host_facts_md"):
            preamble_parts.append(str(state.get("host_facts_md")))
        preamble = ("\n".join(preamble_parts) + "\n\n---\n\n") if preamble_parts else ""
        # Full report stays on disk; chat gets management summary + archive only.
        disk_report = f"{header}{preamble}{summary}\n\n---\n\n{full_report}"
        if self.settings.compliance_charts_in_report:
            try:
                disk_report = (
                    f"{disk_report.rstrip()}\n"
                    f"{format_compliance_markdown(full_report, language=report_lang)}"
                )
            except Exception:  # noqa: BLE001
                pass

        chat_text = (
            f"{header}"
            f"## Management summary\n\n{summary.strip()}\n"
        )

        archive_path = ""
        archive_url = ""
        # Multi-framework runs package once in ``_merge_multi_reports``.
        run_id = state.get("evidence_run_id") or (store.run_id if store else "")
        in_multi = any(
            (sess.get("run_id") == run_id) for sess in self._multi_sessions.values()
        )
        if store is not None and self.settings.archive_enabled and not in_multi:
            try:
                store.write_root_report(disk_report)
                packaged = await package_and_publish_archive(
                    store.root, self.settings
                )
                archive_path = str(packaged.get("zip_path") or "")
                archive_url = str(packaged.get("download_url") or "")
                chat_text = (
                    f"{chat_text.rstrip()}\n{packaged.get('chat_section') or ''}"
                )
            except Exception as exc:  # noqa: BLE001
                chat_text = (
                    f"{chat_text.rstrip()}\n\n---\n\n"
                    f"(Archive packaging failed: {type(exc).__name__}: {exc})\n"
                )
        elif store is not None and not in_multi:
            store.write_root_report(disk_report)

        if not in_multi and mlflow_run_id:
            end_mlflow_run_safe(
                self.settings,
                run_id=mlflow_run_id,
                client_name=str(state.get("client_name") or ""),
                archive_path=archive_path or None,
            )

        chat_text = f"{chat_text.rstrip()}{followup_footer()}"

        return {
            "report": chat_text,
            "evidence_run_id": state.get("evidence_run_id") or "",
            "evidence_run_dir": state.get("evidence_run_dir") or (
                str(store.root) if store else ""
            ),
            "archive_path": archive_path,
            "archive_url": archive_url,
            "pending_ids": [],
            "awaiting_hitl": False,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                AIMessage(content=chat_text),
            ],
        }

    def _decorate_result(
        self,
        result: dict[str, Any],
        *,
        thread_id: str,
        store: EvidenceStore | None,
        intake: bool = False,
    ) -> dict[str, Any]:
        """Attach HITL/intake pause messaging when the graph returned ``__interrupt__``."""
        result = dict(result)
        result.setdefault("evidence_run_id", store.run_id if store else "")
        result.setdefault("evidence_run_dir", str(store.root) if store else "")
        result["thread_id"] = thread_id

        interrupts = result.get("__interrupt__") or []
        if not interrupts:
            result["awaiting_hitl"] = False
            return result

        first = interrupts[0]
        value = getattr(first, "value", first)
        prompt = interrupt_payload_to_prompt(value)
        is_intake = intake or (
            isinstance(value, dict) and str(value.get("type") or "") == "intake"
        )
        if is_intake:
            msg = format_intake_assistant_message(prompt, thread_id)
        else:
            msg = format_hitl_assistant_message(prompt, thread_id)
        result["report"] = msg
        result["awaiting_hitl"] = True
        result["awaiting_intake"] = is_intake
        result["messages"] = [AIMessage(content=msg)]
        return result

    async def arun_intake(
        self,
        user_text: str,
        *,
        run_id: str,
        thread_id: str,
        store: EvidenceStore,
    ) -> dict[str, Any]:
        """Run the intake questionnaire graph (may interrupt)."""
        report_lang = detect_report_language(user_text)
        initial: AuditorState = {
            "messages": [HumanMessage(content=user_text)],
            "user_request": truncate_text(
                user_text,
                self.settings.max_user_request_chars,
                "user_request",
            ),
            "report_language": report_lang.code,
            "evidence_run_id": store.run_id,
            "evidence_run_dir": str(store.root),
            "intake_complete": False,
            "intake": {},
            "thread_id": thread_id,
        }
        config = {"configurable": {"thread_id": thread_id}}
        result = await self.intake_graph.ainvoke(initial, config)
        return self._decorate_result(result, thread_id=thread_id, store=store, intake=True)

    async def arun_one(
        self,
        user_text: str,
        *,
        framework_id: str | None = None,
        run_id: str | None = None,
        thread_id: str | None = None,
        intake_state: dict[str, Any] | None = None,
        evidence_host_id: str | None = None,
        ssh_target: InventorySshTarget | None = None,
    ) -> dict[str, Any]:
        """Run a single-framework audit graph (optionally pinned)."""
        rid = run_id or new_run_id()
        tid = thread_id or f"audit-{uuid.uuid4().hex[:12]}"
        store = self._evidence_by_run.get(rid)
        if store is None:
            store = EvidenceStore(self.settings.evidence_dir, run_id=rid)
            self._evidence_by_run[store.run_id] = store
        if evidence_host_id:
            store.host_segment = evidence_host_id
        meta: dict[str, Any] = {
            "user_request": truncate_text(
                user_text,
                self.settings.max_user_request_chars,
                "user_request",
            ),
            "thread_id": tid,
        }
        if framework_id:
            meta["framework_id"] = framework_id
        if evidence_host_id:
            meta["evidence_host_id"] = evidence_host_id
        report_lang = detect_report_language(user_text)
        meta["report_language"] = report_lang.code
        if intake_state:
            meta["intake"] = intake_state.get("intake") or intake_state
            meta["client_name"] = intake_state.get("client_name")
            meta["audit_types"] = intake_state.get("audit_types")
            if intake_state.get("results_session_number") is not None:
                meta["results_session_number"] = intake_state[
                    "results_session_number"
                ]
        store.write_run_meta(**meta)
        ensure_mlflow_run_safe(
            self.settings,
            run_id=store.run_id,
            client_name=str((intake_state or {}).get("client_name") or ""),
            params={
                "model": self.settings.litellm_model,
                "framework_id": framework_id or "",
                "client_name": str((intake_state or {}).get("client_name") or ""),
                "hitl_enabled": self.settings.hitl_enabled,
            },
            tags={
                "auditor.thread_id": tid,
                "auditor.framework_id": framework_id or "",
            },
        )
        initial: AuditorState = {
            "messages": [HumanMessage(content=user_text)],
            "user_request": truncate_text(
                user_text,
                self.settings.max_user_request_chars,
                "user_request",
            ),
            "report_language": report_lang.code,
            "retry_count": 0,
            "evidence_run_id": store.run_id,
            "evidence_run_dir": str(store.root),
            "hitl_skipped": [],
            "awaiting_hitl": False,
            "intake_complete": True,
            "thread_id": tid,
        }
        if intake_state:
            initial.update(
                {
                    "intake": dict(intake_state.get("intake") or intake_state),
                    "client_name": str(intake_state.get("client_name") or ""),
                    "has_cmdb": bool(intake_state.get("has_cmdb")),
                    "has_access": bool(intake_state.get("has_access")),
                    "audit_types": str(intake_state.get("audit_types") or ""),
                }
            )
            if intake_state.get("results_session_number") is not None:
                initial["results_session_number"] = int(
                    intake_state["results_session_number"]
                )
        if framework_id:
            initial["framework_id"] = framework_id
        if evidence_host_id:
            initial["evidence_host_id"] = evidence_host_id
        config = {"configurable": {"thread_id": tid}}

        async def _invoke() -> dict[str, Any]:
            """Run the main graph and decorate with HITL/intake messaging."""
            result = await self.graph.ainvoke(initial, config)
            return self._decorate_result(result, thread_id=tid, store=store)

        intake_for_scope = (
            (intake_state.get("intake") if intake_state else None)
            or intake_state
            or {}
        )
        if not isinstance(intake_for_scope, dict):
            intake_for_scope = {}
        with self._target_scope(intake=intake_for_scope, ssh_target=ssh_target):
            with bind_host_segment(evidence_host_id):
                return await _invoke()

    async def aresume(self, thread_id: str, user_text: str) -> dict[str, Any]:
        """Resume a graph paused on intake or ``human_gate``."""
        config = {"configurable": {"thread_id": thread_id}}
        is_intake = ":intake" in thread_id or thread_id.endswith("intake")
        graph = self.intake_graph if is_intake else self.graph
        try:
            pre = await graph.aget_state(config)
            pre_values = pre.values or {}
        except Exception:  # noqa: BLE001
            pre_values = {}
        slug = self._client_slug_from_values(pre_values)
        with self._target_scope(client_slug=slug, intake=pre_values.get("intake") if isinstance(pre_values.get("intake"), dict) else None):
            result = await graph.ainvoke(Command(resume=user_text), config)
        snap = await graph.aget_state(config)
        values = snap.values or {}
        run_id = values.get("evidence_run_id") or ""
        store = self._evidence_by_run.get(run_id)
        if store is None and values.get("evidence_run_dir"):
            store = EvidenceStore(
                self.settings.evidence_dir,
                run_id=run_id or Path(str(values["evidence_run_dir"])).name,
            )
            self._evidence_by_run[store.run_id] = store
        decorated = self._decorate_result(
            result, thread_id=thread_id, store=store, intake=is_intake
        )
        if decorated.get("awaiting_hitl"):
            return decorated

        if is_intake and values.get("intake_complete"):
            # Continue into framework audits using intake answers.
            session = self._forget_multi_session(thread_id) or {}
            user_req = session.get("user_text") or values.get("user_request") or user_text
            base_thread = session.get("base_thread") or thread_id.replace(":intake", "")
            run_id = (
                values.get("evidence_run_id")
                or session.get("run_id")
                or run_id
            )
            intake = values.get("intake") or {}
            return await self._start_frameworks_after_intake(
                user_text=str(user_req),
                base_thread=base_thread,
                run_id=str(run_id),
                intake=intake if isinstance(intake, dict) else {},
            )

        # If this thread was part of a multi-framework run, continue the queue.
        return await self._continue_multi_after_resume(thread_id, decorated)

    async def acontinue(self, thread_id: str, *, run_id: str | None = None) -> dict[str, Any]:
        """Resume an interrupted mid-assess (or HITL) run after disconnect/restart."""
        emit_phase(f"Continuing audit from checkpoint (`{thread_id}`)…")
        config = {"configurable": {"thread_id": thread_id}}
        is_intake = ":intake" in thread_id or thread_id.endswith("intake")
        graph = self.intake_graph if is_intake else self.graph

        rid = run_id or ""
        if not rid:
            found = find_interrupted_run(self.settings.evidence_dir)
            if found:
                rid, meta = found
                if not thread_id:
                    thread_id = str(meta.get("continue_thread_id") or thread_id)
            else:
                # Fall back to thread meta on any run folder
                rid = ""

        if rid:
            self._reload_multi_sessions(rid)
            store = self._evidence_by_run.get(rid)
            if store is None:
                try:
                    store = EvidenceStore.open_existing(self.settings.evidence_dir, rid)
                    self._evidence_by_run[rid] = store
                except Exception:  # noqa: BLE001
                    store = None
        else:
            store = None

        # Prefer LangGraph checkpoint if the graph still has work / interrupt.
        try:
            snap = await graph.aget_state(config)
        except Exception:  # noqa: BLE001
            snap = None

        if snap is not None and (snap.next or (snap.tasks and any(
            getattr(t, "interrupts", None) for t in (snap.tasks or [])
        ))):
            # Pending interrupt → treat as resume with continue/skip-all friendly text
            interrupts = []
            for task in snap.tasks or []:
                interrupts.extend(list(getattr(task, "interrupts", None) or []))
            if interrupts:
                return await self.aresume(thread_id, "continue")
            slug = self._client_slug_from_values(snap.values or {})
            with self._target_scope(
                client_slug=slug,
                intake=(snap.values or {}).get("intake")
                if isinstance((snap.values or {}).get("intake"), dict)
                else None,
            ):
                result = await graph.ainvoke(None, config)
            values = (await graph.aget_state(config)).values or {}
            run_id2 = values.get("evidence_run_id") or rid
            if store is None and run_id2:
                try:
                    store = EvidenceStore.open_existing(
                        self.settings.evidence_dir, str(run_id2)
                    )
                    self._evidence_by_run[store.run_id] = store
                except Exception:  # noqa: BLE001
                    pass
            decorated = self._decorate_result(
                result, thread_id=thread_id, store=store, intake=is_intake
            )
            if decorated.get("awaiting_hitl"):
                return decorated
            if rid:
                write_run_status(
                    self.settings.evidence_dir, str(run_id2 or rid), status="running"
                )
            return await self._continue_multi_after_resume(thread_id, decorated)

        # Evidence fallback: rebuild pending_ids from disk and re-enter assess.
        if not rid:
            return {
                "report": (
                    "No interrupted audit checkpoint found. "
                    "Start a new audit or reply from a message that still has "
                    "`[AUDIT_CONTINUE:…]` / `[AUDIT_HITL:…]`."
                ),
                "awaiting_hitl": False,
                "messages": [],
            }

        assert store is not None or rid
        if store is None:
            store = EvidenceStore.open_existing(self.settings.evidence_dir, rid)
            self._evidence_by_run[rid] = store

        meta = store.read_run_meta()
        framework_id = str(
            meta.get("framework_id")
            or (thread_id.split(":")[-1] if ":" in thread_id else "")
        )
        host_id = str(meta.get("evidence_host_id") or "")
        if host_id:
            store.host_segment = host_id
        # Resolve framework folder under host if needed
        fw_key = f"{host_id}/{framework_id}" if host_id else framework_id
        disk_findings = store.load_findings(fw_key)
        if not disk_findings and framework_id:
            disk_findings = store.load_findings(framework_id)

        from auditor.checklist import load_checklist
        from auditor.frameworks import get_framework

        fw = get_framework(framework_id, self.settings.agents_dir)
        if fw is None:
            return {
                "report": f"Cannot continue: framework `{framework_id}` not found.",
                "awaiting_hitl": False,
            }
        checklist = load_checklist(fw.path)
        done = set(disk_findings.keys())
        pending = [rid_ for rid_ in checklist.ids() if rid_ not in done]
        meta_pending = meta.get("pending_ids")
        if isinstance(meta_pending, list) and meta_pending:
            pending = [str(x) for x in meta_pending if str(x) not in done]

        findings_objs: dict[str, Finding] = {}
        for req_id, raw in disk_findings.items():
            try:
                findings_objs[req_id] = Finding.model_validate(raw)
            except Exception:  # noqa: BLE001
                continue

        write_run_status(
            self.settings.evidence_dir,
            rid,
            status="running",
            thread_id=thread_id,
            pending_ids=pending,
            framework_id=framework_id,
        )

        continue_intake = meta.get("intake") if isinstance(meta.get("intake"), dict) else None
        continue_slug = str(
            meta.get("client_slug")
            or ((continue_intake or {}).get("client_slug") if continue_intake else "")
            or ""
        ).strip() or None

        if not pending:
            # All REQs done — finalize via graph update + finalize node path
            await graph.aupdate_state(
                config,
                {
                    "findings": findings_objs,
                    "pending_ids": [],
                    "requirements": {r.id: r for r in checklist.requirements},
                    "framework_id": framework_id,
                    "framework_title": fw.title,
                    "checklist_title": checklist.title,
                    "evidence_run_id": rid,
                    "evidence_run_dir": str(store.root),
                    "evidence_host_id": host_id,
                    "thread_id": thread_id,
                    "user_request": str(meta.get("user_request") or "continue"),
                    "intake_complete": True,
                    "awaiting_hitl": False,
                },
                as_node="assess_parallel",
            )
            with self._target_scope(client_slug=continue_slug, intake=continue_intake):
                result = await graph.ainvoke(None, config)
            decorated = self._decorate_result(
                result, thread_id=thread_id, store=store
            )
            return await self._continue_multi_after_resume(thread_id, decorated)

        await graph.aupdate_state(
            config,
            {
                "findings": findings_objs,
                "pending_ids": pending,
                "requirements": {r.id: r for r in checklist.requirements},
                "framework_id": framework_id,
                "framework_title": fw.title,
                "checklist_title": checklist.title,
                "evidence_run_id": rid,
                "evidence_run_dir": str(store.root),
                "evidence_host_id": host_id,
                "thread_id": thread_id,
                "user_request": str(meta.get("user_request") or "continue"),
                "intake_complete": True,
                "awaiting_hitl": False,
                "retry_count": 0,
                "hitl_skipped": list(meta.get("hitl_skipped") or []),
            },
            as_node="load_framework",
        )
        with self._target_scope(client_slug=continue_slug, intake=continue_intake):
            result = await graph.ainvoke(None, config)
        decorated = self._decorate_result(result, thread_id=thread_id, store=store)
        if decorated.get("awaiting_hitl"):
            return decorated
        write_run_status(self.settings.evidence_dir, rid, status="completed")
        return await self._continue_multi_after_resume(thread_id, decorated)

    def interrupted_continue_message(self, thread_id: str, run_id: str) -> str:
        """Build operator-facing interrupt message with continue marker."""
        session_note = ""
        try:
            store = EvidenceStore.open_existing(self.settings.evidence_dir, run_id)
            meta = store.read_run_meta()
            sess = meta.get("results_session_number")
            client = meta.get("client_name") or run_id
            if sess is not None:
                session_note = (
                    f"\nResults warehouse session **#{sess}** "
                    f"(client `{client}`).\n"
                    "Ask *which sessions need continue?* to list interrupted audits.\n"
                )
        except Exception:  # noqa: BLE001
            session_note = ""
        return format_continue_assistant_message(
            (
                "## Audit interrupted\n\n"
                f"Run `{run_id}` stopped before all requirements finished.\n"
                f"{session_note}"
                "Reply **continue** (or **продолжи**) to resume from the last checkpoint."
            ),
            thread_id,
        )

    async def alist_sessions(
        self,
        user_text: str = "",
        *,
        interrupted_only: bool = False,
    ) -> dict[str, Any]:
        """Answer which warehouse sessions exist / need continue."""
        from auditor.results_store import list_sessions_report

        client = None
        # Optional "for Acme" / "для Acme"
        m = re.search(
            r"\b(?:for|для)\s+([A-Za-z0-9][A-Za-z0-9 _.-]{1,80})",
            user_text or "",
            re.I,
        )
        if m:
            client = m.group(1).strip().rstrip("?.!,")
        text = await list_sessions_report(
            self.settings,
            client_name=client,
            interrupted_only=interrupted_only
            or bool(
                re.search(
                    r"interrupt|need\s+continue|прерв|продолж|resume",
                    user_text or "",
                    re.I,
                )
            ),
        )
        return {
            "report": text,
            "messages": [AIMessage(content=text)],
            "awaiting_hitl": False,
        }

    async def alist_results(self, user_text: str = "") -> dict[str, Any]:
        """Show warehouse REQ cells for a client session (``/list-results``)."""
        from auditor.results_store import list_results_report, parse_list_results_request

        client, session_num = parse_list_results_request(user_text or "")
        text = await list_results_report(
            self.settings,
            client_name=client,
            session_number=session_num,
        )
        return {
            "report": text,
            "messages": [AIMessage(content=text)],
            "awaiting_hitl": False,
        }

    async def alist_status(self, user_text: str = "") -> dict[str, Any]:
        """Show host progress table for a session (``/list-status``)."""
        from auditor.results_store import list_status_report, parse_list_status_request

        client, session_num = parse_list_status_request(user_text or "")
        text = await list_status_report(
            self.settings,
            client_name=client,
            session_number=session_num,
        )
        return {
            "report": text,
            "messages": [AIMessage(content=text)],
            "awaiting_hitl": False,
        }

    async def alist_host(self, user_text: str = "") -> dict[str, Any]:
        """Show REQ cells for one host+framework (``/list-host``)."""
        from auditor.results_store import list_host_report, parse_list_host_request

        hostname, framework_id, client = parse_list_host_request(user_text or "")
        text = await list_host_report(
            self.settings,
            hostname=hostname,
            framework_id=framework_id,
            client_name=client,
        )
        return {
            "report": text,
            "messages": [AIMessage(content=text)],
            "awaiting_hitl": False,
        }

    async def _llm_route_frameworks_from_software(
        self,
        facts: HostFacts,
    ) -> dict[str, Any]:
        """Ask the LLM which agents/ frameworks match collected software signals.

        Args:
            facts: Host facts including binaries/packages from LLM discovery.

        Returns:
            Dict with ``framework_ids``, ``highlight_packages``,
            ``highlight_binaries``, ``notes`` (empty lists on failure).
        """
        known = {fw.id for fw in list_frameworks(self.settings.agents_dir)}
        pkg_lines = "\n".join(f"PKG:{p}" for p in (facts.packages or []))
        bin_lines = "\n".join(f"BIN:{b}" for b in (facts.binaries or []))
        file_lines = "\n".join(f"FILE:{f}" for f in (facts.key_files or []))
        inventory = "\n".join(
            x for x in (bin_lines, file_lines, pkg_lines) if x
        ) or "(empty inventory)"
        # Keep routing prompt small — full dumps belong on disk, not in the LLM.
        inventory = truncate_text(
            inventory,
            min(self.settings.max_tool_output_chars * 4, 24_000),
            "software_inventory",
        )
        os_line = (
            facts.os_pretty_name
            or f"{facts.os_id} {facts.os_version_id}".strip()
            or "unknown"
        )
        messages = [
            SystemMessage(content=SOFTWARE_FRAMEWORK_ROUTE_SYSTEM),
            HumanMessage(
                content=SOFTWARE_FRAMEWORK_ROUTE_PROMPT.format(
                    ssh_host=facts.ssh_host or "(unknown)",
                    os_line=os_line,
                    framework_catalog=frameworks_detect_catalog_text(
                        self.settings.agents_dir
                    ),
                    software_inventory=inventory,
                )
            ),
        ]
        try:
            response = await self.fill_model.ainvoke(messages)
            payload = _extract_json(str(response.content or "")) or {}
        except Exception as exc:  # noqa: BLE001
            return {
                "framework_ids": [],
                "highlight_packages": [],
                "highlight_binaries": [],
                "notes": f"LLM software routing failed: {type(exc).__name__}: {exc}",
            }
        ids = [
            str(x).strip()
            for x in (payload.get("framework_ids") or [])
            if str(x).strip() in known
        ]
        highlights = [
            str(x).strip()
            for x in (payload.get("highlight_packages") or [])
            if str(x).strip()
        ][:40]
        hl_bins = [
            str(x).strip()
            for x in (payload.get("highlight_binaries") or [])
            if str(x).strip()
        ][:40]
        return {
            "framework_ids": ids,
            "highlight_packages": highlights,
            "highlight_binaries": hl_bins,
            "notes": str(payload.get("notes") or "").strip()[:500],
        }

    async def _discover_inventory_hosts(
        self,
        *,
        intake: dict[str, Any],
        store: EvidenceStore,
    ) -> list[tuple[InventorySshTarget, HostFacts]]:
        """SSH-discover every inventory host for inventory-only flow."""
        slug = str(intake.get("client_slug") or client_slug(str(intake.get("client_name") or "")))
        targets = list_client_ssh_targets(self.settings.inventory_dir, slug)
        effective = effective_settings(self.settings)
        if not targets and effective.ssh_host:
            targets = [
                InventorySshTarget(
                    host=effective.ssh_host,
                    port=str(effective.ssh_port or 22),
                    user=effective.ssh_user or "",
                    password=effective.ssh_password or "",
                    private_key_path=effective.ssh_private_key_path or "",
                )
            ]
        discovered: list[tuple[InventorySshTarget, HostFacts]] = []
        for target in targets:
            with self._target_scope(client_slug=slug, ssh_target=target, intake=intake):
                facts = await self._collect_host_facts(
                    store=store,
                    host_id=target.slug,
                    user_request=str(intake.get("client_name") or ""),
                )
                # Optional LLM routing hints from collected software signals.
                try:
                    route = await self._llm_route_frameworks_from_software(facts)
                except Exception as exc:  # noqa: BLE001
                    route = {
                        "framework_ids": [],
                        "highlight_packages": [],
                        "highlight_binaries": list(facts.binaries or [])[:20],
                        "notes": f"route_error: {type(exc).__name__}: {exc}",
                    }
                facts.raw["software_route"] = str(route)
                facts.raw["software_inventory_source"] = "llm"
            facts.ssh_host = target.host
            # Stash LLM routing on facts.raw for proposed_jobs builder.
            facts.raw["_llm_framework_ids"] = ",".join(
                route.get("framework_ids") or []
            )
            facts.raw["_llm_highlight_packages"] = "\n".join(
                route.get("highlight_packages") or []
            )
            facts.raw["_llm_highlight_binaries"] = "\n".join(
                route.get("highlight_binaries") or []
            )
            facts.raw["_llm_software_notes"] = str(route.get("notes") or "")
            host_base = store.host_root(target.slug)
            write_host_facts_json(host_base / "host_facts.json", facts, [])
            md = format_host_facts_markdown(facts, None, language="en")
            (host_base / "host_facts.md").write_text(md, encoding="utf-8")
            if facts.packages:
                (host_base / "packages_full.txt").write_text(
                    "\n".join(facts.packages) + "\n",
                    encoding="utf-8",
                )
            discovered.append((target, facts))
        return discovered

    def _jobs_from_selected_intake(
        self,
        *,
        intake: dict[str, Any],
        store: EvidenceStore,
        selected_rows: list[dict[str, Any]],
    ) -> list[tuple[InventorySshTarget, HostFacts, Any]]:
        """Rebuild (target, facts, framework) jobs from intake selected_jobs.

        Prefers host_facts.json written during stage-3 discovery so SSH is not
        repeated. Falls back to empty facts when the artifact is missing.
        """
        slug = str(
            intake.get("client_slug")
            or client_slug(str(intake.get("client_name") or ""))
        )
        targets = list_client_ssh_targets(self.settings.inventory_dir, slug)
        if not targets and self.settings.ssh_host:
            targets = [
                InventorySshTarget(
                    host=self.settings.ssh_host,
                    port=str(self.settings.ssh_port or 22),
                    user=self.settings.ssh_user or "",
                    password=self.settings.ssh_password or "",
                    private_key_path=self.settings.ssh_private_key_path or "",
                )
            ]
        by_slug = {t.slug: t for t in targets}
        by_host = {t.host: t for t in targets}
        jobs: list[tuple[InventorySshTarget, HostFacts, Any]] = []
        for row in selected_rows:
            host_id = str(row.get("host_id") or "").strip()
            ssh_host = str(row.get("ssh_host") or "").strip()
            target = by_slug.get(host_id) or by_host.get(ssh_host)
            if target is None:
                continue
            facts_path = store.host_root(target.slug) / "host_facts.json"
            facts = HostFacts(ssh_host=target.host)
            if facts_path.is_file():
                try:
                    payload = json.loads(facts_path.read_text(encoding="utf-8"))
                    facts = parse_host_facts_json(
                        payload.get("facts") or {},
                        ssh_host=target.host,
                    )
                except Exception:  # noqa: BLE001
                    facts = HostFacts(ssh_host=target.host)
            for fw_id in row.get("frameworks") or []:
                fw = get_framework(str(fw_id), self.settings.agents_dir)
                if fw is not None:
                    jobs.append((target, facts, fw))
        return jobs

    def _format_host_framework_plan(
        self,
        jobs: list[tuple[InventorySshTarget, HostFacts, Any]],
    ) -> str:
        """Build markdown summary of host → framework routing plan.

        Args:
            jobs: List of ``(ssh_target, host_facts, framework)`` tuples.

        Returns:
            Markdown section listing each host and assigned frameworks.
        """
        lines = [
            "## Host → framework selection",
            "",
        ]
        if not jobs:
            lines.append(
                "_No hosts discovered — falling back to NLP framework routing._"
            )
            return "\n".join(lines)
        by_host: dict[str, list[str]] = {}
        labels: dict[str, str] = {}
        for target, facts, fw in jobs:
            key = target.slug
            labels[key] = (
                f"`{target.host}` "
                f"({facts.hostname or '—'}, {facts.os_id or 'os?'})"
            )
            by_host.setdefault(key, []).append(fw.id)
        for key, fws in by_host.items():
            lines.append(f"- {labels[key]} → {', '.join(f'`{x}`' for x in fws)}")
        lines.append("")
        return "\n".join(lines)

    async def _start_frameworks_after_intake(
        self,
        *,
        user_text: str,
        base_thread: str,
        run_id: str,
        intake: dict[str, Any],
    ) -> dict[str, Any]:
        """Discover hosts, select frameworks, and start sequential audit jobs.

        Allocates a results-warehouse session, builds host-driven or NLP-routed
        framework jobs, and delegates to ``_run_framework_jobs``.

        Args:
            user_text: Original operator request.
            base_thread: Parent LangGraph thread id.
            run_id: Shared evidence run id from intake.
            intake: Completed intake answers dict.

        Returns:
            Single-framework result or merged multi-framework report.
        """
        audit_type = str(intake.get("audit_types") or "both")
        domains = domains_for_audit_type(audit_type)
        has_access = bool(intake.get("has_access"))

        store = self._evidence_by_run.get(run_id)
        if store is None:
            store = EvidenceStore(self.settings.evidence_dir, run_id=run_id)
            self._evidence_by_run[run_id] = store

        intake_state = {
            "intake_complete": True,
            "intake": intake,
            "client_name": str(intake.get("client_name") or ""),
            "has_cmdb": bool(intake.get("has_cmdb")),
            "has_access": has_access,
            "audit_types": audit_type,
        }

        # New audit → allocate next results warehouse session_number (Postgres tracker).
        # Prefer the post-intake client folder name (after rebind_run_id), not the
        # temporary ``YYYYMMDD…`` id — continue must find evidence on disk.
        evidence_run = store.run_id or run_id
        session_info = await start_session_safe(
            self.settings,
            client_name=str(intake.get("client_name") or evidence_run),
            evidence_run_id=evidence_run,
            continue_thread_id=base_thread,
            evidence_path=str(store.root),
        )
        if session_info is not None:
            store.write_run_meta(
                results_session_number=session_info.session_number,
                results_session_id=session_info.id,
                status="running",
            )
            intake_state["results_session_number"] = session_info.session_number

        # Jobs: (ssh_target, facts, framework)
        jobs: list[tuple[InventorySshTarget, HostFacts, Any]] = []
        selected_rows = list(intake.get("selected_jobs") or [])
        if has_access and selected_rows:
            jobs = self._jobs_from_selected_intake(
                intake=intake, store=store, selected_rows=selected_rows
            )
        elif has_access:
            discovered = await self._discover_inventory_hosts(
                intake=intake, store=store
            )
            for target, facts in discovered:
                if facts.error:
                    # Still allow it_audit if domain includes IT
                    matched = []
                    if "it" in domains:
                        it_fw = get_framework("it_audit", self.settings.agents_dir)
                        if it_fw is not None:
                            matched = [it_fw]
                else:
                    matched = select_frameworks_for_host(
                        facts,
                        domains=domains,
                        agents_dir=self.settings.agents_dir,
                    )
                for fw in matched:
                    jobs.append((target, facts, fw))

        if not jobs:
            # Fallback: NLP routing without per-host discovery
            fw_ids = frameworks_for_audit_type(
                audit_type,  # type: ignore[arg-type]
                user_request=user_text,
                agents_dir=self.settings.agents_dir,
            )
            selected = []
            for fid in fw_ids:
                fw = get_framework(fid, self.settings.agents_dir)
                if fw is not None:
                    selected.append(fw)
            if not selected:
                selected = route_frameworks(user_text, self.settings.agents_dir)
            store.write_run_meta(
                frameworks=[fw.id for fw in selected],
                intake_complete=True,
                intake=intake,
                client_name=intake.get("client_name"),
                audit_types=audit_type,
                host_driven=False,
            )
            return await self._run_framework_jobs(
                user_text=user_text,
                base_thread=base_thread,
                run_id=run_id,
                intake_state=intake_state,
                jobs=[(None, None, fw) for fw in selected],
                plan_md="",
            )

        plan_md = self._format_host_framework_plan(jobs)
        store.write_run_meta(
            frameworks=[f"{t.slug}/{fw.id}" for t, _f, fw in jobs],
            intake_complete=True,
            intake=intake,
            client_name=intake.get("client_name"),
            audit_types=audit_type,
            host_driven=True,
            host_plan=plan_md,
        )
        return await self._run_framework_jobs(
            user_text=user_text,
            base_thread=base_thread,
            run_id=run_id,
            intake_state=intake_state,
            jobs=jobs,
            plan_md=plan_md,
        )

    @staticmethod
    def _host_lock_key_from_target(target: InventorySshTarget | None) -> str:
        """Return same-host lock key for an inventory SSH target."""
        if target is None:
            return "_none_"
        return target.slug or target.host or "_none_"

    @staticmethod
    def _host_lock_key_from_job(job: dict[str, Any]) -> str:
        """Return same-host lock key for a serialized job dict."""
        host = str(job.get("evidence_host_id") or "").strip()
        return host or "_none_"

    @staticmethod
    def _serialize_host_job(
        target: InventorySshTarget | None,
        fw: Any,
    ) -> dict[str, Any]:
        """Serialize one (host, framework) job for multi-session persistence."""
        return {
            "framework_id": fw.id,
            "framework_title": fw.title,
            "evidence_host_id": target.slug if target else "",
            "ssh_host": target.host if target else "",
            "ssh_port": target.port if target else "",
            "ssh_user": target.user if target else "",
            "ssh_password": target.password if target else "",
            "ssh_key": target.private_key_path if target else "",
            "ssh_strict": target.strict_host_key if target else "",
            "ssh_label": target.label if target else "",
            "transport": target.transport if target else "ssh",
            "winrm_transport": target.winrm_transport if target else "",
            "winrm_use_ssl": target.winrm_use_ssl if target else "",
            "winrm_verify_ssl": target.winrm_verify_ssl if target else "",
        }

    @staticmethod
    def _job_dict_key(job: dict[str, Any]) -> str:
        """Stable key for a serialized host/framework job."""
        host = str(job.get("evidence_host_id") or "").strip()
        fw = str(job.get("framework_id") or "")
        return f"{host}/{fw}" if host else fw

    @staticmethod
    def _job_dict_thread_id(base_thread: str, job: dict[str, Any]) -> str:
        """Derive LangGraph thread id for a serialized job."""
        host = str(job.get("evidence_host_id") or "").strip()
        fw = str(job.get("framework_id") or "")
        return f"{base_thread}:{host}:{fw}" if host else f"{base_thread}:{fw}"

    @staticmethod
    def _target_from_job_dict(job: dict[str, Any]) -> InventorySshTarget | None:
        """Rebuild ``InventorySshTarget`` from a serialized multi-session job."""
        host = str(job.get("ssh_host") or "").strip()
        if not host:
            return None
        return InventorySshTarget(
            host=host,
            port=str(job.get("ssh_port") or "22"),
            user=str(job.get("ssh_user") or ""),
            password=str(job.get("ssh_password") or ""),
            private_key_path=str(job.get("ssh_key") or ""),
            strict_host_key=str(job.get("ssh_strict") or ""),
            label=str(job.get("ssh_label") or ""),
            transport=str(job.get("transport") or "ssh"),
            winrm_transport=str(job.get("winrm_transport") or "ntlm"),
            winrm_use_ssl=str(job.get("winrm_use_ssl") or ""),
            winrm_verify_ssl=str(job.get("winrm_verify_ssl") or ""),
        )

    @staticmethod
    def _job_display_title(job: dict[str, Any]) -> str:
        """Human-readable title for progress / merge sections."""
        host = str(job.get("ssh_host") or job.get("evidence_host_id") or "").strip()
        title = str(job.get("framework_title") or job.get("framework_id") or "")
        return f"{host} — {title}" if host else title

    async def _run_framework_jobs(
        self,
        *,
        user_text: str,
        base_thread: str,
        run_id: str,
        intake_state: dict[str, Any],
        jobs: list[tuple[InventorySshTarget | None, HostFacts | None, Any]],
        plan_md: str,
    ) -> dict[str, Any]:
        """Run (host, framework) audits with bounded cross-host parallelism."""
        if not jobs:
            return {
                "report": "No frameworks selected.",
                "messages": [AIMessage(content="No frameworks selected.")],
                "awaiting_hitl": False,
            }

        pending = [self._serialize_host_job(target, fw) for target, _facts, fw in jobs]
        if len(pending) == 1:
            result = await self._schedule_framework_jobs(
                user_text=user_text,
                base_thread=base_thread,
                run_id=run_id,
                intake_state=intake_state,
                pending_jobs=pending,
                completed=[],
                plan_md=plan_md,
            )
            if plan_md and result.get("report"):
                report = str(result.get("report") or "")
                if not report.startswith(plan_md):
                    result["report"] = f"{plan_md}\n{report}"
            return result

        return await self._schedule_framework_jobs(
            user_text=user_text,
            base_thread=base_thread,
            run_id=run_id,
            intake_state=intake_state,
            pending_jobs=pending,
            completed=[],
            plan_md=plan_md,
        )

    async def _schedule_framework_jobs(
        self,
        *,
        user_text: str,
        base_thread: str,
        run_id: str,
        intake_state: dict[str, Any] | None,
        pending_jobs: list[dict[str, Any]],
        completed: list[tuple[str, str, str]],
        plan_md: str,
    ) -> dict[str, Any]:
        """Run pending host/framework jobs with host-exclusive concurrency.

        Up to ``max_parallel_host_jobs`` graphs run at once, but at most one job
        per host slug. On HITL, new starts stop; in-flight jobs drain; the first
        paused job is returned with remaining work recorded for resume.
        """
        pending = list(pending_jobs)
        if not pending:
            merged = await self._merge_multi_reports(
                completed,
                run_id=run_id,
                base_thread=base_thread,
            )
            if plan_md:
                merged["report"] = f"{plan_md}\n{merged.get('report') or ''}"
            return merged

        limit = max(1, int(self.settings.max_parallel_host_jobs))
        completed_list = list(completed)
        stop_starting = False
        in_flight: dict[asyncio.Task[dict[str, Any]], dict[str, Any]] = {}
        busy_hosts: set[str] = set()
        hitl_paused: list[dict[str, Any]] = []

        def _session_payload(
            job: dict[str, Any],
            *,
            remaining: list[dict[str, Any]],
            siblings: list[dict[str, Any]] | None = None,
            hitl_report: str = "",
        ) -> dict[str, Any]:
            """Build multi-session orchestration state for one job thread."""
            return {
                "base_thread": base_thread,
                "run_id": run_id,
                "user_text": user_text,
                "framework_id": str(job.get("framework_id") or ""),
                "framework_title": str(
                    job.get("framework_title") or job.get("framework_id") or ""
                ),
                "job_key": self._job_dict_key(job),
                "evidence_host_id": str(job.get("evidence_host_id") or ""),
                "ssh_target": self._target_from_job_dict(job),
                "remaining_jobs": list(remaining),
                "remaining": [
                    str(j.get("framework_id") or "") for j in remaining
                ],
                "completed": list(completed_list),
                "intake_state": intake_state,
                "plan_md": plan_md,
                "paused_siblings": list(siblings or []),
                "hitl_report": hitl_report,
                "parallel_scheduler": True,
            }

        async def _run_one(job: dict[str, Any]) -> dict[str, Any]:
            """Invoke a single host/framework audit for the scheduler."""
            fw_id = str(job.get("framework_id") or "")
            host_id = str(job.get("evidence_host_id") or "")
            tid = self._job_dict_thread_id(base_thread, job)
            return await self.arun_one(
                user_text,
                framework_id=fw_id,
                run_id=run_id,
                thread_id=tid,
                intake_state=intake_state,
                evidence_host_id=host_id or None,
                ssh_target=self._target_from_job_dict(job),
            )

        while pending or in_flight:
            while (
                not stop_starting
                and len(in_flight) < limit
                and pending
            ):
                started = False
                for index, job in enumerate(pending):
                    host_key = self._host_lock_key_from_job(job)
                    if host_key in busy_hosts:
                        continue
                    pending.pop(index)
                    tid = self._job_dict_thread_id(base_thread, job)
                    self._remember_multi_session(
                        tid,
                        _session_payload(job, remaining=list(pending)),
                    )
                    task = asyncio.create_task(
                        _run_one(job),
                        name=f"host-job:{self._job_dict_key(job)}",
                    )
                    in_flight[task] = {
                        "job": job,
                        "thread_id": tid,
                        "host_key": host_key,
                    }
                    busy_hosts.add(host_key)
                    started = True
                    break
                if not started:
                    break

            if not in_flight:
                break

            done, _ = await asyncio.wait(
                set(in_flight.keys()),
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                meta = in_flight.pop(task)
                busy_hosts.discard(str(meta["host_key"]))
                job = meta["job"]
                tid = str(meta["thread_id"])
                key = self._job_dict_key(job)
                try:
                    result = task.result()
                except Exception as exc:  # noqa: BLE001
                    result = {
                        "report": (
                            f"Host/framework job `{key}` failed: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                        "awaiting_hitl": False,
                        "thread_id": tid,
                        "messages": [
                            AIMessage(
                                content=(
                                    f"Host/framework job `{key}` failed: "
                                    f"{type(exc).__name__}: {exc}"
                                )
                            )
                        ],
                    }

                if result.get("awaiting_hitl"):
                    stop_starting = True
                    hitl_paused.append(
                        {
                            "job": job,
                            "thread_id": tid,
                            "result": result,
                            "job_key": key,
                        }
                    )
                    continue

                self._forget_multi_session(tid)
                completed_list.append(
                    (key, self._job_display_title(job), result.get("report") or "")
                )

        if hitl_paused:
            siblings = [
                {
                    "thread_id": item["thread_id"],
                    "job_key": item["job_key"],
                    "framework_id": str(item["job"].get("framework_id") or ""),
                    "framework_title": str(
                        item["job"].get("framework_title")
                        or item["job"].get("framework_id")
                        or ""
                    ),
                    "evidence_host_id": str(
                        item["job"].get("evidence_host_id") or ""
                    ),
                }
                for item in hitl_paused
            ]
            for item in hitl_paused:
                others = [
                    s
                    for s in siblings
                    if s["thread_id"] != item["thread_id"]
                ]
                report = str(item["result"].get("report") or "")
                self._remember_multi_session(
                    str(item["thread_id"]),
                    _session_payload(
                        item["job"],
                        remaining=list(pending),
                        siblings=others,
                        hitl_report=report,
                    ),
                )
            primary = hitl_paused[0]
            prefix = self._multi_progress_preamble(
                completed_list,
                str(primary["job_key"]),
                in_flight_keys=[
                    str(p["job_key"]) for p in hitl_paused[1:]
                ],
                queued_keys=[self._job_dict_key(j) for j in pending],
            )
            preamble = f"{plan_md}\n{prefix}" if plan_md else prefix
            result = dict(primary["result"])
            body = str(result.get("report") or "")
            report = f"{preamble}{body}" if preamble else body
            result["report"] = report
            result["awaiting_hitl"] = True
            result["thread_id"] = primary["thread_id"]
            result["messages"] = [AIMessage(content=report)]
            return result

        merged = await self._merge_multi_reports(
            completed_list,
            run_id=run_id,
            base_thread=base_thread,
        )
        if plan_md:
            merged["report"] = f"{plan_md}\n{merged.get('report') or ''}"
        return merged

    async def _continue_multi_after_resume(
        self,
        thread_id: str,
        finished: dict[str, Any],
    ) -> dict[str, Any]:
        """Advance a multi-framework queue after one graph thread finishes.

        Pops session state for ``thread_id``, records the completed report,
        surfaces any sibling HITL pauses, then schedules remaining jobs.

        Args:
            thread_id: LangGraph thread that just completed or paused.
            finished: Result dict from the completed invocation.

        Returns:
            Next job result, merged multi-report, or ``finished`` unchanged.
        """
        session = self._forget_multi_session(thread_id)
        if not session:
            return finished

        completed: list[tuple[str, str, str]] = list(session.get("completed") or [])
        job_key = session.get("job_key") or session.get("framework_id") or ""
        fw_title = session.get("framework_title") or job_key
        host_id = session.get("evidence_host_id") or ""
        title = f"{host_id} — {fw_title}" if host_id else fw_title
        completed.append((job_key, title, finished.get("report") or ""))

        remaining_jobs: list[dict[str, Any]] = list(session.get("remaining_jobs") or [])
        remaining: list[str] = list(session.get("remaining") or [])
        user_text = session.get("user_text") or ""
        run_id = session.get("run_id") or finished.get("evidence_run_id")
        base_thread = session.get("base_thread") or thread_id.split(":")[0]
        plan_md = session.get("plan_md") or ""
        intake_state = session.get("intake_state")

        # Surface other HITL-paused siblings before starting new work.
        paused_siblings = [
            s
            for s in list(session.get("paused_siblings") or [])
            if isinstance(s, dict)
            and str(s.get("thread_id") or "") in self._multi_sessions
        ]
        if paused_siblings:
            for sib in paused_siblings:
                sib_tid = str(sib.get("thread_id") or "")
                sib_sess = self._multi_sessions.get(sib_tid)
                if not sib_sess:
                    continue
                others = [
                    s
                    for s in paused_siblings
                    if str(s.get("thread_id") or "") != sib_tid
                ]
                sib_sess = dict(sib_sess)
                sib_sess["completed"] = list(completed)
                sib_sess["remaining_jobs"] = list(remaining_jobs)
                sib_sess["remaining"] = [
                    str(j.get("framework_id") or "") for j in remaining_jobs
                ]
                sib_sess["paused_siblings"] = others
                self._remember_multi_session(sib_tid, sib_sess)

            nxt = paused_siblings[0]
            nxt_tid = str(nxt.get("thread_id") or "")
            nxt_key = str(nxt.get("job_key") or nxt.get("framework_id") or "")
            sib_sess = self._multi_sessions.get(nxt_tid) or {}
            body = str(sib_sess.get("hitl_report") or "")
            if not body:
                body = (
                    f"Continue human review for `{nxt_key}` "
                    f"(thread `{nxt_tid}`)."
                )
            prefix = self._multi_progress_preamble(
                completed,
                nxt_key,
                in_flight_keys=[
                    str(s.get("job_key") or "")
                    for s in paused_siblings[1:]
                ],
                queued_keys=[self._job_dict_key(j) for j in remaining_jobs],
            )
            preamble = f"{plan_md}\n{prefix}" if plan_md else prefix
            report = f"{preamble}{body}" if preamble else body
            return {
                "report": report,
                "awaiting_hitl": True,
                "thread_id": nxt_tid,
                "evidence_run_id": str(run_id or ""),
                "messages": [AIMessage(content=report)],
            }

        if remaining_jobs:
            return await self._schedule_framework_jobs(
                user_text=str(user_text),
                base_thread=str(base_thread),
                run_id=str(run_id or ""),
                intake_state=intake_state if isinstance(intake_state, dict) else None,
                pending_jobs=remaining_jobs,
                completed=completed,
                plan_md=str(plan_md or ""),
            )

        if remaining:
            # Legacy remaining framework ids (no host) → serialize and schedule.
            legacy_jobs: list[dict[str, Any]] = []
            for fw_id in remaining:
                fw = get_framework(str(fw_id), self.settings.agents_dir)
                legacy_jobs.append(
                    {
                        "framework_id": str(fw_id),
                        "framework_title": fw.title if fw else str(fw_id),
                        "evidence_host_id": "",
                        "ssh_host": "",
                        "ssh_port": "",
                        "ssh_user": "",
                        "ssh_password": "",
                        "ssh_key": "",
                        "ssh_strict": "",
                        "ssh_label": "",
                    }
                )
            return await self._schedule_framework_jobs(
                user_text=str(user_text),
                base_thread=str(base_thread),
                run_id=str(run_id or ""),
                intake_state=intake_state if isinstance(intake_state, dict) else None,
                pending_jobs=legacy_jobs,
                completed=completed,
                plan_md=str(plan_md or ""),
            )

        merged = await self._merge_multi_reports(
            completed,
            run_id=str(run_id or ""),
            base_thread=base_thread,
        )
        if plan_md:
            merged["report"] = f"{plan_md}\n{merged.get('report') or ''}"
        return merged

    def _multi_progress_preamble(
        self,
        completed: list[tuple[str, str, str]],
        current_id: str,
        *,
        in_flight_keys: list[str] | None = None,
        queued_keys: list[str] | None = None,
    ) -> str:
        """Build a short markdown header for multi-framework HITL pauses.

        Args:
            completed: ``(job_key, title, report)`` tuples finished so far.
            current_id: Job key currently waiting on operator input.
            in_flight_keys: Other paused / in-flight job keys.
            queued_keys: Not-yet-started job keys.

        Returns:
            Preamble string (may be empty when there is nothing useful to show).
        """
        if not completed and not in_flight_keys and not queued_keys:
            return ""
        lines = [
            "# Multi-framework audit (in progress)",
            "",
        ]
        if completed:
            lines.append(
                "Completed before pause: "
                + ", ".join(f"`{c[0]}`" for c in completed)
            )
        lines.append(f"Now waiting on: `{current_id}`")
        if in_flight_keys:
            lines.append(
                "Also paused / in flight: "
                + ", ".join(f"`{k}`" for k in in_flight_keys if k)
            )
        if queued_keys:
            lines.append(
                "Queued: " + ", ".join(f"`{k}`" for k in queued_keys if k)
            )
        lines.extend(["", "---", ""])
        return "\n".join(lines)

    async def _merge_multi_reports(
        self,
        completed: list[tuple[str, str, str]],
        *,
        run_id: str,
        base_thread: str,
    ) -> dict[str, Any]:
        """Combine per-framework reports, write root report, and package ZIP.

        Prefers on-disk framework reports (survive HITL) over in-memory text.

        Args:
            completed: ``(framework_id, title, report)`` tuples in order.
            run_id: Shared evidence run id.
            base_thread: Parent thread id for the combined result.

        Returns:
            Result dict with merged ``report``, archive URLs, and metadata.
        """
        store = self._evidence_by_run.get(run_id)
        # Prefer on-disk framework reports (survive HITL / mid-run zips).
        disk_reports: dict[str, str] = {}
        if store is not None:
            for path in store.framework_report_paths():
                try:
                    rel = path.parent.relative_to(store.root)
                    key = str(rel).replace("\\", "/")
                except ValueError:
                    key = path.parent.name
                disk_reports[key] = path.read_text(encoding="utf-8")

        full_sections = [
            "# Multi-host / multi-framework audit",
            "",
            "Sections: " + ", ".join(f"`{c[0]}`" for c in completed),
            "",
        ]
        summary_sections = [
            "# Management summary",
            "",
            "Sections: " + ", ".join(f"`{c[0]}`" for c in completed),
            "",
        ]
        if store is not None:
            full_sections.extend([f"Evidence directory: `{store.root}`", ""])
            summary_sections.extend([f"Evidence directory: `{store.root}`", ""])
        for fw_id, title, report in completed:
            body = (disk_reports.get(fw_id) or report or "(empty report)").strip()
            if "## Audit archive" in body:
                body = body.split("## Audit archive", 1)[0].rstrip()
            full_sections.append(f"## `{fw_id}` — {title}")
            full_sections.append("")
            full_sections.append(body)
            full_sections.append("")
            full_sections.append("---")
            full_sections.append("")
            mgmt = extract_management_summary(body) or "(no summary)"
            summary_sections.append(f"## `{fw_id}` — {title}")
            summary_sections.append("")
            summary_sections.append(mgmt)
            summary_sections.append("")
        # Include any extra on-disk framework reports not listed in completed.
        known = {c[0] for c in completed}
        for fw_id, body in disk_reports.items():
            if fw_id in known:
                continue
            if "## Audit archive" in body:
                body = body.split("## Audit archive", 1)[0].rstrip()
            full_sections.append(f"## `{fw_id}`")
            full_sections.append("")
            full_sections.append(body.strip())
            full_sections.append("")
            full_sections.append("---")
            full_sections.append("")
            mgmt = extract_management_summary(body) or "(no summary)"
            summary_sections.append(f"## `{fw_id}`")
            summary_sections.append("")
            summary_sections.append(mgmt)
            summary_sections.append("")
        combined_full = "\n".join(full_sections).strip() + "\n"
        chat_text = "\n".join(summary_sections).strip() + "\n"
        archive_path = ""
        archive_url = ""
        if store is not None:
            store.write_root_report(combined_full)
            if self.settings.archive_enabled:
                try:
                    packaged = await package_and_publish_archive(
                        store.root, self.settings
                    )
                    archive_path = str(packaged.get("zip_path") or "")
                    archive_url = str(packaged.get("download_url") or "")
                    chat_text = (
                        f"{chat_text.rstrip()}\n{packaged.get('chat_section') or ''}"
                    )
                except Exception as exc:  # noqa: BLE001
                    chat_text = (
                        f"{chat_text.rstrip()}\n\n---\n\n"
                        f"(Archive packaging failed: {type(exc).__name__}: {exc})\n"
                    )
        chat_text = f"{chat_text.rstrip()}{followup_footer()}"
        client_name = ""
        if store is not None:
            client_name = str(store.read_run_meta().get("client_name") or "")
        end_mlflow_run_safe(
            self.settings,
            run_id=run_id,
            client_name=client_name,
            archive_path=archive_path or None,
        )
        return {
            "report": chat_text,
            "messages": [AIMessage(content=chat_text)],
            "framework_id": ",".join(c[0] for c in completed),
            "evidence_run_id": run_id,
            "evidence_run_dir": str(store.root) if store else "",
            "archive_path": archive_path,
            "archive_url": archive_url,
            "thread_id": base_thread,
            "awaiting_hitl": False,
            "findings": {},
        }

    async def arun_revise_req(
        self,
        user_text: str,
        *,
        messages: list | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Gather more evidence (and optionally refill cells) into the prior run."""
        del thread_id
        return await run_revise_req(self, user_text, messages=messages)

    async def arun_refill_finding(
        self,
        user_text: str,
        *,
        messages: list | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Rewrite observation/recommendation from stored evidence only."""
        del thread_id
        return await run_refill_finding(self, user_text, messages=messages)

    async def arun_update_report(
        self,
        user_text: str,
        *,
        messages: list | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Rebuild report.md / ZIP from on-disk findings after follow-up checks."""
        del thread_id
        return await run_update_report(self, user_text, messages=messages)

    async def arun_adhoc(
        self,
        user_text: str,
        *,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Run operator-requested audit commands (no checklist report).

        Args:
            user_text: Operator message asking to run SSH/SQL/playbook commands.
            thread_id: Unused today (reserved for future HITL on ad-hoc).

        Returns:
            Result dict with ``report`` Markdown and ``adhoc=True``.
        """
        del thread_id
        if not self.settings.adhoc_commands_enabled:
            return await self.arun(user_text)
        return await run_adhoc_commands(self, user_text)

    async def arun(
        self,
        user_text: str,
        *,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Run audit(s) for the request.

        When intake is enabled, asks client/access/audit-type first, then
        runs one or more framework graphs. Multiple frameworks run as separate
        graphs (sequential when HITL is on).
        """
        run_id = new_run_id()
        base_thread = thread_id or f"audit-{uuid.uuid4().hex[:12]}"
        shared = EvidenceStore(self.settings.evidence_dir, run_id=run_id)
        self._evidence_by_run[run_id] = shared
        shared.write_run_meta(
            user_request=truncate_text(
                user_text,
                self.settings.max_user_request_chars,
                "user_request",
            ),
            thread_id=base_thread,
        )
        ensure_mlflow_run_safe(
            self.settings,
            run_id=run_id,
            params={
                "model": self.settings.litellm_model,
                "hitl_enabled": self.settings.hitl_enabled,
                "thread_id": base_thread,
            },
            tags={"auditor.thread_id": base_thread},
        )

        if self.settings.intake_enabled:
            intake_tid = f"{base_thread}:intake"
            self._remember_multi_session(intake_tid, {
                "base_thread": base_thread,
                "run_id": run_id,
                "user_text": user_text,
            })
            intake_result = await self.arun_intake(
                user_text,
                run_id=run_id,
                thread_id=intake_tid,
                store=shared,
            )
            if intake_result.get("awaiting_hitl"):
                return intake_result
            # Intake finished in one shot (should be rare without interrupts)
            snap = await self.intake_graph.aget_state(
                {"configurable": {"thread_id": intake_tid}}
            )
            intake = (snap.values or {}).get("intake") or {}
            self._forget_multi_session(intake_tid)
            return await self._start_frameworks_after_intake(
                user_text=user_text,
                base_thread=base_thread,
                run_id=run_id,
                intake=intake if isinstance(intake, dict) else {},
            )

        try:
            selected = route_frameworks(user_text, self.settings.agents_dir)
        except FileNotFoundError as exc:
            return {
                "report": str(exc),
                "messages": [AIMessage(content=str(exc))],
                "error": str(exc),
            }

        shared.write_run_meta(frameworks=[fw.id for fw in selected])

        if len(selected) == 1:
            return await self.arun_one(
                user_text,
                framework_id=selected[0].id,
                run_id=run_id,
                thread_id=f"{base_thread}:{selected[0].id}",
            )

        # HITL-friendly sequential graphs (parallel would tangle chat interrupts).
        if self.settings.hitl_enabled:
            completed: list[tuple[str, str, str]] = []
            for index, fw in enumerate(selected):
                fw_tid = f"{base_thread}:{fw.id}"
                remaining = [f.id for f in selected[index + 1 :]]
                self._remember_multi_session(fw_tid, {
                    "base_thread": base_thread,
                    "run_id": run_id,
                    "user_text": user_text,
                    "framework_id": fw.id,
                    "framework_title": fw.title,
                    "remaining": remaining,
                    "completed": list(completed),
                })
                result = await self.arun_one(
                    user_text,
                    framework_id=fw.id,
                    run_id=run_id,
                    thread_id=fw_tid,
                )
                if result.get("awaiting_hitl"):
                    prefix = self._multi_progress_preamble(completed, fw.id)
                    result["report"] = f"{prefix}{result.get('report') or ''}"
                    return result
                self._forget_multi_session(fw_tid)
                completed.append((fw.id, fw.title, result.get("report") or ""))
            return await self._merge_multi_reports(
                completed,
                run_id=run_id,
                base_thread=base_thread,
            )

        results = await asyncio.gather(
            *[
                self.arun_one(
                    user_text,
                    framework_id=fw.id,
                    run_id=run_id,
                    thread_id=f"{base_thread}:{fw.id}",
                )
                for fw in selected
            ]
        )
        completed = [
            (fw.id, fw.title, result.get("report") or "")
            for fw, result in zip(selected, results, strict=True)
        ]
        return await self._merge_multi_reports(
            completed,
            run_id=run_id,
            base_thread=base_thread,
        )


_graph: AuditorGraph | None = None


def get_auditor_graph() -> AuditorGraph:
    """Return the process-wide singleton ``AuditorGraph`` (lazy-initialized)."""
    global _graph
    if _graph is None:
        _graph = AuditorGraph()
    return _graph


async def get_auditor_graph_ready() -> AuditorGraph:
    """Return the singleton after durable Sqlite checkpointer setup."""
    graph = get_auditor_graph()
    await graph.ensure_async_checkpointer()
    return graph


async def reset_auditor_checkpointer() -> AuditorGraph:
    """Force-reopen the Sqlite checkpointer after a closed-connection failure."""
    graph = get_auditor_graph()
    graph._async_cp_ready = False
    graph._checkpoint_conn = None
    await graph.ensure_async_checkpointer()
    return graph
