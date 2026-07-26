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
import re
from contextlib import contextmanager
from typing import Any

from langchain_core.messages import (
    AIMessage,
)
from langgraph.checkpoint.memory import MemorySaver

from auditor.adhoc import run_adhoc_commands
from auditor.config import Settings, get_settings
from auditor.evidence_store import (
    EvidenceStore,
)
from auditor.followup import (
    run_anonymize_report,
    run_refill_finding,
    run_revise_req,
    run_update_report,
)
from auditor.hitl import (
    format_hitl_assistant_message,
    interrupt_payload_to_prompt,
)
from auditor.intake import (
    format_intake_assistant_message,
)
from auditor.llm import build_chat_model
from auditor.memory.playbook_store import PlaybookMemory
from auditor.task_registry import TaskRegistry
from auditor.tools.mcp_client import PostgresMcpPool, build_mcp_tools
from auditor.tools.ssh import get_ssh_tools
from auditor.tools.winrm import get_winrm_tools
from auditor.workflows import assessment as _wf_assessment
from auditor.workflows import builder as _wf_builder
from auditor.workflows import discovery as _wf_discovery
from auditor.workflows import finalize as _wf_finalize
from auditor.workflows import hitl as _wf_hitl
from auditor.workflows import intake as _wf_intake
from auditor.workflows import multi_runner as _wf_multi_runner
from auditor.workflows import runner as _wf_runner
from auditor.workflows import tool_execution as _wf_tool_execution
from auditor.workflows.dependencies import (
    EvidenceRegistry,
    GraphDependencies,
    MultiSessionRegistry,
)
from auditor.workflows.helpers import (
    _as_finding,
    _extract_json,
    _hitl_candidates,
    _is_recoverable_finding,
    _normalize_status,
    _tool_result_looks_failed,
)

__all__ = [
    "AuditorGraph",
    "get_auditor_graph",
    "get_auditor_graph_ready",
    "reset_auditor_checkpointer",
    "_as_finding",
    "_extract_json",
    "_hitl_candidates",
    "_is_recoverable_finding",
    "_normalize_status",
    "_tool_result_looks_failed",
]


def _all_tools(mcp_pool: PostgresMcpPool | None = None) -> list:
    """Collect LangChain tools for evidence gathering."""
    pool = mcp_pool or PostgresMcpPool()
    return [*get_ssh_tools(), *get_winrm_tools(), *build_mcp_tools(pool)]


def _host_tools() -> list:
    """Remote host tools (SSH + WinRM) for discovery / host_facts."""
    return [*get_ssh_tools(), *get_winrm_tools()]


class AuditorGraph:
    """Compile and run the cyclic multi-framework audit StateGraph.

    Owns tool-bound LLMs, evidence stores per run, procedural playbooks,
    intake and main compiled graphs, and multi-framework session bookkeeping
    across HITL pauses.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        mcp_pool: PostgresMcpPool | None = None,
        results_store: Any | None = None,
        task_registry: TaskRegistry | None = None,
    ) -> None:
        """Wire settings, models, tools, memory, and compile LangGraph workflows.

        Args:
            settings: Application settings; defaults to ``get_settings()``.
            mcp_pool: Runtime-owned MCP pool; a private pool is created when omitted.
            results_store: Optional results warehouse bound into playbooks/tools.
            task_registry: Background task registry (created when omitted).
        """
        self.settings = settings or get_settings()
        self._owns_mcp_pool = mcp_pool is None
        self.mcp_pool = mcp_pool or PostgresMcpPool(size=self.settings.mcp_postgres_pool_size)
        self.results_store = results_store
        self._owns_task_registry = task_registry is None
        self.task_registry = task_registry or TaskRegistry()
        self.tools = _all_tools(self.mcp_pool)
        self.tools_by_name = {t.name: t for t in self.tools}
        self._evidence = EvidenceRegistry()
        # Shared dict for back-compat with followup/adhoc/tests.
        self._evidence_by_run = self._evidence.stores
        self._multi = MultiSessionRegistry()
        self._multi_sessions = self._multi.sessions
        self._checkpointer = MemorySaver()
        self._checkpoint_conn = None
        self._checkpoint_scope_key = ""
        self._scoped_checkpoints: dict[str, Any] = {}
        self._scoped_acquire_locks: dict[str, asyncio.Lock] = {}
        self._scoped_meta_lock = asyncio.Lock()
        self._async_cp_ready = False
        self._sqlite_cm = None
        self._orphan_tasks: dict[str, asyncio.Task[Any]] = {}
        self.playbooks = (
            PlaybookMemory(
                playbooks_dir=self.settings.playbooks_dir,
                memory_dir=self.settings.memory_dir,
                learn=self.settings.memory_learn,
                settings=self.settings,
                results_store=self.results_store,
            )
            if self.settings.memory_enabled
            else None
        )
        self.evidence_model = build_chat_model(self.settings).bind_tools(self.tools)
        self.evidence_model_ssh = build_chat_model(self.settings).bind_tools(_host_tools())
        self.fill_model = build_chat_model(self.settings)
        self.deps = GraphDependencies(
            settings=self.settings,
            tools=self.tools,
            tools_by_name=self.tools_by_name,
            evidence_model=self.evidence_model,
            evidence_model_ssh=self.evidence_model_ssh,
            fill_model=self.fill_model,
            playbooks=self.playbooks,
            evidence=self._evidence,
            multi_sessions=self._multi,
            mcp_pool=self.mcp_pool,
            results_store=self.results_store,
            task_registry=self.task_registry,
            orphan_tasks=self._orphan_tasks,
        )
        self.graph = self._build()
        self.intake_graph = self._build_intake()

    @contextmanager
    def _target_scope(self, *args, **kwargs):
        return _wf_runner.target_scope(self, *args, **kwargs)

    def _client_slug_from_values(self, *args, **kwargs):
        return _wf_runner.client_slug_from_values(self, *args, **kwargs)

    async def ensure_async_checkpointer(self, *args, **kwargs):
        return await _wf_runner.ensure_async_checkpointer(self, *args, **kwargs)

    def _remember_multi_session(self, *args, **kwargs):
        return _wf_multi_runner.remember_multi_session(self, *args, **kwargs)

    def _forget_multi_session(self, *args, **kwargs):
        return _wf_multi_runner.forget_multi_session(self, *args, **kwargs)

    def _reload_multi_sessions(self, *args, **kwargs):
        return _wf_multi_runner.reload_multi_sessions(self, *args, **kwargs)

    def _evidence_llm(self):
        """Return the inventory-only evidence model bound to SSH + MCP tools."""
        return self.evidence_model

    def _build(self, *args, **kwargs):
        return _wf_builder.build_main_graph(self, *args, **kwargs)

    def _build_intake(self, *args, **kwargs):
        return _wf_builder.build_intake_graph(self, *args, **kwargs)

    async def _intake_llm_json(self, *args, **kwargs):
        return await _wf_intake.intake_llm_json(self, *args, **kwargs)

    async def _intake_resolve_yes_no(self, *args, **kwargs):
        return await _wf_intake.intake_resolve_yes_no(self, *args, **kwargs)

    async def _intake_resolve_client_name(self, *args, **kwargs):
        return await _wf_intake.intake_resolve_client_name(self, *args, **kwargs)

    async def _intake_resolve_audit_type(self, *args, **kwargs):
        return await _wf_intake.intake_resolve_audit_type(self, *args, **kwargs)

    def _persist_intake_progress(self, *args, **kwargs):
        return _wf_intake.persist_intake_progress(self, *args, **kwargs)

    def _load_intake_progress(self, *args, **kwargs):
        return _wf_intake.load_intake_progress(self, *args, **kwargs)

    async def intake_gate(self, *args, **kwargs):
        return await _wf_intake.intake_gate(self, *args, **kwargs)

    async def _collect_host_facts(self, *args, **kwargs):
        return await _wf_discovery.collect_host_facts_dispatch(self, *args, **kwargs)

    async def _facts_from_host_facts_evidence(self, *args, **kwargs):
        return await _wf_discovery.facts_from_host_facts_evidence(self, *args, **kwargs)

    async def _collect_host_facts_compact(self, *args, **kwargs):
        return await _wf_discovery.collect_host_facts_compact(self, *args, **kwargs)

    async def _collect_host_facts_llm(self, *args, **kwargs):
        return await _wf_discovery.collect_host_facts_llm(self, *args, **kwargs)

    async def collect_host_facts(self, *args, **kwargs):
        return await _wf_discovery.collect_host_facts(self, *args, **kwargs)

    async def route_framework_node(self, *args, **kwargs):
        return await _wf_discovery.route_framework_node(self, *args, **kwargs)

    async def load_framework(self, *args, **kwargs):
        return await _wf_discovery.load_framework(self, *args, **kwargs)

    async def assess_parallel(self, *args, **kwargs):
        return await _wf_assessment.assess_parallel(self, *args, **kwargs)

    def route_after_assess(self, *args, **kwargs):
        return _wf_hitl.route_after_assess(self, *args, **kwargs)

    def route_after_hitl(self, *args, **kwargs):
        return _wf_hitl.route_after_hitl(self, *args, **kwargs)

    async def reconnect_session(self, *args, **kwargs):
        return await _wf_assessment.reconnect_session(self, *args, **kwargs)

    async def human_gate(self, *args, **kwargs):
        return await _wf_hitl.human_gate(self, *args, **kwargs)

    def _deterministic_it_audit_finding(self, *args, **kwargs):
        return _wf_assessment.deterministic_it_audit_finding(self, *args, **kwargs)

    @staticmethod
    @staticmethod
    def _skipped_finding(*args, **kwargs):
        return _wf_hitl.skipped_finding(*args, **kwargs)

    def _store_from_state(self, *args, **kwargs):
        return _wf_assessment.store_from_state(self, *args, **kwargs)

    def _results_session_number(self, *args, **kwargs):
        return _wf_assessment.results_session_number(self, *args, **kwargs)

    async def _warehouse_live_upsert(self, *args, **kwargs):
        return await _wf_assessment.warehouse_live_upsert(self, *args, **kwargs)

    async def _fill_requirement_cells(self, *args, **kwargs):
        return await _wf_assessment.fill_requirement_cells(self, *args, **kwargs)

    async def _gather_evidence(self, *args, **kwargs):
        return await _wf_assessment.gather_evidence(self, *args, **kwargs)

    async def _execute_tool_calls(self, *args, **kwargs):
        return await _wf_tool_execution.execute_tool_calls(self, *args, **kwargs)

    def _cells_to_finding(self, *args, **kwargs):
        return _wf_assessment.cells_to_finding(self, *args, **kwargs)

    def _report_language(self, *args, **kwargs):
        return _wf_finalize.report_language(self, *args, **kwargs)

    def _report_language_from_request(self, *args, **kwargs):
        return _wf_finalize.report_language_from_request(self, *args, **kwargs)

    async def finalize(self, *args, **kwargs):
        return await _wf_finalize.finalize(self, *args, **kwargs)

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
        if store is not None:
            meta = store.read_run_meta()
            if meta.get("client_id"):
                result.setdefault("client_id", str(meta.get("client_id") or ""))
            if meta.get("audit_run_id"):
                result.setdefault("audit_run_id", str(meta.get("audit_run_id") or ""))

        interrupts = result.get("__interrupt__") or []
        if not interrupts:
            result["awaiting_hitl"] = False
            return result

        first = interrupts[0]
        value = getattr(first, "value", first)
        prompt = interrupt_payload_to_prompt(value)
        is_intake = intake or (isinstance(value, dict) and str(value.get("type") or "") == "intake")
        if is_intake:
            msg = format_intake_assistant_message(prompt, thread_id)
        else:
            msg = format_hitl_assistant_message(prompt, thread_id)
        result["report"] = msg
        result["awaiting_hitl"] = True
        result["awaiting_intake"] = is_intake
        result["messages"] = [AIMessage(content=msg)]
        return result

    async def arun_intake(self, *args, **kwargs):
        return await _wf_runner.arun_intake(self, *args, **kwargs)

    async def arun_one(self, *args, **kwargs):
        return await _wf_runner.arun_one(self, *args, **kwargs)

    async def aresume(self, *args, **kwargs):
        return await _wf_runner.aresume(self, *args, **kwargs)

    async def acontinue(self, *args, **kwargs):
        return await _wf_runner.acontinue(self, *args, **kwargs)

    async def aclose_runtime_resources(self, timeout: float = 10.0) -> None:
        """Close scoped checkpoints and clear in-memory run registries."""
        from auditor.workflows.runner import release_run_checkpointer

        cache = dict(self._scoped_checkpoints)
        for bundle in cache.values():
            await release_run_checkpointer(
                self,
                client_id=bundle.client_id,
                audit_run_id=bundle.audit_run_id,
                close=True,
                force=True,
            )
        if self._sqlite_cm is not None:
            try:
                await self._sqlite_cm.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            self._sqlite_cm = None
        self._checkpoint_conn = None
        self._async_cp_ready = False
        self._evidence.stores.clear()
        self._multi.sessions.clear()
        self._scoped_acquire_locks.clear()
        if self._owns_mcp_pool:
            await self.mcp_pool.close()
        if self._owns_task_registry:
            await self.task_registry.shutdown(timeout=timeout)

    def cancel_audit_run(self, audit_run_id: str):
        """Cancel open jobs and the AuditRun (same ``audit_run_id``)."""
        from auditor.audit_registry import get_audit_registry

        return get_audit_registry(self.settings.evidence_dir).cancel_run(audit_run_id)

    def resume_audit_run(self, audit_run_id: str):
        """Resume a cancelled AuditRun without allocating a new run id."""
        from auditor.audit_registry import get_audit_registry

        return get_audit_registry(self.settings.evidence_dir).resume_run(audit_run_id)

    def interrupted_continue_message(self, *args, **kwargs):
        return _wf_runner.interrupted_continue_message(self, *args, **kwargs)

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

    async def _llm_route_frameworks_from_software(self, *args, **kwargs):
        return await _wf_discovery.llm_route_frameworks_from_software(self, *args, **kwargs)

    async def _discover_inventory_hosts(self, *args, **kwargs):
        return await _wf_discovery.discover_inventory_hosts(self, *args, **kwargs)

    def _jobs_from_selected_intake(self, *args, **kwargs):
        return _wf_multi_runner.jobs_from_selected_intake(self, *args, **kwargs)

    def _format_host_framework_plan(self, *args, **kwargs):
        return _wf_multi_runner.format_host_framework_plan(self, *args, **kwargs)

    async def _start_frameworks_after_intake(self, *args, **kwargs):
        return await _wf_multi_runner.start_frameworks_after_intake(self, *args, **kwargs)

    @staticmethod
    def _host_lock_key_from_target(*args, **kwargs):
        return _wf_multi_runner.host_lock_key_from_target(*args, **kwargs)

    @staticmethod
    def _host_lock_key_from_job(*args, **kwargs):
        return _wf_multi_runner.host_lock_key_from_job(*args, **kwargs)

    @staticmethod
    def _serialize_host_job(*args, **kwargs):
        return _wf_multi_runner.serialize_host_job(*args, **kwargs)

    @staticmethod
    def _job_dict_key(*args, **kwargs):
        return _wf_multi_runner.job_dict_key(*args, **kwargs)

    @staticmethod
    def _job_dict_thread_id(*args, **kwargs):
        return _wf_multi_runner.job_dict_thread_id(*args, **kwargs)

    @staticmethod
    def _target_from_job_dict(*args, **kwargs):
        return _wf_multi_runner.target_from_job_dict(*args, **kwargs)

    @staticmethod
    def _job_display_title(*args, **kwargs):
        return _wf_multi_runner.job_display_title(*args, **kwargs)

    async def _run_framework_jobs(self, *args, **kwargs):
        return await _wf_multi_runner.run_framework_jobs(self, *args, **kwargs)

    async def _schedule_framework_jobs(self, *args, **kwargs):
        return await _wf_multi_runner.schedule_framework_jobs(self, *args, **kwargs)

    async def _continue_multi_after_resume(self, *args, **kwargs):
        return await _wf_multi_runner.continue_multi_after_resume(self, *args, **kwargs)

    def _multi_progress_preamble(self, *args, **kwargs):
        return _wf_multi_runner.multi_progress_preamble(self, *args, **kwargs)

    async def _merge_multi_reports(self, *args, **kwargs):
        return await _wf_multi_runner.merge_multi_reports(self, *args, **kwargs)

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

    async def arun_anonymize_report(
        self,
        user_text: str,
        *,
        messages: list | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Create reversible anonymized evidence/report copy in `<run>_anon`."""
        del thread_id
        return await run_anonymize_report(self, user_text, messages=messages)

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

    async def arun(self, *args, **kwargs):
        return await _wf_multi_runner.arun(self, *args, **kwargs)


_graph: AuditorGraph | None = None


def get_auditor_graph() -> AuditorGraph:
    """Deprecated/test-only process-wide ``AuditorGraph`` (lazy-initialized).

    Production HTTP handlers must use :class:`~auditor.application_runtime.ApplicationRuntime`.
    """
    global _graph
    if _graph is None:
        _graph = AuditorGraph()
    return _graph


async def get_auditor_graph_ready() -> AuditorGraph:
    """Deprecated/test-only: singleton after legacy Sqlite checkpointer setup.

    Not for production API paths.
    """
    graph = get_auditor_graph()
    await graph.ensure_async_checkpointer()
    return graph


async def reset_auditor_checkpointer() -> AuditorGraph:
    """Deprecated/test-only: reopen legacy process checkpointer on the singleton.

    Production retry must call ``runtime.reconnect_run_checkpointer`` for the run.
    """
    graph = get_auditor_graph()
    graph._async_cp_ready = False
    graph._checkpoint_conn = None
    await graph.ensure_async_checkpointer()
    return graph
