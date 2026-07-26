#!/usr/bin/env python3
"""One-shot extractor: move AuditorGraph methods into workflows modules.

Transforms ``def foo(self, ...)`` → ``def foo(runtime: AuditRuntime, ...)`` and
``self.`` → ``runtime.``. Writes thin wrappers back onto AuditorGraph.
"""

from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "src/auditor/graph.py"
WF = ROOT / "src/auditor/workflows"

# method_name -> (module_stem, export_name)
MOVES: dict[str, tuple[str, str]] = {
    # helpers already in helpers.py — not moved here
    "route_after_assess": ("hitl", "route_after_assess"),
    "route_after_hitl": ("hitl", "route_after_hitl"),
    "human_gate": ("hitl", "human_gate"),
    "_skipped_finding": ("hitl", "skipped_finding"),
    "_execute_tool_calls": ("tool_execution", "execute_tool_calls"),
    "assess_parallel": ("assessment", "assess_parallel"),
    "reconnect_session": ("assessment", "reconnect_session"),
    "_fill_requirement_cells": ("assessment", "fill_requirement_cells"),
    "_gather_evidence": ("assessment", "gather_evidence"),
    "_cells_to_finding": ("assessment", "cells_to_finding"),
    "_deterministic_it_audit_finding": ("assessment", "deterministic_it_audit_finding"),
    "_store_from_state": ("assessment", "store_from_state"),
    "_warehouse_live_upsert": ("assessment", "warehouse_live_upsert"),
    "_results_session_number": ("assessment", "results_session_number"),
    "finalize": ("finalize", "finalize"),
    "_report_language": ("finalize", "report_language"),
    "_report_language_from_request": ("finalize", "report_language_from_request"),
    "route_framework_node": ("discovery", "route_framework_node"),
    "load_framework": ("discovery", "load_framework"),
    "collect_host_facts": ("discovery", "collect_host_facts"),
    "_collect_host_facts": ("discovery", "collect_host_facts_dispatch"),
    "_collect_host_facts_llm": ("discovery", "collect_host_facts_llm"),
    "_collect_host_facts_compact": ("discovery", "collect_host_facts_compact"),
    "_facts_from_host_facts_evidence": ("discovery", "facts_from_host_facts_evidence"),
    "_discover_inventory_hosts": ("discovery", "discover_inventory_hosts"),
    "_llm_route_frameworks_from_software": ("discovery", "llm_route_frameworks_from_software"),
    "intake_gate": ("intake", "intake_gate"),
    "_intake_llm_json": ("intake", "intake_llm_json"),
    "_intake_resolve_yes_no": ("intake", "intake_resolve_yes_no"),
    "_intake_resolve_client_name": ("intake", "intake_resolve_client_name"),
    "_intake_resolve_audit_type": ("intake", "intake_resolve_audit_type"),
    "_persist_intake_progress": ("intake", "persist_intake_progress"),
    "_load_intake_progress": ("intake", "load_intake_progress"),
    "_build": ("builder", "build_main_graph"),
    "_build_intake": ("builder", "build_intake_graph"),
    "arun_one": ("runner", "arun_one"),
    "aresume": ("runner", "aresume"),
    "acontinue": ("runner", "acontinue"),
    "arun_intake": ("runner", "arun_intake"),
    "interrupted_continue_message": ("runner", "interrupted_continue_message"),
    "ensure_async_checkpointer": ("runner", "ensure_async_checkpointer"),
    "_target_scope": ("runner", "target_scope"),
    "_client_slug_from_values": ("runner", "client_slug_from_values"),
    "_schedule_framework_jobs": ("multi_runner", "schedule_framework_jobs"),
    "_run_framework_jobs": ("multi_runner", "run_framework_jobs"),
    "_merge_multi_reports": ("multi_runner", "merge_multi_reports"),
    "_continue_multi_after_resume": ("multi_runner", "continue_multi_after_resume"),
    "_start_frameworks_after_intake": ("multi_runner", "start_frameworks_after_intake"),
    "_multi_progress_preamble": ("multi_runner", "multi_progress_preamble"),
    "_host_lock_key_from_target": ("multi_runner", "host_lock_key_from_target"),
    "_host_lock_key_from_job": ("multi_runner", "host_lock_key_from_job"),
    "_serialize_host_job": ("multi_runner", "serialize_host_job"),
    "_job_dict_key": ("multi_runner", "job_dict_key"),
    "_job_dict_thread_id": ("multi_runner", "job_dict_thread_id"),
    "_target_from_job_dict": ("multi_runner", "target_from_job_dict"),
    "_job_display_title": ("multi_runner", "job_display_title"),
    "_jobs_from_selected_intake": ("multi_runner", "jobs_from_selected_intake"),
    "_format_host_framework_plan": ("multi_runner", "format_host_framework_plan"),
    "_remember_multi_session": ("multi_runner", "remember_multi_session"),
    "_forget_multi_session": ("multi_runner", "forget_multi_session"),
    "_reload_multi_sessions": ("multi_runner", "reload_multi_sessions"),
    "arun": ("multi_runner", "arun"),
}


MODULE_HEADERS: dict[str, str] = {
    "hitl": '''"""HITL gate, skip/retry interrupts, and post-assess/HITL routers."""\n\nfrom __future__ import annotations\n\nfrom typing import Any\n\nfrom auditor.state import AuditorState, Finding\nfrom auditor.workflows.helpers import _as_finding, _hitl_candidates\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
    "tool_execution": '''"""Tool-call execution with progress events and evidence logging."""\n\nfrom __future__ import annotations\n\nfrom typing import Any\n\nfrom langchain_core.messages import ToolMessage\n\nfrom auditor.evidence_store import EvidenceStore\nfrom auditor.progress import emit_tool_call, emit_tool_result\nfrom auditor.context import truncate_text\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
    "assessment": '''"""Requirement assessment, evidence gathering, and reconnect."""\n\nfrom __future__ import annotations\n\nimport asyncio\nfrom typing import Any\n\nfrom auditor.checklist import Requirement\nfrom auditor.evidence_store import EvidenceStore\nfrom auditor.progress import emit_phase, emit_req_status\nfrom auditor.session_store import sync_session_status_from_run_meta, write_run_status\nfrom auditor.state import AuditorState, Finding\nfrom auditor.workflows.helpers import _as_finding, _is_recoverable_finding, _normalize_status\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
    "finalize": '''"""Report finalization and result decoration."""\n\nfrom __future__ import annotations\n\nfrom typing import Any\n\nfrom auditor.state import AuditorState\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
    "discovery": '''"""Framework routing, checklist load, and host_facts collection."""\n\nfrom __future__ import annotations\n\nfrom typing import Any\n\nfrom auditor.state import AuditorState\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
    "intake": '''"""Pre-audit intake questionnaire workflow node."""\n\nfrom __future__ import annotations\n\nfrom typing import Any\n\nfrom auditor.state import AuditorState\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
    "builder": '''"""LangGraph StateGraph construction and compilation."""\n\nfrom __future__ import annotations\n\nfrom typing import Any\n\nfrom langgraph.graph import END, START, StateGraph\n\nfrom auditor.state import AuditorState\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
    "runner": '''"""Single-run lifecycle: arun_one, aresume, acontinue, intake invoke."""\n\nfrom __future__ import annotations\n\nfrom typing import Any\n\nfrom auditor.state import AuditorState\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
    "multi_runner": '''"""Multi-host / multi-framework scheduling and report merge."""\n\nfrom __future__ import annotations\n\nfrom typing import Any\n\nfrom auditor.state import AuditorState\nfrom auditor.workflows.protocols import AuditRuntime\n\n''',
}


def method_sources(tree: ast.AST, src: str) -> dict[str, tuple[int, int, str, bool]]:
    """name -> (start_line, end_line, source, is_async)."""
    out: dict[str, tuple[int, int, str, bool]] = {}
    lines = src.splitlines(keepends=True)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "AuditorGraph":
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = m.lineno
                    end = m.end_lineno or m.lineno
                    chunk = "".join(lines[start - 1 : end])
                    out[m.name] = (start, end, chunk, isinstance(m, ast.AsyncFunctionDef))
    return out


def transform_method(src: str, export_name: str) -> str:
    """Rewrite method source as a module-level function."""
    # Dedent class-body indent (4 spaces)
    text = textwrap.dedent(src)
    # Rename def
    text = re.sub(
        r"^(async\s+)?def\s+\w+\(\s*self\s*,?",
        lambda m: f"{m.group(1) or ''}def {export_name}(runtime: AuditRuntime,",
        text,
        count=1,
        flags=re.M,
    )
    # Fix `(runtime: AuditRuntime,)` → `(runtime: AuditRuntime)` and `(runtime: AuditRuntime, )`
    text = re.sub(
        rf"def {re.escape(export_name)}\(runtime: AuditRuntime,\s*\)",
        f"def {export_name}(runtime: AuditRuntime)",
        text,
        count=1,
    )
    # self → runtime (word boundary); avoid replacing in strings naively — good enough for this codebase
    text = re.sub(r"\bself\b", "runtime", text)
    return text.rstrip() + "\n\n"


def wrapper_for(method_name: str, module: str, export: str, is_async: bool) -> str:
    alias = f"_wf_{module}"
    if method_name in {"_build", "_build_intake"}:
        # special: returns compiled graph using runtime
        pass
    prefix = "async " if is_async else ""
    await_ = "await " if is_async else ""
    # Keep original signature via *args/**kwargs for compatibility
    return (
        f"    {prefix}def {method_name}(self, *args, **kwargs):\n"
        f"        return {await_}{alias}.{export}(self, *args, **kwargs)\n\n"
    )


def main() -> None:
    src = GRAPH.read_text(encoding="utf-8")
    tree = ast.parse(src)
    methods = method_sources(tree, src)

    by_module: dict[str, list[str]] = {}
    wrappers: dict[str, str] = {}
    missing = []
    for method_name, (module, export) in MOVES.items():
        if method_name not in methods:
            missing.append(method_name)
            continue
        _s, _e, chunk, is_async = methods[method_name]
        by_module.setdefault(module, []).append(transform_method(chunk, export))
        wrappers[method_name] = wrapper_for(method_name, module, export, is_async)

    if missing:
        print("MISSING methods:", missing)

    for module, bodies in by_module.items():
        header = MODULE_HEADERS.get(
            module,
            '"""Workflow module."""\n\nfrom __future__ import annotations\n\nfrom auditor.workflows.protocols import AuditRuntime\n\n',
        )
        path = WF / f"{module}.py"
        path.write_text(header + "".join(bodies), encoding="utf-8")
        print(f"wrote {path} ({len(bodies)} funcs)")

    # Replace method bodies in graph.py with wrappers (from bottom to top by line)
    lines = src.splitlines(keepends=True)
    ranges = []
    for method_name in wrappers:
        if method_name in methods:
            ranges.append((methods[method_name][0], methods[method_name][1], method_name))
    ranges.sort(reverse=True)
    for start, end, method_name in ranges:
        # preserve indent of original method (4 spaces for class body)
        wrap = wrappers[method_name]
        lines[start - 1 : end] = [wrap]

    new_src = "".join(lines)

    # Remove old helper defs if still present; add imports
    helper_block_pat = re.compile(
        r"\n# Tight markers only.*?def _tool_result_looks_failed\(text: str\) -> bool:.*?\)\n\)\n",
        re.S,
    )
    # Simpler: if helpers still defined, leave — we'll patch graph imports separately

    # Inject workflow imports after existing imports
    import_block = """
from auditor.workflows import assessment as _wf_assessment
from auditor.workflows import builder as _wf_builder
from auditor.workflows import discovery as _wf_discovery
from auditor.workflows import finalize as _wf_finalize
from auditor.workflows import hitl as _wf_hitl
from auditor.workflows import intake as _wf_intake
from auditor.workflows import multi_runner as _wf_multi_runner
from auditor.workflows import runner as _wf_runner
from auditor.workflows import tool_execution as _wf_tool_execution
from auditor.workflows.helpers import (
    _as_finding,
    _extract_json,
    _hitl_candidates,
    _is_recoverable_finding,
    _normalize_status,
    _tool_result_looks_failed,
)
from auditor.workflows.dependencies import (
    EvidenceRegistry,
    GraphDependencies,
    MultiSessionRegistry,
)
"""
    if "from auditor.workflows import assessment" not in new_src:
        # Insert before class AuditorGraph
        new_src = new_src.replace(
            "\nclass AuditorGraph:",
            import_block + "\nclass AuditorGraph:",
            1,
        )

    # Strip duplicate helper definitions that remain above the class
    new_src = re.sub(
        r"\n# Tight markers only — bare \"session\".*?def _tool_result_looks_failed\(text: str\) -> bool:.*?(?=\nclass AuditorGraph:)",
        "\n",
        new_src,
        count=1,
        flags=re.S,
    )

    GRAPH.write_text(new_src, encoding="utf-8")
    print(f"updated {GRAPH}")


if __name__ == "__main__":
    main()
