"""Report finalization and result decoration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, SystemMessage
from langgraph.graph.message import REMOVE_ALL_MESSAGES

from auditor.hitl import (
    format_hitl_assistant_message,
    interrupt_payload_to_prompt,
)
from auditor.intake import format_intake_assistant_message
from auditor.language import (
    ReportLanguage,
    detect_report_language,
    language_instruction,
    language_name,
)
from auditor.prompts import FINALIZE_PROMPT
from auditor.report_archive import package_and_publish_archive
from auditor.state import AuditorState, render_report
from auditor.compliance import format_compliance_markdown
from auditor.followup import followup_footer
from auditor.context import compact_findings_for_summary
from auditor.results_store import record_results_safe
from auditor.workflows.protocols import AuditRuntime

async def finalize(runtime: AuditRuntime, state: AuditorState) -> dict[str, Any]:
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
    report_lang = runtime._report_language(state)
    lang_instr = language_instruction(report_lang)
    full_report = render_report(
        title, findings, requirements, language=report_lang
    )
    digest = compact_findings_for_summary(
        findings,
        evidence_chars=runtime.settings.max_finalize_evidence_chars,
    )
    try:
        response = await runtime.fill_model.ainvoke(
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
    store = runtime._store_from_state(state)
    evidence_note = ""
    if store is not None:
        host_id = str(state.get("evidence_host_id") or "").strip()
        if host_id:
            store.host_segment = host_id
        store.write_report(
            fw or "framework", f"{summary}\n\n---\n\n{full_report}"
        )
        evidence_note = f" | evidence: `{store.root}`"

    if findings or requirements:
        evidence_rel = ""
        if store is not None:
            try:
                evidence_rel = str(
                    store.root.relative_to(
                        Path(runtime.settings.evidence_dir).resolve()
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
            runtime.settings,
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
            audit_run_id=str(state.get("audit_run_id") or ""),
            client_id=str(state.get("client_id") or ""),
        )
    else:
        session_number = None

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
    if runtime.settings.compliance_charts_in_report:
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
        (sess.get("run_id") == run_id) for sess in runtime._multi_sessions.values()
    )
    if store is not None and runtime.settings.archive_enabled and not in_multi:
        try:
            store.write_root_report(disk_report)
            packaged = await package_and_publish_archive(
                store.root, runtime.settings
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

def report_language(runtime: AuditRuntime, state: AuditorState | None = None, user_request: str = ""
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

def report_language_from_request(runtime: AuditRuntime, user_request: str) -> ReportLanguage:
    """Detect report language from the operator request string only."""
    return detect_report_language(user_request)

