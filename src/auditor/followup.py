"""Post-audit follow-up: revise REQ evidence and rebuild reports from disk."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from auditor.compliance import format_compliance_markdown
from auditor.context import compact_findings_for_summary, truncate_text
from auditor.frameworks import get_framework, load_framework_checklist
from auditor.prompts import FINALIZE_PROMPT
from auditor.report_archive import package_and_publish_archive
from auditor.run_resolve import resolve_target
from auditor.state import Finding, render_report

if TYPE_CHECKING:
    from auditor.graph import AuditorGraph

_FOLLOWUP_FOOTER = (
    "\n\n---\n\n"
    "**Next steps:** revise a requirement "
    "(`Revise REQ-002` / `Run another check for REQ-002: \\`…\\``) "
    "or ask `Update the report` after new evidence is collected.\n"
)


def followup_footer() -> str:
    """Short operator hint appended after a completed checklist audit."""
    return _FOLLOWUP_FOOTER


async def run_revise_req(
    graph: AuditorGraph,
    user_text: str,
    *,
    messages: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Gather more evidence for REQ(s) into the **existing** audit folder."""
    settings = graph.settings
    user_request = truncate_text(
        user_text,
        settings.max_user_request_chars,
        "user_request",
    )
    try:
        target = resolve_target(
            user_text=user_request,
            evidence_dir=settings.evidence_dir,
            agents_dir=settings.agents_dir,
            messages=messages,
            require_req=True,
        )
    except (FileNotFoundError, ValueError) as exc:
        # No prior audit → fall back to freeform ad-hoc (new folder).
        if isinstance(exc, FileNotFoundError):
            from auditor.adhoc import run_adhoc_commands

            result = await run_adhoc_commands(graph, user_text)
            result["report"] = (
                f"{result.get('report') or ''}\n\n"
                "_Note: no prior checklist audit was found, so evidence was "
                "stored in a new ad-hoc run folder._\n"
            )
            return result
        return {
            "report": f"Could not revise requirement: {exc}",
            "messages": [AIMessage(content=f"Could not revise requirement: {exc}")],
            "error": str(exc),
            "followup": True,
        }

    store = target.store
    graph._evidence_by_run[store.run_id] = store
    fw = get_framework(target.framework_id, settings.agents_dir)
    if fw is None:
        msg = (
            f"Framework `{target.framework_id}` not found under agents/. "
            "Cannot refill checklist cells."
        )
        return {
            "report": msg,
            "messages": [AIMessage(content=msg)],
            "error": msg,
            "followup": True,
        }

    checklist = load_framework_checklist(fw)
    req_map = {r.id: r for r in checklist.requirements}
    sections: list[str] = [
        "## Post-audit requirement revision",
        "",
        f"**Run:** `{target.run_id}` (resolved via {target.source})",
        f"**Framework:** `{target.framework_id}`",
        f"**Evidence folder:** `{store.root}`",
        "",
    ]

    revised: list[str] = []
    for req_id in target.req_ids:
        requirement = req_map.get(req_id)
        if requirement is None:
            sections.append(f"### {req_id}")
            sections.append("")
            sections.append(
                f"Requirement `{req_id}` is not in checklist `{fw.id}` — skipped."
            )
            sections.append("")
            continue

        finding = await graph._fill_requirement_cells(
            req_id,
            requirement,
            user_request,
            target.framework_id,
            store=store,
        )
        revised.append(req_id)
        sections.extend(
            [
                f"### {req_id}: {finding.title or requirement.title}",
                "",
                f"- **Status:** `{finding.status}`",
                f"- **Observation:** {finding.evidence or '—'}",
                f"- **Recommendation:** {finding.remediation or '—'}",
                f"- Logs appended under `{store.root / target.framework_id / req_id}`",
                "",
            ]
        )

    store.write_run_meta(
        last_followup="revise_req",
        last_followup_at=datetime.now(timezone.utc).isoformat(),
        revised_reqs=revised,
        followup_framework=target.framework_id,
    )

    sections.extend(
        [
            "---",
            "",
            "When ready, ask: **Update the report** "
            "(or `Обнови отчёт`) to regenerate `report.md` / ZIP from new evidence.",
            "",
        ]
    )
    report = "\n".join(sections)
    return {
        "report": report,
        "messages": [AIMessage(content=report)],
        "framework_id": target.framework_id,
        "evidence_run_id": store.run_id,
        "evidence_run_dir": str(store.root),
        "awaiting_hitl": False,
        "followup": True,
        "mode": "revise_req",
        "revised_reqs": revised,
    }


async def run_update_report(
    graph: AuditorGraph,
    user_text: str,
    *,
    messages: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Rebuild Markdown report(s) from on-disk ``finding.json`` files."""
    settings = graph.settings
    user_request = truncate_text(
        user_text,
        settings.max_user_request_chars,
        "user_request",
    )
    try:
        # require_req=False — update whole run (or named framework).
        from auditor.run_resolve import (
            extract_run_id,
            extract_run_id_from_messages,
            latest_run_id,
            resolve_framework_for_req,
        )
        from auditor.evidence_store import EvidenceStore

        run_id = extract_run_id(user_request)
        source = "explicit"
        if not run_id and messages:
            run_id = extract_run_id_from_messages(messages)
            if run_id:
                source = "history"
        if not run_id:
            run_id = latest_run_id(settings.evidence_dir)
            source = "disk"
        if not run_id:
            raise FileNotFoundError(
                "No prior audit evidence found. Run a checklist audit first."
            )
        store = EvidenceStore.open_existing(settings.evidence_dir, run_id)
    except FileNotFoundError as exc:
        return {
            "report": str(exc),
            "messages": [AIMessage(content=str(exc))],
            "error": str(exc),
            "followup": True,
        }

    graph._evidence_by_run[store.run_id] = store
    frameworks = store.list_framework_ids()
    meta = store.read_run_meta()
    if not frameworks:
        frameworks = [
            str(x) for x in (meta.get("frameworks") or []) if x and x != "adhoc"
        ]

    # Optional single-framework filter from text.
    try:
        only_fw = resolve_framework_for_req(
            user_text=user_request,
            store=store,
            req_id="",
            agents_dir=settings.agents_dir,
        )
        if only_fw in frameworks:
            # Only narrow if the user clearly named a framework that exists.
            from auditor.frameworks import route_framework

            routed = route_framework(user_request, settings.agents_dir)
            # Heuristic: if aliases scored and folder exists, allow filter when
            # user text mentions that framework more specifically than others.
            lowered = user_request.lower()
            if routed.id == only_fw and (
                routed.id.lower() in lowered
                or any(a.lower() in lowered for a in (routed.aliases or []))
            ):
                frameworks = [only_fw]
    except (FileNotFoundError, ValueError):
        pass

    if not frameworks:
        msg = f"No framework evidence folders found under run `{store.run_id}`."
        return {
            "report": msg,
            "messages": [AIMessage(content=msg)],
            "error": msg,
            "followup": True,
        }

    completed: list[tuple[str, str, str]] = []
    for fw_id in frameworks:
        fw = get_framework(fw_id, settings.agents_dir)
        title = fw.title if fw else fw_id
        requirements = {}
        if fw is not None:
            checklist = load_framework_checklist(fw)
            requirements = {r.id: r for r in checklist.requirements}
            title = checklist.title or title

        raw_findings = store.load_findings(fw_id)
        findings: dict[str, Finding] = {}
        for req_id, payload in raw_findings.items():
            try:
                findings[req_id] = Finding.model_validate(payload)
            except Exception:  # noqa: BLE001
                continue

        if not findings and not requirements:
            continue

        full_report = render_report(title, findings, requirements or None)
        digest = compact_findings_for_summary(
            findings,
            evidence_chars=settings.max_finalize_evidence_chars,
        )
        try:
            response = await graph.fill_model.ainvoke(
                [
                    SystemMessage(
                        content=(
                            "You write short executive summaries for fixed-format "
                            "security audit reports. Evidence was updated after the "
                            "original audit; summarize the current findings only."
                        )
                    ),
                    HumanMessage(content=FINALIZE_PROMPT.format(report=digest)),
                ]
            )
            summary = str(response.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            summary = f"(Summary generation failed: {exc})"

        body = f"{summary}\n\n---\n\n{full_report}"
        if settings.compliance_charts_in_report:
            try:
                body = f"{body.rstrip()}\n{format_compliance_markdown(full_report)}"
            except Exception:  # noqa: BLE001
                pass
        header = (
            f"Framework: `{fw_id}` | report rebuilt from evidence "
            f"(run `{store.run_id}`, via {source})\n\n"
        )
        final_text = f"{header}{body}"
        store.write_report(fw_id, final_text)
        completed.append((fw_id, title, final_text))

    if not completed:
        msg = (
            f"No findings found under run `{store.run_id}`. "
            "Revise a REQ first so `finding.json` exists."
        )
        return {
            "report": msg,
            "messages": [AIMessage(content=msg)],
            "error": msg,
            "followup": True,
        }

    if len(completed) == 1:
        combined = completed[0][2]
    else:
        sections = [
            "# Multi-framework audit (updated)",
            "",
            "Frameworks: " + ", ".join(f"`{c[0]}`" for c in completed),
            "",
            f"Evidence directory: `{store.root}`",
            "",
        ]
        for fw_id, title, report in completed:
            sections.append(f"## Framework: `{fw_id}` — {title}")
            sections.append("")
            body = (report or "").strip()
            if "## Audit archive" in body:
                body = body.split("## Audit archive", 1)[0].rstrip()
            sections.append(body)
            sections.append("")
            sections.append("---")
            sections.append("")
        combined = "\n".join(sections).strip() + "\n"
        (store.root / "report.md").write_text(combined, encoding="utf-8")

    archive_path = ""
    archive_url = ""
    if settings.archive_enabled:
        try:
            packaged = await package_and_publish_archive(store.root, settings)
            archive_path = str(packaged.get("zip_path") or "")
            archive_url = str(packaged.get("download_url") or "")
            combined = f"{combined.rstrip()}\n{packaged.get('chat_section') or ''}"
        except Exception as exc:  # noqa: BLE001
            combined = (
                f"{combined.rstrip()}\n\n---\n\n"
                f"(Archive packaging failed: {type(exc).__name__}: {exc})\n"
            )

    store.write_run_meta(
        last_followup="update_report",
        last_followup_at=datetime.now(timezone.utc).isoformat(),
        report_updated_at=datetime.now(timezone.utc).isoformat(),
    )

    return {
        "report": combined,
        "messages": [AIMessage(content=combined)],
        "framework_id": ",".join(c[0] for c in completed),
        "evidence_run_id": store.run_id,
        "evidence_run_dir": str(store.root),
        "archive_path": archive_path,
        "archive_url": archive_url,
        "awaiting_hitl": False,
        "followup": True,
        "mode": "update_report",
    }
