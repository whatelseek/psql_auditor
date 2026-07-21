"""Post-audit follow-up: gather evidence, refill cells, rebuild reports."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Sequence

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from auditor.compliance import format_compliance_markdown
from auditor.context import compact_findings_for_summary, truncate_text
from auditor.frameworks import get_framework, load_framework_checklist
from auditor.intent import extract_req_ids, wants_full_revise
from auditor.language import (
    ReportLanguage,
    detect_report_language,
    language_instruction,
    language_name,
)
from auditor.prompts import FILL_CELL_PROMPT, FILL_SYSTEM_PROMPT, FINALIZE_PROMPT
from auditor.report_archive import package_and_publish_archive
from auditor.run_resolve import (
    ResolvedTarget,
    checklist_framework_id,
    resolve_target,
    split_evidence_framework_key,
)
from auditor.secrets_file import (
    InventorySshTarget,
    bind_ssh_target,
    list_client_ssh_targets,
)
from auditor.results_store import record_results_safe
from auditor.state import Finding, render_report

if TYPE_CHECKING:
    from auditor.graph import AuditorGraph

_FOLLOWUP_FOOTER = (
    "\n\n---\n\n"
    "**Next steps (post-audit):**\n"
    "1. Gather more evidence — name **REQ + framework + host** when multi-host, "
    "and say what to check / which commands to run, e.g. "
    "`Evaluate REQ-001 on ubuntu_cis for host 10.200.29.78. "
    "Try read /etc/ssh/sshd_config`.\n"
    "2. Rewrite that REQ’s cells — "
    "`Prepare new observation and recommendation for REQ-001`.\n"
    "   You may repeat steps 1–2 for **other REQs** before rebuilding.\n"
    "3. Rebuild report + ZIP once ready — `Update the report` / `Обнови отчёт`.\n"
    "   One-shot: `Revise REQ-001 on ubuntu_cis for host …` "
    "(gather + refill; still ask to update the report).\n"
)


def followup_footer() -> str:
    """Short operator hint appended after a completed checklist audit."""
    return _FOLLOWUP_FOOTER


def _resolve_ssh_target(
    *,
    inventory_dir: Path,
    client_run_id: str,
    host_id: str | None,
) -> InventorySshTarget | None:
    """Match inventory SSH row for a multi-host evidence host slug."""
    if not host_id:
        return None
    try:
        targets = list_client_ssh_targets(inventory_dir, client_run_id)
    except (OSError, ValueError, FileNotFoundError):
        return None
    host_l = host_id.lower()
    for target in targets:
        if target.slug.lower() == host_l or target.host.lower() == host_l:
            return target
    for target in targets:
        if host_l in target.host.lower() or host_l in target.slug.lower():
            return target
    return None


@contextmanager
def _ssh_bind_for_target(
    settings: Any,
    target: ResolvedTarget,
) -> Iterator[InventorySshTarget | None]:
    """Bind process SSH env to the evidence host for tool gather / full revise."""
    ssh = _resolve_ssh_target(
        inventory_dir=settings.inventory_dir,
        client_run_id=target.run_id,
        host_id=target.host_id,
    )
    if ssh is None:
        yield None
        return
    with bind_ssh_target(ssh):
        yield ssh


async def run_revise_req(
    graph: AuditorGraph,
    user_text: str,
    *,
    messages: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Gather more evidence for REQ(s) into the **existing** audit folder.

    By default this is **evidence-only** (tools are stored; finding cells keep
    prior values). When the operator says ``revise`` / ``reassess`` /
    ``re-audit``, observation + recommendation are also rewritten immediately.
    """
    settings = graph.settings
    user_request = truncate_text(
        user_text,
        settings.max_user_request_chars,
        "user_request",
    )
    full = wants_full_revise(user_request)
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
    bare_fw = checklist_framework_id(target.framework_id)
    fw = get_framework(bare_fw, settings.agents_dir)
    if fw is None:
        msg = (
            f"Framework `{bare_fw}` (from `{target.framework_id}`) not found "
            "under agents/. Cannot refill checklist cells."
        )
        return {
            "report": msg,
            "messages": [AIMessage(content=msg)],
            "error": msg,
            "followup": True,
        }

    checklist = load_framework_checklist(fw)
    req_map = {r.id: r for r in checklist.requirements}
    mode = "revise_full" if full else "gather_evidence"
    evidence_req_root = store.root / target.framework_id
    sections: list[str] = [
        "## Post-audit evidence collection"
        if not full
        else "## Post-audit requirement revision",
        "",
        f"**Run:** `{target.run_id}` (resolved via {target.source})",
        f"**Framework:** `{target.framework_id}`",
    ]
    revised: list[str] = []
    with _ssh_bind_for_target(settings, target) as ssh:
        if ssh is not None:
            sections.append(f"**SSH host:** `{ssh.host}` (bound for this follow-up)")
        sections.extend(
            [
                f"**Mode:** `{mode}`",
                f"**Evidence folder:** `{store.root}`",
                "",
            ]
        )
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

            store.write_requirement(
                target.framework_id,
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

            if full:
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
                        f"- Logs under `{evidence_req_root / req_id}`",
                        "",
                    ]
                )
                continue

            evidence = await graph._gather_evidence(
                req_id,
                requirement,
                user_request,
                target.framework_id,
                store=store,
            )
            revised.append(req_id)
            tool_files = store.list_tool_result_files(target.framework_id, req_id)
            sections.extend(
                [
                    f"### {req_id}: {requirement.title}",
                    "",
                    f"- **Tools stored:** {len(tool_files)} file(s) under "
                    f"`{evidence_req_root / req_id}`",
                    "",
                    "#### Evidence summary",
                    "",
                    evidence.strip() or "_(no tool output)_",
                    "",
                ]
            )

    store.write_run_meta(
        last_followup=mode,
        last_followup_at=datetime.now(timezone.utc).isoformat(),
        revised_reqs=revised,
        followup_framework=target.framework_id,
        followup_host=target.host_id or "",
    )

    if full:
        sections.extend(
            [
                "---",
                "",
                "Cells updated for this REQ. You may **Evaluate / Revise** another "
                "REQ next, or ask **Update the report** "
                "(or `Обнови отчёт`) to regenerate `report.md` / ZIP.",
                "",
            ]
        )
    else:
        sections.extend(
            [
                "---",
                "",
                "Evidence was appended. Finding cells were **not** changed yet.",
                "",
                "Next, ask for example:",
                f"- **Prepare new observation and recommendation for {revised[0]}**"
                if revised
                else "- **Prepare new observation and recommendation for REQ-001**",
                "- (optional) gather/refill **another REQ**",
                "- then **Update the report** when finished reviewing",
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
        "mode": mode,
        "revised_reqs": revised,
    }


async def run_refill_finding(
    graph: AuditorGraph,
    user_text: str,
    *,
    messages: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Rewrite status / observation / recommendation from **stored** evidence only."""
    settings = graph.settings
    user_request = truncate_text(
        user_text,
        settings.max_user_request_chars,
        "user_request",
    )
    req_ids = extract_req_ids(user_request)
    try:
        target = resolve_target(
            user_text=user_request,
            evidence_dir=settings.evidence_dir,
            agents_dir=settings.agents_dir,
            messages=messages,
            require_req=bool(req_ids),
        )
    except (FileNotFoundError, ValueError) as exc:
        return {
            "report": f"Could not refill finding: {exc}",
            "messages": [AIMessage(content=f"Could not refill finding: {exc}")],
            "error": str(exc),
            "followup": True,
        }

    store = target.store
    graph._evidence_by_run[store.run_id] = store
    meta = store.read_run_meta()
    if not target.req_ids:
        # Never refill every REQ in the run — only prior revised ids or an
        # explicit REQ in the operator message.
        prior = [str(x) for x in (meta.get("revised_reqs") or []) if x]
        if prior:
            target = ResolvedTarget(
                run_id=target.run_id,
                framework_id=target.framework_id,
                req_ids=prior,
                store=store,
                source=target.source,
                host_id=target.host_id,
            )
        else:
            msg = (
                "Name a requirement id (e.g. `REQ-001`) or gather evidence "
                "for a REQ first (`Evaluate REQ-001 …`)."
            )
            return {
                "report": msg,
                "messages": [AIMessage(content=msg)],
                "error": msg,
                "followup": True,
            }

    bare_fw = checklist_framework_id(target.framework_id)
    fw = get_framework(bare_fw, settings.agents_dir)
    if fw is None:
        msg = (
            f"Framework `{bare_fw}` (from `{target.framework_id}`) "
            "not found under agents/."
        )
        return {
            "report": msg,
            "messages": [AIMessage(content=msg)],
            "error": msg,
            "followup": True,
        }

    checklist = load_framework_checklist(fw)
    req_map = {r.id: r for r in checklist.requirements}
    lang_code = str(meta.get("report_language") or "").strip()
    if lang_code:
        report_lang = ReportLanguage(code=lang_code, name=language_name(lang_code))
    else:
        report_lang = detect_report_language(user_request)
    lang_instr = language_instruction(report_lang)

    sections: list[str] = [
        "## Updated observation / recommendation",
        "",
        f"**Run:** `{target.run_id}`",
        f"**Framework:** `{target.framework_id}`",
        f"**Language:** {report_lang.name}",
        "",
        "_Filled from stored tool evidence only (no new commands were run)._",
        "",
    ]
    refilled: list[str] = []

    for req_id in target.req_ids:
        requirement = req_map.get(req_id)
        if requirement is None:
            sections.append(f"### {req_id}\n\nNot in checklist — skipped.\n")
            continue

        evidence = store.load_evidence_text(
            target.framework_id,
            req_id,
            max_chars=settings.max_tool_output_chars,
        )
        if not evidence:
            sections.extend(
                [
                    f"### {req_id}: {requirement.title}",
                    "",
                    "No stored tool evidence found. Gather evidence first, e.g. "
                    f"`Evaluate {req_id}. Try read the relevant config file`.",
                    "",
                ]
            )
            continue

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
                    evidence=evidence,
                )
            ),
        ]
        response = await graph.fill_model.ainvoke(fill_messages)
        finding = graph._cells_to_finding(req_id, requirement, response, evidence)
        store.write_finding(target.framework_id, req_id, finding.model_dump())
        refilled.append(req_id)
        sections.extend(
            [
                f"### {req_id}: {finding.title or requirement.title}",
                "",
                f"- **Status:** `{finding.status}`",
                f"- **Observation:** {finding.evidence or '—'}",
                f"- **Recommendation:** {finding.remediation or '—'}",
                "",
            ]
        )

    store.write_run_meta(
        last_followup="refill_finding",
        last_followup_at=datetime.now(timezone.utc).isoformat(),
        revised_reqs=refilled or target.req_ids,
        followup_framework=target.framework_id,
        followup_host=target.host_id or "",
    )
    sections.extend(
        [
            "---",
            "",
            "You may review **another REQ** next, or ask **Update the report** "
            "to regenerate the full Markdown / ZIP.",
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
        "mode": "refill_finding",
        "revised_reqs": refilled,
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
            from auditor.frameworks import route_framework

            routed = route_framework(user_request, settings.agents_dir)
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
        bare_fw = checklist_framework_id(fw_id)
        fw = get_framework(bare_fw, settings.agents_dir)
        title = fw.title if fw else bare_fw
        requirements = {}
        if fw is not None:
            checklist = load_framework_checklist(fw)
            requirements = {r.id: r for r in checklist.requirements}
            title = checklist.title or title
        host_part, _ = split_evidence_framework_key(fw_id)
        if host_part:
            title = f"{host_part} — {title}"

        raw_findings = store.load_findings(fw_id)
        findings: dict[str, Finding] = {}
        for req_id, payload in raw_findings.items():
            try:
                findings[req_id] = Finding.model_validate(payload)
            except Exception:  # noqa: BLE001
                continue

        if not findings and not requirements:
            continue

        meta = store.read_run_meta()
        lang_code = str(meta.get("report_language") or "").strip()
        if lang_code:
            report_lang_code = lang_code
            report_lang_name = language_name(lang_code)
        else:
            detected = detect_report_language(user_request)
            report_lang_code = detected.code
            report_lang_name = detected.name
        lang_instr = language_instruction(report_lang_name)
        full_report = render_report(
            title, findings, requirements or None, language=report_lang_code
        )
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
                            "original audit; summarize the current findings only. "
                            f"{lang_instr}"
                        )
                    ),
                    HumanMessage(
                        content=FINALIZE_PROMPT.format(
                            report=digest,
                            report_language=report_lang_name,
                            language_instruction=lang_instr,
                        )
                    ),
                ]
            )
            summary = str(response.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            summary = f"(Summary generation failed: {exc})"

        body = f"{summary}\n\n---\n\n{full_report}"
        if settings.compliance_charts_in_report:
            try:
                body = (
                    f"{body.rstrip()}\n"
                    f"{format_compliance_markdown(full_report, language=report_lang_code)}"
                )
            except Exception:  # noqa: BLE001
                pass
        header = (
            f"Framework: `{fw_id}` | report rebuilt from evidence "
            f"(run `{store.run_id}`, via {source})\n\n"
        )
        final_text = f"{header}{body}"
        store.write_report(fw_id, final_text)
        completed.append((fw_id, title, final_text))

        evidence_rel = ""
        try:
            evidence_rel = str(
                store.root.relative_to(Path(settings.evidence_dir).resolve())
            )
        except ValueError:
            evidence_rel = str(store.root)
        client = str(meta.get("client_name") or store.run_id or "")
        session_number = None
        raw_sess = meta.get("results_session_number")
        if raw_sess is not None:
            try:
                session_number = int(raw_sess)
            except (TypeError, ValueError):
                session_number = None
        await record_results_safe(
            settings,
            client_name=client,
            evidence_run_id=store.run_id,
            framework_id=fw_id,
            evidence_host_id=host_part,
            findings=findings,
            requirements=requirements or None,
            evidence_relpath=evidence_rel,
            source="update_report",
            report_language=report_lang_code or None,
            session_number=session_number,
        )

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
        parts = [
            f"## {title} (`{fw_id}`)\n\n{body}" for fw_id, title, body in completed
        ]
        combined = "# Multi-framework report update\n\n" + "\n\n---\n\n".join(parts)

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
    )
    store.write_root_report(combined)
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
