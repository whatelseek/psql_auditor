"""Post-audit follow-up: gather evidence, refill cells, rebuild reports.

This module implements the **post-checklist** operator workflow after an initial
audit completes. It supports incremental evidence collection, rewriting finding
cells from stored tool logs, and regenerating Markdown reports plus archives.

Pipeline role:
    Called from the graph when intent routing detects follow-up phrases such as
    "Evaluate REQ-001", "Prepare new observation", or "Update the report".
    All operations target an **existing** evidence run resolved via
    :mod:`auditor.run_resolve`.

Key entry points:
    :func:`run_revise_req` — gather more evidence (optionally full cell rewrite).
    :func:`run_refill_finding` — rewrite observation/recommendation from disk only.
    :func:`run_update_report` — rebuild ``report.md`` and optional ZIP archive.
    :func:`followup_footer` — operator hint appended after checklist completion.
"""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Sequence

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from auditor.anonymization import (
    ReversibleAnonymizer,
    anonymize_directory_tree,
    write_mapping_file,
)
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
from auditor.results_store import (
    record_requirement_result_safe,
    record_results_safe,
)
from auditor.run_resolve import (
    ResolvedTarget,
    checklist_framework_id,
    resolve_target,
    split_evidence_framework_key,
)
from auditor.runtime_target import bind_runtime_credentials
from auditor.secrets_file import (
    InventorySshTarget,
    bind_ssh_target,
    list_client_access_endpoints,
    list_client_ssh_targets,
    read_client_credentials,
)
from auditor.state import Finding, render_report

if TYPE_CHECKING:
    from auditor.graph import AuditorGraph

_FOLLOWUP_FOOTER = (
    "\n\n---\n\n"
    "Need anonymized copy? Reply "
    "`Anonymize the report domain=example.com` / "
    "`Анонимизируй отчёт домен example.com` "
    "to create `<client>_anon` with reversible mapping.\n"
)


def followup_footer() -> str:
    """Return the short post-audit hint (anonymization only).

    Appended to completed checklist audit reports.

    Returns:
        Markdown footer with anonymize instruction (EN/RU examples).
    """
    return _FOLLOWUP_FOOTER


def _resolve_ssh_target(
    *,
    inventory_dir: Path,
    client_run_id: str,
    host_id: str | None,
) -> InventorySshTarget | None:
    """Match an inventory SSH row for a multi-host evidence host slug.

    Looks up SSH credentials from ``inventory/<client>/INVENTORY.md`` and
    matches by exact slug/host or partial substring.

    Args:
        inventory_dir: Root inventory directory from settings.
        client_run_id: Client or evidence run folder name.
        host_id: Host hint from evidence key (IP, hostname, or slug).

    Returns:
        Matching :class:`~auditor.secrets_file.InventorySshTarget`, or
        ``None`` when ``host_id`` is empty or no row matches.
    """
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
    """Temporarily bind run-scoped SSH/PG credentials for tool calls.

    Resolves the inventory SSH target for ``target.host_id`` and enters
    :func:`~auditor.secrets_file.bind_ssh_target` (ContextVar) for the duration
    of the context. Also binds client inventory PostgreSQL credentials when the
    client slug is known. When ``host_id`` is empty (single-host runs such as
    ``it_audit``), falls back to the first SSH row in the client inventory.

    Args:
        settings: Auditor settings (``inventory_dir``).
        target: Resolved evidence target including run id and host slug.

    Yields:
        Bound :class:`~auditor.secrets_file.InventorySshTarget`, or ``None``.
    """
    from contextlib import ExitStack

    ssh = _resolve_ssh_target(
        inventory_dir=settings.inventory_dir,
        client_run_id=target.run_id,
        host_id=target.host_id,
    )
    if ssh is None and not target.host_id:
        try:
            targets = list_client_ssh_targets(settings.inventory_dir, target.run_id)
        except (OSError, ValueError, FileNotFoundError):
            targets = []
        ssh = targets[0] if targets else None

    with ExitStack() as stack:
        try:
            creds = read_client_credentials(settings.inventory_dir, target.run_id)
        except (OSError, ValueError, FileNotFoundError):
            creds = {}
        if creds:
            stack.enter_context(bind_runtime_credentials(creds))
        if ssh is not None:
            stack.enter_context(bind_ssh_target(ssh))
            yield ssh
        else:
            yield None


async def run_revise_req(
    graph: AuditorGraph,
    user_text: str,
    *,
    messages: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Gather more evidence for REQ(s) into the **existing** audit folder.

    By default this is **evidence-only** (tools are stored; finding cells keep
    prior values). When the operator says ``revise`` / ``reassess`` /
    ``re-audit``, observation + recommendation are also rewritten immediately
    via :meth:`AuditorGraph._fill_requirement_cells`.

    Falls back to :func:`~auditor.adhoc.run_adhoc_commands` when no prior
    checklist run exists on disk.

    Args:
        graph: Auditor graph with models and tool execution.
        user_text: Operator message naming REQ id(s) and optional host/framework.
        messages: Optional chat history for run-id resolution.

    Returns:
        Result dict with ``report``, ``messages``, ``followup=True``,
        ``mode`` (``gather_evidence`` or ``revise_full``), and ``revised_reqs``.
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
        "## Post-audit evidence collection" if not full else "## Post-audit requirement revision",
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
                sections.append(f"Requirement `{req_id}` is not in checklist `{fw.id}` — skipped.")
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
                        (
                            "- **Observation:** "
                            + str(
                                getattr(finding, "observation", None)
                                or getattr(finding, "evidence", None)
                                or "—"
                            )
                        ),
                        (
                            "- **Recommendation:** "
                            + str(
                                getattr(finding, "recommendation", None)
                                or getattr(finding, "remediation", None)
                                or "—"
                            )
                        ),
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
    """Rewrite status / observation / recommendation from **stored** evidence only.

    Loads concatenated tool logs from :class:`~auditor.evidence_store.EvidenceStore`
    and invokes the fill model — **no new SSH/MCP commands** are executed.

    When no REQ id is named, refills only requirements listed in run meta
    ``revised_reqs`` from a prior gather step.

    Args:
        graph: Auditor graph (fill model required).
        user_text: Operator message; may name REQ id(s) and framework/host.
        messages: Optional chat history for run resolution.

    Returns:
        Result dict with ``mode="refill_finding"``, ``revised_reqs``, and
        per-requirement status/observation/recommendation in ``report``.
    """
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
        msg = f"Framework `{bare_fw}` (from `{target.framework_id}`) not found under agents/."
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
            SystemMessage(content=FILL_SYSTEM_PROMPT.format(language_instruction=lang_instr)),
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
        from auditor.result_identity_bind import attach_result_identity

        finding = attach_result_identity(
            finding,
            state={
                "client_id": str(meta.get("client_id") or ""),
                "client_name": str(meta.get("client_name") or ""),
                "audit_run_id": str(meta.get("audit_run_id") or ""),
                "asset_id": str(meta.get("asset_id") or ""),
                "framework_version": str(meta.get("framework_version") or ""),
            },
            framework_id=target.framework_id,
            framework_version=str(meta.get("framework_version") or ""),
        )
        from auditor.domain.assessment_result import AssessmentResult as _AR

        _payload = (
            finding.to_persist_dict()
            if isinstance(finding, _AR)
            else _AR.from_finding(finding).to_persist_dict()
        )
        store.write_finding(target.framework_id, req_id, _payload)
        session_number = None
        raw_sess = meta.get("results_session_number")
        if raw_sess is not None:
            try:
                session_number = int(raw_sess)
            except (TypeError, ValueError):
                session_number = None
        evidence_rel = ""
        try:
            evidence_rel = str(store.root.relative_to(Path(settings.evidence_dir).resolve()))
        except ValueError:
            evidence_rel = str(store.root)
        await record_requirement_result_safe(
            settings,
            client_name=str(meta.get("client_name") or store.run_id),
            evidence_run_id=store.run_id,
            framework_id=target.framework_id,
            evidence_host_id=target.host_id or None,
            finding=finding,
            requirement=requirement,
            evidence_relpath=evidence_rel,
            source="refill",
            session_number=session_number,
            audit_run_id=str(finding.audit_run_id or meta.get("audit_run_id") or ""),
            client_id=str(finding.client_id or meta.get("client_id") or ""),
        )
        refilled.append(req_id)
        sections.extend(
            [
                f"### {req_id}: {finding.title or requirement.title}",
                "",
                f"- **Status:** `{finding.status}`",
                (
                    "- **Observation:** "
                    + str(
                        getattr(finding, "observation", None)
                        or getattr(finding, "evidence", None)
                        or "—"
                    )
                ),
                (
                    "- **Recommendation:** "
                    + str(
                        getattr(finding, "recommendation", None)
                        or getattr(finding, "remediation", None)
                        or "—"
                    )
                ),
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
    """Rebuild Markdown report(s) from on-disk ``finding.json`` files.

    For each framework folder in the resolved evidence run:

    1. Loads findings and checklist metadata.
    2. Renders the deterministic report body via :func:`~auditor.state.render_report`.
    3. Generates a short executive summary with the fill model.
    4. Optionally appends compliance charts and packages a ZIP archive.
    5. Records results in the PostgreSQL warehouse when enabled.

    Args:
        graph: Auditor graph (fill model for summary).
        user_text: Operator message; may filter to one framework or name run id.
        messages: Optional chat history for run-id extraction.

    Returns:
        Result dict with combined ``report``, ``archive_path`` / ``archive_url``
        when archiving is enabled, and ``mode="update_report"``.
    """
    settings = graph.settings
    user_request = truncate_text(
        user_text,
        settings.max_user_request_chars,
        "user_request",
    )
    try:
        # require_req=False — update whole run (or named framework).
        from auditor.evidence_store import EvidenceStore
        from auditor.run_resolve import (
            extract_run_id,
            extract_run_id_from_messages,
            resolve_framework_for_req,
        )

        run_id = extract_run_id(user_request, evidence_dir=settings.evidence_dir)
        source = "explicit"
        if not run_id and messages:
            run_id = extract_run_id_from_messages(messages, evidence_dir=settings.evidence_dir)
            if run_id:
                source = "history"
        if not run_id:
            raise FileNotFoundError(
                "No audit_run_id in your message or chat history. "
                "Include an explicit `arun_…` id (CORE-001: no latest-run fallback)."
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
        frameworks = [str(x) for x in (meta.get("frameworks") or []) if x and x != "adhoc"]

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
        for _key, payload in raw_findings.items():
            try:
                finding = Finding.model_validate(payload)
                key = finding.result_id or finding.requirement_id
                if key:
                    findings[key] = finding
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
            evidence_rel = str(store.root.relative_to(Path(settings.evidence_dir).resolve()))
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
            audit_run_id=str(meta.get("audit_run_id") or ""),
            client_id=str(meta.get("client_id") or ""),
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
        parts = [f"## {title} (`{fw_id}`)\n\n{body}" for fw_id, title, body in completed]
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


def _literal_groups_for_anonymization(
    *,
    settings: Any,
    run_id: str,
    meta: dict[str, Any],
    domain_name: str,
) -> dict[str, set[str]]:
    """Collect known identifiers for deterministic literal masking."""
    groups: dict[str, set[str]] = {
        "CLIENT": set(),
        "HOST": set(),
        "USER": set(),
        "EMAIL": set(),
        "DOMAIN": set(),
    }
    for key, kind in (
        ("client_name", "CLIENT"),
        ("client_slug", "CLIENT"),
        ("run_id", "CLIENT"),
        ("ssh_user", "USER"),
        ("ssh_host", "HOST"),
        ("hostname", "HOST"),
    ):
        value = str(meta.get(key) or "").strip()
        if value:
            groups[kind].add(value)
    groups["CLIENT"].add(run_id)
    groups["DOMAIN"].add(domain_name.strip().lower())
    # Inventory has the best source for host/user/email values.
    try:
        for target in list_client_ssh_targets(settings.inventory_dir, run_id):
            if target.host:
                groups["HOST"].add(target.host)
            if target.user:
                groups["USER"].add(target.user)
    except (OSError, ValueError, FileNotFoundError):
        pass
    try:
        for endpoint in list_client_access_endpoints(settings.inventory_dir, run_id):
            host = str(endpoint.get("host") or "").strip()
            if host:
                groups["HOST"].add(host)
    except (OSError, ValueError, FileNotFoundError):
        pass
    try:
        creds = read_client_credentials(settings.inventory_dir, run_id)
    except (OSError, ValueError, FileNotFoundError):
        creds = {}
    for key, value in creds.items():
        text = str(value or "").strip()
        if not text:
            continue
        low = key.lower()
        if "mail" in low or "email" in low:
            groups["EMAIL"].add(text)
        elif "user" in low or "login" in low:
            groups["USER"].add(text)
        elif "host" in low or "addr" in low:
            groups["HOST"].add(text)
        elif "client" in low or "company" in low or "name" in low:
            groups["CLIENT"].add(text)
    return groups


def _extract_domain_name(user_text: str, meta: dict[str, Any]) -> str | None:
    """Parse anonymization domain from operator request or run metadata."""
    patterns = (
        re.compile(
            r"\b(?:domain|домен)\s*(?:name)?\s*[:=]\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
            re.I,
        ),
        re.compile(
            r"\b(?:domain|домен)\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
            re.I,
        ),
    )
    for pattern in patterns:
        match = pattern.search(user_text or "")
        if match:
            return match.group(1).lower()
    for key in ("anonymization_domain", "domain_name", "domain"):
        value = str(meta.get(key) or "").strip().lower()
        if value and "." in value:
            return value
    return None


async def run_anonymize_report(
    graph: AuditorGraph,
    user_text: str,
    *,
    messages: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Create `<run_id>_anon` copy with reversible anonymized artifacts."""
    settings = graph.settings
    user_request = truncate_text(
        user_text,
        settings.max_user_request_chars,
        "user_request",
    )
    del user_request
    try:
        from auditor.evidence_store import EvidenceStore
        from auditor.run_resolve import (
            extract_run_id,
            extract_run_id_from_messages,
        )

        run_id = extract_run_id(user_text, evidence_dir=settings.evidence_dir)
        if not run_id and messages:
            run_id = extract_run_id_from_messages(messages, evidence_dir=settings.evidence_dir)
        if not run_id:
            raise FileNotFoundError(
                "No audit_run_id in your message or chat history. "
                "Include an explicit `arun_…` id (CORE-001: no latest-run fallback)."
            )
        source = EvidenceStore.open_existing(settings.evidence_dir, run_id)
    except FileNotFoundError as exc:
        return {
            "report": str(exc),
            "messages": [AIMessage(content=str(exc))],
            "error": str(exc),
            "followup": True,
        }

    anon_run_id = f"{source.run_id}_anon"
    anon_root = Path(settings.evidence_dir) / anon_run_id
    anonymizer = ReversibleAnonymizer()
    meta = source.read_run_meta()
    domain_name = _extract_domain_name(user_text, meta)
    if not domain_name:
        msg = (
            "Set a domain name for anonymization and retry, for example:\n\n"
            "- `Anonymize the report domain=example.com`\n"
            "- `Анонимизируй отчёт домен example.com`\n\n"
            "Domain is required to anonymize hostnames/FQDNs consistently."
        )
        return {
            "report": msg,
            "messages": [AIMessage(content=msg)],
            "error": "missing_anonymization_domain",
            "followup": True,
        }
    literals = _literal_groups_for_anonymization(
        settings=settings,
        run_id=source.run_id,
        meta=meta,
        domain_name=domain_name,
    )
    anonymize_directory_tree(
        source.root,
        anon_root,
        anonymizer=anonymizer,
        literal_groups=literals,
    )
    mapping_path = write_mapping_file(anon_root, anonymizer)

    # Keep anonymized run detached from warehouse tracking.
    anon_meta_path = anon_root / "meta.json"
    if anon_meta_path.is_file():
        try:
            anon_meta = json.loads(anon_meta_path.read_text(encoding="utf-8"))
            if isinstance(anon_meta, dict):
                anon_meta.pop("results_session_number", None)
                anon_meta["run_id"] = anon_run_id
                anon_meta["anonymized"] = True
                anon_meta["anonymized_from"] = source.run_id
                anon_meta["anonymization_domain"] = domain_name
                anon_meta["anonymization_mapping_file"] = mapping_path.name
                anon_meta_path.write_text(
                    json.dumps(anon_meta, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
        except (OSError, json.JSONDecodeError):
            pass

    root_report = anon_root / "report.md"
    if root_report.is_file():
        try:
            from auditor.report_exports import write_report_exports

            write_report_exports(
                anon_root,
                root_report.read_text(encoding="utf-8"),
            )
        except Exception:  # noqa: BLE001
            pass

    archive_path = ""
    archive_url = ""
    report = (
        "## Anonymized copy created\n\n"
        f"- Source run: `{source.run_id}`\n"
        f"- Anonymized run: `{anon_run_id}`\n"
        f"- Folder: `{anon_root}`\n"
        f"- Mapping file: `{mapping_path}`\n\n"
        "Regex anonymization applied for IPs/emails plus deterministic "
        "literal replacements for known client/host/user identifiers.\n"
    )
    if settings.archive_enabled:
        try:
            packaged = await package_and_publish_archive(anon_root, settings)
            archive_path = str(packaged.get("zip_path") or "")
            archive_url = str(packaged.get("download_url") or "")
            report = f"{report.rstrip()}\n{packaged.get('chat_section') or ''}"
        except Exception as exc:  # noqa: BLE001
            report = (
                f"{report.rstrip()}\n\n---\n\n"
                f"(Archive packaging failed: {type(exc).__name__}: {exc})\n"
            )

    return {
        "report": report,
        "messages": [AIMessage(content=report)],
        "framework_id": "",
        "evidence_run_id": anon_run_id,
        "evidence_run_dir": str(anon_root),
        "archive_path": archive_path,
        "archive_url": archive_url,
        "awaiting_hitl": False,
        "followup": True,
        "mode": "anonymize_report",
    }
