"""Ad-hoc audit command execution (operator-requested SSH / SQL / playbooks).

This module implements the **freeform command** path in the auditor pipeline.
Unlike the checklist graph, it does **not** load a framework report or iterate
over requirements. Instead it runs tools the operator explicitly asked for
and returns a Markdown result block suitable for chat UIs.

Pipeline role:
    Invoked when the operator issues a one-off command request (e.g. "run
    ``cat /etc/ssh/sshd_config`` on the host") rather than a full CIS audit.
    Evidence is written under ``<evidence_dir>/<run_id>/<framework>/CMD-*/`` or
    appended to an existing checklist run when one is found on disk.

Key entry points:
    :func:`run_adhoc_commands` — main async handler; chooses playbook vs LLM path.
    :func:`_playbook_hint` — resolves REQ-* ids to stored playbook tool recipes.
    :func:`_format_adhoc_report` — wraps tool output in a chat-ready Markdown block.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from auditor.context import count_tool_rounds, truncate_text
from auditor.evidence_store import EvidenceStore, new_run_id
from auditor.frameworks import route_framework
from auditor.intent import extract_req_ids
from auditor.language import detect_report_language, language_instruction
from auditor.prompts import ADHOC_FORCE_PROMPT, ADHOC_USER_PROMPT
from auditor.run_resolve import latest_run_id

if TYPE_CHECKING:
    from auditor.graph import AuditorGraph

_CODE_FENCE = re.compile(r"```(?:bash|sh|shell|sql|powershell)?\s*\n(.*?)```", re.I | re.S)


def _playbook_hint(graph: AuditorGraph, user_text: str) -> tuple[str, str, list[str]]:
    """Build playbook guidance when the operator names REQ-* requirement ids.

    Extracts requirement ids from ``user_text``, routes to a framework when
    possible, and formats stored playbook tool blocks for the LLM or for
    deterministic execution in :func:`run_adhoc_commands`.

    Args:
        graph: Active auditor graph; supplies playbooks registry and settings.
        user_text: Raw operator message (may contain ``REQ-001`` etc.).

    Returns:
        A 3-tuple ``(hint_markdown, framework_id, req_ids)`` where
        ``hint_markdown`` is Markdown for the prompt (or empty when no playbooks
        apply), ``framework_id`` is the routed framework id (or ``""``), and
        ``req_ids`` is the list of extracted requirement ids (possibly empty).
    """
    req_ids = extract_req_ids(user_text)
    if not req_ids or graph.playbooks is None:
        return "", "", req_ids

    try:
        fw = route_framework(user_text, graph.settings.agents_dir)
        framework_id = fw.id
    except FileNotFoundError:
        framework_id = ""

    if not framework_id:
        return "", "", req_ids

    blocks: list[str] = []
    for req_id in req_ids:
        block = graph.playbooks.format_prompt_block(framework_id, req_id)
        if block and "no playbook" not in block.lower():
            blocks.append(f"### {framework_id} / {req_id}\n{block}")
    if not blocks:
        return (
            f"Operator named {', '.join(req_ids)} for `{framework_id}` but no "
            "playbook tools are stored yet — infer sensible commands.",
            framework_id,
            req_ids,
        )
    hint = (
        "Preferred playbook commands for the named requirement(s) "
        "(run these first):\n\n" + "\n\n".join(blocks)
    )
    return hint, framework_id, req_ids


async def run_adhoc_commands(graph: AuditorGraph, user_text: str) -> dict[str, Any]:
    """Execute operator-requested tools and return a chat-ready result dict.

    Resolves or creates an evidence run (preferring attachment to the latest
    checklist audit when present), then either:

    1. **Playbook path** — when REQ-* ids map to stored playbook tools, runs
       those tools deterministically and asks the fill model for a summary.
    2. **Freeform path** — otherwise uses the evidence model in a short
       tool-calling loop guided by :mod:`auditor.prompts` ad-hoc templates.

    Args:
        graph: Auditor graph with models, tools, and settings.
        user_text: Operator command request (may include REQ ids or fenced code).

    Returns:
        Dict with keys ``report``, ``messages``, ``framework_id``,
        ``evidence_run_id``, ``evidence_run_dir``, ``awaiting_hitl``,
        ``adhoc``, and ``mode`` (``"playbook"`` or ``"freeform"``).
    """
    settings = graph.settings
    user_request = truncate_text(
        user_text,
        settings.max_user_request_chars,
        "user_request",
    )
    report_lang = detect_report_language(user_request)
    lang_instr = language_instruction(report_lang)

    # Prefer appending into the latest checklist audit run when one exists.
    prior_run = latest_run_id(settings.evidence_dir)
    attached_to_prior = False
    if prior_run:
        try:
            store = EvidenceStore.open_existing(settings.evidence_dir, prior_run)
            meta = store.read_run_meta()
            frameworks = [
                str(x)
                for x in (meta.get("frameworks") or store.list_framework_ids())
                if x and x != "adhoc"
            ]
            if frameworks or store.list_framework_ids():
                attached_to_prior = True
                run_id = store.run_id
                graph._evidence_by_run[run_id] = store
                store.write_run_meta(
                    last_followup="adhoc_command",
                    last_followup_at=datetime.now(timezone.utc).isoformat(),
                    report_language=meta.get("report_language") or report_lang.code,
                )
            else:
                store = None  # type: ignore[assignment]
        except FileNotFoundError:
            store = None  # type: ignore[assignment]
    else:
        store = None  # type: ignore[assignment]

    if not attached_to_prior or store is None:
        run_id = new_run_id()
        store = EvidenceStore(settings.evidence_dir, run_id=run_id)
        graph._evidence_by_run[run_id] = store
        store.write_run_meta(
            user_request=user_request,
            frameworks=["adhoc"],
            thread_id=f"adhoc-{run_id}",
            report_language=report_lang.code,
        )

    hint, framework_id, req_ids = _playbook_hint(graph, user_request)
    if attached_to_prior and (not framework_id or framework_id == "adhoc"):
        prior_fws = store.list_framework_ids()
        if len(prior_fws) == 1:
            framework_id = prior_fws[0]
        elif prior_fws:
            framework_id = prior_fws[0]
        else:
            framework_id = "adhoc"
    framework_id = framework_id or "adhoc"
    if req_ids:
        req_label = req_ids[0]
    elif attached_to_prior:
        # Store freeform post-audit commands under a dedicated CMD bucket.
        existing = [
            p.name
            for p in (store.root / framework_id).glob("CMD-*")
            if p.is_dir()
        ] if (store.root / framework_id).is_dir() else []
        next_n = len(existing) + 1
        req_label = f"CMD-{next_n:03d}"
    else:
        req_label = "CMD-001"

    # Deterministic path: execute stored playbook tools for named REQs.
    playbook_ran = False
    tool_chunks: list[str] = []
    if req_ids and graph.playbooks is not None and framework_id != "adhoc":
        for req_id in req_ids:
            entry = graph.playbooks.get_entry(framework_id, req_id)
            tools = list(entry.get("tools") or []) if isinstance(entry, dict) else []
            if not tools:
                continue
            playbook_ran = True
            synthetic_calls = [
                {
                    "name": t.get("name") or "",
                    "args": t.get("arguments") or t.get("args") or {},
                    "id": f"playbook-{req_id}-{i}",
                }
                for i, t in enumerate(tools)
                if t.get("name")
            ]
            if not synthetic_calls:
                continue
            store.write_requirement(
                framework_id,
                req_id,
                {"id": req_id, "source": "adhoc_playbook", "title": "Ad-hoc playbook run"},
            )
            tool_messages = await graph._execute_tool_calls(
                synthetic_calls,
                framework_id=framework_id,
                req_id=req_id,
                store=store,
            )
            for tm in tool_messages:
                tool_chunks.append(f"### `{tm.name}` ({req_id})\n```\n{tm.content}\n```")

    if playbook_ran and tool_chunks:
        summary_messages = [
            SystemMessage(
                content=(
                    "You summarize ad-hoc audit command results. "
                    "Do not invent output. Reply in Markdown. "
                    f"{lang_instr}"
                )
            ),
            HumanMessage(
                content=(
                    f"Language: {report_lang.name}\n{lang_instr}\n\n"
                    f"Operator request:\n{user_request}\n\n"
                    f"Command results:\n\n" + "\n\n".join(tool_chunks)
                )
            ),
        ]
        response = await graph.fill_model.ainvoke(summary_messages)
        body = str(response.content or "").strip() or "\n\n".join(tool_chunks)
        report = _format_adhoc_report(
            user_request,
            body,
            run_id=run_id,
            attached_to_prior=attached_to_prior,
            framework_id=framework_id,
            req_label=req_label,
        )
        store.write_finding(
            framework_id,
            req_label,
            {"status": "executed", "observation": body[:2000], "mode": "playbook"},
        )
        return {
            "report": report,
            "messages": [AIMessage(content=report)],
            "framework_id": framework_id,
            "evidence_run_id": run_id,
            "evidence_run_dir": str(store.root),
            "awaiting_hitl": False,
            "adhoc": True,
            "mode": "playbook",
        }

    # Freeform path: LLM chooses tools from the operator request.
    messages: list = [
        HumanMessage(
            content=ADHOC_USER_PROMPT.format(
                report_language=report_lang.name,
                language_instruction=lang_instr,
                user_request=user_request,
                playbook_hint=hint or "(no playbook hint)",
            )
        ),
    ]
    chunks: list[str] = []
    max_rounds = settings.max_tool_rounds_per_item
    store.write_requirement(
        framework_id,
        req_label,
        {"id": req_label, "source": "adhoc_freeform", "title": "Ad-hoc command run"},
    )

    for _ in range(max_rounds + 1):
        rounds = count_tool_rounds(messages)
        if rounds >= max_rounds:
            messages.append(
                HumanMessage(
                    content=ADHOC_FORCE_PROMPT.format(language_instruction=lang_instr)
                )
            )
            response = await graph.fill_model.ainvoke(messages)
            chunks.append(str(response.content or ""))
            break

        response = await graph.evidence_model.ainvoke(messages)
        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            chunks.append(str(response.content or ""))
            break

        tool_messages = await graph._execute_tool_calls(
            tool_calls,
            framework_id=framework_id,
            req_id=req_label,
            store=store,
        )
        messages.extend(tool_messages)
        for tm in tool_messages:
            chunks.append(f"[{tm.name}] {tm.content}")

    body = "\n\n".join(c.strip() for c in chunks if c and c.strip()) or (
        "No tool output was produced. Check SSH/Postgres credentials and rephrase "
        "the command request."
    )
    # If the model never called tools but the user pasted a fenced command,
    # surface that we expected tool use (helps debugging).
    if not any(c.startswith("[") for c in chunks) and _CODE_FENCE.search(user_request):
        body = (
            f"{body}\n\n_Note: a fenced command was present in the request; "
            "if nothing ran, verify SSH/MCP connectivity._"
        )

    report = _format_adhoc_report(
        user_request,
        body,
        run_id=run_id,
        attached_to_prior=attached_to_prior,
        framework_id=framework_id,
        req_label=req_label,
    )
    store.write_finding(
        framework_id,
        req_label,
        {"status": "executed", "observation": body[:2000], "mode": "freeform"},
    )
    return {
        "report": report,
        "messages": [AIMessage(content=report)],
        "framework_id": framework_id,
        "evidence_run_id": run_id,
        "evidence_run_dir": str(store.root),
        "awaiting_hitl": False,
        "adhoc": True,
        "mode": "freeform",
    }


def _format_adhoc_report(
    user_request: str,
    body: str,
    *,
    run_id: str,
    attached_to_prior: bool = False,
    framework_id: str = "adhoc",
    req_label: str = "CMD-001",
) -> str:
    """Wrap ad-hoc command output in a standard Markdown report section.

    Args:
        user_request: Original operator text (truncated in the header).
        body: Main result content (tool output or LLM summary).
        run_id: Evidence run folder id.
        attached_to_prior: When True, note that evidence was appended to a prior run.
        framework_id: Framework or host/framework key under the run.
        req_label: Requirement or CMD bucket label (e.g. ``CMD-001``).

    Returns:
        Markdown string with heading, request echo, body, and evidence location.
    """
    where = (
        f"Appended to prior audit run `{run_id}` → "
        f"`{framework_id}/{req_label}/`"
        if attached_to_prior
        else f"Evidence run: `{run_id}`"
    )
    return (
        "## Ad-hoc command results\n\n"
        f"**Request:** {user_request.strip()[:400]}\n\n"
        f"{body.strip()}\n\n"
        f"_{where}_\n"
    )
