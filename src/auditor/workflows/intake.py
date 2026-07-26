"""Pre-audit intake questionnaire workflow node."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.types import interrupt

from auditor.access_probe import probe_access_endpoints, probe_access_services
from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry
from auditor.evidence_store import client_artifacts_id
from auditor.frameworks import get_framework, prefer_framework_ids, select_frameworks_for_host
from auditor.host_facts import resolve_client_dir, resolve_client_inventory
from auditor.intake import (
    client_slug,
    enrich_facts_from_access_rows,
    filter_scope_framework_ids,
    format_host_access_list_markdown,
    format_proposed_jobs_markdown,
    intake_clarification_from_payload,
    intake_interrupt_payload,
    load_client_audit_plan,
    looks_like_plan_file_notice,
    normalize_scope_jobs,
    parse_audit_plan_markdown,
    parse_client_name,
    prompts_for_language,
    resolve_audit_type,
    resolve_scope_decision,
    resolve_yes_no,
)
from auditor.prompts import (
    INTAKE_INTERPRET_AUDIT_TYPE_PROMPT,
    INTAKE_INTERPRET_AUDIT_TYPE_SYSTEM,
    INTAKE_INTERPRET_CLIENT_PROMPT,
    INTAKE_INTERPRET_CLIENT_SYSTEM,
    INTAKE_INTERPRET_SCOPE_PROMPT,
    INTAKE_INTERPRET_SCOPE_SYSTEM,
    INTAKE_INTERPRET_YES_NO_PROMPT,
    INTAKE_INTERPRET_YES_NO_SYSTEM,
)
from auditor.runtime_target import bind_runtime_credentials, effective_settings
from auditor.secrets_file import list_client_access_endpoints, read_client_credentials
from auditor.state import AuditorState
from auditor.workflows.helpers import _extract_json
from auditor.workflows.protocols import AuditRuntime

async def intake_gate(runtime: AuditRuntime, state: AuditorState) -> dict[str, Any]:
    """Многошаговый предварительный опрос через последовательные interrupt."""
    if not runtime.settings.intake_enabled or state.get("intake_complete"):
        return {"intake_complete": True}

    lang = runtime._report_language(state)
    base_prompts = prompts_for_language(lang.code)
    prompts = base_prompts
    thread_hint = str(state.get("thread_id") or "")
    intake: dict[str, Any] = runtime._load_intake_progress(
        state, thread_id=thread_hint
    )

    # 1) Название клиента (LLM check + convention guard)
    while not intake.get("client_name"):
        raw = interrupt(
            intake_interrupt_payload(step="client_name", prompt=prompts.client)
        )
        name, err = await runtime._intake_resolve_client_name(str(raw or ""))
        if name:
            intake["client_name"] = name
            intake["client_slug"] = client_slug(name)
            from auditor.host_facts import resolve_client_dir

            client_dir = resolve_client_dir(
                Path(runtime.settings.inventory_dir),
                intake["client_slug"],
                display_name=name,
            )
            # Inventory folder for credentials / PLAN.md (display slug only).
            if not client_dir.is_dir():
                client_dir = (
                    Path(runtime.settings.inventory_dir) / client_artifacts_id(name)
                )
            client_dir.mkdir(parents=True, exist_ok=True)

            # CORE-001: durable client_id + new AuditRun for this execution.
            client = get_client_registry(runtime.settings.evidence_dir).ensure_client(
                display_name=name,
                slug=intake["client_slug"],
                client_id=str(intake.get("client_id") or state.get("client_id") or "")
                or None,
            )
            intake["client_id"] = client.client_id
            audit_run_id = str(
                intake.get("audit_run_id") or state.get("audit_run_id") or ""
            ).strip()
            registry = get_audit_registry(runtime.settings.evidence_dir)
            if not audit_run_id:
                arun = registry.create_run(
                    client_id=client.client_id,
                    scope={
                        "client_name": name,
                        "client_slug": client.slug,
                    },
                    evidence_run_id="",
                    base_thread_id=thread_hint or "",
                )
                registry.mark_run_started(arun.audit_run_id)
                audit_run_id = arun.audit_run_id
            intake["audit_run_id"] = audit_run_id

            # Evidence root = <client_slug>/<audit_run_id> (never client name alone).
            evidence_key = f"{client.slug}/{audit_run_id}"
            store = runtime._store_from_state(state)
            if store is not None:
                old_id = store.run_id
                store.rebind_run_id(evidence_key)
                runtime._evidence_by_run.pop(old_id, None)
                runtime._evidence_by_run[store.run_id] = store
                runtime._evidence_by_run[old_id] = store
                for sess in runtime._multi_sessions.values():
                    if sess.get("run_id") == old_id:
                        sess["run_id"] = store.run_id
                        sess["audit_run_id"] = audit_run_id
                intake["artifacts_run_id"] = store.run_id
                state["evidence_run_id"] = store.run_id  # type: ignore[typeddict-item]
                state["evidence_run_dir"] = str(store.root)  # type: ignore[typeddict-item]
                state["client_id"] = client.client_id  # type: ignore[typeddict-item]
                state["audit_run_id"] = audit_run_id  # type: ignore[typeddict-item]
                store.write_run_meta(
                    client_id=client.client_id,
                    client_name=name,
                    client_slug=client.slug,
                    audit_run_id=audit_run_id,
                    status="running",
                )
                # Keep AuditRun.evidence_run_id in sync with nested path.
                run_row = registry.get_run(audit_run_id)
                if run_row is not None:
                    run_row.evidence_run_id = store.run_id
                    registry.save_run(run_row)

            applied = read_client_credentials(
                runtime.settings.inventory_dir,
                intake["client_slug"],
            )
            intake["credentials_loaded"] = sorted(applied.keys())
            runtime._persist_intake_progress(
                state, intake, thread_id=thread_hint
            )
            break
        if lang.code.startswith("ru"):
            if err == "invalid_chars":
                hint = (
                    "\n\n_Неверный формат: используйте только латинские буквы, "
                    "цифры и `_`, без пробелов и спецсимволов._"
                )
            elif err == "empty":
                hint = "\n\n_Укажите непустое название клиента._"
            else:
                hint = "\n\n_Название клиента не соответствует правилам._"
        else:
            if err == "invalid_chars":
                hint = (
                    "\n\n_Invalid format: use only Latin letters, digits, and `_`, "
                    "with no spaces or special symbols._"
                )
            elif err == "empty":
                hint = "\n\n_Please provide a non-empty client name._"
            else:
                hint = "\n\n_Client name is not compliant with naming convention._"
        prompts = type(base_prompts)(
            client=base_prompts.client + hint,
            cmdb="",
            access=base_prompts.access,
            scope=base_prompts.scope,
            audit_type=base_prompts.audit_type,
        )

    # 2) Доступ — спросить да/нет, затем список достижимости хостов/сервисов (один раз).
    inv_path, scope, found = resolve_client_inventory(
        Path(runtime.settings.inventory_dir),
        str(intake.get("client_slug") or ""),
    )
    intake["has_cmdb"] = False
    intake["cmdb_probe"] = {}
    intake["inventory_scope"] = scope
    intake["inventory_found"] = found
    intake["inventory_path"] = str(inv_path) if inv_path else ""
    runtime._persist_intake_progress(state, intake, thread_id=thread_hint)

    inv_found = bool(intake.get("inventory_found"))
    inv_display_path = intake.get("inventory_path") or ""
    if lang.code.startswith("ru"):
        status = (
            f"**Инвентарник найден:** `{inv_display_path}`"
            if inv_found
            else f"**Инвентарник не найден** по пути `{inv_display_path}`"
        )
    else:
        status = (
            f"**Inventory found:** `{inv_display_path}`"
            if inv_found
            else f"**Inventory not found** at `{inv_display_path}`"
        )
    # Keep this short — a full inventory dump in the prompt confused yes/no.
    scope_block = f"\n\n### Client inventory check\n\n{status}\n"
    access_prompt = f"{prompts.access}{scope_block}"
    while "has_access" not in intake:
        raw = interrupt(
            intake_interrupt_payload(step="access", prompt=access_prompt)
        )
        yn, clarification = await runtime._intake_resolve_yes_no(
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
        runtime._persist_intake_progress(state, intake, thread_id=thread_hint)

    # 2b) Probe endpoints + discover hosts once (skipped on exclude resume).
    if intake.get("has_access") and not intake.get("discovery_complete"):
        slug = str(intake.get("client_slug") or "").strip()
        try:
            creds = (
                read_client_credentials(runtime.settings.inventory_dir, slug)
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
            list_client_access_endpoints(runtime.settings.inventory_dir, slug)
            if slug
            else []
        )
        try:
            host_access_rows = await probe_access_endpoints(endpoints)
        except Exception as exc:  # noqa: BLE001
            host_access_rows = []
            intake["access_list_error"] = f"{type(exc).__name__}: {exc}"
        intake["host_access_rows"] = host_access_rows

        store = runtime._store_from_state(state)
        if store is not None:
            try:
                discovered = await runtime._discover_inventory_hosts(
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
                inv_service_name = ""
                # Prefer explicit service labels from INVENTORY.md (e.g. pg-server, 1c-server)
                # when live hostname discovery is empty.
                for row in host_access_rows:
                    if str(row.get("host") or "") != target.host:
                        continue
                    svc = str(row.get("service") or "").strip()
                    if not svc:
                        continue
                    if not inv_service_name:
                        inv_service_name = svc
                    kind = str(row.get("kind") or "").strip().lower()
                    if kind not in {"pg", "ssh", "winrm"}:
                        inv_service_name = svc
                        break
                display_hostname = (
                    (facts.hostname or "").strip()
                    or inv_service_name
                    or target.host
                    or target.slug
                )
                if facts.error:
                    matched_ids: list[str] = []
                    it_fw = get_framework(
                        "it_audit", runtime.settings.agents_dir
                    )
                    if it_fw is not None:
                        matched_ids = [it_fw.id]
                    for fid in llm_ids:
                        if fid not in matched_ids and get_framework(
                            fid, runtime.settings.agents_dir
                        ):
                            matched_ids.append(fid)
                    # Still match detect rules from enriched ports/binaries.
                    for fw in select_frameworks_for_host(
                        facts,
                        domains=["it", "cybersecurity"],
                        agents_dir=runtime.settings.agents_dir,
                        preferred_language=lang.code,
                    ):
                        if fw.id not in matched_ids:
                            matched_ids.append(fw.id)
                    matched_ids = prefer_framework_ids(
                        matched_ids,
                        agents_dir=runtime.settings.agents_dir,
                        preferred_language=lang.code,
                    )
                    matched_ids = filter_scope_framework_ids(matched_ids)
                    proposed.append(
                        {
                            "host_id": target.slug,
                            "hostname": display_hostname,
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
                        agents_dir=runtime.settings.agents_dir,
                        preferred_language=lang.code,
                    )
                    matched_ids = [fw.id for fw in matched]
                    for fid in llm_ids:
                        if fid not in matched_ids and get_framework(
                            fid, runtime.settings.agents_dir
                        ):
                            matched_ids.append(fid)
                    matched_ids = prefer_framework_ids(
                        matched_ids,
                        agents_dir=runtime.settings.agents_dir,
                        preferred_language=lang.code,
                    )
                    matched_ids = filter_scope_framework_ids(matched_ids)
                    proposed.append(
                        {
                            "host_id": target.slug,
                            "hostname": display_hostname,
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
            intake["proposed_jobs"] = normalize_scope_jobs(proposed)
            intake["host_access_rows"] = host_access_rows
        else:
            intake["proposed_jobs"] = []
        intake["discovery_complete"] = True
        runtime._persist_intake_progress(state, intake, thread_id=thread_hint)
    elif not intake.get("has_access") and not intake.get("discovery_complete"):
        intake["access_probe"] = {
            "services": [],
            "any_ok": False,
            "skipped": True,
        }
        intake["proposed_jobs"] = []
        intake["host_access_rows"] = []
        intake["discovery_complete"] = True
        runtime._persist_intake_progress(state, intake, thread_id=thread_hint)

    proposed_jobs = list(intake.get("proposed_jobs") or [])
    # Prefer operator PLAN.md (host → frameworks) over auto-discovery when present.
    slug = str(
        intake.get("client_slug")
        or client_slug(str(intake.get("client_name") or ""))
    ).strip()
    plan_note = ""
    if slug and "plan_file_checked" not in intake:
        plan_jobs, plan_path = load_client_audit_plan(
            runtime.settings.inventory_dir,
            slug,
            agents_dir=runtime.settings.agents_dir,
        )
        intake["plan_file_checked"] = True
        if plan_path is not None:
            intake["plan_file_path"] = str(plan_path)
        if plan_jobs:
            cleaned_plan = normalize_scope_jobs(plan_jobs)
            if cleaned_plan:
                intake["proposed_jobs"] = cleaned_plan
                proposed_jobs = cleaned_plan
                intake["plan_source"] = "markdown"
                rel = str(plan_path) if plan_path else "PLAN.md"
                plan_note = (
                    f"\n\n_Loaded audit plan from `{rel}` "
                    "(overrides auto-detected frameworks)._\n"
                    if lang.code == "en"
                    else f"\n\n_Загружен план аудита из `{rel}` "
                    "(перекрывает автоопределение фреймворков)._\n"
                )
                runtime._persist_intake_progress(
                    state, intake, thread_id=thread_hint
                )

    has_plan = bool(
        proposed_jobs
        and any((row.get("frameworks") or []) for row in proposed_jobs)
    )
    host_access_md = format_host_access_list_markdown(
        list(intake.get("host_access_rows") or []),
        language=lang.code,
        proposed_jobs=proposed_jobs,
    )

    # 3) Scope: confirm / exclude / include / paste PLAN.md table; after trim, re-confirm.
    if has_plan:
        working_jobs = [dict(r) for r in proposed_jobs]
        original_jobs = [dict(r) for r in proposed_jobs]
        plan_md = format_proposed_jobs_markdown(working_jobs)
        scope_prompt = (
            f"{prompts.scope}{plan_note}\n\n{plan_md}"
        )
        while "selected_jobs" not in intake:
            raw = interrupt(
                intake_interrupt_payload(step="scope", prompt=scope_prompt)
            )
            reply = str(raw or "").strip()
            # Operator pasted a Host|Frameworks markdown plan → replace & re-confirm.
            pasted = parse_audit_plan_markdown(reply)
            if pasted and (
                "|" in reply or reply.lstrip().startswith(("-", "*", "•"))
            ):
                working_jobs = pasted
                intake["proposed_jobs"] = working_jobs
                intake["plan_source"] = "markdown_paste"
                plan_md = format_proposed_jobs_markdown(working_jobs)
                if lang.code.startswith("ru"):
                    confirm_block = (
                        "\n\n### План из Markdown\n\n"
                        "Принят вставленный список хостов/проверок. "
                        "Ответьте **подтвердить**, чтобы запустить этот план, "
                        "или снова исключите / вставьте таблицу.\n"
                    )
                else:
                    confirm_block = (
                        "\n\n### Plan from Markdown\n\n"
                        "Accepted the pasted host/checks list. "
                        "Reply **confirm** to run this plan, or exclude / "
                        "paste another table.\n"
                    )
                scope_prompt = (
                    f"{prompts.scope}{confirm_block}\n\n{plan_md}"
                )
                runtime._persist_intake_progress(
                    state, intake, thread_id=thread_hint
                )
                continue

            # «положил PLAN.md» / put plan → re-read inventory file & re-confirm.
            if looks_like_plan_file_notice(reply) and slug:
                plan_jobs, plan_path = load_client_audit_plan(
                    runtime.settings.inventory_dir,
                    slug,
                    agents_dir=runtime.settings.agents_dir,
                )
                cleaned_plan = normalize_scope_jobs(plan_jobs)
                if cleaned_plan:
                    working_jobs = cleaned_plan
                    intake["proposed_jobs"] = working_jobs
                    intake["plan_source"] = "markdown"
                    if plan_path is not None:
                        intake["plan_file_path"] = str(plan_path)
                    plan_md = format_proposed_jobs_markdown(working_jobs)
                    rel = str(plan_path) if plan_path else "PLAN.md"
                    if lang.code.startswith("ru"):
                        confirm_block = (
                            f"\n\n### План из `{rel}`\n\n"
                            "Файл прочитан заново. Ответьте **подтвердить**, "
                            "чтобы запустить **этот** план, или снова измените "
                            "его / вставьте таблицу.\n"
                        )
                    else:
                        confirm_block = (
                            f"\n\n### Plan from `{rel}`\n\n"
                            "Reloaded the plan file. Reply **confirm** to run "
                            "**this** plan, or exclude / paste another table.\n"
                        )
                    scope_prompt = (
                        f"{prompts.scope}{confirm_block}\n\n{plan_md}"
                    )
                    runtime._persist_intake_progress(
                        state, intake, thread_id=thread_hint
                    )
                    continue
                hint = (
                    "\n\n_No parseable `PLAN.md` found under "
                    f"`inventory/{slug}/` or `inventory/`. Put the file there "
                    "(Host | Frameworks table), then say you placed it again._"
                    if lang.code == "en"
                    else "\n\n_Не найден читаемый `PLAN.md` в "
                    f"`inventory/{slug}/` или `inventory/`. Положите файл "
                    "туда (таблица Host | Frameworks) и снова напишите "
                    "«положил»._"
                )
                scope_prompt = f"{prompts.scope}{hint}\n\n{plan_md}"
                continue

            payload = await runtime._intake_llm_json(
                INTAKE_INTERPRET_SCOPE_SYSTEM,
                INTAKE_INTERPRET_SCOPE_PROMPT.format(
                    reply=reply or "(empty)",
                    plan=plan_md,
                ),
            )
            action = str((payload or {}).get("action") or "").strip().lower()
            selected = resolve_scope_decision(
                reply, working_jobs, payload
            )
            if selected is None:
                hint = (
                    "\n\n_Could not parse that. Reply **confirm**, describe "
                    "what to **exclude** / keep **only**, or paste a "
                    "Host | Frameworks Markdown table._"
                    if lang.code == "en"
                    else "\n\n_Не удалось разобрать ответ. Напишите "
                    "**подтвердить**, что **исключить** / оставить **только**, "
                    "или вставьте таблицу Host | Frameworks._"
                )
                scope_prompt = (
                    f"{prompts.scope}{hint}\n\n{plan_md}"
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
                    f"{prompts.scope}{hint}\n\n{plan_md}"
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
                f"{prompts.scope}{confirm_block}\n\n{plan_md}"
            )
            runtime._persist_intake_progress(
                state, intake, thread_id=thread_hint
            )
            continue
    else:
        # No host/framework plan to confirm: skip domain-selection question.
        # Use the broad default and continue automatically.
        intake["audit_types"] = "both"

    store = runtime._store_from_state(state)
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

async def intake_llm_json(runtime: AuditRuntime, system: str, user: str
) -> dict[str, Any] | None:
    """Один вызов fill_model для интерпретации ответа intake."""
    try:
        response = await runtime.fill_model.ainvoke(
            [
                SystemMessage(content=system),
                HumanMessage(content=user),
            ]
        )
        return _extract_json(str(response.content or ""))
    except Exception:  # noqa: BLE001
        return None

async def intake_resolve_yes_no(runtime: AuditRuntime, raw: str, *, question_hint: str
) -> tuple[str, str]:
    """Интерпретировать да/нет intake через LLM; вернуть ответ + уточнение.

    Args:
        raw: Текст ответа оператора.
        question_hint: Контекст для промпта классификатора.

    Returns:
        ``(yes|no|unknown, clarification)``. Clarification заполняется,
        когда оператор спросил смысл шага (например «что это?»).
    """
    payload = await runtime._intake_llm_json(
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

async def intake_resolve_client_name(runtime: AuditRuntime, raw: str) -> tuple[str, str]:
    """Resolve client name with LLM check + deterministic convention guard.

    Args:
        raw: Operator reply naming the audit client.

    Returns:
        ``(name, error_code)`` where ``error_code`` is:
        ``empty`` / ``invalid_chars`` / ``llm_invalid``.
    """
    text = str(raw or "").strip()
    payload = await runtime._intake_llm_json(
        INTAKE_INTERPRET_CLIENT_SYSTEM,
        INTAKE_INTERPRET_CLIENT_PROMPT.format(reply=text or "(empty)"),
    )
    llm_name = ""
    llm_invalid = False
    if isinstance(payload, dict):
        llm_name = parse_client_name(str(payload.get("client_name") or ""))
        llm_invalid = payload.get("is_compliant") is False

    name = llm_name or parse_client_name(text)
    if not name:
        return "", "empty"
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        return "", "invalid_chars"
    if llm_invalid:
        return "", "llm_invalid"
    return name, ""

async def intake_resolve_audit_type(runtime: AuditRuntime, raw: str) -> str | None:
    """Сопоставить ответ intake с типом аудита только через JSON LLM (шаг 4).

    Args:
        raw: Ответ оператора о желаемой области аудита.

    Returns:
        Каноническая строка типа аудита или ``None``, если неясно.
    """
    payload = await runtime._intake_llm_json(
        INTAKE_INTERPRET_AUDIT_TYPE_SYSTEM,
        INTAKE_INTERPRET_AUDIT_TYPE_PROMPT.format(
            reply=str(raw or "").strip() or "(empty)",
        ),
    )
    return resolve_audit_type(str(raw or ""), payload)

def persist_intake_progress(runtime: AuditRuntime,
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
    store = runtime._store_from_state(state)
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

def load_intake_progress(runtime: AuditRuntime,
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
    store = runtime._store_from_state(state)
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

