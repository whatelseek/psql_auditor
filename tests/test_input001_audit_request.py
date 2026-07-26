"""INPUT-001: Strict, versioned AuditRequest contract and production wiring."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry
from auditor.config import Settings
from auditor.domain import (
    AUDIT_REQUEST_SCHEMA_VERSION,
    POC_TOOL_PROFILE,
    AuditRequest,
    AuditRequestRejected,
    load_persisted_audit_request,
    parse_audit_request,
    persistable_audit_request,
    scope_with_audit_request,
    validate_audit_request_semantics,
)
from auditor.domain.audit_request import (
    AuditRunSettings,
    AuditTarget,
    FrameworkReference,
    InventoryReference,
    build_audit_request_from_selected_jobs,
)
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph
from auditor.session_store import _sanitize_session, save_multi_session
from auditor.workflows import multi_runner

CANARY = "CANARY_PW_INPUT001_UNIQUE_7f3a"


def _inventory_md(*, host: str = "db_server_01", password: str = CANARY) -> str:
    return f"""# Inventory

## Credentials & access

| Access | Host / URL | Port | Username | Password / Token | Database |
|--------|------------|------|----------|------------------|----------|
| SSH | {host} | 22 | audit | {password} | |
"""


def _setup_client(tmp_path: Path, *, slug: str = "acme_corp", host: str = "db_server_01"):
    inv_root = tmp_path / "inventory"
    client_dir = inv_root / slug
    client_dir.mkdir(parents=True)
    (client_dir / "INVENTORY.md").write_text(_inventory_md(host=host), encoding="utf-8")

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    client = get_client_registry(evidence).ensure_client(display_name="Acme Corp", slug=slug)

    settings = Settings(
        _env_file=None,
        evidence_dir=evidence,
        inventory_dir=inv_root,
        agents_dir=Path("agents"),
        intake_enabled=False,
        hitl_enabled=False,
        archive_enabled=False,
        max_parallel_assessments=5,
        max_parallel_host_jobs=2,
    )
    return settings, client, host


def _valid_payload(client_id: str, *, slug: str = "acme_corp", host: str = "db_server_01") -> dict:
    return {
        "schema_version": 1,
        "client_id": client_id,
        "inventory": {"kind": "client_file", "ref": f"{slug}/INVENTORY.md"},
        "targets": [
            {
                "inventory_target_ref": host,
                "frameworks": [
                    {"framework_id": "postgres_cis", "framework_version": "1.0"},
                ],
            }
        ],
        "tool_profile": POC_TOOL_PROFILE,
        "run_settings": {
            "report_language": "en",
            "hitl_enabled": True,
            "archive_enabled": True,
            "max_parallel_assessments": 5,
            "max_parallel_host_jobs": 2,
        },
    }


# ---------------------------------------------------------------------------
# A. Strict model
# ---------------------------------------------------------------------------


def test_a_valid_v1_round_trip_immutable(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    payload = _valid_payload(client.client_id, host=host)
    req = parse_audit_request(payload)
    assert req.schema_version == AUDIT_REQUEST_SCHEMA_VERSION
    dumped = persistable_audit_request(req)
    again = AuditRequest.model_validate(dumped)
    assert again == req
    with pytest.raises(ValidationError):
        req.client_id = "client_other"  # type: ignore[misc]


def test_a_missing_mandatory_and_extra_fields_rejected(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    base = _valid_payload(client.client_id, host=host)
    for key in (
        "schema_version",
        "client_id",
        "inventory",
        "targets",
        "tool_profile",
        "run_settings",
    ):
        bad = dict(base)
        bad.pop(key)
        with pytest.raises(AuditRequestRejected):
            parse_audit_request(bad)
    with pytest.raises(AuditRequestRejected):
        parse_audit_request({**base, "extra_field": "nope"})


def test_a_unsupported_version_and_no_coercion(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    base = _valid_payload(client.client_id, host=host)
    with pytest.raises(AuditRequestRejected):
        parse_audit_request({**base, "schema_version": 2})
    with pytest.raises(AuditRequestRejected):
        parse_audit_request({**base, "schema_version": "1"})
    with pytest.raises(AuditRequestRejected):
        parse_audit_request(
            {
                **base,
                "run_settings": {
                    **base["run_settings"],
                    "hitl_enabled": "true",
                    "max_parallel_assessments": "5",
                },
            }
        )


def test_a_empty_and_duplicate_scope_rejected(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    base = _valid_payload(client.client_id, host=host)
    with pytest.raises(AuditRequestRejected):
        parse_audit_request({**base, "targets": []})
    with pytest.raises(AuditRequestRejected):
        parse_audit_request(
            {
                **base,
                "targets": [{"inventory_target_ref": host, "frameworks": []}],
            }
        )
    with pytest.raises(AuditRequestRejected):
        parse_audit_request(
            {
                **base,
                "targets": [
                    {
                        "inventory_target_ref": host,
                        "frameworks": [
                            {"framework_id": "postgres_cis", "framework_version": "1.0"},
                        ],
                    },
                    {
                        "inventory_target_ref": host,
                        "frameworks": [
                            {"framework_id": "ubuntu_cis_24_l2", "framework_version": "1.0"},
                        ],
                    },
                ],
            }
        )
    with pytest.raises(AuditRequestRejected):
        parse_audit_request(
            {
                **base,
                "targets": [
                    {
                        "inventory_target_ref": host,
                        "frameworks": [
                            {"framework_id": "postgres_cis", "framework_version": "1.0"},
                            {"framework_id": "postgres_cis", "framework_version": "1.0"},
                        ],
                    }
                ],
            }
        )


@pytest.mark.parametrize("secret_key", ["password", "token", "database_url", "ssh_password"])
def test_a_secret_looking_fields_rejected(tmp_path: Path, secret_key: str):
    settings, client, host = _setup_client(tmp_path)
    base = _valid_payload(client.client_id, host=host)
    with pytest.raises(AuditRequestRejected):
        parse_audit_request({**base, secret_key: "should-not-appear"})


# ---------------------------------------------------------------------------
# B. Semantic validation
# ---------------------------------------------------------------------------


def test_b_unknown_client_and_cross_client_inventory(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    get_client_registry(settings.evidence_dir).ensure_client(
        display_name="Other", slug="other_corp"
    )
    (settings.inventory_dir / "other_corp").mkdir(parents=True)
    (settings.inventory_dir / "other_corp" / "INVENTORY.md").write_text(
        _inventory_md(host="other_host"), encoding="utf-8"
    )

    unknown = parse_audit_request(_valid_payload("client_deadbeefdeadbeef", host=host))
    with pytest.raises(AuditRequestRejected) as exc:
        validate_audit_request_semantics(unknown, settings)
    assert any(i.code == "unknown_client" for i in exc.value.issues)

    cross = parse_audit_request(
        {
            **_valid_payload(client.client_id, host=host),
            "inventory": {"kind": "client_file", "ref": "other_corp/INVENTORY.md"},
        }
    )
    with pytest.raises(AuditRequestRejected) as exc2:
        validate_audit_request_semantics(cross, settings)
    assert any(i.code == "cross_client_inventory" for i in exc2.value.issues)


def test_b_absolute_traversal_missing_unresolved_framework_profile_settings(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    base = _valid_payload(client.client_id, host=host)

    with pytest.raises(AuditRequestRejected):
        parse_audit_request({**base, "inventory": {"kind": "client_file", "ref": "/etc/passwd"}})
    with pytest.raises(AuditRequestRejected):
        parse_audit_request(
            {
                **base,
                "inventory": {"kind": "client_file", "ref": "acme_corp/../other/INVENTORY.md"},
            }
        )

    # empty inventory file
    (settings.inventory_dir / "acme_corp" / "INVENTORY.md").write_text("", encoding="utf-8")
    with pytest.raises(AuditRequestRejected) as exc_empty:
        validate_audit_request_semantics(parse_audit_request(base), settings)
    assert any(i.code in {"missing_inventory", "empty_inventory"} for i in exc_empty.value.issues)

    # restore inventory then unresolved target
    (settings.inventory_dir / "acme_corp" / "INVENTORY.md").write_text(
        _inventory_md(host=host), encoding="utf-8"
    )
    bad_target = {
        **base,
        "targets": [
            {
                "inventory_target_ref": "missing_host_xyz",
                "frameworks": [{"framework_id": "postgres_cis", "framework_version": "1.0"}],
            }
        ],
    }
    with pytest.raises(AuditRequestRejected) as exc_t:
        validate_audit_request_semantics(parse_audit_request(bad_target), settings)
    assert any(i.code == "unresolved_target" for i in exc_t.value.issues)

    unknown_fw = {
        **base,
        "targets": [
            {
                "inventory_target_ref": host,
                "frameworks": [{"framework_id": "no_such_fw", "framework_version": "1.0"}],
            }
        ],
    }
    with pytest.raises(AuditRequestRejected) as exc_fw:
        validate_audit_request_semantics(parse_audit_request(unknown_fw), settings)
    assert any(i.code == "unknown_framework" for i in exc_fw.value.issues)

    mismatch = {
        **base,
        "targets": [
            {
                "inventory_target_ref": host,
                "frameworks": [{"framework_id": "postgres_cis", "framework_version": "9.9"}],
            }
        ],
    }
    with pytest.raises(AuditRequestRejected) as exc_v:
        validate_audit_request_semantics(parse_audit_request(mismatch), settings)
    assert any(i.code == "framework_version_mismatch" for i in exc_v.value.issues)

    with pytest.raises(AuditRequestRejected):
        parse_audit_request({**base, "tool_profile": "enterprise_full"})

    over = {
        **base,
        "run_settings": {**base["run_settings"], "max_parallel_assessments": 32},
    }
    # structural allows 32; semantic rejects vs settings ceiling 5
    req_over = parse_audit_request(over)
    with pytest.raises(AuditRequestRejected) as exc_r:
        validate_audit_request_semantics(req_over, settings)
    assert any(i.code == "out_of_range" for i in exc_r.value.issues)


# ---------------------------------------------------------------------------
# C. Authority boundary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_c_operator_context_cannot_override_request(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    req = validate_audit_request_semantics(
        parse_audit_request(_valid_payload(client.client_id, host=host)),
        settings,
    )
    graph = AuditorGraph(settings=settings)
    conflicting = (
        "Please audit OtherCorp with ubuntu_cis_24_l2 on host evil_box "
        "using tool_profile=enterprise_full and max_parallel_host_jobs=99"
    )
    route_calls: list[str] = []

    async def fake_run_jobs(self, **kwargs):
        assert kwargs.get("intake_state", {}).get("client_id") == client.client_id
        ar = kwargs.get("intake_state", {}).get("audit_request") or {}
        assert ar.get("tool_profile") == POC_TOOL_PROFILE
        assert ar.get("targets")[0]["inventory_target_ref"] == host
        assert ar["targets"][0]["frameworks"][0]["framework_id"] == "postgres_cis"
        assert kwargs.get("user_text") == conflicting
        return {"report": "ok", "awaiting_hitl": False, "messages": []}

    with (
        patch(
            "auditor.frameworks.route_frameworks",
            side_effect=lambda *a, **k: route_calls.append("called") or [],
        ),
        patch.object(AuditorGraph, "_run_framework_jobs", fake_run_jobs),
    ):
        result = await graph.arun_request(req, operator_context=conflicting)
    assert result["report"] == "ok"
    assert route_calls == []


# ---------------------------------------------------------------------------
# D. Rejection before jobs / sessions / external calls
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_d_invalid_request_no_side_effects(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    registry = get_audit_registry(settings.evidence_dir)
    graph = AuditorGraph(settings=settings)

    create_job = MagicMock(side_effect=AssertionError("create_job must not run"))
    start_session = AsyncMock(side_effect=AssertionError("session must not start"))
    arun_one = AsyncMock(side_effect=AssertionError("arun_one must not run"))

    invalid_intake = {
        "client_id": client.client_id,
        "client_slug": "acme_corp",
        "client_name": "Acme",
        "audit_run_id": "",
        "selected_jobs": [],
    }

    with (
        patch.object(registry, "create_job", create_job),
        patch("auditor.workflows.multi_runner.start_session_safe", start_session),
        patch.object(graph, "arun_one", arun_one),
        patch("auditor.frameworks.route_frameworks", side_effect=AssertionError("NLP")),
    ):
        with pytest.raises(AuditRequestRejected) as exc:
            await multi_runner.start_frameworks_after_intake(
                graph,
                user_text="audit everything",
                base_thread="t-input001",
                run_id="run-input001",
                intake=invalid_intake,
            )
    assert exc.value.code == "invalid_audit_request"
    assert create_job.call_count == 0
    assert start_session.await_count == 0
    assert arun_one.await_count == 0

    # Direct untyped arun fails closed when intake disabled
    with pytest.raises(AuditRequestRejected) as exc2:
        await graph.arun("please route frameworks via NLP")
    assert any(i.code == "typed_request_required" for i in exc2.value.issues)
    assert "traceback" not in exc2.value.operator_message().lower()


# ---------------------------------------------------------------------------
# E. Manifest and restart
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e_manifest_scope_and_resume_request(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    registry = get_audit_registry(settings.evidence_dir)
    run = registry.create_run(client_id=client.client_id)
    req = validate_audit_request_semantics(
        parse_audit_request(_valid_payload(client.client_id, host=host)),
        settings,
    )
    run.scope = scope_with_audit_request(run.scope, req)
    registry.save_run(run)

    loaded = registry.get_run(run.audit_run_id)
    assert loaded is not None
    assert loaded.scope["input_contract_version"] == 1
    roundtrip = load_persisted_audit_request(loaded.scope["audit_request"])
    assert roundtrip == req

    store = EvidenceStore(settings.evidence_dir, run_id="ev-input001")
    store.write_run_meta(
        input_contract_version=1,
        audit_request=persistable_audit_request(req),
        client_id=client.client_id,
        audit_run_id=run.audit_run_id,
    )
    meta = json.loads((store.root / "meta.json").read_text(encoding="utf-8"))
    assert meta["input_contract_version"] == 1
    assert load_persisted_audit_request(meta["audit_request"]) == req

    # unsupported persisted version fails closed
    with pytest.raises(AuditRequestRejected):
        load_persisted_audit_request({"schema_version": 99, "client_id": client.client_id})

    # other client unaffected
    other = get_client_registry(settings.evidence_dir).ensure_client(
        display_name="Beta", slug="beta"
    )
    other_run = registry.create_run(client_id=other.client_id)
    assert other_run.audit_run_id != run.audit_run_id
    assert (other_run.scope or {}).get("audit_request") is None


# ---------------------------------------------------------------------------
# F. Secret canary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f_secret_canary_absent_and_reresolved(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    req = validate_audit_request_semantics(
        parse_audit_request(_valid_payload(client.client_id, host=host)),
        settings,
    )
    dump_json = req.model_dump_json()
    assert CANARY not in dump_json

    from auditor.secrets_file import InventorySshTarget

    target = InventorySshTarget(
        host=host,
        port="22",
        user="audit",
        password=CANARY,
        private_key_path="",
        label="SSH",
    )
    fw = SimpleNamespace(id="postgres_cis", title="PG CIS", version="1.0")
    job = multi_runner.serialize_host_job(target, fw, client_slug="acme_corp")
    blob = json.dumps(job)
    assert CANARY not in blob
    assert "ssh_password" not in job
    assert "ssh_key" not in job
    assert job["inventory_target_ref"] == host

    # Session sanitize strips credentials
    session = {
        "run_id": "ev-canary",
        "remaining_jobs": [{**job, "ssh_password": CANARY}],
        "ssh_target": target,
        "intake_state": {"password": CANARY, "ssh_password": CANARY},
        "completed": [],
    }
    cleaned = _sanitize_session(session)
    cleaned_text = json.dumps(cleaned, default=str)
    assert CANARY not in cleaned_text
    assert "password" not in cleaned.get("intake_state", {})

    save_multi_session(settings.evidence_dir, "ev-canary", "thread-canary", cleaned)
    # save_multi_session may nest under run; find any session.json
    found = list(settings.evidence_dir.rglob("session.json"))
    assert found
    for path in found:
        assert CANARY not in path.read_text(encoding="utf-8")

    # Re-resolve from inventory restores live password for execution
    resolved = multi_runner.target_from_job_dict(job, settings)
    assert resolved is not None
    assert resolved.password == CANARY

    # Legacy password in job ignored
    legacy = {**job, "ssh_password": "LEGACY_SHOULD_IGNORE"}
    resolved2 = multi_runner.target_from_job_dict(legacy, settings)
    assert resolved2 is not None
    assert resolved2.password == CANARY
    assert resolved2.password != "LEGACY_SHOULD_IGNORE"

    registry = get_audit_registry(settings.evidence_dir)
    run = registry.create_run(client_id=client.client_id)
    run.scope = scope_with_audit_request(run.scope, req)
    registry.save_run(run)
    scope_text = json.dumps(registry.get_run(run.audit_run_id).scope)
    assert CANARY not in scope_text


@pytest.mark.asyncio
async def test_d_bootstrap_refuses_new_jobs_without_request(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    graph = AuditorGraph(settings=settings)
    pending = [
        {
            "framework_id": "postgres_cis",
            "framework_title": "PG",
            "evidence_host_id": host,
            "inventory_target_ref": host,
            "client_slug": "acme_corp",
            "ssh_host": host,
            "ssh_port": "22",
            "ssh_user": "audit",
        }
    ]
    with pytest.raises(AuditRequestRejected) as exc:
        multi_runner._bootstrap_audit_run(
            graph,
            run_id="ev-no-req",
            base_thread="t-no-req",
            intake_state={
                "client_id": client.client_id,
                "client_slug": "acme_corp",
                "client_name": "Acme",
                "has_access": True,
            },
            pending=pending,
        )
    assert any(i.code == "typed_request_required" for i in exc.value.issues)


# ---------------------------------------------------------------------------
# G. Compatibility smoke (typed paths)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_g_intake_path_builds_request_then_jobs(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    settings = settings.model_copy(update={"intake_enabled": True})
    registry = get_audit_registry(settings.evidence_dir)
    run = registry.create_run(client_id=client.client_id)
    graph = AuditorGraph(settings=settings)

    selected = [
        {
            "host_id": host,
            "ssh_host": host,
            "hostname": host,
            "frameworks": ["postgres_cis"],
        }
    ]
    intake = {
        "client_id": client.client_id,
        "client_slug": "acme_corp",
        "client_name": "Acme Corp",
        "audit_run_id": run.audit_run_id,
        "selected_jobs": selected,
        "has_access": True,
        "audit_types": "both",
    }

    async def fake_run_jobs(self, **kwargs):
        jobs = kwargs["jobs"]
        assert len(jobs) == 1
        assert kwargs["intake_state"]["audit_request"]["schema_version"] == 1
        # create_job path still reachable via bootstrap — invoke real bootstrap lightly
        return {"report": "ok", "awaiting_hitl": False, "messages": [], "thread_id": "t"}

    start_session = AsyncMock(return_value=SimpleNamespace(session_number=1, id="sess-1"))

    with (
        patch.object(AuditorGraph, "_run_framework_jobs", fake_run_jobs),
        patch("auditor.workflows.multi_runner.start_session_safe", start_session),
        patch("auditor.frameworks.route_frameworks", side_effect=AssertionError("NLP")),
    ):
        out = await multi_runner.start_frameworks_after_intake(
            graph,
            user_text="confirmed",
            base_thread="t-g",
            run_id="ev-g",
            intake=intake,
        )
    assert out["report"] == "ok"
    assert start_session.await_count == 1
    reloaded = registry.get_run(run.audit_run_id)
    assert reloaded is not None
    assert reloaded.scope.get("input_contract_version") == 1
    assert (
        load_persisted_audit_request(reloaded.scope["audit_request"]).client_id == client.client_id
    )


def test_g_build_from_selected_jobs_sets_poc_profile(tmp_path: Path):
    settings, client, host = _setup_client(tmp_path)
    req = build_audit_request_from_selected_jobs(
        client_id=client.client_id,
        client_slug="acme_corp",
        selected_jobs=[{"host_id": host, "frameworks": ["postgres_cis"]}],
        settings=settings,
    )
    assert req.tool_profile == POC_TOOL_PROFILE
    assert isinstance(req.run_settings, AuditRunSettings)
    assert isinstance(req.targets[0], AuditTarget)
    assert isinstance(req.targets[0].frameworks[0], FrameworkReference)
    assert isinstance(req.inventory, InventoryReference)
