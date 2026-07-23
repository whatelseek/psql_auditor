"""Unit tests for optional MLflow helpers (no real MLflow server required)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from auditor.mlflow_store import (
    configure_mlflow_safe,
    end_mlflow_run_safe,
    ensure_mlflow_run_safe,
    experiment_name_for,
    log_mlflow_finalize_safe,
)
from auditor.state import Finding


def _settings(**overrides: object) -> SimpleNamespace:
    base = {
        "mlflow_enabled": True,
        "mlflow_tracking_uri": "http://127.0.0.1:5000",
        "mlflow_experiment_name": "psql-auditor-test",
        "mlflow_autolog": False,
        "litellm_model": "test-model",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_experiment_name_hierarchy() -> None:
    s = _settings()
    assert experiment_name_for(s) == "psql-auditor-test"
    assert experiment_name_for(s, client_name="TestCompany") == (
        "psql-auditor-test/testcompany"
    )
    assert experiment_name_for(
        s, client_name="TestCompany", host="10.200.29.79"
    ) == "psql-auditor-test/testcompany/10.200.29.79"


def test_configure_noop_when_disabled() -> None:
    assert configure_mlflow_safe(_settings(mlflow_enabled=False)) is False


def test_ensure_run_noop_when_disabled() -> None:
    assert (
        ensure_mlflow_run_safe(
            _settings(mlflow_enabled=False),
            run_id="run-1",
        )
        is None
    )


def test_ensure_run_creates_when_missing() -> None:
    client = MagicMock()
    client.get_experiment_by_name.return_value = SimpleNamespace(experiment_id="9")
    client.search_runs.return_value = []
    client.create_run.return_value = SimpleNamespace(
        info=SimpleNamespace(run_id="ml-abc")
    )

    with (
        patch("auditor.mlflow_store._import_mlflow", return_value=MagicMock()),
        patch("auditor.mlflow_store._client", return_value=client),
    ):
        rid = ensure_mlflow_run_safe(
            _settings(),
            run_id="audit-run-1",
            client_name="TestCompany",
            params={"model": "m"},
            tags={"auditor.thread_id": "t1"},
        )

    assert rid == "ml-abc"
    client.create_experiment.assert_not_called()  # experiment already existed
    client.create_run.assert_called_once()
    client.log_param.assert_called()


def test_log_finalize_creates_host_experiment_run() -> None:
    client = MagicMock()
    client.get_experiment_by_name.return_value = SimpleNamespace(experiment_id="2")
    client.search_runs.side_effect = [
        [],  # ensure session: no existing
        [],  # host framework: no existing
        [SimpleNamespace(info=SimpleNamespace(run_id="ml-session"))],  # mirror
    ]
    client.create_run.side_effect = [
        SimpleNamespace(info=SimpleNamespace(run_id="ml-session")),
        SimpleNamespace(info=SimpleNamespace(run_id="ml-fw")),
    ]
    findings = {
        "REQ-001": Finding(
            requirement_id="REQ-001",
            title="t",
            status="pass",
            severity="High",
            evidence="ok",
            remediation="",
        )
    }

    with (
        patch("auditor.mlflow_store._import_mlflow", return_value=MagicMock()),
        patch("auditor.mlflow_store._client", return_value=client),
    ):
        log_mlflow_finalize_safe(
            _settings(),
            run_id="audit-run-1",
            framework_id="ubuntu_cis_24_l2",
            findings=findings,
            client_name="TestCompany",
            evidence_host_id="10.200.29.79",
            retry_count=1,
        )

    assert client.create_run.called
    assert client.log_metric.called
    client.set_terminated.assert_called_with("ml-fw", "FINISHED")


def test_end_run() -> None:
    client = MagicMock()
    client.get_experiment_by_name.return_value = SimpleNamespace(experiment_id="9")
    client.search_runs.return_value = [
        SimpleNamespace(info=SimpleNamespace(run_id="ml-abc"))
    ]

    with (
        patch("auditor.mlflow_store._import_mlflow", return_value=MagicMock()),
        patch("auditor.mlflow_store._client", return_value=client),
    ):
        end_mlflow_run_safe(
            _settings(), run_id="audit-run-1", client_name="TestCompany"
        )

    client.set_terminated.assert_called_once_with("ml-abc", "FINISHED")
