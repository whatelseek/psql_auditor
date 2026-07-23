"""Optional MLflow tracking for audit runs (droppable side channel).

When ``MLFLOW_ENABLED=false`` (default) or the ``mlflow`` package is missing,
all helpers are no-ops. Tracking failures are logged and never abort an audit.

Experiment layout (created on demand)::

    {MLFLOW_EXPERIMENT_NAME}/{client}              — session / intake run
    {MLFLOW_EXPERIMENT_NAME}/{client}/{host}       — per-host framework runs

Pipeline role:
    Complements ``results_store`` (structured warehouse) and on-disk evidence.
    Session run is keyed by evidence ``run_id`` (survives HITL / resume).
    Each framework finalize also creates a finished run under the host experiment.

Key entry points:
    :func:`configure_mlflow_safe` — tracking URI + optional LangChain autolog.
    :func:`ensure_mlflow_run_safe` — create/find session run for ``run_id``.
    :func:`log_mlflow_finalize_safe` — host experiment + framework metrics.
    :func:`end_mlflow_run_safe` — mark the session MLflow run finished.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Mapping

from auditor.compliance import findings_to_compliance_metrics
from auditor.config import Settings, get_settings
from auditor.intake import client_slug
from auditor.state import Finding

logger = logging.getLogger(__name__)

_RUN_TAG = "auditor.run_id"
_FW_TAG = "auditor.framework_id"
_HOST_TAG = "auditor.host"
_SAFE_TAG = re.compile(r"[^a-zA-Z0-9_./:@+-]+")


def _import_mlflow() -> Any | None:
    """Import mlflow lazily; return None when the optional extra is absent."""
    try:
        import mlflow  # type: ignore[import-untyped]
    except ImportError:
        return None
    return mlflow


def _client(settings: Settings) -> Any | None:
    """Return an MlflowClient bound to ``settings.mlflow_tracking_uri``."""
    mlflow = _import_mlflow()
    if mlflow is None:
        return None
    from mlflow.tracking import MlflowClient  # type: ignore[import-untyped]

    uri = (settings.mlflow_tracking_uri or "").strip()
    if not uri:
        return None
    mlflow.set_tracking_uri(uri)
    return MlflowClient(tracking_uri=uri)


def experiment_name_for(
    settings: Settings,
    *,
    client_name: str = "",
    host: str = "",
) -> str:
    """Build a hierarchical experiment name.

    Examples:
        ``psql-auditor``
        ``psql-auditor/testcompany``
        ``psql-auditor/testcompany/10.200.29.79``
    """
    parts = [settings.mlflow_experiment_name.strip().strip("/") or "psql-auditor"]
    if client_name.strip():
        parts.append(client_slug(client_name))
    if host.strip():
        parts.append(client_slug(host))
    return "/".join(parts)


def _experiment_id(client: Any, name: str) -> str:
    """Return experiment id, creating the experiment when missing."""
    exp = client.get_experiment_by_name(name)
    if exp is not None:
        return str(exp.experiment_id)
    return str(client.create_experiment(name))


def _find_run_id(
    client: Any,
    experiment_id: str,
    auditor_run_id: str,
    *,
    framework_id: str = "",
) -> str | None:
    """Locate an MLflow run tagged with ``auditor.run_id`` (optional framework)."""
    safe = auditor_run_id.replace("'", "")
    filt = f"tags.`{_RUN_TAG}` = '{safe}'"
    if framework_id:
        fw = framework_id.replace("'", "")
        filt += f" and tags.`{_FW_TAG}` = '{fw}'"
    try:
        hits = client.search_runs(
            experiment_ids=[experiment_id],
            filter_string=filt,
            max_results=1,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("MLflow search_runs failed: %s", exc)
        return None
    if not hits:
        return None
    return str(hits[0].info.run_id)


def configure_mlflow_safe(settings: Settings | None = None) -> bool:
    """Configure tracking URI and optional LangChain autolog at process start.

    Args:
        settings: Optional settings override.

    Returns:
        True when MLflow was configured; False when disabled/unavailable.
    """
    settings = settings or get_settings()
    if not settings.mlflow_enabled:
        return False
    mlflow = _import_mlflow()
    if mlflow is None:
        logger.warning(
            "MLFLOW_ENABLED=true but mlflow is not installed "
            "(pip install 'auditor[mlflow]')"
        )
        return False
    uri = (settings.mlflow_tracking_uri or "").strip()
    if not uri:
        logger.warning("MLFLOW_ENABLED=true but MLFLOW_TRACKING_URI is empty")
        return False
    try:
        mlflow.set_tracking_uri(uri)
        mlflow.set_experiment(settings.mlflow_experiment_name)
        if settings.mlflow_autolog:
            try:
                mlflow.langchain.autolog(silent=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning("MLflow LangChain autolog skipped: %s", exc)
        logger.info(
            "MLflow tracking enabled → %s (experiment=%s)",
            uri,
            settings.mlflow_experiment_name,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("MLflow configure failed: %s", exc)
        return False


def ensure_mlflow_run_safe(
    settings: Settings,
    *,
    run_id: str,
    client_name: str = "",
    params: Mapping[str, Any] | None = None,
    tags: Mapping[str, str] | None = None,
) -> str | None:
    """Create or reuse a session-level MLflow run for the evidence ``run_id``.

    Uses experiment ``{base}/{client}`` when ``client_name`` is set.

    Args:
        settings: Auditor settings.
        run_id: Evidence / session run id (shared across frameworks / HITL).
        client_name: Optional client for experiment hierarchy.
        params: Optional flat params to log (stringified).
        tags: Optional extra tags (``auditor.run_id`` is always set).

    Returns:
        MLflow run id, or ``None`` when disabled / on error.
    """
    if not settings.mlflow_enabled or not run_id:
        return None
    client = _client(settings)
    if client is None:
        return None
    try:
        exp_name = experiment_name_for(settings, client_name=client_name)
        exp_id = _experiment_id(client, exp_name)
        mlflow_run_id = _find_run_id(client, exp_id, run_id)
        if mlflow_run_id is None:
            tag_map = {
                _RUN_TAG: run_id,
                "auditor.source": "psql-auditor",
                "auditor.kind": "session",
            }
            if client_name:
                tag_map["auditor.client"] = client_slug(client_name)
            if tags:
                for key, value in tags.items():
                    if value is None:
                        continue
                    tag_map[str(key)] = _SAFE_TAG.sub("_", str(value))[:250]
            run = client.create_run(
                experiment_id=exp_id,
                tags=tag_map,
                run_name=run_id[:250],
            )
            mlflow_run_id = str(run.info.run_id)
        if params:
            for key, value in params.items():
                if value is None:
                    continue
                try:
                    client.log_param(mlflow_run_id, str(key)[:250], str(value)[:8000])
                except Exception:  # noqa: BLE001
                    pass
        return mlflow_run_id
    except Exception as exc:  # noqa: BLE001
        logger.warning("MLflow ensure_run failed: %s", exc)
        return None


def log_mlflow_finalize_safe(
    settings: Settings,
    *,
    run_id: str,
    framework_id: str,
    findings: Mapping[str, Finding] | None = None,
    client_name: str = "",
    evidence_host_id: str = "",
    retry_count: int = 0,
    session_number: int | None = None,
    report_path: str | Path | None = None,
    archive_path: str | Path | None = None,
) -> None:
    """Log a finished per-framework run under the host experiment.

    Creates ``{base}/{client}/{host}`` (host defaults to ``default``) and a
    run named ``{framework_id}``. Also mirrors summary metrics onto the
    session run when present.
    """
    if not settings.mlflow_enabled or not run_id:
        return
    client = _client(settings)
    if client is None:
        return
    try:
        fw = (framework_id or "framework").replace(" ", "_")
        host = (evidence_host_id or "").strip() or "default"
        # Ensure client + host experiments exist (hierarchical discovery in UI).
        ensure_mlflow_run_safe(
            settings,
            run_id=run_id,
            client_name=client_name,
            params={"client_name": client_name} if client_name else None,
        )
        host_exp = experiment_name_for(
            settings, client_name=client_name or "client", host=host
        )
        exp_id = _experiment_id(client, host_exp)
        mlflow_run_id = _find_run_id(
            client, exp_id, run_id, framework_id=fw
        )
        if mlflow_run_id is None:
            tags = {
                _RUN_TAG: run_id,
                _FW_TAG: fw,
                _HOST_TAG: host,
                "auditor.source": "psql-auditor",
                "auditor.kind": "framework",
            }
            if client_name:
                tags["auditor.client"] = client_slug(client_name)
            run = client.create_run(
                experiment_id=exp_id,
                tags=tags,
                run_name=f"{fw}-{run_id[:12]}"[:250],
            )
            mlflow_run_id = str(run.info.run_id)

        params: dict[str, Any] = {
            "framework_id": fw,
            "host": host,
            "model": settings.litellm_model,
            "auditor_run_id": run_id,
        }
        if client_name:
            params["client_name"] = client_name
        if session_number is not None:
            params["results_session_number"] = session_number
        for key, value in params.items():
            try:
                client.log_param(mlflow_run_id, str(key)[:250], str(value)[:8000])
            except Exception:  # noqa: BLE001
                pass

        metrics = (
            findings_to_compliance_metrics(findings)
            if findings
            else {
                "pass": 0,
                "fail": 0,
                "partial": 0,
                "error": 0,
                "skipped": 0,
                "assessed": 0,
                "compliance_pct": 0.0,
            }
        )
        metric_map = {
            "pass": float(metrics.get("pass", 0)),
            "fail": float(metrics.get("fail", 0)),
            "partial": float(metrics.get("partial", 0)),
            "error": float(metrics.get("error", 0)),
            "skipped": float(metrics.get("skipped", 0)),
            "assessed": float(metrics.get("assessed", 0)),
            "compliance_pct": float(metrics.get("compliance_pct", 0.0)),
            "retry_count": float(retry_count),
        }
        for key, value in metric_map.items():
            try:
                client.log_metric(mlflow_run_id, key[:250], value)
            except Exception:  # noqa: BLE001
                pass

        for path in (report_path, archive_path):
            if not path:
                continue
            p = Path(path)
            if p.is_file():
                try:
                    client.log_artifact(mlflow_run_id, str(p))
                except Exception as exc:  # noqa: BLE001
                    logger.warning("MLflow log_artifact(%s) failed: %s", p, exc)

        # Mirror onto session run for rollup views.
        session_exp = experiment_name_for(settings, client_name=client_name)
        session_run = _find_run_id(
            client, _experiment_id(client, session_exp), run_id
        )
        if session_run:
            for key, value in metric_map.items():
                try:
                    client.log_metric(session_run, f"{fw}.{key}"[:250], value)
                except Exception:  # noqa: BLE001
                    pass

        client.set_terminated(mlflow_run_id, "FINISHED")
        logger.info(
            "MLflow framework run logged: experiment=%s framework=%s",
            host_exp,
            fw,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("MLflow finalize log failed: %s", exc)


def end_mlflow_run_safe(
    settings: Settings,
    *,
    run_id: str,
    client_name: str = "",
    status: str = "FINISHED",
    archive_path: str | Path | None = None,
) -> None:
    """Terminate the session-level MLflow run for ``run_id`` (best-effort)."""
    if not settings.mlflow_enabled or not run_id:
        return
    client = _client(settings)
    if client is None:
        return
    try:
        exp_name = experiment_name_for(settings, client_name=client_name)
        exp_id = _experiment_id(client, exp_name)
        mlflow_run_id = _find_run_id(client, exp_id, run_id)
        if not mlflow_run_id and client_name:
            # Fallback: base experiment (run started before client was known).
            exp_id = _experiment_id(client, settings.mlflow_experiment_name)
            mlflow_run_id = _find_run_id(client, exp_id, run_id)
        if not mlflow_run_id:
            return
        if archive_path:
            p = Path(archive_path)
            if p.is_file():
                try:
                    client.log_artifact(mlflow_run_id, str(p))
                except Exception as exc:  # noqa: BLE001
                    logger.warning("MLflow archive artifact failed: %s", exc)
        client.set_terminated(mlflow_run_id, status)
    except Exception as exc:  # noqa: BLE001
        logger.warning("MLflow end_run failed: %s", exc)
