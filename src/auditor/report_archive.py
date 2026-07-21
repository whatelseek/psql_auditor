"""Zip audit evidence/report bundles and optionally push them to Open WebUI."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from auditor.config import Settings

logger = logging.getLogger(__name__)


def archive_filename(run_id: str) -> str:
    """Canonical zip filename for a run id."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in run_id)
    return f"{safe}_audit.zip"


def create_run_archive(run_dir: Path | str, *, zip_path: Path | None = None) -> Path:
    """Zip an evidence run directory (report + per-REQ command outputs).

    Args:
        run_dir: ``artifacts/<run_id>/`` directory.
        zip_path: Optional explicit zip destination.

    Returns:
        Path to the created ``.zip`` file.
    """
    root = Path(run_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"Evidence run directory not found: {root}")

    dest = zip_path or (root.parent / archive_filename(root.name))
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()

    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            # Avoid nesting a previous zip copy inside itself.
            if path.resolve() == dest.resolve():
                continue
            zf.write(path, arcname=str(path.relative_to(root)))

    return dest


def make_download_token(run_id: str, secret: str) -> str:
    """Create a stable HMAC token so browser markdown links can download."""
    key = (secret or "auditor-dev").encode("utf-8")
    return hmac.new(key, run_id.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def verify_download_token(run_id: str, token: str | None, secret: str) -> bool:
    if not token:
        return False
    expected = make_download_token(run_id, secret)
    return hmac.compare_digest(expected, token)


def public_download_url(settings: Settings, run_id: str) -> str:
    """Browser-reachable download URL for the zip (tokenized query)."""
    base = (settings.public_base_url or f"http://localhost:{settings.port}").rstrip("/")
    token = make_download_token(run_id, settings.api_key or "auditor-dev")
    name = quote(archive_filename(run_id))
    return f"{base}/v1/downloads/{name}?token={token}"


def format_archive_chat_section(
    *,
    zip_path: Path,
    download_url: str,
    open_webui_url: str | None = None,
    open_webui_file_id: str | None = None,
) -> str:
    """Markdown block appended to the chat report with download links."""
    size_kb = max(1, zip_path.stat().st_size // 1024)
    lines = [
        "",
        "---",
        "",
        "## Audit archive",
        "",
        f"📦 Report + evidence packaged as **`{zip_path.name}`** ({size_kb} KB).",
        "",
        f"**[Download ZIP]({download_url})**",
        "",
    ]
    if open_webui_file_id:
        # Relative URL works inside the Open WebUI browser origin.
        owui_path = f"/api/v1/files/{open_webui_file_id}/content"
        lines.extend(
            [
                f"Also attached in Open WebUI files: **[Open archive]({owui_path})**",
                "",
            ]
        )
        if open_webui_url:
            abs_owui = f"{open_webui_url.rstrip('/')}{owui_path}"
            lines.append(f"(Absolute Open WebUI URL: {abs_owui})")
            lines.append("")
    lines.append(
        "<a href=\"{}\" download>Click here if the markdown link does not download</a>".format(
            download_url
        )
    )
    lines.append("")
    return "\n".join(lines)


async def _open_webui_bearer_token(
    client: httpx.AsyncClient,
    settings: Settings,
) -> str | None:
    """Return Authorization bearer value for Open WebUI file APIs.

    Prefers ``OPEN_WEBUI_API_KEY``. Otherwise signs in with
    ``OPEN_WEBUI_EMAIL`` / ``OPEN_WEBUI_PASSWORD`` (JWT).
    """
    if settings.open_webui_api_key:
        return settings.open_webui_api_key.strip()
    email = (settings.open_webui_email or "").strip()
    password = settings.open_webui_password or ""
    if not email or not password:
        return None
    base = (settings.open_webui_url or "").rstrip("/")
    response = await client.post(
        f"{base}/api/v1/auths/signin",
        json={"email": email, "password": password},
    )
    if response.status_code >= 400:
        logger.warning(
            "Open WebUI sign-in failed: %s %s",
            response.status_code,
            response.text[:200],
        )
        return None
    data = response.json()
    token = data.get("token") if isinstance(data, dict) else None
    return str(token) if token else None


async def upload_zip_to_open_webui(
    zip_path: Path,
    settings: Settings,
) -> dict[str, Any] | None:
    """Upload the zip to Open WebUI ``POST /api/v1/files/?process=false``.

    Returns:
        Parsed JSON response (includes ``id``) or ``None`` when upload is
        disabled / fails (failures are logged, not raised).
    """
    base = (settings.open_webui_url or "").rstrip("/")
    if not base:
        return None
    if not zip_path.is_file():
        return None

    url = f"{base}/api/v1/files/"
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            token = await _open_webui_bearer_token(client, settings)
            headers: dict[str, str] = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            with zip_path.open("rb") as fh:
                response = await client.post(
                    url,
                    headers=headers,
                    params={"process": "false"},
                    files={
                        "file": (
                            zip_path.name,
                            fh,
                            "application/zip",
                        )
                    },
                )
            if response.status_code >= 400:
                logger.warning(
                    "Open WebUI zip upload failed: %s %s",
                    response.status_code,
                    response.text[:300],
                )
                return None
            data = response.json()
            if isinstance(data, dict):
                return data
    except Exception as exc:  # noqa: BLE001
        logger.warning("Open WebUI zip upload error: %s", exc)
    return None


async def package_and_publish_archive(
    run_dir: Path | str,
    settings: Settings,
) -> dict[str, Any]:
    """Create zip, optionally upload to Open WebUI, return metadata for chat.

    Returns:
        Dict with keys: ``zip_path``, ``download_url``, ``open_webui_file_id``,
        ``chat_section``.
    """
    root = Path(run_dir)
    zip_path = create_run_archive(root)
    run_id = root.name
    download_url = public_download_url(settings, run_id)

    uploaded = await upload_zip_to_open_webui(zip_path, settings)
    file_id = None
    if uploaded:
        file_id = str(uploaded.get("id") or uploaded.get("file_id") or "") or None

    # Persist archive pointers next to the run for later download lookups.
    meta_path = root / "archive.json"
    meta_path.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "zip_path": str(zip_path),
                "download_url": download_url,
                "open_webui_file_id": file_id,
                "token": make_download_token(
                    run_id, settings.api_key or "auditor-dev"
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    section = format_archive_chat_section(
        zip_path=zip_path,
        download_url=download_url,
        open_webui_url=settings.open_webui_public_url or settings.open_webui_url,
        open_webui_file_id=file_id,
    )
    return {
        "zip_path": str(zip_path),
        "download_url": download_url,
        "open_webui_file_id": file_id,
        "chat_section": section,
        "run_id": run_id,
    }


def new_ephemeral_token() -> str:
    """Unused helper kept for tests / future one-time links."""
    return secrets.token_urlsafe(16)
