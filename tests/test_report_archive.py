from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from auditor.api.app import create_app
from auditor.config import Settings, get_settings
from auditor.report_archive import (
    archive_filename,
    create_run_archive,
    format_archive_chat_section,
    make_download_token,
    package_and_publish_archive,
    public_download_url,
    verify_download_token,
)


def test_create_run_archive_includes_report_and_req_files(tmp_path: Path):
    run = tmp_path / "run123"
    req = run / "ubuntu_cis_24_l2" / "REQ-001"
    req.mkdir(parents=True)
    (run / "report.md").write_text("# Report\n", encoding="utf-8")
    (run / "report.docx").write_bytes(b"PK\x03\x04docx-placeholder")
    (run / "report.xlsx").write_bytes(b"PK\x03\x04xlsx-placeholder")
    (req / "001_ssh_run.txt").write_text("exit_code=0\n", encoding="utf-8")

    zip_path = create_run_archive(run)
    assert zip_path.name == archive_filename("run123")
    assert zip_path.is_file()

    import zipfile

    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert "report.md" in names
    assert "report.docx" in names
    assert "report.xlsx" in names
    assert "ubuntu_cis_24_l2/REQ-001/001_ssh_run.txt" in names


def test_download_token_roundtrip():
    token = make_download_token("run-abc", "secret")
    assert verify_download_token("run-abc", token, "secret")
    assert not verify_download_token("run-abc", "nope", "secret")


def test_format_archive_chat_section_has_download_link(tmp_path: Path):
    z = tmp_path / "x_audit.zip"
    z.write_bytes(b"PK\x03\x04fake")
    text = format_archive_chat_section(
        zip_path=z,
        download_url="http://localhost:8000/v1/downloads/x_audit.zip?token=t",
        open_webui_file_id="file-1",
    )
    assert "Download ZIP" in text
    assert "file-1" in text
    assert "Audit archive" in text


@pytest.mark.asyncio
async def test_package_and_publish_without_open_webui(tmp_path: Path):
    run = tmp_path / "run_pkg"
    run.mkdir()
    (run / "report.md").write_text("ok\n", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        public_base_url="http://localhost:8000",
        api_key="sk-test",
        open_webui_url=None,
        archive_enabled=True,
    )
    result = await package_and_publish_archive(run, settings)
    assert Path(result["zip_path"]).is_file()
    assert "token=" in result["download_url"]
    assert "Download ZIP" in result["chat_section"]
    assert result["open_webui_file_id"] is None
    assert (run / "archive.json").is_file()


@pytest.mark.asyncio
async def test_package_uploads_via_signin_when_no_api_key(tmp_path: Path):
    run = tmp_path / "run_signin"
    run.mkdir()
    (run / "report.md").write_text("ok\n", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        public_base_url="http://localhost:8000",
        api_key="sk-test",
        open_webui_url="http://open-webui:8080",
        open_webui_api_key=None,
        open_webui_email="admin@localhost",
        open_webui_password="admin",
    )

    signin = AsyncMock()
    signin.status_code = 200
    signin.json = lambda: {"token": "jwt-lab"}
    signin.text = "ok"

    upload = AsyncMock()
    upload.status_code = 200
    upload.json = lambda: {"id": "file-from-jwt"}
    upload.text = "ok"

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(side_effect=[signin, upload])

    with patch("auditor.report_archive.httpx.AsyncClient", return_value=mock_client):
        result = await package_and_publish_archive(run, settings)

    assert result["open_webui_file_id"] == "file-from-jwt"
    assert mock_client.post.await_count == 2
    # Second call is the file upload with JWT
    upload_call = mock_client.post.await_args_list[1]
    assert upload_call.kwargs["headers"]["Authorization"] == "Bearer jwt-lab"


def test_download_endpoint_serves_zip(tmp_path: Path):
    get_settings.cache_clear()
    run_id = "dlrun1"
    run = tmp_path / run_id
    run.mkdir()
    (run / "report.md").write_text("# r\n", encoding="utf-8")
    zip_path = create_run_archive(run)
    assert zip_path.is_file()

    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        api_key="sk-test",
        public_base_url="http://localhost:8000",
    )
    with patch("auditor.api.openai_compat.get_settings", return_value=settings):
        app = create_app()
        client = TestClient(app)
        url = public_download_url(settings, run_id)
        # path only for TestClient
        path = url.replace("http://localhost:8000", "")
        resp = client.get(path)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/zip")
        assert resp.content[:2] == b"PK"

    get_settings.cache_clear()
