"""Compatibility shim for Open WebUI terminal-server verification.

Open WebUI 0.10.x verifies plain terminal servers by calling GET /api/config.
The current Open Terminal image used in this project does not expose that
endpoint, so the UI reports a false "connection failed" even though file
operations work.

This module reuses Open Terminal's FastAPI app and adds a minimal /api/config
endpoint so verification succeeds.
"""

from __future__ import annotations

from open_terminal.main import app


@app.get("/api/config")
async def api_config() -> dict[str, object]:
    """Return minimal config metadata expected by Open WebUI verifier."""
    return {
        "terminal": {"enabled": True},
        "features": {"terminals": True},
    }

