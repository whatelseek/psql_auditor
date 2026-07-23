"""FastAPI application entrypoint.

Creates the ASGI app that Open WebUI (or curl / the OpenAI SDK) talks to.
The OpenAI-compatible routes live under ``/v1``; ``/healthz`` is a simple
liveness probe for Compose / orchestrators.

Pipeline role:
    Boots the HTTP server that receives chat requests, authenticates API keys,
    and delegates audit work to ``auditor.graph`` through ``openai_compat``.

Key entry points:
    * ``create_app()`` — Factory that builds a configured ``FastAPI`` instance.
    * ``app`` — Module-level ASGI app for ``uvicorn auditor.api.app:app``.
    * ``main()`` — Console-script entry invoked by the ``auditor`` command.

Run via::

    uvicorn auditor.api.app:app --host 0.0.0.0 --port 8000

or the console script ``auditor`` which calls ``main()``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI

from auditor import __version__
from auditor.api.openai_compat import router as openai_router
from auditor.config import get_settings
from auditor.mlflow_store import configure_mlflow_safe


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Configure optional MLflow tracking once at process start."""
    configure_mlflow_safe(get_settings())
    yield


def create_app() -> FastAPI:
    """Build and configure the FastAPI application.

    Mounts the OpenAI-compatible ``/v1`` router and registers a ``/healthz``
    liveness endpoint. Kept as a factory (rather than only a module-level
    ``app``) so tests can create isolated instances with different settings.

    Returns:
        Configured ``FastAPI`` instance with title, version, and routers.
    """
    app = FastAPI(
        title="LangGraph Auditor",
        version=__version__,
        description=(
            "OpenAI-compatible API for a LangGraph IT infrastructure security auditor. "
            "Point Open WebUI at /v1."
        ),
        lifespan=_lifespan,
    )
    app.include_router(openai_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness probe used by Docker Compose and load balancers.

        Returns:
            JSON object with ``status`` (always ``"ok"``) and ``version``
            (the installed ``auditor`` package version).
        """
        return {"status": "ok", "version": __version__}

    return app


# Module-level app for ``uvicorn auditor.api.app:app``.
app = create_app()


def main() -> None:
    """CLI entrypoint: start uvicorn with host/port from settings.

    Reads ``Settings.host`` and ``Settings.port`` (environment-driven) and
    runs the module-level ``app`` without auto-reload. Invoked by the
    ``auditor`` console script defined in ``pyproject.toml``.
    """
    settings = get_settings()
    uvicorn.run(
        "auditor.api.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )
