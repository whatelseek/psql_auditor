"""FastAPI application entrypoint.

Creates the ASGI app that Open WebUI (or curl / the OpenAI SDK) talks to.
The OpenAI-compatible routes live under ``/v1``; ``/healthz`` is a simple
liveness probe for Compose / orchestrators.

Run via::

    uvicorn auditor.api.app:app --host 0.0.0.0 --port 8000

or the console script ``auditor`` which calls ``main()``.
"""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from auditor import __version__
from auditor.api.openai_compat import router as openai_router
from auditor.config import get_settings


def create_app() -> FastAPI:
    """Build and configure the FastAPI application.

    Mounts the OpenAI-compatible router and registers a health endpoint.
    Kept as a factory (rather than only a module-level ``app``) so tests can
    create isolated instances if needed.

    Returns:
        Configured ``FastAPI`` instance.
    """
    app = FastAPI(
        title="LangGraph Auditor",
        version=__version__,
        description=(
            "OpenAI-compatible API for a LangGraph IT infrastructure security auditor. "
            "Point Open WebUI at /v1."
        ),
    )
    app.include_router(openai_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness probe used by Docker / load balancers.

        Returns:
            JSON ``{"status": "ok", "version": "<pkg version>"}``.
        """
        return {"status": "ok", "version": __version__}

    return app


# Module-level app for ``uvicorn auditor.api.app:app``.
app = create_app()


def main() -> None:
    """CLI entrypoint: start uvicorn with host/port from settings.

    Invoked by the ``auditor`` console script defined in ``pyproject.toml``.
    """
    settings = get_settings()
    uvicorn.run(
        "auditor.api.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
