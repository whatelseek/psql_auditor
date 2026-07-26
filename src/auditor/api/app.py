"""FastAPI application entrypoint.

Creates the ASGI app that Open WebUI (or curl / the OpenAI SDK) talks to.
The OpenAI-compatible routes live under ``/v1``; ``/healthz`` is a simple
liveness probe for Compose / orchestrators.

Pipeline role:
    Boots the HTTP server that receives chat requests, authenticates API keys,
    and delegates audit work to ``ApplicationRuntime`` through ``openai_compat``.

Key entry points:
    * ``create_app()`` — Factory that builds a configured ``FastAPI`` instance.
    * ``app`` — Module-level ASGI app for ``uvicorn auditor.api.app:app``.
    * ``main()`` — Console-script entry invoked by the ``auditor`` command.

Run via::

    uvicorn auditor.api.app:app --host 0.0.0.0 --port 8000

or the console script ``auditor`` which calls ``main()``.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any, Callable

import uvicorn
from fastapi import FastAPI

from auditor import __version__
from auditor.api.openai_compat import router as openai_router
from auditor.application_runtime import ApplicationRuntime, RuntimeState, build_application_runtime
from auditor.config import Settings, load_settings


def create_app(
    settings: Settings | None = None,
    *,
    runtime_factory: Callable[[], Any] | None = None,
) -> FastAPI:
    """Build and configure the FastAPI application with runtime lifespan.

    Mounts the OpenAI-compatible ``/v1`` router and registers a ``/healthz``
    liveness endpoint. Each app instance owns an :class:`ApplicationRuntime`.

    Args:
        settings: Optional settings snapshot for the runtime.
        runtime_factory: Optional factory for tests (returns or awaits runtime).

    Returns:
        Configured ``FastAPI`` instance with title, version, and routers.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        runtime: ApplicationRuntime | None = None
        try:
            if runtime_factory is not None:
                produced = runtime_factory()
                runtime = await produced if asyncio.iscoroutine(produced) else produced
                if runtime.state is not RuntimeState.RUNNING:
                    await runtime.start()
            else:
                runtime = await build_application_runtime(settings)
            app.state.runtime = runtime
            yield
        finally:
            if runtime is not None:
                await runtime.close()

    app = FastAPI(
        title="LangGraph Auditor",
        version=__version__,
        description=(
            "OpenAI-compatible API for a LangGraph IT infrastructure security auditor. "
            "Point Open WebUI at /v1."
        ),
        lifespan=lifespan,
    )
    app.include_router(openai_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness probe used by Docker Compose and load balancers."""
        return {"status": "ok", "version": __version__}

    return app


# Module-level app for ``uvicorn auditor.api.app:app``.
app = create_app()


def main() -> None:
    """CLI entrypoint: start uvicorn with host/port from settings."""
    settings = load_settings()
    uvicorn.run(
        "auditor.api.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )
