"""FastAPI application entrypoint."""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from psql_auditor import __version__
from psql_auditor.api.openai_compat import router as openai_router
from psql_auditor.config import get_settings


def create_app() -> FastAPI:
    app = FastAPI(
        title="PostgreSQL LangGraph Auditor",
        version=__version__,
        description=(
            "OpenAI-compatible API for a LangGraph PostgreSQL security auditor. "
            "Point Open WebUI at /v1."
        ),
    )
    app.include_router(openai_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "psql_auditor.api.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
