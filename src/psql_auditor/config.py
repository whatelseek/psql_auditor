"""Application settings loaded from environment variables.

All runtime configuration for the auditor (LiteLLM gateway, API auth, SSH target,
PostgreSQL DSN, MCP server, checklist path) is centralized here via
``pydantic-settings``. Values are typically provided through a ``.env`` file or
process environment; see ``.env.example`` for the full key list.

Environment variable names map from field names in SCREAMING_SNAKE_CASE
(e.g. ``litellm_base_url`` ← ``LITELLM_BASE_URL``).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed configuration for the auditor process.

    Attributes:
        litellm_base_url: Base URL of the LiteLLM proxy (without or with ``/v1``).
        litellm_api_key: API key / master key sent to LiteLLM as Bearer token.
        litellm_model: Model name registered in LiteLLM ``model_list``.
        api_key: Optional Bearer token required by this agent's ``/v1`` API.
            When ``None`` or empty, the API is open (dev-friendly default).
        host: Bind address for the FastAPI/uvicorn server.
        port: Bind port for the FastAPI/uvicorn server.
        model_id: Model id advertised on ``GET /v1/models`` and used as default
            in chat completions (Open WebUI selects this name).
        checklist_path: Filesystem path to the Markdown checklist.
        ssh_host: Target host for SSH tools; ``None`` disables SSH until set.
        ssh_port: SSH port (default 22).
        ssh_user: SSH username.
        ssh_private_key_path: Path to a private key file inside the container/host.
        ssh_password: Password auth fallback when no key path is set.
        ssh_connect_timeout: Seconds to wait for the SSH TCP/handshake.
        database_url: Full PostgreSQL DSN for SQL tools (preferred).
        pg_host / pg_port / pg_user / pg_password / pg_database: Discrete DSN
            parts used when ``database_url`` is unset.
        mcp_postgres_url: SSE/HTTP URL of a Postgres MCP server.
        mcp_postgres_command: Executable for a stdio MCP server.
        mcp_postgres_args: Space-separated args for the stdio MCP command.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- LiteLLM gateway (agent → models) ---
    litellm_base_url: str = "http://localhost:4000"
    litellm_api_key: str = "sk-litellm-local"
    litellm_model: str = "gpt-4o-mini"

    # --- Agent HTTP API (Open WebUI → agent) ---
    api_key: str | None = None
    host: str = "0.0.0.0"
    port: int = 8000
    model_id: str = "psql-auditor"

    # --- Checklist source of truth ---
    checklist_path: Path = Field(default=Path("checklists/postgres_cis.md"))

    # --- SSH target (PostgreSQL host) ---
    ssh_host: str | None = None
    ssh_port: int = 22
    ssh_user: str = "postgres"
    ssh_private_key_path: str | None = None
    ssh_password: str | None = None
    ssh_connect_timeout: int = 15

    # --- Direct PostgreSQL connection for SQL tools ---
    database_url: str | None = None
    pg_host: str | None = None
    pg_port: int = 5432
    pg_user: str = "postgres"
    pg_password: str | None = None
    pg_database: str = "postgres"

    # --- Optional Postgres MCP server ---
    mcp_postgres_url: str | None = None
    mcp_postgres_command: str | None = None
    mcp_postgres_args: str | None = None  # space-separated CLI args

    def resolve_database_url(self) -> str | None:
        """Build a PostgreSQL DSN from settings.

        Preference order:

        1. ``database_url`` if set (used as-is).
        2. Discrete ``pg_*`` fields when ``pg_host`` is set.
        3. ``None`` when neither is configured (SQL tools return a clear error).

        Returns:
            A ``postgresql://…`` connection string, or ``None`` if incomplete.
        """
        if self.database_url:
            return self.database_url
        if self.pg_host:
            password = self.pg_password or ""
            # Include password in the userinfo section only when present.
            auth = f"{self.pg_user}:{password}@" if password else f"{self.pg_user}@"
            return (
                f"postgresql://{auth}{self.pg_host}:{self.pg_port}/{self.pg_database}"
            )
        return None


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached ``Settings`` instance.

    Caching avoids re-reading the environment on every tool call. Call
    ``get_settings.cache_clear()`` in tests after mutating ``os.environ``.

    Returns:
        The singleton ``Settings`` object for this process.
    """
    return Settings()
