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
from urllib.parse import unquote, urlparse

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
        agents_dir: Directory of drop-in framework Markdown files (``agents/*.md``).
        playbooks_dir: Seed YAML playbooks for long-term procedural memory
            (default ``agents/playbooks``).
        memory_dir: Persisted learned playbook overlay (LangGraph-style store).
        memory_enabled: Inject playbook memory into evidence prompts.
        memory_learn: When true, remember successful tool recipes (hot-path).
        evidence_dir: Root directory for per-run / per-requirement command
            artifacts (``<evidence_dir>/<run_id>/<framework>/<REQ-NNN>/``).
        hitl_enabled: When true, pause on failed requirements and ask the
            operator to skip or retry (LangGraph interrupt + chat resume).
        archive_enabled: When true, zip the evidence/report bundle after the
            audit completes and expose a download link in chat.
        public_base_url: Browser-reachable base URL for agent download links
            (e.g. ``http://localhost:8000``).
        open_webui_url: Internal Open WebUI base URL for uploading the zip
            (e.g. ``http://open-webui:8080``). Empty disables upload.
        open_webui_public_url: Optional public Open WebUI URL for absolute
            file links in chat (defaults to ``open_webui_url``).
        open_webui_api_key: Bearer token for Open WebUI file upload when auth
            is enabled.
        compliance_charts_in_report: When true, append SVG compliance charts
            to the finalized Markdown report.
        adhoc_commands_enabled: When true, command-style chat requests use the
            ad-hoc executor instead of a full checklist audit.
        max_session_retries: Max cyclic MCP/session reconnect attempts.
        ssh_host: Target host for SSH tools; ``None`` disables SSH until set.
        ssh_port: SSH port (default 22).
        ssh_user: SSH username.
        ssh_private_key_path: Path to a private key file inside the container/host.
        ssh_password: Password auth fallback when no key path is set.
        ssh_connect_timeout: Seconds to wait for the SSH TCP/handshake.
        database_url: Optional PostgreSQL DSN; parsed into PG_* for the MCP
            subprocess when discrete fields are incomplete.
        pg_host / pg_port / pg_user / pg_password / pg_database: Credentials
            passed to antonorlov/mcp-postgres-server as ``PG_*`` env vars.
        mcp_postgres_command: Stdio MCP executable (default ``npx``).
        mcp_postgres_args: Args for the MCP command (default
            ``-y mcp-postgres-server`` from antonorlov/mcp-postgres-server).
        max_tool_rounds_per_item: Cap ReAct tool loops per requirement (context
            safety). After the cap, the model must judge from gathered evidence.
        max_tool_output_chars: Truncate each tool result before it enters the
            LLM context.
        max_finding_evidence_chars: Cap stored finding evidence length.
        max_user_request_chars: Cap operator prompt injected into assess prompts.
        max_finalize_evidence_chars: Evidence snippet size in the finalize digest.
        max_parallel_assessments: Max concurrent requirement workers (LLM/tool
            fan-out). MCP stdio calls remain serialized for protocol safety.
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
    model_id: str = "auditor"

    # --- Drop-in frameworks (you create these) ---
    agents_dir: Path = Field(default=Path("agents"))
    # Long-term procedural memory (framework command playbooks)
    playbooks_dir: Path = Field(default=Path("agents/playbooks"))
    memory_dir: Path = Field(default=Path("memory"))
    memory_enabled: bool = True
    memory_learn: bool = True
    # Per-requirement command execution artifacts
    evidence_dir: Path = Field(default=Path("artifacts"))
    # Human-in-the-loop pause on failed REQs (skip / retry)
    hitl_enabled: bool = True
    # Zip report+evidence and link it in Open WebUI chat
    archive_enabled: bool = True
    public_base_url: str = "http://localhost:8000"
    open_webui_url: str | None = None
    open_webui_public_url: str | None = None
    open_webui_api_key: str | None = None
    # Append CIS compliance % bar charts to the final report text
    compliance_charts_in_report: bool = True
    # Allow chat to run ad-hoc SSH/SQL/playbook commands without a full audit
    adhoc_commands_enabled: bool = True
    max_session_retries: int = 2

    # --- SSH target (PostgreSQL host) ---
    ssh_host: str | None = None
    ssh_port: int = 22
    ssh_user: str = "postgres"
    ssh_private_key_path: str | None = None
    ssh_password: str | None = None
    ssh_connect_timeout: int = 15

    # --- PostgreSQL credentials for antonorlov/mcp-postgres-server ---
    database_url: str | None = None
    pg_host: str | None = None
    pg_port: int = 5432
    pg_user: str = "postgres"
    pg_password: str | None = None
    pg_database: str = "postgres"

    # --- MCP stdio: https://github.com/antonorlov/mcp-postgres-server ---
    mcp_postgres_command: str = "npx"
    mcp_postgres_args: str = "-y mcp-postgres-server"

    # --- Context window / quality / parallelism guards ---
    # One requirement per LLM window; truncate tools; cap ReAct depth.
    max_tool_rounds_per_item: int = 4
    max_tool_output_chars: int = 6000
    max_finding_evidence_chars: int = 2500
    max_user_request_chars: int = 1500
    max_finalize_evidence_chars: int = 240
    # Concurrent REQ-* workers (LLM overlap). MCP stdio is still single-flight.
    max_parallel_assessments: int = 5

    def resolve_pg_fields(self) -> dict[str, str | int]:
        """Resolve discrete PG connection fields, parsing ``database_url`` if needed.

        Returns:
            Dict with keys host, port, user, password, database. Missing values
            may be empty strings.
        """
        host = self.pg_host or ""
        port = self.pg_port
        user = self.pg_user
        password = self.pg_password or ""
        database = self.pg_database

        if self.database_url and not host:
            parsed = urlparse(self.database_url)
            host = parsed.hostname or ""
            port = parsed.port or 5432
            user = unquote(parsed.username) if parsed.username else user
            password = unquote(parsed.password) if parsed.password else password
            database = (parsed.path or "/").lstrip("/") or database

        return {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "database": database,
        }

    def pg_env_for_mcp(self) -> dict[str, str]:
        """Environment variables expected by antonorlov/mcp-postgres-server.

        The MCP server reads ``PG_HOST``, ``PG_PORT``, ``PG_USER``,
        ``PG_PASSWORD``, ``PG_DATABASE`` and auto-connects when all are set.

        Returns:
            Mapping suitable for ``StdioServerParameters.env`` overlays.
        """
        fields = self.resolve_pg_fields()
        env: dict[str, str] = {}
        if fields["host"]:
            env["PG_HOST"] = str(fields["host"])
        env["PG_PORT"] = str(fields["port"])
        if fields["user"]:
            env["PG_USER"] = str(fields["user"])
        if fields["password"]:
            env["PG_PASSWORD"] = str(fields["password"])
        if fields["database"]:
            env["PG_DATABASE"] = str(fields["database"])
        return env

    def resolve_database_url(self) -> str | None:
        """Build a PostgreSQL DSN from settings (diagnostics / fallbacks).

        Returns:
            A ``postgresql://…`` connection string, or ``None`` if incomplete.
        """
        if self.database_url:
            return self.database_url
        fields = self.resolve_pg_fields()
        if not fields["host"]:
            return None
        password = str(fields["password"] or "")
        user = str(fields["user"])
        auth = f"{user}:{password}@" if password else f"{user}@"
        return (
            f"postgresql://{auth}{fields['host']}:{fields['port']}/{fields['database']}"
        )


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached ``Settings`` instance.

    Caching avoids re-reading the environment on every tool call. Call
    ``get_settings.cache_clear()`` in tests after mutating ``os.environ``.

    Returns:
        The singleton ``Settings`` object for this process.
    """
    return Settings()
