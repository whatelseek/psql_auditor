"""Application settings loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LiteLLM
    litellm_base_url: str = "http://localhost:4000"
    litellm_api_key: str = "sk-litellm-local"
    litellm_model: str = "gpt-4o-mini"

    # API
    api_key: str | None = None
    host: str = "0.0.0.0"
    port: int = 8000
    model_id: str = "psql-auditor"

    # Checklist
    checklist_path: Path = Field(default=Path("checklists/postgres_cis.md"))

    # SSH
    ssh_host: str | None = None
    ssh_port: int = 22
    ssh_user: str = "postgres"
    ssh_private_key_path: str | None = None
    ssh_password: str | None = None
    ssh_connect_timeout: int = 15

    # PostgreSQL
    database_url: str | None = None
    pg_host: str | None = None
    pg_port: int = 5432
    pg_user: str = "postgres"
    pg_password: str | None = None
    pg_database: str = "postgres"

    # MCP
    mcp_postgres_url: str | None = None
    mcp_postgres_command: str | None = None
    mcp_postgres_args: str | None = None  # space-separated

    def resolve_database_url(self) -> str | None:
        if self.database_url:
            return self.database_url
        if self.pg_host:
            password = self.pg_password or ""
            auth = f"{self.pg_user}:{password}@" if password else f"{self.pg_user}@"
            return (
                f"postgresql://{auth}{self.pg_host}:{self.pg_port}/{self.pg_database}"
            )
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()
