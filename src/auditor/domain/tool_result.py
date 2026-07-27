"""Normalized tool evidence payload (EVID-001 / EVID-003).

Every registered tool invocation produces a :class:`ToolResult` with status,
output, error, tool identity, target (secret-free), timestamps, and provenance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

ToolResultStatus = Literal["ok", "error", "denied", "timeout", "unauthorized"]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ToolTargetRef(BaseModel):
    """Secret-free target identity resolved from inventory/run context."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: StrictStr = ""
    port: StrictInt | None = None
    username: StrictStr = ""
    transport: StrictStr = ""
    asset_id: StrictStr = ""
    label: StrictStr = ""


class ToolProvenance(BaseModel):
    """Provenance linking one tool result to the active audit context."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    client_id: StrictStr = ""
    audit_run_id: StrictStr = ""
    framework_id: StrictStr = ""
    requirement_id: StrictStr = ""
    requirement_title: StrictStr = ""
    asset_id: StrictStr = ""
    source: StrictStr = "tool_registry"
    tool_catalog_hash: StrictStr = ""
    capability_policy_hash: StrictStr = ""
    policy_decision: StrictStr = "allow"
    command_hash: StrictStr = ""


class ToolResult(BaseModel):
    """Normalized, secret-safe tool invocation result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ToolResultStatus
    output: StrictStr = ""
    error: StrictStr | None = None
    tool_id: StrictStr = Field(min_length=1)
    tool_version: StrictStr = ""
    target: ToolTargetRef = Field(default_factory=ToolTargetRef)
    started_at: StrictStr = Field(min_length=1)
    finished_at: StrictStr = Field(min_length=1)
    provenance: ToolProvenance = Field(default_factory=ToolProvenance)
    exit_code: StrictInt | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)

    def to_llm_text(self) -> str:
        """Format for LangChain ``ToolMessage`` content (compatible with SSH audits)."""
        if self.status == "denied":
            return f"Tool denied: {self.error or 'capability policy rejected invocation'}"
        if self.status == "unauthorized":
            return f"Tool unauthorized: {self.error or 'tool not authorized for this profile'}"
        if self.status == "timeout":
            return f"SSH error: TimeoutError: {self.error or 'command timed out'}"
        if self.status == "error" and self.error and not self.output:
            return self.error
        if self.output:
            return self.output
        if self.error:
            return self.error
        return f"status={self.status}"

    def to_evidence_record(self) -> dict[str, Any]:
        """Machine-readable sidecar payload (secrets already redacted in arguments)."""
        return {
            "schema": "tool_result.v1",
            "status": self.status,
            "output": self.output,
            "error": self.error,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "tool": self.tool_id,
            "arguments": dict(self.arguments),
            "exit_code": self.exit_code,
            "target": self.target.model_dump(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "written_at": _utc_now_iso(),
            "provenance": self.provenance.model_dump(),
            "result": self.to_llm_text(),
        }
