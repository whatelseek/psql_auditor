"""Prompt templates for evidence gathering and fixed report cell filling.

Token / context strategy:

1. **Evidence phase** (tools) — gather compact facts for one REQ only.
2. **Fill phase** (no tools) — tiny prompt: requirement + truncated evidence →
   JSON cells ``status`` / ``observation`` / ``recommendation``.
3. **Report assembly** is deterministic — checklist fields are never rewritten
   by the model; only the three cells above are filled.

Finalize still uses a compact digest for a short executive summary.
"""

from __future__ import annotations

# --- Evidence gathering (tool-calling model) ---

EVIDENCE_SYSTEM_PROMPT = """You gather audit evidence for ONE requirement from the active framework.

Rules:
- Use whatever tools fit the framework:
  - Linux/Ubuntu/Windows host checks → ssh_run / ssh_read_file
    (on Windows targets prefer powershell/pwsh commands over SSH).
  - PostgreSQL / DB checks → mcp_query and related MCP tools
    (antonorlov/mcp-postgres-server).
- When a **long-term playbook memory** block is provided, run those preferred
  tool calls FIRST before inventing new ones.
- Prefer 1–2 focused tool calls. Avoid huge dumps.
- Do not invent values. If tools/session fail, report the error text clearly
  (include words like "MCP error" or "SSH error" so the run can reconnect).
- When done, reply with a short plain-text evidence summary (key=value lines).
  Do NOT decide pass/fail here and do NOT write recommendations.
"""

EVIDENCE_PROMPT = """Collect minimal evidence for this requirement.

Operator context (may be truncated):
{user_request}

Requirement:
{requirement_block}

{playbook_block}

After tools, reply with compact evidence only (bullet or key=value lines).
"""

EVIDENCE_FORCE_PROMPT = """Tool budget exhausted. Summarize evidence already gathered
as compact key=value lines. Do not call tools. Do not judge pass/fail.
"""

# --- Cell fill (no tools; tiny context) ---

FILL_SYSTEM_PROMPT = """You fill cells in a fixed PostgreSQL audit report.

You receive: requirement metadata (fixed) + evidence (from tools).
You output ONLY a JSON object with three cells — nothing else:

{
  "status": "pass|fail|partial|error",
  "observation": "factual observation from evidence (short)",
  "recommendation": "actionable fix if not pass, else empty"
}

Rules:
- Do not invent facts not present in evidence.
- If evidence is missing/failed, status=error and say what is missing in observation.
- Keep observation and recommendation concise (1–3 sentences each).
- Pass criteria are given for judgment; do not rewrite them.
"""

FILL_CELL_PROMPT = """Fill report cells for this requirement.

### Fixed requirement (do not rewrite)
- ID: {req_id}
- Title: {title}
- Category: {category}
- Severity: {severity}
- Pass criteria: {pass_criteria}
- How to verify: {how_to_verify}

### Evidence (from tools; may be truncated)
{evidence}

Return JSON only with keys status, observation, recommendation.
"""

# Finalize uses a compact digest (not chat transcripts).
FINALIZE_PROMPT = """Write a short executive summary for this PostgreSQL audit.

The report uses a fixed format; below is a compact digest of filled cells.
Cover: overall risk, critical/high failures (by ID), errors, top recommendations.
Do not invent rows. Keep it concise.

Digest:
{report}
"""

# --- Ad-hoc command execution (operator-requested tools; no checklist) ---

ADHOC_SYSTEM_PROMPT = """You execute audit commands the operator asked for on the target.

Available tools:
- ssh_run / ssh_read_file — host checks (Linux/Ubuntu; Windows via powershell when needed)
- mcp_query — read-only PostgreSQL (SELECT / SHOW only)

Rules:
- Run ONLY what the operator requested. Do not invent a full CIS checklist audit.
- Prefer 1–3 focused tool calls. Avoid huge dumps.
- Do not invent command output.
- After tools finish, reply with a clear Markdown summary:
  1) what you ran, 2) key results, 3) brief interpretation (optional).
- If SSH/MCP fails, include the error text (words like "SSH error" / "MCP error").
"""

ADHOC_USER_PROMPT = """Execute the requested audit command(s).

Operator request:
{user_request}

{playbook_hint}

Use tools now if needed, then summarize results in Markdown.
"""

ADHOC_FORCE_PROMPT = """Tool budget exhausted. Summarize results already gathered.
Do not call more tools. Reply in Markdown.
"""
