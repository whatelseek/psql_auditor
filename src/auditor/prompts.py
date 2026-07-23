"""Prompt templates for evidence gathering and fixed report cell filling.

This module holds **string constants** for LLM system/user prompts across the
auditor pipeline. Templates use ``str.format`` placeholders; callers supply
language instructions, requirement blocks, and evidence digests.

Token / context strategy:

1. **Evidence phase** (tools) — gather compact facts for one REQ only.
2. **Fill phase** (no tools) — tiny prompt: requirement + truncated evidence →
   JSON cells ``status`` / ``observation`` / ``recommendation``.
3. **Report assembly** is deterministic — checklist fields are never rewritten
   by the model; only the three cells above are filled.

Finalize still uses a compact digest for a short executive summary.

Key template groups:
    ``EVIDENCE_*`` — per-requirement tool-calling during checklist audit.
    ``FILL_*`` / ``FINALIZE_PROMPT`` — cell fill and executive summary.
    ``ADHOC_*`` — operator-requested commands (:mod:`auditor.adhoc`).
    ``HOST_FACTS_*`` — fill HostFacts JSON after checklist discovery (and
    compact SSH fallback when ``agents/host_facts.md`` is missing).
    ``INTAKE_INTERPRET_*`` — structured parsing of intake questionnaire replies.
"""

from __future__ import annotations

# --- Evidence gathering (tool-calling model) ---

EVIDENCE_SYSTEM_PROMPT = """You gather audit evidence for ONE requirement from the active framework.

Rules:
- Use whatever tools fit the framework:
  - Linux/Ubuntu/Windows host checks → ssh_run / ssh_read_file
    (on Windows targets prefer powershell/pwsh commands over SSH).
  - PostgreSQL / DB checks → mcp_query and related MCP tools
    (LangChain MCP adapters → antonorlov/mcp-postgres-server).
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

FILL_SYSTEM_PROMPT = """You fill cells in a fixed security audit report.

You receive: requirement metadata (fixed) + evidence (from tools).
You output ONLY a JSON object with three cells — nothing else:

{{
  "status": "pass|fail|partial|error",
  "observation": "factual observation from evidence (short)",
  "recommendation": "actionable fix if not pass, else empty"
}}

Rules:
- Do not invent facts not present in evidence.
- If evidence is missing/failed, status=error and say what is missing in observation.
- Keep observation and recommendation concise (1–3 sentences each).
- Pass criteria are given for judgment; do not rewrite them.
- {language_instruction}
"""

FILL_CELL_PROMPT = """Fill report cells for this requirement.

Language: {report_language}
{language_instruction}

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
FINALIZE_PROMPT = """Write a short executive summary for this security audit.

Language: {report_language}
{language_instruction}

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
- {language_instruction}
"""

ADHOC_USER_PROMPT = """Execute the requested audit command(s).

Language: {report_language}
{language_instruction}

Operator request:
{user_request}

{playbook_hint}

Use tools now if needed, then summarize results in Markdown.
"""

ADHOC_FORCE_PROMPT = """Tool budget exhausted. Summarize results already gathered.
Do not call more tools. Reply in Markdown.
{language_instruction}
"""

# --- Host facts discovery (SSH tools only → structured HostFacts JSON) ---

HOST_FACTS_SYSTEM_PROMPT = """You gather live host inventory facts via SSH for framework selection.

Rules:
- Use ONLY ssh_run / ssh_read_file (Linux; on Windows use PowerShell via ssh_run).
- Collect: hostname, OS identity, IPs, CPU, RAM, disk summary, listening TCP ports,
  and a short set of audit-relevant binaries (postgres, mysql, docker, nginx, …).
- Prefer 1–3 focused tool calls. Do NOT dump the entire package database here —
  a dedicated software-inventory step collects the full list.
- Disk: use `df -hl -x tmpfs -x devtmpfs | head -n 15` (local only). NEVER bare
  `df -h` — it can hang for minutes on stale NFS/CIFS mounts.
- Do not invent values. If SSH fails, include "SSH error" in the summary.
- When done, reply with compact plain-text evidence (key=value or short bullets).
  Do NOT choose frameworks and do NOT write recommendations.
"""

HOST_FACTS_PROMPT = """Discover inventory facts on the current SSH target.

Operator context (may be truncated):
{user_request}

SSH target hint: {ssh_host}

After tools, reply with compact evidence only (key=value lines preferred).
"""

HOST_FACTS_FORCE_PROMPT = """Tool budget exhausted. Summarize host facts already gathered
as compact key=value lines. Do not call tools.
"""

HOST_FACTS_FILL_SYSTEM_PROMPT = """You extract structured host inventory from tool evidence.

Output ONLY a JSON object with these keys — nothing else:

{{
  "hostname": "",
  "ips": [],
  "os_id": "",
  "os_version_id": "",
  "os_pretty_name": "",
  "binaries": [],
  "packages": [],
  "key_files": [],
  "listening_ports": [],
  "cpu": "",
  "ram": "",
  "disk": "",
  "error": ""
}}

Rules:
- Do not invent facts not present in evidence.
- os_id must be lowercase (e.g. ubuntu, debian, windows, rhel, alpine).
- binaries: short names present on PATH, not full paths.
- packages: installed package/product names when present in evidence.
- listening_ports: integers only.
- If SSH/evidence failed, put the failure in "error" and leave other fields empty/default.
"""

HOST_FACTS_FILL_PROMPT = """Fill HostFacts JSON from this evidence.

SSH target: {ssh_host}

### Evidence (from tools; may be truncated)
{evidence}

Return JSON only with the HostFacts keys listed in the system prompt.
"""

# --- Prerun: LLM collects FULL package inventory (deb / rpm / Windows / …) ---

SOFTWARE_INVENTORY_SYSTEM_PROMPT = """You collect the COMPLETE installed-software inventory on the SSH target.

Rules:
- Use ONLY ssh_run / ssh_read_file. On Windows hosts use PowerShell via ssh_run.
- Detect the OS/package ecosystem yourself and use the right listing command:
  - Debian/Ubuntu: `dpkg-query -W -f='${{Package}}\\n'` (or `apt-cache` / `apt list --installed`)
  - RHEL/CentOS/Fedora/SUSE: `rpm -qa --qf '%{{NAME}}\\n'` (or `dnf`/`zypper` list)
  - Alpine: `apk info`
  - Arch: `pacman -Q`
  - Windows: `Get-Package` and/or Uninstall registry keys / `winget list`
- Goal: every installed package/product name, one per line.
- Also collect cheap signals when useful: OS id, a few BIN: names on PATH,
  and FILE: paths that prove stacks (e.g. /etc/postgresql, Program Files paths).
- Final assistant reply MUST be machine lines (no markdown tables):
  PKG:name
  BIN:name
  FILE:path
  OSID:id
  OSVER:version
  OSPRETTY:pretty name
- Do not invent packages. If a command fails, try an alternate for that OS family.
- Do NOT choose audit frameworks.
"""

SOFTWARE_INVENTORY_PROMPT = """Collect the full installed package/product inventory on this host.

SSH target hint: {ssh_host}
Extra binaries worth checking on PATH (from current agents/ detect rules): {extra_binaries}

Use the correct package manager for this OS (deb, rpm, apk, pacman, or Windows).
When done, reply with PKG:/BIN:/FILE:/OS* lines only.
"""

SOFTWARE_INVENTORY_FORCE_PROMPT = """Tool budget exhausted. From evidence already gathered,
emit PKG:/BIN:/FILE:/OS* lines only. Do not call more tools. Do not invent names.
"""

# --- Prerun: LLM maps full installed software → frameworks in agents/ ---

SOFTWARE_FRAMEWORK_ROUTE_SYSTEM = """You select audit frameworks from a FULL installed-software inventory.

You receive:
1) Complete package/product list (and binaries/files/OS) collected by an LLM tool pass
   that already chose the right package manager (deb / rpm / Windows / …)
2) Detect rules for every framework currently in agents/

Task: decide which frameworks apply to THIS host based on installed software
and OS — including stacks that are only visible as packages (e.g. mysql-server)
even when a short binary PATH check might miss them.

Output ONLY JSON:
{{
  "framework_ids": ["it_audit", "ubuntu_cis_24_l2"],
  "highlight_packages": ["postgresql-16", "openssh-server"],
  "highlight_binaries": ["psql", "sshd"],
  "notes": "short reason"
}}

Rules:
- framework_ids MUST be a subset of the provided framework ids (never invent ids).
- Include it_audit when it is in the catalog and domain allows (always-true detect).
- Prefer precision: do not select a DB framework unless packages/binaries/ports
  clearly indicate that database.
- highlight_* lists are the packages/binaries that justified the selection
  (for the operator UI). Keep each list ≤ 40 items.
- Do not invent packages not present in the inventory.
"""

SOFTWARE_FRAMEWORK_ROUTE_PROMPT = """Host: {ssh_host}
OS: {os_line}

### Framework detect catalog
{framework_catalog}

### Installed software inventory (from host; may be truncated)
{software_inventory}

Return JSON only as specified in the system prompt.
"""

# --- Интерпретация ответов intake (без tools; свободный текст → структура) ---

INTAKE_INTERPRET_YES_NO_SYSTEM = """You assess the operator's INTENT for a pre-audit availability question.

Judge meaning only. The operator answers in free form; do not expect any
particular vocabulary from them.

Output ONLY JSON in one of these shapes:
{{"answer":"yes"}}
{{"answer":"no"}}
{{"answer":"unknown"}}
{{"answer":"unknown","clarification":"short explanation of the question for the operator"}}

Internal labels (for JSON only — never tell the operator to say these words):
- yes = positive/available for the question
- no = negative/unavailable
- unknown = cannot tell from the reply

Critical — who the question is about:
- Access question asks whether the AUDIT AGENT / bot can reach servers
  (SSH, DB, APIs) — NOT whether the human operator personally has access.
- "ну ты можешь попасть, я нет" / "you can get in, I can't" → yes
  (agent may connect; operator cannot / will not).
- "SSH на .79" / "ты можешь туда попасть" / "go ahead and connect" → yes
- "пока только документы, без SSH" / "агенту доступа нет" → no

Inventory / access examples (when the question is about CMDB-style systems):
- "We track assets in Excel only" / "ведём учёт в Excel" → no
- "CMDB нет" / "только бумажный учёт" → no

Other rules:
- Answering a yes/no availability question with a colloquial affirmative
  ("ага", "угу", "да", "ок", "ok", "yeah", "yep", "sure", "конечно", "есть")
  → yes
- Colloquial negative ("неа", "не", "nope", "no", "нет") → no
- Bare meta-ack with no grant/deny ("понял", "ясно", "понятно") → unknown
- Clarifying questions ("что это?", "what is this?", "поясни") → unknown AND
  ``clarification`` in the SAME LANGUAGE as the operator (1–3 short sentences).
  Explain what you are asking (agent access vs human). Do NOT invent facts.
- Off-topic / nonsense ("Follow white rabbit") → unknown
- Do not invent facts beyond the reply.
- Always set ``answer`` to exactly ``yes``, ``no``, or ``unknown`` (English
  labels only) — never echo the operator's slang into ``answer``.
"""

INTAKE_INTERPRET_YES_NO_PROMPT = """Question context: {question_hint}

Operator reply:
{reply}

Assess intent from meaning. For access questions, decide whether the audit
agent can reach servers — not whether the human operator can.
Return JSON with answer = yes|no|unknown (optional clarification).
"""

INTAKE_INTERPRET_CLIENT_SYSTEM = """You extract the client / organization name from an operator reply.

Output ONLY JSON:
{{"client_name":"..."}} or {{"client_name":""}}

Rules:
- Strip prefixes like "Client:", "клиент:", etc.
- Return the organization/engagement name only.
- Empty string if the reply has no usable name.
"""

INTAKE_INTERPRET_CLIENT_PROMPT = """Operator reply:
{reply}

Return JSON with key client_name.
"""

INTAKE_INTERPRET_AUDIT_TYPE_SYSTEM = """You map an operator reply to an audit domain.

Output ONLY JSON:
{{"audit_type":"it"}} or {{"audit_type":"cybersecurity"}} or {{"audit_type":"both"}}
or {{"audit_type":null}}

Rules:
- Free-form is OK (e.g. "just the IT checklist", "CIS and Ubuntu").
- IT / inventory / ит → it
- CIS / cyber / cybersecurity / кибер / security / hardening → cybersecurity
- both / оба / cis+it / everything → both
- Numbers: 1 or cyber → cybersecurity; 2 or it → it; 3 → both
- null if unclear or off-topic
"""

INTAKE_INTERPRET_AUDIT_TYPE_PROMPT = """Operator reply:
{reply}

Return JSON with key audit_type = it|cybersecurity|both|null.
"""

INTAKE_INTERPRET_SCOPE_SYSTEM = """You map an operator reply about an audit host→framework plan.

Output ONLY JSON in one of these shapes:
{{"action":"confirm"}}
{{"action":"exclude","exclude_frameworks":["ubuntu_cis_24_l2"],"exclude_pairs":["10.0.0.1/postgres_cis"]}}
{{"action":"include","include_frameworks":["postgres_cis"],"include_pairs":["10.0.0.1/ubuntu_cis_24_l2"]}}
{{"action":"unknown"}}

Rules:
- Free-form is OK. Infer confirm / exclude / include from meaning, not only keywords.
- confirm / all / run all / ok / да / все / подтвердить / "looks good run it"
  / "да, запускай этот план" → confirm (accept the CURRENT plan as shown)
- exclude / skip / remove / исключи / убери / "skip ubuntu on .78" → exclude
  with ids from the CURRENT plan (remove those; keep the rest)
- include / only / keep / только / оставь / "only postgres" → include
  with ids from the CURRENT plan (keep ONLY those; drop the rest)
- host/framework pairs go in exclude_pairs / include_pairs; bare framework ids
  in exclude_frameworks / include_frameworks
- Only use framework ids / hosts that appear in the proposed plan
- unknown if off-topic or unclear
"""

INTAKE_INTERPRET_SCOPE_PROMPT = """Current proposed plan:
{plan}

Operator reply:
{reply}

Return JSON with action confirm|exclude|include|unknown.
"""
