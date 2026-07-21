"""Drop-in audit frameworks from the ``agents/`` directory.

Discovery and routing layer at the start of every audit run. Operators add
Markdown checklists under ``agents/<name>.md``; this module scans that directory,
parses optional YAML frontmatter, and selects the best match for a natural-
language request or for live host facts.

Pipeline integration:

1. :func:`route_framework` / :func:`route_frameworks` pick framework(s) from chat.
2. :func:`select_frameworks_for_host` auto-selects by OS, binaries, and ports.
3. :func:`load_framework_checklist` feeds the LangGraph ``load_checklist`` node.

You create frameworks — the code only discovers them. Use the standard
``REQ-NNN`` Markdown shape (see existing files) and optional frontmatter for
aliases, description, and ``detect:`` host-matching rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from auditor.checklist import Checklist, parse_checklist_markdown

_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)


@dataclass(frozen=True, slots=True)
class FrameworkDetect:
    """Host-matching rules from agent frontmatter ``detect:`` block.

  Used by :func:`framework_matches_host` during intake to decide which
  cybersecurity or IT frameworks apply to the target without explicit operator
  naming.

  Attributes:
      os_ids: ``/etc/os-release`` id prefixes that must match (e.g. ``ubuntu``).
      binaries: At least one of these command names must be present on the host.
      ports: At least one listening TCP port must match.
      always: When ``True``, the framework matches every host in its domain.
  """

    os_ids: tuple[str, ...] = ()
    binaries: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    always: bool = False


@dataclass(frozen=True, slots=True)
class Framework:
    """One drop-in framework discovered from ``agents/*.md``.

  Attributes:
      id: Stable framework slug (from frontmatter or filename stem).
      title: Human-readable checklist title.
      path: Absolute or relative path to the Markdown file.
      description: Short summary for catalogs and prompts.
      aliases: Search tokens for :func:`route_framework` scoring.
      domain: ``it`` or ``cybersecurity`` for intake filtering.
      detect: Host auto-detection rules parsed from frontmatter.
  """

    id: str
    title: str
    path: Path
    description: str = ""
    aliases: tuple[str, ...] = ()
    domain: str = "cybersecurity"  # it | cybersecurity
    detect: FrameworkDetect = field(default_factory=FrameworkDetect)


def _default_aliases(stem: str, title: str) -> tuple[str, ...]:
    """Derive search aliases from filename stem and document title.

  Splits the title on whitespace and punctuation and keeps tokens of length ≥ 3.
  Includes underscore/hyphen variants of the stem for flexible operator matching.

  Args:
      stem: Filename without extension (e.g. ``postgres_cis``).
      title: H1 title from the checklist body.

  Returns:
      Sorted unique lowercase alias strings.
  """
    parts = {stem.lower(), stem.replace("_", " ").lower(), stem.replace("-", " ").lower()}
    for token in re.split(r"[\s_/.-]+", title.lower()):
        if len(token) >= 3:
            parts.add(token)
    return tuple(sorted(parts))


def _parse_detect(raw: Any) -> FrameworkDetect:
    """Parse a frontmatter ``detect`` mapping into :class:`FrameworkDetect`.

  Accepts comma-separated strings or lists for ``os_ids``, ``binaries``, and
  ``ports``. Invalid port values are skipped silently.

  Args:
      raw: YAML-loaded value under the ``detect`` key (dict or non-dict).

  Returns:
      Normalized detect rules, or empty rules when ``raw`` is not a dict.
  """
    if not isinstance(raw, dict):
        return FrameworkDetect()
    os_ids_raw = raw.get("os_ids") or raw.get("os") or []
    binaries_raw = raw.get("binaries") or raw.get("commands") or []
    ports_raw = raw.get("ports") or []
    if isinstance(os_ids_raw, str):
        os_ids = tuple(x.strip().lower() for x in os_ids_raw.split(",") if x.strip())
    else:
        os_ids = tuple(str(x).strip().lower() for x in os_ids_raw if str(x).strip())
    if isinstance(binaries_raw, str):
        binaries = tuple(x.strip() for x in binaries_raw.split(",") if x.strip())
    else:
        binaries = tuple(str(x).strip() for x in binaries_raw if str(x).strip())
    ports: list[int] = []
    if isinstance(ports_raw, (list, tuple)):
        for p in ports_raw:
            try:
                ports.append(int(p))
            except (TypeError, ValueError):
                continue
    elif ports_raw not in (None, ""):
        try:
            ports.append(int(ports_raw))
        except (TypeError, ValueError):
            pass
    always = bool(raw.get("always"))
    return FrameworkDetect(
        os_ids=os_ids,
        binaries=binaries,
        ports=tuple(ports),
        always=always,
    )


def _parse_agent_file(path: Path) -> Framework:
    """Parse one ``agents/*.md`` file into a :class:`Framework`.

  Reads optional YAML frontmatter, extracts title from H1 or meta, builds
  aliases, infers domain, and applies IT-audit defaults when detect rules are
  absent.

  Args:
      path: Path to a framework Markdown file.

  Returns:
      Fully populated :class:`Framework` instance.

  Raises:
      OSError: If the file cannot be read (propagated from :meth:`Path.read_text`).
  """
    text = path.read_text(encoding="utf-8")
    meta: dict = {}
    body = text
    match = _FRONTMATTER.match(text)
    if match:
        try:
            loaded = yaml.safe_load(match.group(1)) or {}
            if isinstance(loaded, dict):
                meta = loaded
        except yaml.YAMLError:
            meta = {}
        body = match.group(2)

    title_match = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
    title = str(meta.get("title") or (title_match.group(1).strip() if title_match else path.stem))
    fw_id = str(meta.get("id") or path.stem)
    description = str(meta.get("description") or title)

    aliases_raw = meta.get("aliases") or []
    if isinstance(aliases_raw, str):
        aliases = tuple(a.strip() for a in aliases_raw.split(",") if a.strip())
    elif isinstance(aliases_raw, (list, tuple)):
        aliases = tuple(str(a).strip() for a in aliases_raw if str(a).strip())
    else:
        aliases = ()

    if not aliases:
        aliases = _default_aliases(path.stem, title)
    else:
        # Always include stem so `audit postgres_cis` works.
        aliases = tuple(dict.fromkeys((path.stem.lower(), *aliases)))

    domain = str(meta.get("domain") or "").strip().lower()
    if domain not in {"it", "cybersecurity"}:
        # Heuristic: it_audit → it; everything else → cybersecurity
        domain = "it" if fw_id == "it_audit" or "it_audit" in fw_id else "cybersecurity"

    detect = _parse_detect(meta.get("detect"))
    # it_audit defaults to always-on when domain is IT and no detect block
    if domain == "it" and fw_id == "it_audit" and not (
        detect.os_ids or detect.binaries or detect.ports or detect.always
    ):
        detect = FrameworkDetect(always=True)

    return Framework(
        id=fw_id,
        title=title,
        path=path,
        description=description,
        aliases=aliases,
        domain=domain,
        detect=detect,
    )


def list_frameworks(agents_dir: Path | str | None = None) -> list[Framework]:
    """Discover all frameworks by scanning ``agents/*.md``.

    Args:
        agents_dir: Directory containing drop-in Markdown frameworks.

    Returns:
        Sorted list of frameworks (by id). Missing directory → empty list.
    """
    root = Path(agents_dir or "agents")
    if not root.is_dir():
        return []
    frameworks = [_parse_agent_file(path) for path in sorted(root.glob("*.md"))]
    return sorted(frameworks, key=lambda f: f.id)


def get_framework(
    framework_id: str,
    agents_dir: Path | str | None = None,
) -> Framework | None:
    """Look up a discovered framework by id.

  Args:
      framework_id: Framework slug to match (exact id comparison).
      agents_dir: Directory to scan; defaults to ``agents``.

  Returns:
      The matching :class:`Framework`, or ``None`` if not found.
  """
    for fw in list_frameworks(agents_dir):
        if fw.id == framework_id:
            return fw
    return None


def _score_frameworks(
    user_request: str,
    agents_dir: Path | str | None = None,
) -> list[tuple[int, Framework]]:
    """Score every discovered framework against the operator request text.

  Scoring weights: exact id match (+10), alias word-boundary hits (+1–3 by
  length), title substring (+4). Results are sorted by descending score, then id.

  Args:
      user_request: Natural-language audit request from chat.
      agents_dir: Framework directory to scan.

  Returns:
      List of ``(score, framework)`` tuples, highest score first.

  Raises:
      FileNotFoundError: When ``agents_dir`` contains no ``*.md`` frameworks.
  """
    frameworks = list_frameworks(agents_dir)
    if not frameworks:
        raise FileNotFoundError(
            f"No frameworks found in {Path(agents_dir or 'agents')}. "
            "Add Markdown files like agents/ubuntu_cis.md"
        )

    text = f" {user_request.lower()} "
    scored: list[tuple[int, Framework]] = []
    for fw in frameworks:
        score = 0
        if re.search(rf"\b{re.escape(fw.id.lower())}\b", text):
            score += 10
        for alias in fw.aliases:
            alias_l = alias.lower().strip()
            if not alias_l:
                continue
            # Word-boundary match so short aliases like ``it`` do not hit
            # substrings inside ``audit``.
            if re.search(rf"\b{re.escape(alias_l)}\b", text):
                score += 3 if len(alias_l) > 4 else 1
        if fw.title.lower() in text:
            score += 4
        scored.append((score, fw))

    scored.sort(key=lambda x: (-x[0], x[1].id))
    return scored


def route_framework(
    user_request: str,
    agents_dir: Path | str | None = None,
) -> Framework:
    """Pick the single best framework for a natural-language audit request.

  When no alias/id scores above zero, falls back to the first framework whose
  id contains ``postgres``, else the first discovered framework alphabetically.

  Args:
      user_request: Operator chat text naming or implying a standard.
      agents_dir: Framework directory to scan.

  Returns:
      The highest-scoring :class:`Framework`.

  Raises:
      FileNotFoundError: When no frameworks exist in ``agents_dir``.
  """
    scored = _score_frameworks(user_request, agents_dir)
    best_score, best = scored[0]
    if best_score == 0:
        for _score, fw in scored:
            if "postgres" in fw.id.lower():
                return fw
        return scored[0][1]
    return best


def route_frameworks(
    user_request: str,
    agents_dir: Path | str | None = None,
    *,
    min_score: int = 3,
) -> list[Framework]:
    """Return all frameworks clearly referenced in the request.

    Used for multi-standard audits, e.g. \"PostgreSQL and Ubuntu CIS\":
    each match runs as its own graph in parallel.

    A framework is included when its score is ``>= min_score`` (default 3 ≈
    one solid alias / title hit). If nothing clears the threshold, falls back
    to a single ``route_framework`` result.
    """
    scored = _score_frameworks(user_request, agents_dir)
    matched = [fw for score, fw in scored if score >= min_score]
    if not matched:
        return [route_framework(user_request, agents_dir)]
    # Preserve score order (already sorted).
    return matched


def framework_matches_host(fw: Framework, facts: Any) -> bool:
    """True when host facts satisfy the framework's ``detect`` rules.

    Rule groups:
    - ``always`` → match
    - ``os_ids`` → OS id must match (when specified)
    - ``binaries`` / ``ports`` → at least one binary **or** listening port
      (OR within software signals)
    """
    detect = fw.detect
    if detect.always:
        return True

    has_rules = bool(detect.os_ids or detect.binaries or detect.ports)
    if not has_rules:
        return False

    os_id = str(getattr(facts, "os_id", "") or "").strip().lower()
    binaries = {
        str(b).strip().lower()
        for b in (getattr(facts, "binaries", None) or [])
        if str(b).strip()
    }
    ports: set[int] = set()
    for p in getattr(facts, "listening_ports", None) or []:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            continue

    if detect.os_ids:
        if not os_id or not any(
            os_id == want or os_id.startswith(want) for want in detect.os_ids
        ):
            return False

    if detect.binaries or detect.ports:
        soft = False
        if detect.binaries and any(b.lower() in binaries for b in detect.binaries):
            soft = True
        if detect.ports and any(p in ports for p in detect.ports):
            soft = True
        if not soft:
            return False

    return True


def select_frameworks_for_host(
    facts: Any,
    *,
    domains: list[str] | tuple[str, ...] | None = None,
    agents_dir: Path | str | None = None,
) -> list[Framework]:
    """Pick frameworks whose domain + detect rules match host facts.

    Order: IT frameworks first (by id), then cybersecurity (by id).
    When domain includes ``it`` and nothing matches, fall back to ``it_audit``.
    """
    wanted = {d.lower() for d in (domains or ["it", "cybersecurity"])}
    matched: list[Framework] = []
    for fw in list_frameworks(agents_dir):
        if fw.domain not in wanted:
            continue
        if framework_matches_host(fw, facts):
            matched.append(fw)

    if "it" in wanted and not any(f.domain == "it" for f in matched):
        it_fw = get_framework("it_audit", agents_dir)
        if it_fw is not None and it_fw not in matched:
            matched.insert(0, it_fw)

    matched.sort(key=lambda f: (0 if f.domain == "it" else 1, f.id))
    return matched


def load_framework_checklist(framework: Framework) -> Checklist:
    """Load checklist body from a framework file, stripping YAML frontmatter.

  Delegates to :func:`auditor.checklist.parse_checklist_markdown` on the body
  after optional frontmatter removal.

  Args:
      framework: Discovered framework whose :attr:`~Framework.path` is read.

  Returns:
      Parsed :class:`Checklist` with requirements in document order.
  """
    text = framework.path.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(text)
    body = match.group(2) if match else text
    return parse_checklist_markdown(body, source_path=str(framework.path))


def frameworks_catalog_text(agents_dir: Path | str | None = None) -> str:
    """Build a human-readable catalog of available frameworks for prompts.

  Args:
      agents_dir: Directory to scan for ``*.md`` frameworks.

  Returns:
      Multi-line bullet list suitable for system prompts or help text.
  """
    frameworks = list_frameworks(agents_dir)
    if not frameworks:
        return "No frameworks in agents/. Drop a .md checklist file to add one."
    lines = ["Available frameworks (from agents/):"]
    for fw in frameworks:
        alias_preview = ", ".join(fw.aliases[:6])
        lines.append(
            f"- `{fw.id}` [{fw.domain}]: {fw.title} — {fw.description} "
            f"(aliases: {alias_preview})"
        )
    return "\n".join(lines)
