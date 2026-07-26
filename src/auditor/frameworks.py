"""Drop-in audit frameworks from the ``agents/`` directory.

Discovery and routing layer at the start of every audit run. Operators add
Markdown checklists under ``agents/<name>.md``; this module discovers them via
:mod:`auditor.framework_registry`, attaches validation results, and selects the
best match for a natural-language request or for live host facts.

Pipeline integration:

1. :func:`route_framework` / :func:`route_frameworks` pick **executable** frameworks.
2. :func:`select_frameworks_for_host` auto-selects by OS, binaries, and ports.
3. :func:`load_framework_checklist` feeds the LangGraph ``load_checklist`` node
   (raises if the framework failed registry validation).

You create frameworks — the code only discovers and validates them. Use
``REQ-NNN`` / ``WIN-NNN`` Markdown headings (see existing files) with YAML
frontmatter for ``id``, ``version``, aliases, description, applicability,
discovery guidance, and ``detect:`` host-matching rules. Invalid frameworks
remain visible in the catalog with errors but are not routed or executed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from auditor.checklist import Checklist, parse_checklist_markdown
from auditor.language import detect_report_language

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
        language: Preferred checklist language (``en`` / ``ru`` / ``any``).
        family_id: Logical family key used to prefer language variants.
        version: Explicit framework version from frontmatter (required to execute).
        applicability: Optional human-readable applicability statement.
        discovery_guidance: Optional discovery / pre-assessment guidance.
        executable: False when registry validation reported errors.
        validation_errors: Human-readable validation error messages.
    """

    id: str
    title: str
    path: Path
    description: str = ""
    aliases: tuple[str, ...] = ()
    domain: str = "cybersecurity"  # it | cybersecurity
    detect: FrameworkDetect = field(default_factory=FrameworkDetect)
    language: str = "any"  # any | en | ru
    family_id: str = ""
    version: str = ""
    applicability: str = ""
    discovery_guidance: str = ""
    executable: bool = True
    validation_errors: tuple[str, ...] = ()


def _normalize_framework_language(value: Any) -> str:
    """Normalize frontmatter language to ``any``/``en``/``ru``."""
    text = str(value or "").strip().lower().replace("_", "-")
    if not text:
        return "any"
    primary = text.split("-", 1)[0]
    if primary in {"en", "english", "английский"}:
        return "en"
    if primary in {"ru", "russian", "русский"}:
        return "ru"
    return "any"


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
    language = _normalize_framework_language(meta.get("language") or meta.get("lang"))
    family_id = str(meta.get("family_id") or "").strip()
    if not family_id:
        family_id = re.sub(r"_(en|ru)$", "", fw_id.lower())

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
    if (
        domain == "it"
        and fw_id == "it_audit"
        and not (detect.os_ids or detect.binaries or detect.ports or detect.always)
    ):
        detect = FrameworkDetect(always=True)

    version = str(meta.get("version") or meta.get("framework_version") or "").strip()
    if not version:
        # Match FrameworkRegistry: optional frontmatter → source-hash version.
        source_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        version = f"src-{source_hash[:12]}"
    applicability = str(
        meta.get("applicability") or meta.get("applies_to") or meta.get("scope") or ""
    ).strip()
    discovery_guidance = str(meta.get("discovery_guidance") or meta.get("discovery") or "").strip()

    return Framework(
        id=fw_id or path.stem,
        title=title,
        path=path,
        description=description,
        aliases=aliases,
        domain=domain,
        detect=detect,
        language=language,
        family_id=family_id,
        version=version,
        applicability=applicability,
        discovery_guidance=discovery_guidance,
    )


def _prefer_language_variants(
    frameworks: list[Framework],
    preferred_language: str | None,
) -> list[Framework]:
    """Prefer requested language variants per framework family when available."""
    lang = _normalize_framework_language(preferred_language)
    if lang not in {"en", "ru"}:
        return frameworks

    by_family: dict[str, list[Framework]] = {}
    for fw in frameworks:
        key = fw.family_id or fw.id
        by_family.setdefault(key, []).append(fw)

    selected: list[Framework] = []
    for group in by_family.values():
        matches = [fw for fw in group if fw.language == lang]
        if matches:
            selected.extend(matches)
            continue
        selected.extend(group)
    return selected


def list_frameworks(
    agents_dir: Path | str | None = None,
    *,
    include_invalid: bool = True,
) -> list[Framework]:
    """Discover all frameworks by scanning ``agents/*.md``.

    Uses the Markdown :class:`~auditor.framework_registry.FrameworkRegistry`
    so validation errors are attached. Invalid frameworks remain listed when
    ``include_invalid`` is true (default) but have ``executable=False``.

    Args:
        agents_dir: Directory containing drop-in Markdown frameworks.
        include_invalid: When false, omit frameworks that failed validation.

    Returns:
        Sorted list of frameworks (by id). Missing directory → empty list.
    """
    from auditor.framework_registry import load_framework_registry

    registry = load_framework_registry(agents_dir)
    out: list[Framework] = []
    for entry in registry.list_all():
        if not include_invalid and not entry.executable:
            continue
        errors = tuple(i.message for i in entry.issues if i.level == "error")
        out.append(
            replace_framework(
                entry.framework,
                executable=entry.executable,
                validation_errors=errors,
            )
        )
    return sorted(out, key=lambda f: f.id)


def list_executable_frameworks(agents_dir: Path | str | None = None) -> list[Framework]:
    """Return only frameworks that passed registry validation."""
    return list_frameworks(agents_dir, include_invalid=False)


def replace_framework(
    framework: Framework,
    *,
    executable: bool | None = None,
    validation_errors: tuple[str, ...] | None = None,
) -> Framework:
    """Return a copy of ``framework`` with selected fields replaced."""
    if executable is None and validation_errors is None:
        return framework
    if executable is None:
        return replace(framework, validation_errors=validation_errors or ())
    if validation_errors is None:
        return replace(framework, executable=executable)
    return replace(
        framework,
        executable=executable,
        validation_errors=validation_errors,
    )


def get_framework(
    framework_id: str,
    agents_dir: Path | str | None = None,
    *,
    executable_only: bool = False,
) -> Framework | None:
    """Look up a discovered framework by id.

    Args:
        framework_id: Framework slug to match (exact id comparison).
        agents_dir: Directory to scan; defaults to ``agents``.
        executable_only: When true, return ``None`` for invalid frameworks.

    Returns:
        The matching :class:`Framework`, or ``None`` if not found.
    """
    for fw in list_frameworks(agents_dir, include_invalid=not executable_only):
        if fw.id == framework_id:
            if executable_only and not fw.executable:
                return None
            return fw
    return None


def _score_frameworks(
    user_request: str,
    agents_dir: Path | str | None = None,
    *,
    preferred_language: str | None = None,
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
    frameworks = list_executable_frameworks(agents_dir)
    frameworks = _prefer_language_variants(frameworks, preferred_language)
    if not frameworks:
        # Surface invalid frameworks in the error when the directory is not empty.
        all_fw = list_frameworks(agents_dir, include_invalid=True)
        if all_fw and not any(f.executable for f in all_fw):
            raise FileNotFoundError(
                f"No executable frameworks in {Path(agents_dir or 'agents')}. "
                "All discovered Markdown frameworks failed validation."
            )
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
    *,
    preferred_language: str | None = None,
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
    lang = preferred_language or detect_report_language(user_request).code
    scored = _score_frameworks(user_request, agents_dir, preferred_language=lang)
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
    preferred_language: str | None = None,
) -> list[Framework]:
    """Return all frameworks clearly referenced in the request.

    Used for multi-standard audits, e.g. \"PostgreSQL and Ubuntu CIS\":
    each match runs as its own graph in parallel.

    A framework is included when its score is ``>= min_score`` (default 3 ≈
    one solid alias / title hit). If nothing clears the threshold, falls back
    to a single ``route_framework`` result.
    """
    lang = preferred_language or detect_report_language(user_request).code
    scored = _score_frameworks(user_request, agents_dir, preferred_language=lang)
    matched = [fw for score, fw in scored if score >= min_score]
    if not matched:
        return [
            route_framework(
                user_request,
                agents_dir,
                preferred_language=lang,
            )
        ]
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
        str(b).strip().lower() for b in (getattr(facts, "binaries", None) or []) if str(b).strip()
    }
    packages = {
        str(p).strip().lower() for p in (getattr(facts, "packages", None) or []) if str(p).strip()
    }
    ports: set[int] = set()
    for p in getattr(facts, "listening_ports", None) or []:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            continue

    if detect.os_ids:
        if not os_id or not any(os_id == want or os_id.startswith(want) for want in detect.os_ids):
            return False

    if detect.binaries or detect.ports:
        soft = False
        if detect.binaries and any(b.lower() in binaries for b in detect.binaries):
            soft = True
        # Package names (full dpkg/rpm list) — e.g. mysql-server ↔ binary "mysql".
        if detect.binaries and packages:
            for want in detect.binaries:
                w = want.lower()
                if any(w == pkg or w in pkg or pkg.startswith(w) for pkg in packages):
                    soft = True
                    break
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
    preferred_language: str | None = None,
) -> list[Framework]:
    """Pick frameworks whose domain + detect rules match host facts.

    Order: IT frameworks first (by id), then cybersecurity (by id).
    When domain includes ``it`` and nothing matches, fall back to ``it_audit``.
    """
    wanted = {d.lower() for d in (domains or ["it", "cybersecurity"])}
    candidates = _prefer_language_variants(
        list_executable_frameworks(agents_dir),
        preferred_language,
    )
    matched: list[Framework] = []
    for fw in candidates:
        if fw.domain not in wanted:
            continue
        if framework_matches_host(fw, facts):
            matched.append(fw)

    if "it" in wanted and not any(f.domain == "it" for f in matched):
        it_fw = get_framework("it_audit", agents_dir, executable_only=True)
        if it_fw is not None and it_fw not in matched:
            matched.insert(0, it_fw)

    matched.sort(key=lambda f: (0 if f.domain == "it" else 1, f.id))
    return matched


def prefer_framework_ids(
    framework_ids: list[str],
    *,
    agents_dir: Path | str | None = None,
    preferred_language: str | None = None,
) -> list[str]:
    """Deduplicate framework ids by family, preferring requested language.

    Keeps first-seen family order while replacing with the preferred-language
    variant when both RU/EN ids are present.
    """
    lang = _normalize_framework_language(preferred_language)
    order: list[str] = []
    chosen: dict[str, tuple[int, Framework | None, str]] = {}

    for index, fid in enumerate(framework_ids):
        fw = get_framework(fid, agents_dir)
        family = fw.family_id if fw and fw.family_id else (fw.id if fw else fid)
        if family not in chosen:
            order.append(family)
            chosen[family] = (index, fw, fid)
            continue

        prev_index, prev_fw, prev_fid = chosen[family]
        if (
            lang in {"en", "ru"}
            and fw is not None
            and fw.language == lang
            and (prev_fw is None or prev_fw.language != lang)
        ):
            chosen[family] = (prev_index, fw, fid)
            continue
        # Keep earlier entry otherwise.
        chosen[family] = (prev_index, prev_fw, prev_fid)

    result: list[str] = []
    for family in order:
        _idx, _fw, fid = chosen[family]
        if fid not in result:
            result.append(fid)
    return result


def load_framework_checklist(framework: Framework) -> Checklist:
    """Load checklist body for an **executable** framework only.

    Uses the Markdown registry so requirement blocks include content hashes and
    extended metadata. Non-executable frameworks raise
    :class:`~auditor.framework_registry.FrameworkNotExecutable`.

    Args:
        framework: Discovered framework whose :attr:`~Framework.path` is read.

    Returns:
        Parsed :class:`Checklist` with requirements in document order.
    """
    from auditor.framework_registry import FrameworkNotExecutable, load_framework_registry

    registry = load_framework_registry(framework.path.parent)
    entry = registry.get(framework.id)
    if entry is None:
        # Fallback for ad-hoc paths outside a registry scan.
        text = framework.path.read_text(encoding="utf-8")
        match = _FRONTMATTER.match(text)
        body = match.group(2) if match else text
        return parse_checklist_markdown(body, source_path=str(framework.path))
    if not entry.executable:
        raise FrameworkNotExecutable(framework.id, entry.issues)
    return entry.to_checklist()


def frameworks_catalog_text(agents_dir: Path | str | None = None) -> str:
    """Build a compact catalog of frameworks for selection prompts.

    Includes invalid frameworks with error markers so administrators can see
    them, but routing/execution uses only executable entries.
    """
    from auditor.framework_registry import load_framework_registry

    return load_framework_registry(agents_dir).catalog_text(executable_only=False)


def requirement_index_text(
    framework_id: str,
    agents_dir: Path | str | None = None,
) -> str:
    """Compact requirement index for a selected framework (no full bodies)."""
    from auditor.framework_registry import load_framework_registry

    return load_framework_registry(agents_dir).requirement_index_text(framework_id)


def get_requirement_prompt_block(
    framework_id: str,
    requirement_id: str,
    agents_dir: Path | str | None = None,
) -> str:
    """Return full text for the currently assessed requirement only."""
    from auditor.framework_registry import load_framework_registry

    req = load_framework_registry(agents_dir).get_requirement(framework_id, requirement_id)
    if req is None:
        return ""
    return req.to_prompt_block()


def frameworks_detect_catalog_text(agents_dir: Path | str | None = None) -> str:
    """Catalog frameworks with ``detect`` rules for LLM software routing.

    Args:
        agents_dir: Directory to scan for ``*.md`` frameworks.

    Returns:
        Multi-line text listing id, domain, and detect signals per framework.
    """
    frameworks = list_frameworks(agents_dir)
    if not frameworks:
        return "No frameworks in agents/."
    lines = ["Framework detect rules (from agents/ frontmatter):"]
    for fw in frameworks:
        d = fw.detect
        parts = [f"`{fw.id}` [{fw.domain}]"]
        if d.always:
            parts.append("always=true")
        if d.os_ids:
            parts.append("os_ids=" + ",".join(d.os_ids))
        if d.binaries:
            parts.append("binaries=" + ",".join(d.binaries))
        if d.ports:
            parts.append("ports=" + ",".join(str(p) for p in d.ports))
        parts.append(fw.description or fw.title)
        lines.append("- " + " | ".join(parts))
    return "\n".join(lines)
