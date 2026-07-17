"""Drop-in audit frameworks from the ``agents/`` directory.

You create frameworks — the code only discovers them:

1. Add ``agents/<name>.md`` (CIS Postgres, Ubuntu, Windows, custom, …)
2. Use the standard ``REQ-NNN`` Markdown shape (see existing files)
3. Optionally add YAML frontmatter for aliases / description

On each audit the agent routes the operator request to the best matching
``.md`` file and loads it as the fixed report skeleton.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from psql_auditor.checklist import Checklist, load_checklist, parse_checklist_markdown

_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)


@dataclass(frozen=True, slots=True)
class Framework:
    """One drop-in framework discovered from ``agents/*.md``."""

    id: str
    title: str
    path: Path
    description: str = ""
    aliases: tuple[str, ...] = ()


def _default_aliases(stem: str, title: str) -> tuple[str, ...]:
    """Derive search aliases from filename and title."""
    parts = {stem.lower(), stem.replace("_", " ").lower(), stem.replace("-", " ").lower()}
    for token in re.split(r"[\s_/.-]+", title.lower()):
        if len(token) >= 3:
            parts.add(token)
    return tuple(sorted(parts))


def _parse_agent_file(path: Path) -> Framework:
    """Parse one agents/*.md file into a Framework (frontmatter optional)."""
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

    return Framework(
        id=fw_id,
        title=title,
        path=path,
        description=description,
        aliases=aliases,
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
    """Lookup a discovered framework by id."""
    for fw in list_frameworks(agents_dir):
        if fw.id == framework_id:
            return fw
    return None


def route_framework(
    user_request: str,
    agents_dir: Path | str | None = None,
) -> Framework:
    """Pick the best framework for a natural-language audit request.

    Raises:
        FileNotFoundError: If ``agents/`` has no ``*.md`` frameworks.
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
            alias_l = alias.lower()
            if alias_l and alias_l in text:
                score += 3 if len(alias_l) > 4 else 1
        if fw.title.lower() in text:
            score += 4
        scored.append((score, fw))

    scored.sort(key=lambda x: (-x[0], x[1].id))
    best_score, best = scored[0]
    if best_score == 0:
        # Vague request: prefer a name containing 'postgres' if present, else first.
        for fw in frameworks:
            if "postgres" in fw.id.lower():
                return fw
        return frameworks[0]
    return best


def load_framework_checklist(framework: Framework) -> Checklist:
    """Load checklist body (strips YAML frontmatter if present)."""
    text = framework.path.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(text)
    body = match.group(2) if match else text
    return parse_checklist_markdown(body, source_path=str(framework.path))


def frameworks_catalog_text(agents_dir: Path | str | None = None) -> str:
    """Catalog string for prompts / help."""
    frameworks = list_frameworks(agents_dir)
    if not frameworks:
        return "No frameworks in agents/. Drop a .md checklist file to add one."
    lines = ["Available frameworks (from agents/):"]
    for fw in frameworks:
        alias_preview = ", ".join(fw.aliases[:6])
        lines.append(f"- `{fw.id}`: {fw.title} — {fw.description} (aliases: {alias_preview})")
    return "\n".join(lines)
