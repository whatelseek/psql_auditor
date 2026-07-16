"""Parse Markdown checklist into structured requirements."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_REQ_HEADING = re.compile(
    r"^##\s+(REQ-\d+)\s*:\s*(.+?)\s*$",
    re.MULTILINE,
)
_META = re.compile(
    r"^\*\*(Category|Severity|How to verify|Pass criteria):\*\*\s*(.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)


@dataclass(slots=True)
class Requirement:
    id: str
    title: str
    category: str = ""
    severity: str = ""
    how_to_verify: str = ""
    pass_criteria: str = ""
    raw: str = ""

    def to_prompt_block(self) -> str:
        return (
            f"### {self.id}: {self.title}\n"
            f"- Category: {self.category}\n"
            f"- Severity: {self.severity}\n"
            f"- How to verify: {self.how_to_verify}\n"
            f"- Pass criteria: {self.pass_criteria}\n"
        )


@dataclass(slots=True)
class Checklist:
    title: str
    requirements: list[Requirement] = field(default_factory=list)
    source_path: str | None = None

    def by_id(self) -> dict[str, Requirement]:
        return {r.id: r for r in self.requirements}

    def ids(self) -> list[str]:
        return [r.id for r in self.requirements]


def parse_checklist_markdown(text: str, source_path: str | None = None) -> Checklist:
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else "PostgreSQL Checklist"

    headings = list(_REQ_HEADING.finditer(text))
    requirements: list[Requirement] = []

    for idx, match in enumerate(headings):
        start = match.start()
        end = headings[idx + 1].start() if idx + 1 < len(headings) else len(text)
        block = text[start:end].strip()
        meta = {
            key.lower(): value.strip()
            for key, value in _META.findall(block)
        }
        requirements.append(
            Requirement(
                id=match.group(1),
                title=match.group(2).strip(),
                category=meta.get("category", ""),
                severity=meta.get("severity", ""),
                how_to_verify=meta.get("how to verify", ""),
                pass_criteria=meta.get("pass criteria", ""),
                raw=block,
            )
        )

    return Checklist(title=title, requirements=requirements, source_path=source_path)


def load_checklist(path: str | Path) -> Checklist:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    return parse_checklist_markdown(text, source_path=str(path))
