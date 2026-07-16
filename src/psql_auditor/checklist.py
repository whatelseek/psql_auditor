"""Parse Markdown audit checklists into structured requirement objects.

The auditor treats a Markdown file as the source of truth. Each requirement must
use a stable heading id of the form ``REQ-NNN`` plus metadata fields:

.. code-block:: markdown

    ## REQ-001: Authentication method
    **Category:** Access Control
    **Severity:** High
    **How to verify:** …
    **Pass criteria:** …

``parse_checklist_markdown`` extracts these blocks; ``load_checklist`` reads a
file from disk. The LangGraph ``load_checklist`` node calls ``load_checklist``
at the start of every audit run so checklist edits take effect without restart
(path itself still comes from settings).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Matches "## REQ-001: Title" headings (requirement boundaries).
_REQ_HEADING = re.compile(
    r"^##\s+(REQ-\d+)\s*:\s*(.+?)\s*$",
    re.MULTILINE,
)

# Matches bold metadata lines inside a requirement block.
_META = re.compile(
    r"^\*\*(Category|Severity|How to verify|Pass criteria):\*\*\s*(.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)


@dataclass(slots=True)
class Requirement:
    """A single auditable checklist item.

    Attributes:
        id: Stable identifier such as ``REQ-001``.
        title: Short human-readable name from the heading.
        category: Grouping label (e.g. Access Control, Encryption).
        severity: Risk severity hint (Critical / High / Medium / Low).
        how_to_verify: Instructions the agent should follow (tools / queries).
        pass_criteria: Conditions that define a passing assessment.
        raw: Original Markdown block for debugging or prompt fallback.
    """

    id: str
    title: str
    category: str = ""
    severity: str = ""
    how_to_verify: str = ""
    pass_criteria: str = ""
    raw: str = ""

    def to_prompt_block(self) -> str:
        """Format this requirement for injection into the assessment prompt.

        Returns:
            A compact Markdown-ish bullet block the LLM can reason over.
        """
        return (
            f"### {self.id}: {self.title}\n"
            f"- Category: {self.category}\n"
            f"- Severity: {self.severity}\n"
            f"- How to verify: {self.how_to_verify}\n"
            f"- Pass criteria: {self.pass_criteria}\n"
        )


@dataclass(slots=True)
class Checklist:
    """Parsed checklist document containing ordered requirements.

    Attributes:
        title: Document H1 title (or a default if missing).
        requirements: Requirements in document order (assessment order).
        source_path: Optional filesystem path the checklist was loaded from.
    """

    title: str
    requirements: list[Requirement] = field(default_factory=list)
    source_path: str | None = None

    def by_id(self) -> dict[str, Requirement]:
        """Index requirements by id for O(1) lookup during assessment.

        Returns:
            Mapping of ``REQ-NNN`` → ``Requirement``.
        """
        return {r.id: r for r in self.requirements}

    def ids(self) -> list[str]:
        """Return requirement ids in checklist order.

        Returns:
            Ordered list used to seed LangGraph ``pending_ids``.
        """
        return [r.id for r in self.requirements]


def parse_checklist_markdown(text: str, source_path: str | None = None) -> Checklist:
    """Parse checklist Markdown text into a ``Checklist`` object.

    Algorithm:

    1. Read the first H1 as the document title.
    2. Find all ``## REQ-NNN: …`` headings.
    3. For each heading, slice text until the next heading (or EOF).
    4. Extract ``Category``, ``Severity``, ``How to verify``, ``Pass criteria``.

    Args:
        text: Full Markdown document contents.
        source_path: Optional path stored on the resulting ``Checklist`` for
            diagnostics (not used for reading).

    Returns:
        A ``Checklist`` with zero or more ``Requirement`` entries. Missing
        metadata fields default to empty strings.
    """
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else "PostgreSQL Checklist"

    headings = list(_REQ_HEADING.finditer(text))
    requirements: list[Requirement] = []

    for idx, match in enumerate(headings):
        # Slice this requirement's Markdown block [heading, next_heading).
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
    """Load and parse a checklist Markdown file from disk.

    Args:
        path: Filesystem path to a UTF-8 Markdown checklist.

    Returns:
        Parsed ``Checklist``.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        OSError: On other I/O failures.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    return parse_checklist_markdown(text, source_path=str(path))
