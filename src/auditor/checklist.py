"""Parse Markdown audit checklists into structured requirement objects.

The auditor treats a Markdown file as the source of truth. Each requirement
uses a stable heading id plus metadata fields. Supported heading shapes:

.. code-block:: markdown

    ## REQ-001: Authentication method
    ### WIN-001 — Host identity

    **Category:** Access Control
    **Severity:** High
    **Applicability:** Windows Server
    **Evidence required:** WinRM hostname output
    **How to verify:** …   / **Verification guidance:** …
    **Pass criteria:** …
    **Fail criteria:** …
    **Insufficient evidence criteria:** …
    **Recommendation:** …

``parse_checklist_markdown`` extracts these blocks; ``load_checklist`` reads a
file from disk. Assessment prompts receive only the current requirement via
:meth:`Requirement.to_prompt_block` — never the entire framework body.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

# Matches "## REQ-001: Title" or "### WIN-001 — Title" (and hyphen variants).
_REQ_HEADING = re.compile(
    r"^(#{2,3})\s+"
    r"([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*-\d+)\s*"
    r"[—–\-:]\s*"
    r"(.+?)\s*$",
    re.MULTILINE,
)

# Bold metadata lines inside a requirement block (aliases allowed).
# Value may be empty so registry validation can reject blank required fields.
# Use horizontal whitespace only so an empty value does not swallow the next line.
_META = re.compile(
    r"^\*\*("
    r"Category|Severity|Applicability|"
    r"Evidence required|Evidence Required|"
    r"How to verify|Verification guidance|Verification Guidance|"
    r"Pass criteria|Fail criteria|"
    r"Insufficient evidence criteria|Insufficient-evidence criteria|"
    r"Insufficient evidence|Recommendation"
    r"):\*\*[^\S\n]*(.*?)[^\S\n]*$",
    re.MULTILINE | re.IGNORECASE,
)

_META_ALIASES = {
    "category": "category",
    "severity": "severity",
    "applicability": "applicability",
    "evidence required": "evidence_required",
    "how to verify": "verification_guidance",
    "verification guidance": "verification_guidance",
    "pass criteria": "pass_criteria",
    "fail criteria": "fail_criteria",
    "insufficient evidence criteria": "insufficient_evidence_criteria",
    "insufficient-evidence criteria": "insufficient_evidence_criteria",
    "insufficient evidence": "insufficient_evidence_criteria",
    "recommendation": "recommendation",
}


@dataclass(slots=True)
class Requirement:
    """A single auditable checklist item.

    Attributes:
        id: Stable identifier such as ``REQ-001`` or ``WIN-001``.
        title: Short human-readable name from the heading.
        category: Grouping label (e.g. Access Control, Encryption).
        severity: Risk severity hint (Critical / High / Medium / Low).
        how_to_verify: Instructions the agent should follow (tools / queries).
        pass_criteria: Conditions that define a passing assessment.
        applicability: Optional scope / OS / role applicability.
        evidence_required: Optional evidence expectations.
        fail_criteria: Optional explicit fail conditions.
        insufficient_evidence_criteria: When status should be insufficient.
        recommendation: Optional remediation guidance.
        content_hash: Deterministic hash of normalized requirement content.
        raw: Original Markdown block for debugging or prompt fallback.
        verification_guidance: Alias of ``how_to_verify`` (registry naming).
    """

    id: str
    title: str
    category: str = ""
    severity: str = ""
    how_to_verify: str = ""
    pass_criteria: str = ""
    applicability: str = ""
    evidence_required: str = ""
    fail_criteria: str = ""
    insufficient_evidence_criteria: str = ""
    recommendation: str = ""
    content_hash: str = ""
    raw: str = ""
    verification_guidance: str = ""

    def __post_init__(self) -> None:
        if not self.verification_guidance and self.how_to_verify:
            self.verification_guidance = self.how_to_verify
        elif not self.how_to_verify and self.verification_guidance:
            self.how_to_verify = self.verification_guidance
        if not self.content_hash:
            self.content_hash = content_hash_for_requirement(self)

    def to_prompt_block(self) -> str:
        """Format this requirement for injection into the assessment prompt.

        Returns only this requirement — never the full framework body.
        """
        lines = [
            f"### {self.id}: {self.title}",
            f"- Category: {self.category}",
            f"- Severity: {self.severity}",
        ]
        if self.applicability:
            lines.append(f"- Applicability: {self.applicability}")
        if self.evidence_required:
            lines.append(f"- Evidence required: {self.evidence_required}")
        lines.append(f"- How to verify: {self.how_to_verify or self.verification_guidance}")
        lines.append(f"- Pass criteria: {self.pass_criteria}")
        if self.fail_criteria:
            lines.append(f"- Fail criteria: {self.fail_criteria}")
        if self.insufficient_evidence_criteria:
            lines.append(f"- Insufficient evidence criteria: {self.insufficient_evidence_criteria}")
        if self.recommendation:
            lines.append(f"- Recommendation: {self.recommendation}")
        return "\n".join(lines) + "\n"


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
        """Index requirements by id for O(1) lookup during assessment."""
        return {r.id: r for r in self.requirements}

    def ids(self) -> list[str]:
        """Return requirement ids in checklist order."""
        return [r.id for r in self.requirements]


def content_hash_for_requirement(req: Requirement) -> str:
    """SHA-256 of normalized requirement fields (stable across reloads)."""
    payload = "\n".join(
        [
            (req.id or "").strip(),
            (req.title or "").strip(),
            (req.category or "").strip(),
            (req.severity or "").strip(),
            (req.applicability or "").strip(),
            (req.evidence_required or "").strip(),
            (req.how_to_verify or req.verification_guidance or "").strip(),
            (req.pass_criteria or "").strip(),
            (req.fail_criteria or "").strip(),
            (req.insufficient_evidence_criteria or "").strip(),
            (req.recommendation or "").strip(),
            (req.raw or "").strip(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_checklist_markdown(text: str, source_path: str | None = None) -> Checklist:
    """Parse checklist Markdown text into a ``Checklist`` object.

    Algorithm:

    1. Read the first H1 as the document title.
    2. Find all ``##`` / ``###`` requirement headings (``REQ-`` / ``WIN-`` / …).
    3. For each heading, slice text until the next heading (or EOF).
    4. Extract metadata fields (category, severity, criteria, …).

    Args:
        text: Full Markdown document contents.
        source_path: Optional path stored on the resulting ``Checklist``.

    Returns:
        A ``Checklist`` with zero or more ``Requirement`` entries. Missing
        optional metadata fields default to empty strings.
    """
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else "Audit Checklist"

    headings = list(_REQ_HEADING.finditer(text))
    requirements: list[Requirement] = []

    for idx, match in enumerate(headings):
        start = match.start()
        end = headings[idx + 1].start() if idx + 1 < len(headings) else len(text)
        block = text[start:end].strip()
        meta_raw = {key.lower(): value.strip() for key, value in _META.findall(block)}
        meta: dict[str, str] = {}
        for key, value in meta_raw.items():
            canon = _META_ALIASES.get(key)
            if canon:
                meta[canon] = value

        verification = meta.get("verification_guidance", "")
        requirements.append(
            Requirement(
                id=match.group(2).strip(),
                title=match.group(3).strip(),
                category=meta.get("category", ""),
                severity=meta.get("severity", ""),
                how_to_verify=verification,
                verification_guidance=verification,
                pass_criteria=meta.get("pass_criteria", ""),
                applicability=meta.get("applicability", ""),
                evidence_required=meta.get("evidence_required", ""),
                fail_criteria=meta.get("fail_criteria", ""),
                insufficient_evidence_criteria=meta.get("insufficient_evidence_criteria", ""),
                recommendation=meta.get("recommendation", ""),
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
