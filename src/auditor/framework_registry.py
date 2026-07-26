"""Administrator-managed Markdown framework registry (INPUT-002).

Discovers ``agents/*.md`` frameworks, parses framework-level metadata and
per-requirement blocks, validates them, and exposes compact catalog / index
views so assessment prompts receive only the current requirement's full text.

Adding a new framework requires only a new Markdown file — no Python changes.
Invalid frameworks remain visible with validation errors but are not executable.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Literal

import yaml

from auditor.checklist import Checklist, Requirement, parse_checklist_markdown
from auditor.frameworks import (
    _FRONTMATTER,
    Framework,
    FrameworkDetect,
    _default_aliases,
    _normalize_framework_language,
    _parse_detect,
)

ValidationLevel = Literal["error", "warning", "information"]


@dataclass(frozen=True, slots=True)
class FrameworkValidationIssue:
    """One validation finding for a framework or requirement."""

    level: ValidationLevel
    code: str
    message: str
    framework_id: str = ""
    requirement_id: str = ""
    location: str = ""


@dataclass(frozen=True, slots=True)
class FrameworkCatalogEntry:
    """Compact framework row for selection prompts (never full body)."""

    id: str
    version: str
    title: str
    description: str
    applicability: str
    discovery_guidance: str
    domain: str
    language: str
    executable: bool
    requirement_count: int
    validation_errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RequirementIndexEntry:
    """Compact requirement row for selected-framework indexes."""

    id: str
    title: str
    category: str
    severity: str
    applicability: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class RegisteredRequirement:
    """One validated (or invalid) requirement with provenance hash."""

    id: str
    title: str
    category: str = ""
    severity: str = ""
    applicability: str = ""
    evidence_required: str = ""
    verification_guidance: str = ""
    pass_criteria: str = ""
    fail_criteria: str = ""
    insufficient_evidence_criteria: str = ""
    recommendation: str = ""
    content_hash: str = ""
    raw: str = ""

    def to_requirement(self) -> Requirement:
        """Adapt to the legacy :class:`Requirement` used by assessment prompts."""
        return Requirement(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=self.severity,
            how_to_verify=self.verification_guidance,
            pass_criteria=self.pass_criteria,
            applicability=self.applicability,
            evidence_required=self.evidence_required,
            fail_criteria=self.fail_criteria,
            insufficient_evidence_criteria=self.insufficient_evidence_criteria,
            recommendation=self.recommendation,
            content_hash=self.content_hash,
            raw=self.raw,
        )

    def to_index_entry(self) -> RequirementIndexEntry:
        return RequirementIndexEntry(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=self.severity,
            applicability=self.applicability,
            content_hash=self.content_hash,
        )

    def to_prompt_block(self) -> str:
        return self.to_requirement().to_prompt_block()


@dataclass(frozen=True, slots=True)
class RegisteredFramework:
    """One ``agents/*.md`` framework with validation outcome."""

    framework: Framework
    applicability: str = ""
    discovery_guidance: str = ""
    requirements: tuple[RegisteredRequirement, ...] = ()
    issues: tuple[FrameworkValidationIssue, ...] = ()
    source_hash: str = ""

    @property
    def id(self) -> str:
        return self.framework.id

    @property
    def version(self) -> str:
        return self.framework.version

    @property
    def executable(self) -> bool:
        return not any(i.level == "error" for i in self.issues)

    def to_catalog_entry(self) -> FrameworkCatalogEntry:
        errors = tuple(i.message for i in self.issues if i.level == "error")
        return FrameworkCatalogEntry(
            id=self.framework.id,
            version=self.framework.version,
            title=self.framework.title,
            description=self.framework.description,
            applicability=self.applicability,
            discovery_guidance=self.discovery_guidance,
            domain=self.framework.domain,
            language=self.framework.language,
            executable=self.executable,
            requirement_count=len(self.requirements),
            validation_errors=errors,
        )

    def requirement_index(self) -> tuple[RequirementIndexEntry, ...]:
        return tuple(r.to_index_entry() for r in self.requirements)

    def get_requirement(self, requirement_id: str) -> RegisteredRequirement | None:
        wanted = (requirement_id or "").strip()
        for req in self.requirements:
            if req.id == wanted:
                return req
        return None

    def to_checklist(self) -> Checklist:
        return Checklist(
            title=self.framework.title,
            requirements=[r.to_requirement() for r in self.requirements],
            source_path=str(self.framework.path),
        )


class FrameworkNotExecutable(ValueError):
    """Raised when a non-executable framework is used for assessment."""

    def __init__(self, framework_id: str, issues: Iterable[FrameworkValidationIssue]) -> None:
        self.framework_id = framework_id
        self.issues = tuple(issues)
        detail = "; ".join(i.message for i in self.issues[:5]) or "validation failed"
        super().__init__(f"framework {framework_id!r} is not executable: {detail}")


@dataclass(slots=True)
class FrameworkRegistry:
    """In-memory registry of Markdown frameworks under ``agents/``."""

    agents_dir: Path
    frameworks: tuple[RegisteredFramework, ...] = ()
    _by_id: dict[str, RegisteredFramework] = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, agents_dir: Path | str | None = None) -> FrameworkRegistry:
        root = Path(agents_dir or "agents")
        if not root.is_dir():
            return cls(agents_dir=root, frameworks=())

        parsed: list[RegisteredFramework] = []
        for path in sorted(root.glob("*.md")):
            parsed.append(_parse_registered_framework(path))

        # Cross-framework duplicate IDs — mark every colliding entry.
        by_lower: dict[str, list[RegisteredFramework]] = {}
        for entry in parsed:
            by_lower.setdefault(entry.id.lower(), []).append(entry)

        adjusted: list[RegisteredFramework] = []
        for entry in parsed:
            issues = list(entry.issues)
            siblings = by_lower.get(entry.id.lower(), [])
            if len(siblings) > 1:
                others = ", ".join(
                    str(s.framework.path)
                    for s in siblings
                    if s.framework.path != entry.framework.path
                )
                issues.append(
                    FrameworkValidationIssue(
                        level="error",
                        code="duplicate_framework_id",
                        message=(f"duplicate framework id {entry.id!r} (also defined in {others})"),
                        framework_id=entry.id,
                        location=str(entry.framework.path),
                    )
                )
            adjusted.append(replace(entry, issues=tuple(issues)))

        by_id = {e.id: e for e in adjusted}
        return cls(agents_dir=root, frameworks=tuple(adjusted), _by_id=by_id)

    def get(self, framework_id: str) -> RegisteredFramework | None:
        return self._by_id.get((framework_id or "").strip())

    def list_all(self) -> list[RegisteredFramework]:
        return list(self.frameworks)

    def list_executable(self) -> list[RegisteredFramework]:
        return [f for f in self.frameworks if f.executable]

    def catalog(self, *, executable_only: bool = False) -> list[FrameworkCatalogEntry]:
        rows = self.list_executable() if executable_only else self.list_all()
        return [r.to_catalog_entry() for r in rows]

    def catalog_text(self, *, executable_only: bool = False) -> str:
        """Compact human-readable catalog for framework selection prompts."""
        entries = self.catalog(executable_only=executable_only)
        if not entries:
            return "No frameworks in agents/. Drop a .md checklist file to add one."
        lines = ["Available frameworks (from agents/):"]
        for entry in entries:
            status = "executable" if entry.executable else "INVALID"
            lines.append(
                f"- `{entry.id}` v{entry.version or '?'} [{entry.domain}/{status}]: "
                f"{entry.title} — {entry.description}"
            )
            if entry.applicability:
                lines.append(f"  applicability: {entry.applicability}")
            if entry.discovery_guidance:
                lines.append(f"  discovery: {entry.discovery_guidance}")
            if entry.validation_errors:
                lines.append(f"  errors: {'; '.join(entry.validation_errors[:3])}")
        return "\n".join(lines)

    def requirement_index(self, framework_id: str) -> list[RequirementIndexEntry]:
        entry = self.get(framework_id)
        if entry is None:
            return []
        return list(entry.requirement_index())

    def requirement_index_text(self, framework_id: str) -> str:
        """Compact requirement index for a selected framework (no full bodies)."""
        entries = self.requirement_index(framework_id)
        if not entries:
            return f"No requirements indexed for framework {framework_id!r}."
        lines = [f"Requirement index for `{framework_id}`:"]
        for item in entries:
            bits = [f"`{item.id}`", item.title]
            if item.category:
                bits.append(f"[{item.category}]")
            if item.severity:
                bits.append(f"sev={item.severity}")
            head = " — ".join(bits[:2])
            tail = (" " + " ".join(bits[2:])) if len(bits) > 2 else ""
            lines.append(f"- {head}{tail}")
        return "\n".join(lines)

    def get_requirement(
        self,
        framework_id: str,
        requirement_id: str,
    ) -> RegisteredRequirement | None:
        """Return full text for one requirement only."""
        entry = self.get(framework_id)
        if entry is None:
            return None
        return entry.get_requirement(requirement_id)

    def require_executable(self, framework_id: str) -> RegisteredFramework:
        entry = self.get(framework_id)
        if entry is None:
            raise FrameworkNotExecutable(
                framework_id,
                [
                    FrameworkValidationIssue(
                        level="error",
                        code="framework_not_found",
                        message=f"framework {framework_id!r} not found",
                        framework_id=framework_id,
                    )
                ],
            )
        if not entry.executable:
            raise FrameworkNotExecutable(framework_id, entry.issues)
        return entry


def load_framework_registry(agents_dir: Path | str | None = None) -> FrameworkRegistry:
    """Load and validate all Markdown frameworks from ``agents_dir``."""
    return FrameworkRegistry.load(agents_dir)


def deterministic_framework_version(source_hash: str) -> str:
    """Stable version token derived from the Markdown source hash.

    Used when YAML frontmatter omits ``version`` (frontmatter is optional).
    """
    digest = (source_hash or "").strip().lower()
    if not digest:
        digest = hashlib.sha256(b"").hexdigest()
    return f"src-{digest[:12]}"


def _parse_registered_framework(path: Path) -> RegisteredFramework:
    text = path.read_text(encoding="utf-8")
    source_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    meta: dict[str, Any] = {}
    body = text
    match = _FRONTMATTER.match(text)
    yaml_error = ""
    # YAML frontmatter is optional. When present it must be a mapping; when
    # absent, id/title/version are derived from filename, H1, and source hash.
    if match:
        try:
            loaded = yaml.safe_load(match.group(1)) or {}
            if isinstance(loaded, dict):
                meta = loaded
            else:
                yaml_error = "frontmatter is not a mapping"
        except yaml.YAMLError as exc:
            yaml_error = f"invalid YAML frontmatter: {exc}"
            meta = {}
        body = match.group(2)

    title_match = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
    title = str(
        meta.get("title") or (title_match.group(1).strip() if title_match else path.stem)
    ).strip()
    fw_id = str(meta.get("id") or path.stem).strip() or path.stem
    description = str(meta.get("description") or title).strip()
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
        aliases = tuple(dict.fromkeys((path.stem.lower(), *aliases)))

    domain = str(meta.get("domain") or "").strip().lower()
    if domain not in {"it", "cybersecurity"}:
        domain = "it" if fw_id == "it_audit" or "it_audit" in fw_id else "cybersecurity"

    detect = _parse_detect(meta.get("detect"))
    if (
        domain == "it"
        and fw_id == "it_audit"
        and not (detect.os_ids or detect.binaries or detect.ports or detect.always)
    ):
        detect = FrameworkDetect(always=True)

    version = str(meta.get("version") or meta.get("framework_version") or "").strip()
    if not version:
        version = deterministic_framework_version(source_hash)
    applicability = str(
        meta.get("applicability") or meta.get("applies_to") or meta.get("scope") or ""
    ).strip()
    discovery_guidance = str(
        meta.get("discovery_guidance")
        or meta.get("discovery")
        or meta.get("discovery_guidance_text")
        or ""
    ).strip()

    framework = Framework(
        id=fw_id,
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

    checklist = parse_checklist_markdown(body, source_path=str(path))
    requirements = tuple(_registered_from_requirement(r) for r in checklist.requirements)
    issues = _validate_framework(framework, requirements, yaml_error=yaml_error, path=path)
    return RegisteredFramework(
        framework=framework,
        applicability=applicability,
        discovery_guidance=discovery_guidance,
        requirements=requirements,
        issues=tuple(issues),
        source_hash=source_hash,
    )


def _registered_from_requirement(req: Requirement) -> RegisteredRequirement:
    return RegisteredRequirement(
        id=req.id,
        title=req.title,
        category=req.category,
        severity=req.severity,
        applicability=req.applicability,
        evidence_required=req.evidence_required,
        verification_guidance=req.how_to_verify or req.verification_guidance,
        pass_criteria=req.pass_criteria,
        fail_criteria=req.fail_criteria,
        insufficient_evidence_criteria=req.insufficient_evidence_criteria,
        recommendation=req.recommendation,
        content_hash=req.content_hash or _hash_requirement(req),
        raw=req.raw,
    )


def _hash_requirement(req: Requirement) -> str:
    payload = "\n".join(
        [
            req.id,
            req.title,
            req.category,
            req.severity,
            req.applicability,
            req.evidence_required,
            req.how_to_verify or req.verification_guidance,
            req.pass_criteria,
            req.fail_criteria,
            req.insufficient_evidence_criteria,
            req.recommendation,
            req.raw,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_framework(
    framework: Framework,
    requirements: tuple[RegisteredRequirement, ...],
    *,
    yaml_error: str,
    path: Path,
) -> list[FrameworkValidationIssue]:
    issues: list[FrameworkValidationIssue] = []
    if yaml_error:
        issues.append(
            FrameworkValidationIssue(
                level="error",
                code="invalid_frontmatter",
                message=yaml_error,
                framework_id=framework.id,
                location=str(path),
            )
        )
    if not framework.id.strip():
        issues.append(
            FrameworkValidationIssue(
                level="error",
                code="missing_framework_id",
                message="framework id is required",
                location=str(path),
            )
        )
    # Version is always populated (explicit frontmatter or source-hash fallback).
    if not requirements:
        issues.append(
            FrameworkValidationIssue(
                level="error",
                code="empty_framework",
                message="framework has no parseable requirement blocks",
                framework_id=framework.id,
                location=str(path),
            )
        )

    seen_req: set[str] = set()
    for req in requirements:
        if req.id in seen_req:
            issues.append(
                FrameworkValidationIssue(
                    level="error",
                    code="duplicate_requirement_id",
                    message=f"duplicate requirement id {req.id!r}",
                    framework_id=framework.id,
                    requirement_id=req.id,
                    location=str(path),
                )
            )
        seen_req.add(req.id)

        if not req.id.strip():
            issues.append(
                FrameworkValidationIssue(
                    level="error",
                    code="missing_requirement_id",
                    message="requirement id is empty",
                    framework_id=framework.id,
                    location=str(path),
                )
            )
        if not req.title.strip():
            issues.append(
                FrameworkValidationIssue(
                    level="error",
                    code="missing_requirement_title",
                    message=f"requirement {req.id!r} has empty title",
                    framework_id=framework.id,
                    requirement_id=req.id,
                )
            )
        if not req.verification_guidance.strip():
            issues.append(
                FrameworkValidationIssue(
                    level="error",
                    code="missing_verification_guidance",
                    message=(
                        f"requirement {req.id!r} missing verification guidance (/ how to verify)"
                    ),
                    framework_id=framework.id,
                    requirement_id=req.id,
                )
            )
        if not req.pass_criteria.strip():
            issues.append(
                FrameworkValidationIssue(
                    level="error",
                    code="missing_pass_criteria",
                    message=f"requirement {req.id!r} missing pass criteria",
                    framework_id=framework.id,
                    requirement_id=req.id,
                )
            )
        if not req.raw.strip() or len(req.raw.strip()) < 8:
            issues.append(
                FrameworkValidationIssue(
                    level="error",
                    code="malformed_requirement",
                    message=f"requirement {req.id!r} body is malformed or empty",
                    framework_id=framework.id,
                    requirement_id=req.id,
                )
            )

    # Optional guidance — information only when absent.
    if not framework.description.strip():
        issues.append(
            FrameworkValidationIssue(
                level="information",
                code="missing_description",
                message="framework description is empty",
                framework_id=framework.id,
            )
        )
    return issues


__all__ = [
    "FrameworkCatalogEntry",
    "FrameworkNotExecutable",
    "FrameworkRegistry",
    "FrameworkValidationIssue",
    "RegisteredFramework",
    "RegisteredRequirement",
    "RequirementIndexEntry",
    "deterministic_framework_version",
    "load_framework_registry",
]
