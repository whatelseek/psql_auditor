"""Framework applicability metadata helpers (INPUT005-09).

Loads structured applicability from Markdown front matter without synthesizing
predicates from legacy ``detect:`` blocks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from auditor.domain.applicability import (
    FrameworkApplicabilityMeta,
    parse_applicability_meta,
)
from auditor.frameworks import (
    Framework,
    list_frameworks,
    read_framework_front_matter,
    replace_framework,
)


def applicability_meta_for_framework(
    framework: Framework,
) -> FrameworkApplicabilityMeta:
    """Return structured applicability metadata for one framework file."""
    path = Path(framework.path)
    try:
        raw = read_framework_front_matter(path)
    except OSError:
        return FrameworkApplicabilityMeta()
    return parse_applicability_meta(raw)


def list_frameworks_with_meta(
    agents_dir: Path | str | None = None,
) -> list[tuple[Framework, FrameworkApplicabilityMeta]]:
    """List every catalog framework with applicability metadata.

    Invalid structured metadata keeps the framework visible but marks it
    non-executable and appends sanitized validation errors.
    """
    result: list[tuple[Framework, FrameworkApplicabilityMeta]] = []
    for framework in list_frameworks(agents_dir, include_invalid=True):
        meta = applicability_meta_for_framework(framework)
        updated = framework
        if meta.has_structured_applicability and not meta.metadata_valid:
            errors = tuple(dict.fromkeys([*framework.validation_errors, *meta.validation_errors]))
            updated = replace_framework(
                framework,
                executable=False,
                validation_errors=errors,
            )
        result.append((updated, meta))
    return result


def applicability_meta_from_mapping(
    raw_front_matter: dict[str, Any] | None,
) -> FrameworkApplicabilityMeta:
    """Parse applicability from an already-loaded front-matter mapping."""
    return parse_applicability_meta(raw_front_matter)
