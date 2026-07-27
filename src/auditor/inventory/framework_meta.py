"""Attach structured applicability metadata to Framework objects."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from auditor.domain.applicability import (
    ApplicabilityPredicate,
    ApplicabilitySpec,
    FrameworkApplicabilityMeta,
    parse_applicability_meta,
)
from auditor.frameworks import _FRONTMATTER, Framework, FrameworkDetect, list_frameworks


def load_framework_front_matter(path: Path) -> dict[str, Any]:
    """Return YAML front matter mapping for one framework file."""
    text = path.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(text)
    if not match:
        return {}
    try:
        loaded = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def applicability_meta_for_framework(framework: Framework) -> FrameworkApplicabilityMeta:
    """Parse structured applicability for a framework, synthesizing from detect if needed."""
    raw = load_framework_front_matter(Path(framework.path))
    meta = parse_applicability_meta(raw)
    if not meta.metadata_valid:
        return meta
    if not meta.applicability.is_empty():
        return meta
    # Synthesize safe predicates from legacy detect: blocks so existing agents
    # participate in dynamic selection without hardcoded Python maps.
    synthesized = _synthesize_from_detect(framework.detect, framework.domain)
    if synthesized.is_empty():
        return meta
    return FrameworkApplicabilityMeta(
        applicability=synthesized,
        required_capabilities=meta.required_capabilities,
        required_facts=meta.required_facts,
        discovery_hints=meta.discovery_hints,
        metadata_valid=True,
        validation_errors=(),
    )


def list_frameworks_with_meta(
    agents_dir: Path | str | None = None,
) -> list[tuple[Framework, FrameworkApplicabilityMeta]]:
    """Return executable-aware frameworks paired with applicability metadata."""
    out: list[tuple[Framework, FrameworkApplicabilityMeta]] = []
    for fw in list_frameworks(agents_dir):
        meta = applicability_meta_for_framework(fw)
        if not meta.metadata_valid:
            fw = replace(
                fw,
                executable=False,
                validation_errors=tuple(
                    dict.fromkeys([*fw.validation_errors, *meta.validation_errors])
                ),
            )
        out.append((fw, meta))
    return out


def _synthesize_from_detect(detect: FrameworkDetect, domain: str) -> ApplicabilitySpec:
    all_preds: list[ApplicabilityPredicate] = []
    any_preds: list[ApplicabilityPredicate] = []
    if detect.always:
        all_preds.append(
            ApplicabilityPredicate(fact="asset.id", operator="exists"),
        )
        return ApplicabilitySpec(all=tuple(all_preds))
    for os_id in detect.os_ids:
        token = os_id.lower()
        if token in {"ubuntu", "debian", "centos", "rhel", "rocky", "fedora", "suse"}:
            any_preds.append(
                ApplicabilityPredicate(
                    fact="os.distribution",
                    operator="in",
                    value=[token],
                )
            )
            any_preds.append(
                ApplicabilityPredicate(
                    fact="technology.ubuntu.status",
                    operator="in",
                    value=["confirmed", "suspected"],
                )
            )
            if token == "ubuntu":
                any_preds.append(
                    ApplicabilityPredicate(
                        fact="technology.linux.status",
                        operator="in",
                        value=["confirmed", "suspected"],
                    )
                )
        elif token == "windows":
            any_preds.append(
                ApplicabilityPredicate(
                    fact="os.family",
                    operator="equals",
                    value="windows",
                )
            )
            any_preds.append(
                ApplicabilityPredicate(
                    fact="technology.windows_server.status",
                    operator="in",
                    value=["confirmed", "suspected"],
                )
            )
        else:
            any_preds.append(
                ApplicabilityPredicate(
                    fact="os.family",
                    operator="equals",
                    value=token,
                )
            )
    for port in detect.ports:
        any_preds.append(
            ApplicabilityPredicate(
                fact=f"port.{int(port)}.status",
                operator="equals",
                value="open",
            )
        )
        if int(port) == 5432:
            any_preds.append(
                ApplicabilityPredicate(
                    fact="technology.postgresql.status",
                    operator="in",
                    value=["confirmed", "suspected"],
                )
            )
    for binary in detect.binaries:
        name = binary.lower()
        if name in {"postgres", "psql"}:
            any_preds.append(
                ApplicabilityPredicate(
                    fact="technology.postgresql.status",
                    operator="in",
                    value=["confirmed", "suspected"],
                )
            )
        else:
            any_preds.append(
                ApplicabilityPredicate(
                    fact=f"technology.{name}.status",
                    operator="in",
                    value=["confirmed", "suspected"],
                )
            )
    if not any_preds and not all_preds:
        if domain == "it":
            return ApplicabilitySpec(
                all=(ApplicabilityPredicate(fact="asset.id", operator="exists"),)
            )
        return ApplicabilitySpec()
    return ApplicabilitySpec(all=tuple(all_preds), any=tuple(any_preds))
