"""Context-window guards for high-quality, bounded audit turns.

Design goals:

* **Safe context** — each checklist item gets a fresh message window; tool
  outputs are truncated; tool rounds are capped; finalize sees a compact
  findings digest rather than the full chat transcript.
* **Maximize quality** — still assess one requirement at a time with full
  requirement text and enough evidence; never batch-score many REQs in one
  LLM call (that hurts judgment quality).
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, BaseMessage

from auditor.state import Finding


def truncate_text(text: str, max_chars: int, label: str = "output") -> str:
    """Truncate ``text`` to ``max_chars``, appending a clear marker if cut.

    Args:
        text: Original string.
        max_chars: Maximum length to keep (must be > 32 to leave room for marker).
        label: Name used in the truncation marker.

    Returns:
        Original text if short enough; otherwise a prefix plus a marker.
    """
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    keep = max(max_chars - 80, 32)
    return (
        f"{text[:keep]}\n\n…[truncated {label}: kept {keep} of {len(text)} chars]"
    )


def count_tool_rounds(messages: list[BaseMessage]) -> int:
    """Count AIMessages that requested tools in the current window.

    Args:
        messages: Current per-item message window.

    Returns:
        Number of assistant turns that included ``tool_calls``.
    """
    n = 0
    for msg in messages:
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            n += 1
    return n


def compact_findings_for_summary(
    findings: dict[str, Finding],
    evidence_chars: int = 240,
) -> str:
    """Build a compact digest for the finalize LLM call.

    Keeps status/severity/title and a short evidence snippet so the summary
    model stays inside a safe context while still seeing what matters.

    Args:
        findings: Full findings map from the audit run.
        evidence_chars: Max evidence characters per finding in the digest.

    Returns:
        Compact Markdown table-like bullet list.
    """
    lines = [
        "| ID | Status | Severity | Title | Observation | Recommendation |",
        "|---|---|---|---|---|---|",
    ]
    ordered = sorted(
        findings.values(),
        key=lambda raw: (
            (raw.requirement_id if isinstance(raw, Finding) else str(raw.get("requirement_id") or ""))
        ),
    )
    for raw in ordered:
        f = raw if isinstance(raw, Finding) else Finding.model_validate(raw)
        obs = truncate_text(
            (f.evidence or "").replace("\n", " "), evidence_chars, "obs"
        )
        rec = truncate_text(
            (f.remediation or "").replace("\n", " "), evidence_chars, "rec"
        )
        lines.append(
            f"| {f.requirement_id} | {f.status} | {f.severity or '-'} | "
            f"{(f.title or '').replace('|', '/')} | "
            f"{obs.replace('|', '/')} | {rec.replace('|', '/')} |"
        )
    return "\n".join(lines)
