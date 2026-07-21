#!/usr/bin/env python3
"""Convert a Nessus/CIS WorkBench .audit file into auditor checklist + playbook.

Usage:
  python scripts/convert_cis_audit.py agents/vendor/CIS_....audit \\
      --framework-id ubuntu_cis_24_l2 \\
      --out-md agents/ubuntu_cis_24_l2.md \\
      --out-playbook agents/playbooks/ubuntu_cis_24_l2.yaml
"""

from __future__ import annotations

import argparse
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_CONTROL_TITLE = re.compile(
    r"^(?P<cid>\d+(?:\.\d+)+)\s+(?P<title>.+)$"
)
_ITEM_START = re.compile(r"^\s*<custom_item>\s*$")
_ITEM_END = re.compile(r"^\s*</custom_item>\s*$")
_REPORT_START = re.compile(r'^\s*<report\s+type:"(?P<rtype>[^"]+)"\s*>\s*$')
_REPORT_END = re.compile(r"^\s*</report>\s*$")
_FIELD = re.compile(r"^\s*(?P<key>[a-z_]+)\s*:\s*(?P<rest>.*)$")
_SKIP_TITLES = {
    "check distribution release",
}


@dataclass
class Control:
    cis_id: str
    title: str
    check_type: str = ""
    info: str = ""
    solution: str = ""
    expect: str = ""
    cmds: list[str] = field(default_factory=list)
    file: str = ""
    regex: str = ""
    reference: str = ""
    see_also: str = ""

    @property
    def heading(self) -> str:
        return f"{self.cis_id} {self.title}".strip()


def _unescape_audit_string(value: str) -> str:
    """Decode Nessus-style quoted string escapes."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "t":
                out.append("\t")
            elif nxt in {'"', "\\", "'"}:
                out.append(nxt)
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_quoted_or_bare(rest: str, lines: list[str], idx: int) -> tuple[str, int]:
    """Parse a field value that may be a quoted multi-line string."""
    rest = rest.strip()
    if not rest.startswith('"'):
        # Bare token until end of line (rare)
        return rest.strip().strip('"'), idx

    # Quoted string — may span lines until closing unescaped "
    buf = rest[1:]
    while True:
        # Find unescaped closing quote
        j = 0
        while j < len(buf):
            if buf[j] == "\\" and j + 1 < len(buf):
                j += 2
                continue
            if buf[j] == '"':
                raw = buf[:j]
                return _unescape_audit_string(raw), idx
            j += 1
        idx += 1
        if idx >= len(lines):
            return _unescape_audit_string(buf), idx
        buf += "\n" + lines[idx]


def _parse_block_fields(lines: list[str], start: int, end_pat: re.Pattern[str]) -> tuple[dict[str, str], int]:
    fields: dict[str, str] = {}
    i = start
    while i < len(lines):
        line = lines[i]
        if end_pat.match(line):
            return fields, i
        m = _FIELD.match(line)
        if m:
            key = m.group("key")
            value, i = _parse_quoted_or_bare(m.group("rest"), lines, i)
            fields[key] = value
        i += 1
    return fields, i


def _category_for(cis_id: str) -> str:
    major = cis_id.split(".", 1)[0]
    return {
        "1": "Initial Setup",
        "2": "Services",
        "3": "Network",
        "4": "Host Based Firewall",
        "5": "Access Authentication Authorization",
        "6": "Logging and Auditing",
        "7": "System Maintenance",
    }.get(major, "CIS Control")


def _severity_for(reference: str) -> str:
    ref = (reference or "").upper()
    if "LEVEL|1" in ref and "LEVEL|2" not in ref:
        return "Medium"
    if "LEVEL|2" in ref:
        return "High"
    return "High"


def _is_control_description(desc: str) -> re.Match[str] | None:
    desc = (desc or "").strip()
    if not desc or desc.lower() in _SKIP_TITLES:
        return None
    if desc.lower().startswith("cis_ubuntu"):
        return None
    return _CONTROL_TITLE.match(desc)


def parse_audit(text: str) -> list[Control]:
    lines = text.splitlines()
    controls: dict[str, Control] = {}
    order: list[str] = []

    def upsert(ctrl: Control) -> None:
        key = ctrl.cis_id
        if key not in controls:
            controls[key] = ctrl
            order.append(key)
            return
        existing = controls[key]
        # Prefer longer title / richer metadata
        if len(ctrl.title) > len(existing.title):
            existing.title = ctrl.title
        if ctrl.info and len(ctrl.info) > len(existing.info):
            existing.info = ctrl.info
        if ctrl.solution and len(ctrl.solution) > len(existing.solution):
            existing.solution = ctrl.solution
        if ctrl.expect and not existing.expect:
            existing.expect = ctrl.expect
        if ctrl.reference and not existing.reference:
            existing.reference = ctrl.reference
        if ctrl.see_also and not existing.see_also:
            existing.see_also = ctrl.see_also
        if ctrl.check_type and not existing.check_type:
            existing.check_type = ctrl.check_type
        if ctrl.file and not existing.file:
            existing.file = ctrl.file
        if ctrl.regex and not existing.regex:
            existing.regex = ctrl.regex
        for cmd in ctrl.cmds:
            if cmd and cmd not in existing.cmds:
                existing.cmds.append(cmd)

    i = 0
    pending_helpers: list[dict[str, str]] = []

    while i < len(lines):
        if _ITEM_START.match(lines[i]):
            fields, i = _parse_block_fields(lines, i + 1, _ITEM_END)
            desc = fields.get("description", "").strip()
            match = _is_control_description(desc)
            if match:
                cmds = []
                if fields.get("cmd"):
                    cmds.append(fields["cmd"].strip())
                ctrl = Control(
                    cis_id=match.group("cid"),
                    title=match.group("title").strip(),
                    check_type=fields.get("type", "").strip(),
                    info=fields.get("info", "").strip(),
                    solution=fields.get("solution", "").strip(),
                    expect=fields.get("expect", "").strip(),
                    cmds=cmds,
                    file=fields.get("file", "").strip(),
                    regex=fields.get("regex", "").strip(),
                    reference=fields.get("reference", "").strip(),
                    see_also=fields.get("see_also", "").strip(),
                )
                upsert(ctrl)
                pending_helpers = []
            else:
                # Helper probe used by a following <report> composite control
                pending_helpers.append(fields)
            i += 1
            continue

        rm = _REPORT_START.match(lines[i])
        if rm:
            fields, i = _parse_block_fields(lines, i + 1, _REPORT_END)
            desc = fields.get("description", "").strip()
            match = _is_control_description(desc)
            if match and rm.group("rtype") in {"PASSED", "FAILED", "WARNING"}:
                cmds: list[str] = []
                check_types: list[str] = []
                for helper in pending_helpers:
                    if helper.get("cmd"):
                        cmds.append(helper["cmd"].strip())
                    if helper.get("type"):
                        check_types.append(helper["type"].strip())
                ctrl = Control(
                    cis_id=match.group("cid"),
                    title=match.group("title").strip(),
                    check_type="+".join(dict.fromkeys(check_types)) or "COMPOSITE",
                    info=fields.get("info", "").strip(),
                    solution=fields.get("solution", "").strip(),
                    expect="composite: all condition checks must pass",
                    cmds=cmds,
                    reference=fields.get("reference", "").strip(),
                    see_also=fields.get("see_also", "").strip(),
                )
                upsert(ctrl)
            pending_helpers = []
            i += 1
            continue

        # Reset helpers outside nested condition/report flow when we hit else/fi-ish tags
        if re.match(r"^\s*</?(?:if|else|then|condition)\b", lines[i]):
            if re.match(r"^\s*</if\b", lines[i]) or re.match(r"^\s*<else\b", lines[i]):
                pending_helpers = []
        i += 1

    return [controls[k] for k in order]


def _truncate(text: str, limit: int = 1200) -> str:
    text = re.sub(r"\n{3,}", "\n\n", (text or "").strip())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _cmd_for_playbook(ctrl: Control) -> str:
    if ctrl.cmds:
        # Prefer first command; collapse extreme scripts for playbook hint
        cmd = ctrl.cmds[0].strip()
        if len(cmd) > 1800:
            # Keep shebang scripts but cap size
            cmd = cmd[:1800] + "\n# … truncated for playbook …"
        return cmd
    if ctrl.file and ctrl.regex:
        return (
            f"grep -E -- '{ctrl.regex}' {ctrl.file} 2>/dev/null || "
            f"python3 -c \"import pathlib,re; t=pathlib.Path('{ctrl.file}').read_text(); "
            f"print('match' if re.search(r'''{ctrl.regex}''', t) else 'no-match')\""
        )
    if ctrl.file:
        return f"cat {ctrl.file} 2>/dev/null | head -n 80"
    return "true  # no automated command extracted"


def _how_to_verify(ctrl: Control) -> str:
    parts: list[str] = []
    if ctrl.check_type:
        parts.append(f"Check type: `{ctrl.check_type}`.")
    if ctrl.cmds:
        if len(ctrl.cmds) == 1 and len(ctrl.cmds[0]) < 500:
            parts.append(f"SSH run:\n```bash\n{ctrl.cmds[0].strip()}\n```")
        else:
            parts.append(
                f"SSH: run the CIS audit probe script(s) for `{ctrl.cis_id}` "
                f"({len(ctrl.cmds)} command(s); prefer playbook `ssh_run`)."
            )
            # Include a short preview of first cmd
            preview = ctrl.cmds[0].strip().splitlines()
            preview = "\n".join(preview[:12])
            if len(ctrl.cmds[0]) > 400:
                preview += "\n# …"
            parts.append(f"```bash\n{preview}\n```")
    elif ctrl.file:
        parts.append(
            f"SSH: inspect `{ctrl.file}`"
            + (f" matching regex `{ctrl.regex}`" if ctrl.regex else "")
            + "."
        )
    else:
        parts.append("SSH: verify manually per CIS recommendation.")
    if ctrl.expect:
        parts.append(f"Expect output matching: `{ctrl.expect}`.")
    return " ".join(parts) if len(parts) == 1 else "\n".join(f"- {p}" if not p.startswith("```") and not p.startswith("SSH run") and not p.startswith("-") else p for p in parts)


def render_markdown(controls: list[Control], *, framework_id: str, title: str, see_also: str) -> str:
    lines = [
        "---",
        f"id: {framework_id}",
        "aliases: [ubuntu24, ubuntu-cis-24, cis-ubuntu-24, ubuntu l2]",
        "description: CIS Ubuntu Linux 24.04 LTS v1.0.0 Level 2 Server (converted from Nessus .audit)",
        "domain: cybersecurity",
        "detect:",
        "  os_ids: [ubuntu]",
        "---",
        f"# {title}",
        "",
        "Converted from CIS WorkBench / Nessus `.audit` for automated SSH verification.",
        f"Source benchmark: {see_also or 'CIS Ubuntu Linux 24.04 LTS'}.",
        "",
        "Notes:",
        "- Many checks need elevated privileges; use an inventory SSH user with sudo where required.",
        "- Composite controls may require several probes; playbook stores the primary `ssh_run` command.",
        "- Overlayfs/squashfs checks can break containers/Snaps — treat fails in context.",
        "",
    ]
    for idx, ctrl in enumerate(controls, start=1):
        req = f"REQ-{idx:03d}"
        sev = _severity_for(ctrl.reference)
        cat = _category_for(ctrl.cis_id)
        how = _how_to_verify(ctrl)
        pass_crit = ctrl.expect or "Audit probe reports PASS / expected pattern matches."
        solution = _truncate(ctrl.solution or "Follow CIS remediation for this control.", 900)
        info = _truncate(ctrl.info, 600)
        lines.extend(
            [
                f"## {req}: {ctrl.heading}",
                f"**Category:** {cat}",
                f"**Severity:** {sev}",
                f"**CIS ID:** `{ctrl.cis_id}`",
                f"**How to verify:** {how}",
                f"**Pass criteria:** {pass_crit}",
            ]
        )
        if info:
            lines.append(f"**Background:** {info}")
        lines.append(f"**Remediation (CIS):** {solution}")
        if ctrl.see_also:
            lines.append(f"**See also:** {ctrl.see_also}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_playbook(controls: list[Control], *, framework_id: str) -> str:
    data: dict = {
        "framework_id": framework_id,
        "framework_tips": [
            "Prefer non-interactive SSH commands from this playbook first.",
            "Large CIS scripts may need sudo; capture stdout and exit_code.",
            "Interpret PASS/FAIL markers in script output when present.",
            "Do not disable overlayfs/squashfs on container hosts without operator confirmation.",
        ],
        "requirements": {},
    }
    for idx, ctrl in enumerate(controls, start=1):
        req = f"REQ-{idx:03d}"
        cmd = _cmd_for_playbook(ctrl)
        data["requirements"][req] = {
            "tools": [{"name": "ssh_run", "arguments": {"command": cmd}}],
            "notes": f"CIS {ctrl.cis_id}",
        }
    return yaml.safe_dump(data, sort_keys=False, width=100, allow_unicode=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("audit", type=Path)
    ap.add_argument("--framework-id", default="ubuntu_cis_24_l2")
    ap.add_argument("--out-md", type=Path, required=True)
    ap.add_argument("--out-playbook", type=Path, required=True)
    ap.add_argument(
        "--title",
        default="CIS Ubuntu Linux 24.04 LTS v1.0.0 (Level 2 Server)",
    )
    args = ap.parse_args()

    text = args.audit.read_text(encoding="utf-8", errors="replace")
    controls = parse_audit(text)
    if not controls:
        raise SystemExit("No CIS controls parsed from audit file")

    see_also = ""
    for c in controls:
        if c.see_also:
            see_also = c.see_also
            break

    md = render_markdown(
        controls,
        framework_id=args.framework_id,
        title=args.title,
        see_also=see_also,
    )
    pb = render_playbook(controls, framework_id=args.framework_id)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_playbook.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(md, encoding="utf-8")
    args.out_playbook.write_text(pb, encoding="utf-8")
    print(f"controls={len(controls)}")
    print(f"wrote {args.out_md} ({args.out_md.stat().st_size} bytes)")
    print(f"wrote {args.out_playbook} ({args.out_playbook.stat().st_size} bytes)")
    print("sample:", ", ".join(f"{c.cis_id}" for c in controls[:8]), "...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
