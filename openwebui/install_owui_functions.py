#!/usr/bin/env python3
"""Install / repair CIS chart Tool + Filter in Open WebUI webui.db."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

DB = Path("/app/backend/data/webui.db")
FILTER_PATH = Path("/tmp/filter.py")
TOOL_PATH = Path("/tmp/tool.py")


def main() -> None:
    filter_content = FILTER_PATH.read_text(encoding="utf-8")
    tool_content = TOOL_PATH.read_text(encoding="utf-8")
    if "class Filter" not in filter_content:
        raise SystemExit("filter.py missing class Filter")
    if "class Tools" not in tool_content:
        raise SystemExit("tool.py missing class Tools")

    con = sqlite3.connect(DB)
    cur = con.cursor()
    now = int(time.time())
    row = cur.execute("SELECT id FROM user WHERE role='admin' LIMIT 1").fetchone()
    if not row:
        raise SystemExit("no admin user")
    user_id = row[0]

    # Filter function — must be active + global to auto-run
    existing = cur.execute(
        "SELECT id FROM function WHERE id IN ('cis_compliance_charts','cis_compliance_charts_filter')"
    ).fetchall()
    ids = {r[0] for r in existing}
    target_id = "cis_compliance_charts" if "cis_compliance_charts" in ids else "cis_compliance_charts_filter"
    meta = json.dumps(
        {
            "description": "Outlet filter — appends CIS compliance % bar charts to auditor Markdown reports.",
            "manifest": {
                "title": "CIS Compliance Charts (Auto Filter)",
                "author": "auditor",
                "version": "0.1.1",
            },
        }
    )
    if target_id in ids:
        cur.execute(
            "UPDATE function SET content=?, is_active=1, is_global=1, type=?, "
            "updated_at=?, name=?, meta=? WHERE id=?",
            (
                filter_content,
                "filter",
                now,
                "CIS Compliance Charts (Auto Filter)",
                meta,
                target_id,
            ),
        )
        print(f"updated function {target_id}")
    else:
        cur.execute(
            "INSERT INTO function "
            "(id,user_id,name,type,content,meta,valves,is_active,is_global,updated_at,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "cis_compliance_charts_filter",
                user_id,
                "CIS Compliance Charts (Auto Filter)",
                "filter",
                filter_content,
                meta,
                None,
                1,
                1,
                now,
                now,
            ),
        )
        print("inserted function cis_compliance_charts_filter")

    specs = [
        {
            "name": "visualize_cis_compliance",
            "description": (
                "Visualize CIS / auditor Markdown report as compliance % "
                "bar charts by severity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "report_markdown": {
                        "type": "string",
                        "description": "Full audit report Markdown "
                        "(summary table with Severity + Status).",
                    },
                    "language": {
                        "type": "string",
                        "description": "Optional en|ru.",
                    },
                },
                "required": ["report_markdown"],
            },
        }
    ]
    tool_meta = json.dumps(
        {
            "description": "CIS compliance charts tool",
            "manifest": {
                "title": "CIS Compliance Charts",
                "author": "auditor",
                "version": "0.1.1",
            },
        }
    )
    if cur.execute("SELECT id FROM tool WHERE id='cis_compliance_charts'").fetchone():
        cur.execute(
            "UPDATE tool SET content=?, specs=?, meta=?, updated_at=?, name=? WHERE id=?",
            (
                tool_content,
                json.dumps(specs),
                tool_meta,
                now,
                "CIS Compliance Charts",
                "cis_compliance_charts",
            ),
        )
        print("updated tool cis_compliance_charts")
    else:
        cur.execute(
            "INSERT INTO tool "
            "(id,user_id,name,content,specs,meta,valves,updated_at,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "cis_compliance_charts",
                user_id,
                "CIS Compliance Charts",
                tool_content,
                json.dumps(specs),
                tool_meta,
                None,
                now,
                now,
            ),
        )
        print("inserted tool cis_compliance_charts")

    con.commit()
    print(
        "function rows:",
        list(
            cur.execute(
                "SELECT id,type,is_active,is_global,length(content) FROM function"
            )
        ),
    )
    print(
        "tool rows:",
        list(cur.execute("SELECT id,name,length(content) FROM tool")),
    )


if __name__ == "__main__":
    main()
