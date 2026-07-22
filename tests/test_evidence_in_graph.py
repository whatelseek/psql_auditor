from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from auditor.config import Settings
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph


@pytest.mark.asyncio
async def test_execute_tool_calls_writes_full_result_to_req_folder(tmp_path: Path):
    settings = Settings(_env_file=None, evidence_dir=tmp_path, agents_dir=Path("agents"))
    graph = AuditorGraph(settings=settings)
    store = EvidenceStore(tmp_path, run_id="graph_run")
    graph._evidence_by_run[store.run_id] = store

    fake_tool = MagicMock()
    fake_tool.ainvoke = AsyncMock(return_value="exit_code=0\nstdout:\nhello-world")
    graph.tools_by_name = {"ssh_run": fake_tool}

    messages = await graph._execute_tool_calls(
        [
            {
                "name": "ssh_run",
                "args": {"command": "echo hello-world"},
                "id": "call-1",
            }
        ],
        framework_id="ubuntu_cis_24_l2",
        req_id="REQ-001",
        store=store,
    )

    assert len(messages) == 1
    assert "hello-world" in messages[0].content
    req_dir = store.root / "ubuntu_cis_24_l2" / "REQ-001"
    txt = next(req_dir.glob("001_ssh_run.txt"))
    body = txt.read_text(encoding="utf-8")
    assert "echo hello-world" in body
    assert "hello-world" in body
