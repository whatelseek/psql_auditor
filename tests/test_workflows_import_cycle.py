"""Guard: workflow modules must not import auditor.graph (no cycles)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

WF = Path(__file__).resolve().parents[1] / "src" / "auditor" / "workflows"


def _imports_graph(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "auditor.graph" or alias.name.startswith("auditor.graph."):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "auditor.graph" or (node.module or "").startswith("auditor.graph."):
                return True
    return False


@pytest.mark.parametrize("path", sorted(WF.glob("*.py")))
def test_workflow_module_does_not_import_graph(path: Path):
    assert not _imports_graph(path), f"{path.name} imports auditor.graph"


def test_workflow_package_imports_cleanly():
    import auditor.workflows.assessment  # noqa: F401
    import auditor.workflows.builder  # noqa: F401
    import auditor.workflows.dependencies  # noqa: F401
    import auditor.workflows.discovery  # noqa: F401
    import auditor.workflows.finalize  # noqa: F401
    import auditor.workflows.helpers  # noqa: F401
    import auditor.workflows.hitl  # noqa: F401
    import auditor.workflows.intake  # noqa: F401
    import auditor.workflows.multi_runner  # noqa: F401
    import auditor.workflows.runner  # noqa: F401
    import auditor.workflows.tool_execution  # noqa: F401
