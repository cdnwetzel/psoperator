"""Static checks for the planner/executor import boundary."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLANNING = ROOT / "psoperator" / "planning"
ISOLATED_CLIENT = ROOT / "examples" / "run_isolated.py"
OBSERVER_CLIENT = ROOT / "psoperator" / "services" / "observer_client.py"
FORBIDDEN = (
    "psoperator.gatekeeper.executor",
    "pynput",
    "pyautogui",
    "serial",
    "ctypes",
)


def _imports(path: Path, package: str | None = None) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package_parts = tuple(package.split(".")) if package else path.relative_to(ROOT).parent.parts
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                keep = max(0, len(package_parts) - node.level + 1)
                base_parts = package_parts[:keep]
                if node.module:
                    base_parts += tuple(node.module.split("."))
                module = ".".join(base_parts)
            else:
                module = node.module or ""
            if module:
                found.add(module)
            found.update(f"{module}.{alias.name}" if module else alias.name for alias in node.names)
    return found


def test_planning_package_has_no_execution_import_path():
    imported = set()
    for path in PLANNING.rglob("*.py"):
        imported.update(_imports(path))
    violations = {
        name
        for name in imported
        if any(name == bad or name.startswith(f"{bad}.") for bad in FORBIDDEN)
    }
    assert not violations


def test_isolated_planner_client_has_no_capture_perception_or_signing_import_path():
    imported = _imports(ISOLATED_CLIENT) | _imports(OBSERVER_CLIENT)
    forbidden = ("psoperator.perception", "psoperator.common.attestation")
    violations = {
        name
        for name in imported
        if any(name == bad or name.startswith(f"{bad}.") for bad in forbidden)
    }
    assert not violations


def test_import_scanner_detects_from_package_alias(tmp_path):
    source = tmp_path / "aliased.py"
    source.write_text(
        "from psoperator import perception\nfrom ..gatekeeper import executor\n",
        encoding="utf-8",
    )
    imported = _imports(source, package="psoperator.planning")
    assert "psoperator.perception" in imported
    assert "psoperator.gatekeeper.executor" in imported
