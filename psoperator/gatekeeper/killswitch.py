"""Operator-controlled global stop sentinel.

The sentinel is checked by the gatekeeper before every action. It never
auto-clears; resuming execution requires an explicit operator action.
"""

from __future__ import annotations

from pathlib import Path


def is_engaged(path: Path) -> bool:
    return Path(path).is_file()


def engage(path: Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("PSOperator stopped by operator.\n", encoding="utf-8")


def disengage(path: Path) -> None:
    Path(path).unlink(missing_ok=True)
