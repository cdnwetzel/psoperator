"""Operator-controlled global stop sentinel.

The sentinel is checked by the gatekeeper before every action. It never
auto-clears; resuming execution requires an explicit operator action.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def is_engaged(path: Path) -> bool:
    return Path(path).is_file()


def engage(path: Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("PSOperator stopped by operator.\n", encoding="utf-8")


def disengage(path: Path) -> None:
    Path(path).unlink(missing_ok=True)


def engage_exclusive(path: Path, marker: str) -> bool:
    """Engage with ``marker`` as the sentinel's content, only if not already
    engaged. Returns whether this call created the stop, i.e. whether the caller
    owns it; an existing stop is left untouched."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(marker)
    return True


def disengage_if_owned(path: Path, marker: str) -> None:
    """Lift a stop only if it is still the one ``engage_exclusive`` created with
    ``marker``.

    An operator who engages while the owner holds the stop rewrites the sentinel,
    so its content no longer matches and it stays. The sentinel is claimed by an
    atomic rename before it is read, so an engagement that lands between the read
    and the delete cannot be the file deleted: it either rewrote the claimed file
    (no longer ours, so it is put back) or created a new sentinel (never touched).
    """
    target = Path(path)
    claim = target.with_name(f"{target.name}.{secrets.token_hex(8)}.claim")
    try:
        os.rename(target, claim)
    except FileNotFoundError:
        return
    try:
        ours = claim.read_text(encoding="utf-8") == marker
    except OSError:
        ours = False
    if ours:
        claim.unlink()
        return
    # Not ours: put the stop back. Replacing a newer sentinel with this one keeps
    # the switch engaged either way.
    os.replace(claim, target)
