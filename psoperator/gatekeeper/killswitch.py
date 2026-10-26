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
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(marker)
    except BaseException:
        # An empty sentinel nobody owns would outlive the caller, which never
        # learned it engaged anything. Remove it and report the failure.
        target.unlink(missing_ok=True)
        raise
    return True


def disengage_if_owned(path: Path, marker: str) -> None:
    """Lift a stop only if it is still the one ``engage_exclusive`` created with
    ``marker``.

    An operator who engages while the owner holds the stop rewrites the sentinel,
    so its content no longer matches and it stays. Ownership is read in place
    first: a stop that is not ours is never moved, so the switch never reads as
    disengaged on its account. Only an apparently owned stop is claimed by an
    atomic rename and re-read, which catches an operator rewrite landing between
    the first read and the rename. Such a stop is put back; if that fails, a
    fresh stop is engaged before the error propagates, so the switch fails closed.
    """
    target = Path(path)
    try:
        if target.read_text(encoding="utf-8") != marker:
            return
    except FileNotFoundError:
        return
    except OSError:
        return  # unreadable: not provably ours, so it stays
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
    try:
        os.replace(claim, target)
    except OSError:
        engage(target)
        raise
