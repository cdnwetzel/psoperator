"""Operator-controlled global stop sentinel.

The sentinel is checked by the gatekeeper before every action. It never
auto-clears; resuming execution requires an explicit operator action.

A stop that is being lifted conditionally (see :func:`disengage_if_owned`) is
first renamed to a ``<name>.<random>.claim`` sibling. A claim still counts as an
engaged stop, so the switch never reads as off while ownership is re-checked,
and a process that dies mid-claim leaves the switch engaged, not lifted.
"""

from __future__ import annotations

import glob
import os
import secrets
from pathlib import Path


def _claims(target: Path) -> list[Path]:
    return [Path(p) for p in glob.glob(f"{glob.escape(str(target))}.*.claim")]


def is_engaged(path: Path) -> bool:
    """Whether a stop is in place, at its path or as a claim.

    A conditional release moves the stop between its path and a claim with one
    atomic rename at a time, so the stop always exists under one of the two
    names. The path is read on both sides of the claim scan: a rename from path
    to claim before the first read is caught by the scan, and a rename from claim
    back to path after the scan is caught by the second read.
    """
    target = Path(path)
    if target.is_file():
        return True
    if any(claim.is_file() for claim in _claims(target)):
        return True
    return target.is_file()


def engage(path: Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("PSOperator stopped by operator.\n", encoding="utf-8")


def disengage(path: Path) -> None:
    """The operator's explicit release: lifts the stop and any claim left by an
    interrupted conditional release."""
    target = Path(path)
    target.unlink(missing_ok=True)
    for claim in _claims(target):
        claim.unlink(missing_ok=True)


def engage_exclusive(path: Path, marker: str) -> bool:
    """Engage with ``marker`` as the sentinel's content, only if not already
    engaged. Returns whether this call created the stop, i.e. whether the caller
    owns it; an existing stop is left untouched.

    The sentinel appears with its content already in place: the marker is
    written to a private temp sibling, which is then hard-linked to the path.
    ``link`` fails if the path exists, so an operator stop engaged at any moment
    before it is never overwritten or taken over. Only the temp file is ever
    removed here, never the path. A filesystem without hard links raises, and the
    caller engaged nothing.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f"{target.name}.{secrets.token_hex(8)}.new")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        try:
            data = marker.encode("utf-8")
            while data:
                data = data[os.write(fd, data) :]
        finally:
            os.close(fd)
        try:
            os.link(temp, target)
        except FileExistsError:
            return False
        return True
    finally:
        temp.unlink(missing_ok=True)


def _holds(path: Path, marker: str) -> bool:
    """Whether ``path`` provably holds ``marker``. Unreadable or undecodable
    content (an operator may write anything) is not provably ours."""
    try:
        return path.read_text(encoding="utf-8") == marker
    except (OSError, ValueError):
        return False


def disengage_if_owned(path: Path, marker: str) -> None:
    """Lift a stop only if it is still the one ``engage_exclusive`` created with
    ``marker``.

    An operator who engages while the owner holds the stop rewrites the sentinel,
    so its content no longer matches and it stays. Ownership is read in place
    first: a stop that is not ours is never moved. Only an apparently owned stop
    is claimed by an atomic rename and re-read, which catches an operator rewrite
    landing between the first read and the rename. The claim itself counts as
    engaged (see :func:`is_engaged`), so the switch stays on throughout, and a
    rewritten stop is put back. If putting it back fails, the claim is left in
    place, still engaged, and the error propagates.
    """
    target = Path(path)
    if not _holds(target, marker):
        return
    claim = target.with_name(f"{target.name}.{secrets.token_hex(8)}.claim")
    try:
        os.rename(target, claim)
    except FileNotFoundError:
        return
    if _holds(claim, marker):
        claim.unlink()
        return
    os.replace(claim, target)
