"""Append-only, SHA-256 hash-chained JSONL audit log.

Each line is one decision:

    {"seq": 3, "ts": ..., "prev_hash": "...", "frame_hash": "...",
     "frame_id": 7, "action": {...}, "tier": 1, "decision": "approved",
     "approver": "auto:tier<=1", "reason": "...", "hash": "..."}

``hash`` = sha256 over the canonical JSON of every field except ``hash``
itself. ``prev_hash`` chains line N to line N-1, so deleting or editing any
historical line breaks verification at that point. ``verify()`` walks the
whole chain and reports the first inconsistency.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(entry: dict[str, Any]) -> bytes:
    return json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True).encode()


def _entry_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


class AuditLog:
    """Appends one hash-chained record per gatekeeper decision."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = self._tail_hash()

    def _tail_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = self.path.read_text().strip().splitlines()[-1]
        return json.loads(last)["hash"]

    def append(
        self,
        *,
        frame_id: int,
        frame_hash: str,
        action: dict,
        tier: int,
        decision: str,
        approver: str,
        reason: str,
    ) -> dict:
        entry: dict[str, Any] = {
            "seq": self._seq(),
            "ts": round(time.time(), 3),
            "prev_hash": self._prev,
            "frame_id": frame_id,
            "frame_hash": frame_hash,
            "action": action,
            "tier": tier,
            "decision": decision,
            "approver": approver,
            "reason": reason,
        }
        entry["hash"] = _entry_hash(entry)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self._prev = entry["hash"]
        return entry

    def _seq(self) -> int:
        if not self.path.exists():
            return 1
        return sum(1 for _ in self.path.open("r", encoding="utf-8")) + 1


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    lines_checked: int
    error: str = ""


def verify(path: Path) -> VerifyResult:
    """Walk the chain; detect edits, deletions, reordering, truncation."""
    path = Path(path)
    if not path.exists():
        return VerifyResult(ok=False, lines_checked=0, error="audit log missing")

    prev = GENESIS
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return VerifyResult(False, i, f"line {i}: invalid JSON")
        if entry.get("prev_hash") != prev:
            return VerifyResult(False, i, f"line {i}: prev_hash chain broken")
        if entry.get("hash") != _entry_hash(entry):
            return VerifyResult(False, i, f"line {i}: content hash mismatch (tampered?)")
        if entry.get("seq") != i:
            return VerifyResult(False, i, f"line {i}: sequence gap (deleted entry?)")
        prev = entry["hash"]
    return VerifyResult(ok=True, lines_checked=len(lines))
