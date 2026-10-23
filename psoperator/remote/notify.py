"""ntfy.sh push notifications + CLI dashboard stub.

ntfy is the one OPTIONAL non-local network integration (operator-configured
URL; default off). Everything else in PSOperator talks only to the local
model endpoint.
"""

from __future__ import annotations

import json
from pathlib import Path


def push(ntfy_url: str | None, title: str, message: str, priority: str = "default") -> bool:
    """Post a notification to ntfy.sh. Returns False (no-op) when unconfigured."""
    if not ntfy_url:
        return False
    import httpx

    try:
        r = httpx.post(
            ntfy_url.rstrip("/"),
            content=message,
            headers={"Title": title, "Priority": priority},
            timeout=10.0,
        )
        return r.status_code == 200
    except Exception:
        return False


def dashboard(audit_path: Path, tail: int = 10) -> str:
    """CLI 'dashboard': render the tail of the hash-chained audit log.

    STUB: a richer live dashboard (textual/rich TUI) is a prod TODO; this
    text view is enough to eyeball decisions and tiering during a demo.
    """
    path = Path(audit_path)
    if not path.exists():
        return "audit log is empty — no decisions recorded yet"
    lines = path.read_text().strip().splitlines()[-tail:]
    rows = []
    for line in lines:
        e = json.loads(line)
        rows.append(
            f"#{e['seq']:<4} T{e['tier']} {e['decision']:<15} "
            f"{json.dumps(e['action'])[:60]:<60} by {e['approver']}"
        )
    return "\n".join(rows)


if __name__ == "__main__":  # pragma: no cover
    import sys

    print(dashboard(Path(sys.argv[1] if len(sys.argv) > 1 else "psoperator_audit.jsonl")))
