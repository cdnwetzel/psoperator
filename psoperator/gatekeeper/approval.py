"""Approval backends for T2/T3 actions.

Human approval is the last line before a sensitive or destructive action
executes. Two backends ship: an interactive CLI prompt (works) and an
ntfy.sh push with action buttons (stubbed: the push posts, but the callback
listener that receives the tap is not implemented in this PoC).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from psoperator.gatekeeper.risk import RiskAssessment
from psoperator.runtime.actions import Action


@dataclass(frozen=True)
class ApprovalRequest:
    action: Action
    risk: RiskAssessment
    frame_id: int

    def summary(self) -> str:
        return f"[{self.risk.tier.name}] {self.action.to_text()}"


@runtime_checkable
class ApprovalBackend(Protocol):
    name: str

    def request(self, req: ApprovalRequest, timeout_s: float = 120.0) -> bool: ...


class CLIApproval:
    """Interactive prompt on the local console. Fail closed on EOF/timeout."""

    name = "cli"

    def request(self, req: ApprovalRequest, timeout_s: float = 120.0) -> bool:
        print("\n=== PSOperator approval required ===")
        print(f"  tier   : {req.risk.tier.name}")
        print(f"  reasons: {', '.join(req.risk.reasons) or '(default)'}")
        print(f"  action : {req.action.to_text()}")
        try:
            ans = input("  approve? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans in ("y", "yes")


class NtfyApproval:
    """Push approval via ntfy.sh with Approve/Deny action buttons.

    STUB: posting the notification works (if ntfy_url is configured), but the
    HTTP listener that would receive the button tap is not implemented, so
    this backend currently always returns False after the timeout — i.e. it
    fails closed. Wire an ntfy -> webhook -> local listener loop for prod.
    """

    name = "ntfy"

    def __init__(self, ntfy_url: str) -> None:
        self._url = ntfy_url.rstrip("/")

    def request(self, req: ApprovalRequest, timeout_s: float = 120.0) -> bool:
        import httpx

        headers = {
            "Title": f"PSOperator: approve {req.risk.tier.name}?",
            "Priority": "urgent",
            # ntfy action buttons; the actions endpoint is a TODO webhook.
            "Actions": (
                "http, Approve, https://example.invalid/psoperator/approve, method=POST; "
                "http, Deny, https://example.invalid/psoperator/deny, method=POST"
            ),
        }
        try:
            httpx.post(self._url, content=req.summary(), headers=headers, timeout=10.0)
        except Exception:
            return False  # couldn't even notify → fail closed
        # TODO(prod): wait for the action-button callback instead of denying.
        return False


class AutoApprove:
    """Test/demo backend: approves everything. Never use unattended."""

    name = "auto"

    def request(self, req: ApprovalRequest, timeout_s: float = 120.0) -> bool:
        return True
