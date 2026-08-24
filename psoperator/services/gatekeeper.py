"""Process-separated gatekeeper service for untrusted planner clients."""

from __future__ import annotations

import json
from dataclasses import dataclass

from psoperator.common.ipc import IPCServer
from psoperator.common.schema import AttestedSnapshot
from psoperator.gatekeeper.gatekeeper import Gatekeeper
from psoperator.gatekeeper.risk import ActionContext
from psoperator.runtime.actions import parse_action
from psoperator.runtime.freshness import FreshnessTracker


@dataclass(frozen=True)
class FrameEvidence:
    frame_id: int
    sha256: str


class GatekeeperService:
    def __init__(self, gatekeeper: Gatekeeper, freshness: FreshnessTracker) -> None:
        self._gatekeeper = gatekeeper
        self._freshness = freshness

    def handle(self, request: dict) -> dict:
        try:
            # R-202 commits the signed envelope interface; this only *parses* and
            # schema-validates it — it does NOT verify the signature, so the
            # enclosed snapshot is NOT yet cryptographically trusted. A compromised
            # planner can still forge this envelope until R-203 adds keyring
            # verification (signature + epoch + nonce/replay) here and rejects on
            # failure. Do not read this parse as authentication.
            attestation = AttestedSnapshot.model_validate(request["attestation"])
            snapshot = attestation.snapshot
            action = parse_action(json.dumps(request["action"]))
            context = ActionContext(**request.get("context", {}))
        except Exception as exc:
            return {"ok": False, "error": f"invalid request: {type(exc).__name__}: {exc}"}

        self._freshness.observe(snapshot.frame_id)
        frame = FrameEvidence(snapshot.frame_id, snapshot.frame_hash)
        decision = self._gatekeeper.request_action(action, frame, context, snapshot)
        return {
            "ok": True,
            "decision": {
                "kind": decision.kind.value,
                "action": decision.action.to_dict(),
                "risk_tier": int(decision.risk.tier) if decision.risk else None,
                "risk_reasons": list(decision.risk.reasons) if decision.risk else [],
                "approver": decision.approver,
                "reason": decision.reason,
                "outcome": decision.outcome,
                "approved": decision.approved,
            },
        }


def serve(host: str, port: int, gatekeeper: Gatekeeper, freshness: FreshnessTracker) -> None:
    IPCServer(host, port).serve_forever(GatekeeperService(gatekeeper, freshness).handle)
