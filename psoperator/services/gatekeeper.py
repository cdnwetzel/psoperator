"""Process-separated gatekeeper service for untrusted planner clients.

This is the trust boundary: a planner — possibly compromised or injected —
connects over IPC and hands the gatekeeper a signed observer envelope. R-203
authenticates that envelope here, before anything downstream trusts the snapshot
inside it. A forged, replayed, stale-epoch, expired, or unknown-key envelope is
refused at this door and never reaches ``request_action``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from psoperator.common.ipc import IPCServer
from psoperator.common.schema import AttestedSnapshot
from psoperator.gatekeeper.attestation_gate import AttestationGate, EnvelopeRejected
from psoperator.gatekeeper.gatekeeper import Gatekeeper
from psoperator.gatekeeper.risk import ActionContext
from psoperator.runtime.actions import parse_action
from psoperator.runtime.freshness import FreshnessTracker


@dataclass(frozen=True)
class FrameEvidence:
    frame_id: int
    sha256: str


class GatekeeperService:
    def __init__(
        self,
        gatekeeper: Gatekeeper,
        freshness: FreshnessTracker,
        attestation_gate: AttestationGate,
    ) -> None:
        self._gatekeeper = gatekeeper
        self._freshness = freshness
        self._gate = attestation_gate

    def handle(self, request: dict) -> dict:
        try:
            # Parse + schema-validate only. This does NOT authenticate — a
            # compromised planner can put any well-formed envelope here.
            attestation = AttestedSnapshot.model_validate(request["attestation"])
            action = parse_action(json.dumps(request["action"]))
            context = ActionContext(**request.get("context", {}))
        except Exception as exc:
            return {"ok": False, "error": f"invalid request: {type(exc).__name__}: {exc}"}

        # R-203: authenticate the observer envelope before anything trusts it —
        # signature, key, epoch, freshness, replay. Fail closed and receipted.
        try:
            self._gate.admit(attestation)
        except EnvelopeRejected as rejection:
            return {
                "ok": False,
                "error": f"unauthenticated observer envelope: {rejection.reason}",
                "reason": rejection.reason,
            }

        # Only now is the enclosed snapshot cryptographically trusted.
        snapshot = attestation.snapshot
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


def serve(
    host: str,
    port: int,
    gatekeeper: Gatekeeper,
    freshness: FreshnessTracker,
    attestation_gate: AttestationGate,
) -> None:
    service = GatekeeperService(gatekeeper, freshness, attestation_gate)
    IPCServer(host, port).serve_forever(service.handle)
