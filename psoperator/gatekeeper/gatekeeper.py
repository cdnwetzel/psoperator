"""The Gatekeeper: the single choke point between intent and actuation.

Call contract (the ONLY way anything reaches an input device):

    decision = gatekeeper.request_action(action, frame, context)
    # decision.approved -> already executed (or dry-run) and audited
    # otherwise        -> rejected/stale/denied, also audited

Pipeline, all deterministic, all audited:
    1. kill switch — a sentinel blocks every action
    2. freshness   — action, frame, and perception snapshot must agree
    3. grounding   — element ids must exist in the current snapshot
    4. risk tier   — pattern-based; the model never classifies its own action
    5. policy      — T0/T1 auto-approve; T2 requires approval; T3 hard-blocks
    6. execution   — delegated to an Executor (DryRun by default)
    7. audit       — every outcome appended to the hash-chained log
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from psoperator.common.schema import PerceptionSnapshot
from psoperator.config import PSOperatorConfig
from psoperator.gatekeeper import killswitch
from psoperator.gatekeeper.approval import ApprovalBackend, ApprovalRequest, CLIApproval
from psoperator.gatekeeper.audit import AuditLog
from psoperator.gatekeeper.executor import DryRunExecutor, Executor
from psoperator.gatekeeper.risk import (
    ActionContext,
    RiskAssessment,
    RiskTier,
    classify,
    load_policy,
)
from psoperator.perception.capture import Frame
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker


class DecisionKind(str, Enum):
    EXECUTED = "executed"
    DRY_RUN = "dry-run"
    REJECTED_STALE = "rejected-stale"
    REJECTED_TARGET = "rejected-target"
    KILL_SWITCHED = "kill-switched"
    DENIED = "denied"
    EXECUTION_FAILED = "execution-failed"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    action: Action
    risk: RiskAssessment | None
    approver: str
    reason: str
    outcome: str = ""

    @property
    def approved(self) -> bool:
        return self.kind in (DecisionKind.EXECUTED, DecisionKind.DRY_RUN, DecisionKind.DONE)

    @property
    def terminal(self) -> bool:
        return self.action.kind in (ActionKind.DONE, ActionKind.FAIL)


class Gatekeeper:
    def __init__(
        self,
        config: PSOperatorConfig,
        freshness: FreshnessTracker,
        approval_backend: ApprovalBackend | None = None,
        executor: Executor | None = None,
    ) -> None:
        self._config = config
        self._freshness = freshness
        self._approval = approval_backend or CLIApproval()
        self._executor = executor or DryRunExecutor()
        self._audit = AuditLog(config.audit_log_path)
        self._policy = load_policy(config.risk_policy_path)

    # ------------------------------------------------------------------ API
    def request_action(
        self,
        action: Action,
        frame: Frame,
        context: ActionContext | None = None,
        snapshot: PerceptionSnapshot | None = None,
    ) -> Decision:
        # 1. global stop — fail closed, including terminal/no-op actions
        if killswitch.is_engaged(self._config.kill_switch_path):
            return self._record(
                DecisionKind.KILL_SWITCHED,
                action,
                None,
                approver="gatekeeper",
                reason="kill switch engaged",
                frame=frame,
            )

        # 2. freshness — fail closed
        verdict = self._freshness.check(action)
        evidence_mismatch = action.frame_id != frame.frame_id
        snapshot_mismatch = snapshot is not None and (
            snapshot.frame_id != frame.frame_id or snapshot.frame_hash != frame.sha256
        )
        if not verdict.ok or evidence_mismatch or snapshot_mismatch:
            return self._record(
                DecisionKind.REJECTED_STALE,
                action,
                None,
                approver="gatekeeper",
                reason=f"{verdict.status.value}: action frame_id={verdict.action_frame_id} "
                f"frame={frame.frame_id} latest={verdict.latest_frame_id}; "
                f"snapshot_match={not snapshot_mismatch}",
                frame=frame,
            )

        # 3. element binding — reject invented/stale ids, then resolve coordinates
        if action.target_element_id:
            element = snapshot.find(action.target_element_id) if snapshot is not None else None
            if element is None:
                return self._record(
                    DecisionKind.REJECTED_TARGET,
                    action,
                    None,
                    approver="gatekeeper",
                    reason="target_element_id is absent from the current perception snapshot",
                    frame=frame,
                )
            if action.kind in (
                ActionKind.CLICK,
                ActionKind.RIGHT_CLICK,
                ActionKind.DOUBLE_CLICK,
            ):
                action = replace(action, x=element.center[0], y=element.center[1])
            if context is None:
                context = ActionContext(target_text=element.label)
            elif not context.target_text:
                context = replace(context, target_text=element.label)

        # Coordinate fallbacks must still land inside the observed frame.
        screen_size = getattr(getattr(frame, "image", None), "size", None)
        if screen_size is None and snapshot is not None:
            screen_size = snapshot.screen_size
        points = [(action.x, action.y)]
        if action.kind is ActionKind.DRAG:
            points.append((action.to_x, action.to_y))
        if screen_size is not None and any(
            x is not None
            and y is not None
            and not (0 <= x < screen_size[0] and 0 <= y < screen_size[1])
            for x, y in points
        ):
            return self._record(
                DecisionKind.REJECTED_TARGET,
                action,
                None,
                approver="gatekeeper",
                reason=f"coordinates outside observed frame {screen_size}",
                frame=frame,
            )

        # 4. risk — deterministic and never reads model reasoning
        risk = classify(action, context, self._policy)

        # 5. terminal actions never touch devices
        if action.kind is ActionKind.DONE:
            return self._record(
                DecisionKind.DONE, action, risk, "auto:terminal", "task complete", frame
            )
        if action.kind is ActionKind.FAIL:
            return self._record(
                DecisionKind.FAILED,
                action,
                risk,
                "auto:terminal",
                action.reason or "agent gave up",
                frame,
            )

        # T3 is a hard block by default: approval is not an override path.
        if risk.tier is RiskTier.T3_DESTRUCTIVE and self._config.hard_block_t3:
            return self._record(
                DecisionKind.DENIED,
                action,
                risk,
                approver="policy",
                reason="T3 destructive action hard-blocked by policy",
                frame=frame,
            )

        needs_approval = (
            risk.tier is RiskTier.T2_SENSITIVE and self._config.require_approval_for_t2
        ) or (risk.tier is RiskTier.T3_DESTRUCTIVE and self._config.require_approval_for_t3)
        if needs_approval:
            ok = self._approval.request(ApprovalRequest(action, risk, frame.frame_id))
            if not ok:
                return self._record(
                    DecisionKind.DENIED,
                    action,
                    risk,
                    f"human:{self._approval.name}",
                    "approval denied/timed out",
                    frame,
                )
            approver = f"human:{self._approval.name}"
        else:
            approver = "auto:tier<=T1"

        # 6. execute; failures are decisions too and must enter the audit chain.
        try:
            outcome = self._executor.execute(action)
        except Exception as exc:  # execution boundary must fail closed
            return self._record(
                DecisionKind.EXECUTION_FAILED,
                action,
                risk,
                approver,
                f"executor failed: {type(exc).__name__}: {exc}",
                frame,
            )
        kind = DecisionKind.DRY_RUN if self._executor.name == "dry-run" else DecisionKind.EXECUTED
        return self._record(kind, action, risk, approver, "ok", frame, outcome=outcome)

    # --------------------------------------------------------------- internals
    def _record(
        self,
        kind: DecisionKind,
        action: Action,
        risk: RiskAssessment | None,
        approver: str,
        reason: str,
        frame: Frame,
        outcome: str = "",
    ) -> Decision:
        d = Decision(
            kind=kind, action=action, risk=risk, approver=approver, reason=reason, outcome=outcome
        )
        self._audit.append(
            frame_id=action.frame_id,
            frame_hash=frame.sha256,
            action=action.to_dict(),
            tier=int(risk.tier) if risk else -1,
            decision=kind.value,
            approver=approver,
            reason=reason,
        )
        return d
