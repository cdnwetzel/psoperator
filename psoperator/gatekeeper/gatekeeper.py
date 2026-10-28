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

import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
from functools import partial

from psoperator.common.schema import PerceptionSnapshot
from psoperator.config import PSOperatorConfig
from psoperator.gatekeeper import killswitch
from psoperator.gatekeeper.approval import ApprovalBackend, ApprovalRequest, CLIApproval
from psoperator.gatekeeper.audit import AuditLog
from psoperator.gatekeeper.bound_target import (
    AllowList,
    BoundKeyRequest,
    Code,
    Observation,
    Refusal,
    audited_hash,
    audited_keys,
    bound_key_problem,
    normalized,
    recipient_of,
    recipient_problem,
    trusted_action,
    unchanged,
    unverified_record,
)
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


_SERVICE_REFUSED_KINDS = frozenset({ActionKind.SCROLL, ActionKind.DRAG})
_INPUT_KINDS = frozenset(
    {
        ActionKind.CLICK,
        ActionKind.RIGHT_CLICK,
        ActionKind.DOUBLE_CLICK,
        ActionKind.TYPE,
        ActionKind.KEY,
    }
)
_KEYBOARD_KINDS = frozenset({ActionKind.TYPE, ActionKind.KEY})
# Every kind that reaches the input device: what bound_input_only closes.
_DEVICE_KINDS = _INPUT_KINDS | _SERVICE_REFUSED_KINDS
_ACTION_KIND_VALUES = frozenset(kind.value for kind in ActionKind)
# The binding recorded for a decision that never went through the bound gate.
_UNBOUND = {"kind": "unbound", "verified": False}
# What the audit records instead of an action that was never read, or was
# rejected: the original object is not read again.
_UNREAD, _REJECTED = "<unread>", "<rejected>"


def _guarded(read):
    """A value read from an untrusted object, or None if reading it fails."""
    try:
        return read()
    except Exception:
        return None


def _service_contract_refusal(
    action: Action, snapshot: PerceptionSnapshot | None
) -> tuple[DecisionKind, str] | None:
    """Why an action falls outside the service contract, or None if it is inside.

    The planner client is untrusted, so the contract is checked here rather
    than relied on from its prompt: no scroll or drag, no coordinate-only or
    unbound input, and keyboard input only into an accessibility element (an
    OCR text box is not a focusable control).
    """
    if action.kind in _SERVICE_REFUSED_KINDS:
        return (
            DecisionKind.DENIED,
            f"{action.kind.value} is not allowed across the service boundary",
        )
    if action.kind not in _INPUT_KINDS:
        return None
    if not action.target_element_id:
        return (
            DecisionKind.REJECTED_TARGET,
            "input must name an element of the attested snapshot",
        )
    element = snapshot.find(action.target_element_id) if snapshot is not None else None
    if element is None:
        return (
            DecisionKind.REJECTED_TARGET,
            "target_element_id is absent from the current perception snapshot",
        )
    if action.kind in _KEYBOARD_KINDS and element.source != "a11y":
        return (
            DecisionKind.REJECTED_TARGET,
            f"keyboard input needs an accessibility element, not {element.source}",
        )
    return None


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
        *,
        bound_input_only: bool = False,
        bound_observer: Callable[[int], Observation] | None = None,
        bound_allow: AllowList | None = None,
        bound_app_image: str | None = None,
        bound_window: tuple[int, tuple[int, int]] | None = None,
        bound_recipient: Callable[[int], tuple] | None = None,
        observation_max_age_s: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # With bound_input_only, input reaches the device only through
        # request_bound_key: request_action refuses every unbound input.
        self._bound_input_only = bound_input_only
        # The observer and the clock are trusted configuration fixed here; a
        # request can neither supply nor replace them.
        self._observe = bound_observer
        # The allow-list and the application it applies to are trusted
        # configuration too: a request only selects a path and step within them.
        self._allow = bound_allow
        self._app_image = bound_app_image
        # The one main window (and its process instance: pid, start time) the
        # gate may send keys to, fixed for this gatekeeper's lifetime.
        self._window = bound_window
        # A fast reader of who would receive a key (win32_state.recipient),
        # read immediately before and after the executor is called.
        self._recipient = bound_recipient
        self._max_age_s = observation_max_age_s
        self._clock = clock
        self._config = config
        self._freshness = freshness
        self._approval = approval_backend or CLIApproval()
        self._executor = executor or DryRunExecutor()
        self._audit = AuditLog(config.audit_log_path)
        self._policy = load_policy(config.risk_policy_path)

    def record_envelope_event(self, receipt: dict) -> None:
        """Append an R-203 envelope-authentication verdict (admitted or a named
        rejection) to the same hash-chained audit the decisions use, so a refused
        forgery leaves a durable, tamper-evident receipt — not just a response.
        The envelope's identity (key, epoch, nonce) is kept, so a receipt can say
        which key or nonce a rejection was about."""
        self._audit.append(
            frame_id=int(receipt.get("frame_id", 0)),
            frame_hash=str(receipt.get("frame_hash", "-")),
            action={
                "envelope": {
                    k: receipt[k]
                    for k in ("key_id", "observer_epoch", "nonce", "detail", "max_nonces", "at")
                    if k in receipt
                }
            },
            tier=-1,  # no risk assessment, the same sentinel as _record
            decision=f"ENVELOPE_{str(receipt['outcome']).upper()}",
            approver="gatekeeper",
            reason=str(receipt.get("reason") or receipt["outcome"]),
        )

    # ------------------------------------------------------------------ API
    def request_bound_key(self, request: BoundKeyRequest, frame: Frame) -> Decision:
        """One key for the pilot application, admitted only through the
        bound-target gate (``bound_target``). The screen is observed by the
        gatekeeper's own observer (fixed at construction): now, and again
        immediately before the key is sent (after any approval); any change
        refuses. Every decision is audited with a fixed reason code, recognised
        key names and identity built from the observation; never text."""
        # The kill switch is checked before anything about the request is read.
        if killswitch.is_engaged(self._config.kill_switch_path):
            return self._record(
                DecisionKind.KILL_SWITCHED,
                None,
                None,
                approver="gatekeeper",
                reason="kill switch engaged",
                frame=frame,
                binding={"kind": "unread", "verified": False},
                placeholder=_UNREAD,
            )
        # Reading the request is itself guarded: a malformed or hostile request
        # becomes an audited refusal, never an exception.
        try:
            request = normalized(request)
            action = request.action
            unverified = unverified_record(request.target, frame.sha256)
            readable = True
        except Exception:
            action = None
            unverified = {"kind": "invalid", "verified": False}
            readable = False

        def refuse(refusal: Refusal) -> Decision:
            reason = refusal.code.value + (f": {refusal.detail}" if refusal.detail else "")
            return self._record(
                DecisionKind.DENIED,
                action,
                None,
                approver="gatekeeper",
                reason=reason,
                frame=frame,
                binding=unverified,
                audit_reason=refusal.code.value,
                placeholder=None if readable else _REJECTED,
            )

        if not readable:
            return refuse(Refusal(Code.INVALID))
        if None in (self._observe, self._allow, self._app_image, self._window, self._recipient):
            return refuse(Refusal(Code.NO_OBSERVER))

        main_hwnd, instance = self._window

        def check() -> tuple[Observation | None, dict | None, Refusal | None]:
            try:
                observed = self._observe(main_hwnd)
            except Exception:
                return None, None, Refusal(Code.OBSERVE_FAILED)
            try:
                identity, refusal = bound_key_problem(
                    request,
                    self._allow,
                    observed,
                    now=self._clock(),
                    max_age_s=self._max_age_s,
                    app_image=self._app_image,
                    main_hwnd=main_hwnd,
                    instance=instance,
                )
            except Exception:
                return observed, None, Refusal(Code.INVALID)
            return observed, identity, refusal

        first, identity, refusal = check()
        if refusal is not None:
            return refuse(refusal)
        binding = {**identity, "verified": True, "frame_hash": unverified["frame_hash"]}

        def recheck() -> str | None:
            second, _, again = check()
            if again is not None:
                return again.code.value
            if not unchanged(first, second):
                return Code.CHANGED.value
            return None

        approved = recipient_of(first)

        def recipient_changed(code: Code, held: Code) -> str | None:
            try:
                now = tuple(self._recipient(main_hwnd))
            except Exception:
                return code.value
            problem = recipient_problem(now, approved, code, held)
            return None if problem is None else problem.value

        return self._decide(
            action,
            frame,
            binding=binding,
            pre_execute=recheck,
            # Before the send, a held modifier refuses with its own code; after
            # it, any difference (a modifier included) is the incident code.
            pre_send=lambda: recipient_changed(Code.RECIPIENT_CHANGED, Code.MODIFIER_HELD),
            post_send=lambda: recipient_changed(Code.SENT_THEN_CHANGED, Code.SENT_THEN_CHANGED),
        )

    def request_action(
        self,
        action: Action,
        frame: Frame,
        context: ActionContext | None = None,
        snapshot: PerceptionSnapshot | None = None,
        *,
        require_bound_input: bool = False,
    ) -> Decision:
        # The action is read once into a private copy: the kind checked here
        # is the kind the pipeline checks and executes. Anything else is
        # recorded through the guarded path, which is safe for a hostile object.
        try:
            action = trusted_action(action)
            untrusted = None
        except Exception:
            untrusted = {"kind": "invalid", "verified": False}
        # The kill switch wins and is recorded as such. Otherwise an invalid
        # action is refused, and with bound_input_only unbound input never
        # reaches the device: neither denial depends on the switch, which may
        # change between two reads.
        if killswitch.is_engaged(self._config.kill_switch_path):
            return self._record(
                DecisionKind.KILL_SWITCHED,
                action,
                None,
                approver="gatekeeper",
                reason="kill switch engaged",
                frame=frame,
                binding=untrusted,
                placeholder=None if untrusted is None else _REJECTED,
            )
        if untrusted is not None:
            return self._record(
                DecisionKind.DENIED,
                action,
                None,
                approver="gatekeeper",
                reason=Code.INVALID.value,
                frame=frame,
                binding=untrusted,
                audit_reason=Code.INVALID.value,
                placeholder=_REJECTED,
            )
        if self._bound_input_only and action.kind in _DEVICE_KINDS:
            return self._record(
                DecisionKind.DENIED,
                action,
                None,
                approver="gatekeeper",
                reason="input must go through the bound-target gate",
                frame=frame,
                audit_reason=Code.UNBOUND_INPUT.value,
            )
        return self._decide(
            action, frame, context, snapshot, require_bound_input=require_bound_input
        )

    def _decide(
        self,
        action: Action,
        frame: Frame,
        context: ActionContext | None = None,
        snapshot: PerceptionSnapshot | None = None,
        *,
        require_bound_input: bool = False,
        binding: dict | None = None,
        pre_execute: Callable[[], str | None] | None = None,
        pre_send: Callable[[], str | None] | None = None,
        post_send: Callable[[], str | None] | None = None,
    ) -> Decision:
        """The pipeline. Private: only request_action (which enforces
        bound_input_only) and request_bound_key (which binds and re-checks)
        call it."""
        record = partial(self._record, binding=binding)
        # 1. global stop — fail closed, including terminal/no-op actions
        if killswitch.is_engaged(self._config.kill_switch_path):
            return record(
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
            return record(
                DecisionKind.REJECTED_STALE,
                action,
                None,
                approver="gatekeeper",
                reason=f"{verdict.status.value}: action frame_id={verdict.action_frame_id} "
                f"frame={frame.frame_id} latest={verdict.latest_frame_id}; "
                f"snapshot_match={not snapshot_mismatch}",
                frame=frame,
            )

        # 2b. service contract (R-306): across the service boundary only the
        # supported kinds are admitted, and all input names an attested element.
        if require_bound_input:
            refusal = _service_contract_refusal(action, snapshot)
            if refusal is not None:
                return record(
                    refusal[0], action, None, approver="gatekeeper", reason=refusal[1], frame=frame
                )

        # 3. element binding — reject invented/stale ids, then resolve coordinates
        risk_contexts: tuple[ActionContext, ...] = ()
        if action.target_element_id:
            element = snapshot.find(action.target_element_id) if snapshot is not None else None
            if element is None:
                return record(
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
            # Caller context must not lower the tier of an attested element: a
            # planner calling "Delete" "safe" does not make it safe. Policy
            # patterns are regexes (anchored, multi-word), so merging texts can
            # break a match; score each reading on its own and keep the highest.
            attested = ActionContext(target_text=element.label)
            if context is None:
                context = attested
            else:
                risk_contexts = (
                    replace(context, target_text=element.label),
                    attested,
                    context,
                )

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
            return record(
                DecisionKind.REJECTED_TARGET,
                action,
                None,
                approver="gatekeeper",
                reason=f"coordinates outside observed frame {screen_size}",
                frame=frame,
            )

        # 4. risk — deterministic and never reads model reasoning
        risk = max(
            (classify(action, c, self._policy) for c in risk_contexts or (context,)),
            key=lambda assessment: assessment.tier,
        )

        # 5. terminal actions never touch devices
        if action.kind is ActionKind.DONE:
            return record(DecisionKind.DONE, action, risk, "auto:terminal", "task complete", frame)
        if action.kind is ActionKind.FAIL:
            return record(
                DecisionKind.FAILED,
                action,
                risk,
                "auto:terminal",
                action.reason or "agent gave up",
                frame,
            )

        # T3 is a hard block by default: approval is not an override path.
        if risk.tier is RiskTier.T3_DESTRUCTIVE and self._config.hard_block_t3:
            return record(
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
                return record(
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

        # 5b. a bound key re-observes the screen immediately before sending;
        # any change since the check (including during approval) refuses.
        if pre_execute is not None:
            try:
                changed = pre_execute()
            except Exception:
                changed = Code.OBSERVE_FAILED.value
            if changed is not None:
                return record(
                    DecisionKind.DENIED,
                    action,
                    risk,
                    approver="gatekeeper",
                    reason=changed,
                    frame=frame,
                    audit_reason=changed,
                )

        # 5c. the kill switch is checked again at the last moment: it may have
        # been engaged while approval or the final observation was pending.
        if killswitch.is_engaged(self._config.kill_switch_path):
            return record(
                DecisionKind.KILL_SWITCHED,
                action,
                risk,
                approver="gatekeeper",
                reason="kill switch engaged",
                frame=frame,
            )

        # 5d. a bound key: who would receive it is read once more, as the last
        # step before the executor is called; any difference from the approved
        # observation (or a failed reading) refuses.
        if pre_send is not None:
            changed = pre_send()
            if changed is not None:
                return record(
                    DecisionKind.DENIED,
                    action,
                    risk,
                    approver="gatekeeper",
                    reason=changed,
                    frame=frame,
                    audit_reason=changed,
                )

        # 6. execute; failures are decisions too and must enter the audit chain.
        # 7. a bound key: read again right after the executor returns or
        # raises (an executor can send the key and then fail). A difference is
        # recorded as an incident, not hidden; a failure keeps its own kind.
        failure: Exception | None = None
        outcome = ""
        incident: str | None = None
        try:
            outcome = self._executor.execute(action)
        except Exception as exc:  # execution boundary must fail closed
            failure = exc
        finally:
            if post_send is not None:
                incident = post_send()
        if failure is not None:
            detail = f"executor failed: {type(failure).__name__}: {failure}"
            return record(
                DecisionKind.EXECUTION_FAILED,
                action,
                risk,
                approver,
                f"{incident}; {detail}" if incident else detail,
                frame,
                audit_reason=incident,
            )
        kind = DecisionKind.DRY_RUN if self._executor.name == "dry-run" else DecisionKind.EXECUTED
        if incident is not None:
            return record(
                kind,
                action,
                risk,
                approver,
                incident,
                frame,
                outcome=outcome,
                audit_reason=incident,
            )
        return record(kind, action, risk, approver, "ok", frame, outcome=outcome)

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
        binding: dict | None = None,
        audit_reason: str | None = None,
        placeholder: str | None = None,
    ) -> Decision:
        d = Decision(
            kind=kind, action=action, risk=risk, approver=approver, reason=reason, outcome=outcome
        )
        if binding is None and placeholder is None and not self._bound_input_only:
            entry = action.to_dict()
            audited = reason
            frame_id = action.frame_id
            frame_hash = frame.sha256
        else:
            # A bound action, and with bound_input_only every decision, is
            # recorded by kind, recognised key names and the binding only, with
            # a fixed reason code: never typed text, never a caller-supplied
            # string, never an executor message. A rejected or unread action is
            # recorded by a fixed placeholder and never read again.
            if placeholder is not None:
                kind_value, frame_id, keys = placeholder, -1, []
            else:
                kind_value = _guarded(lambda: action.kind.value)
                if type(kind_value) is not str or kind_value not in _ACTION_KIND_VALUES:
                    kind_value = "<invalid>"
                frame_id = _guarded(lambda: action.frame_id)
                frame_id = frame_id if type(frame_id) is int else -1
                keys = audited_keys(action)
            entry = {
                "action": kind_value,
                "frame_id": frame_id,
                "keys": keys,
                "binding": binding if binding is not None else _UNBOUND,
            }
            audited = audit_reason or kind.value
            frame_hash = _guarded(lambda: audited_hash(frame.sha256)) or "<invalid>"
        self._audit.append(
            frame_id=frame_id,
            frame_hash=frame_hash,
            action=entry,
            tier=int(risk.tier) if risk else -1,
            decision=kind.value,
            approver=approver,
            reason=audited,
        )
        return d
