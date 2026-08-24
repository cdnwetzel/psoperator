"""SoftLoop harness: state machine, escalation ladder, and split recursion.

All fakes — no pxx, no model, no network. The harness is deterministic, so
these pin its exact control flow.
"""

from __future__ import annotations

import pytest

from psoperator.harness import (
    Budget,
    CoderResult,
    EscalationLadder,
    GateResult,
    JudgeResult,
    Lane,
    SoftLoop,
    State,
    Task,
    next_lane,
)
from psoperator.harness.ladder import Attempt, Rung
from psoperator.harness.model import ReviewResult
from psoperator.harness.protocols import NullReviewer, NullVisionJudge


# --------------------------------------------------------------------- fakes
class ScriptedCoder:
    """Returns queued CoderResults; records the lane of every call."""

    def __init__(self, results):
        self._results = list(results)
        self.calls: list[Lane] = []
        self.goals: list[str] = []

    def run(self, task: Task) -> CoderResult:
        self.calls.append(task.lane)
        self.goals.append(task.goal)
        if self._results:
            return self._results.pop(0)
        return CoderResult(changed=False, summary="no-op")


class ScriptedGate:
    """Returns queued GateResults, holding the last one once exhausted."""

    def __init__(self, results):
        self._results = list(results)
        self._last = results[-1]

    def check(self, task: Task) -> GateResult:
        if self._results:
            self._last = self._results.pop(0)
        return self._last


class Workbench:
    """Honest coder+gate pair over a shared set of independent defects.

    As a Coder it *fixes*: a focused task whose goal names a defect clears it.
    As a Gate it *checks*: a collect-all gate that fails with every still-open
    defect and passes only when none remain. This mirrors reality — the coder
    edits, the gate verifies — and captures why per-defect sub-tasks can't pass
    in isolation against a shared collect-all gate.
    """

    def __init__(self, defects):
        self.open = set(defects)

    def run(self, task: Task) -> CoderResult:
        for defect in list(self.open):
            if defect in task.goal:
                self.open.discard(defect)
        return CoderResult(changed=True, summary=f"worked on {task.goal!r}")

    def check(self, task: Task) -> GateResult:
        if self.open:
            return GateResult(passed=False, violations=tuple(sorted(self.open)))
        return GateResult(passed=True)


class RejectingJudge:
    def __init__(self, findings=("widget too small",)):
        self._findings = tuple(findings)
        self.calls = 0

    def assess(self, task: Task) -> JudgeResult:
        self.calls += 1
        return JudgeResult(acceptable=False, findings=self._findings)


def _pass():
    return GateResult(passed=True)


def _fail(*violations):
    return GateResult(passed=False, violations=tuple(violations))


def _task(**kw):
    base = dict(goal="implement build_app", scope=".", gate_command="pytest -q", lane=Lane.SMALL)
    base.update(kw)
    return Task(**base)


# ---------------------------------------------------------------- data types
def test_task_requires_goal_and_gate_command():
    with pytest.raises(ValueError, match="goal"):
        Task(goal="   ", scope=".", gate_command="pytest -q")
    with pytest.raises(ValueError, match="machine-checkable"):
        Task(goal="do it", scope=".", gate_command="  ")


def test_passing_gate_cannot_hold_violations():
    with pytest.raises(ValueError, match="passing gate"):
        GateResult(passed=True, violations=("x",))


def test_lane_ordering():
    assert next_lane(Lane.SMALL) is Lane.STANDARD
    assert next_lane(Lane.STANDARD) is Lane.DEEP
    assert next_lane(Lane.DEEP) is None


# ---------------------------------------------------------------- happy path
def test_first_attempt_passes_completes():
    coder = ScriptedCoder([CoderResult(changed=True, summary="done", diff_lines=3)])
    gate = ScriptedGate([_pass()])
    ev = SoftLoop(coder, gate).run(_task())
    assert ev.final_state is State.COMPLETED
    assert ev.rounds == 1
    assert coder.calls == [Lane.SMALL]


# ------------------------------------------------------------------- rung: retry
def test_transient_failure_then_pass_via_single_retry():
    coder = ScriptedCoder(
        [CoderResult(changed=False, summary="fumbled"), CoderResult(changed=True, summary="ok")]
    )
    gate = ScriptedGate([_fail("test_x"), _pass()])
    ev = SoftLoop(coder, gate).run(_task())
    assert ev.final_state is State.COMPLETED
    assert ev.rounds == 2
    assert any("ladder=retry" in line for line in ev.trail)


# ---------------------------------------------------------------- rung: escalate
def test_single_stubborn_violation_escalates_lane_then_passes():
    # SMALL fails, retry still fails (single violation) -> escalate to STANDARD, pass.
    coder = ScriptedCoder(
        [
            CoderResult(changed=True, summary="attempt-small-1"),
            CoderResult(changed=True, summary="attempt-small-2"),
            CoderResult(changed=True, summary="attempt-standard"),
        ]
    )
    gate = ScriptedGate([_fail("test_convert"), _fail("test_convert"), _pass()])
    ev = SoftLoop(coder, gate).run(_task())
    assert ev.final_state is State.COMPLETED
    assert coder.calls == [Lane.SMALL, Lane.SMALL, Lane.STANDARD]
    assert any("ladder=escalate" in line for line in ev.trail)


# ------------------------------------------------------------------- rung: split
def test_multi_violation_splits_into_per_defect_fixes_and_completes():
    # Parent goal names none of the defects, so the first attempts fail with all
    # three collected; SPLIT then fixes each in a focused edit; parent re-verifies green.
    bench = Workbench(["entry", "button", "label"])
    ev = SoftLoop(bench, bench).run(_task(goal="size the widgets", lane=Lane.STANDARD))
    assert ev.final_state is State.COMPLETED
    split_fixes = [line for line in ev.trail if "split-fix" in line]
    assert len(split_fixes) == 3
    joined = "\n".join(split_fixes)
    assert all(defect in joined for defect in ("entry", "button", "label"))


def test_split_disabled_when_only_one_violation():
    ladder = EscalationLadder(allow_split=True)
    history = (
        Attempt(Lane.STANDARD, changed=True, gate=_fail("only_one")),
        Attempt(Lane.STANDARD, changed=True, gate=_fail("only_one")),
    )
    decision = ladder.decide(history)
    assert decision.rung is Rung.ESCALATE  # single violation escalates, never splits


# -------------------------------------------------------------------- stall
def test_stall_detection_skips_retry_and_escalates():
    ladder = EscalationLadder()
    history = (
        Attempt(Lane.SMALL, changed=False, gate=_fail("v")),
        Attempt(Lane.SMALL, changed=False, gate=_fail("v")),
    )
    d = ladder.decide(history)
    assert d.rung is Rung.ESCALATE and d.lane is Lane.STANDARD


def test_stall_at_top_lane_with_single_violation_reviews():
    ladder = EscalationLadder(vision_enabled=False)
    history = (
        Attempt(Lane.DEEP, changed=False, gate=_fail("v")),
        Attempt(Lane.DEEP, changed=False, gate=_fail("v")),
    )
    assert ladder.decide(history).rung is Rung.REVIEW


def test_no_false_stall_across_a_lane_escalation():
    # The unchanged first attempt on a freshly-escalated lane must NOT be read as
    # a stall (it is that lane's first try) — it still gets its single retry.
    # Regression for the missing same-lane guard in _stalled.
    ladder = EscalationLadder(vision_enabled=False)
    history = (
        Attempt(Lane.SMALL, changed=False, gate=_fail("v")),  # old lane, unchanged
        Attempt(Lane.STANDARD, changed=False, gate=_fail("v")),  # new lane, first try
    )
    assert ladder.decide(history).rung is Rung.RETRY  # not stall/escalate/review


# ------------------------------------------------------------------- review
def test_exhausted_lanes_end_in_failed_with_evidence():
    coder = ScriptedCoder([CoderResult(changed=True, summary=f"a{i}") for i in range(12)])
    gate = ScriptedGate([_fail("stubborn")])  # never passes
    ev = SoftLoop(coder, gate).run(_task(lane=Lane.DEEP))
    assert ev.final_state is State.FAILED
    assert ev.last_violations == ("stubborn",)
    assert any("reviewing:" in line for line in ev.trail)


def test_budget_max_rounds_stops_at_failed():
    # A single stubborn violation loops retry->escalate without ever splitting;
    # the round cap is what stops it, and the stop is recorded as a budget note.
    coder = ScriptedCoder([CoderResult(changed=True, summary="x") for _ in range(20)])
    gate = ScriptedGate([_fail("stubborn")])
    ev = SoftLoop(coder, gate, budget=Budget(max_rounds=3)).run(_task(lane=Lane.SMALL))
    assert ev.final_state is State.FAILED
    assert ev.rounds <= 3
    assert any("budget" in line for line in ev.trail)


# ------------------------------------------------------------- vision judge
def test_vision_rejects_passing_text_gate_then_fixed():
    # Text gate passes but vision says a widget is too small; coder then satisfies both.
    coder = ScriptedCoder(
        [CoderResult(changed=True, summary="tiny"), CoderResult(changed=True, summary="resized")]
    )
    gate = ScriptedGate([_pass(), _pass()])

    class OnceRejectingJudge:
        def __init__(self):
            self.n = 0

        def assess(self, task):
            self.n += 1
            return JudgeResult(acceptable=self.n > 1, findings=() if self.n > 1 else ("too small",))

    ev = SoftLoop(coder, gate, judge=OnceRejectingJudge()).run(_task(lane=Lane.STANDARD))
    assert ev.final_state is State.COMPLETED
    assert ev.rounds == 2
    assert any("vision rejected" in line for line in ev.trail)
    # the informed retry stays on the same lane and receives the vision context
    assert coder.calls == [Lane.STANDARD, Lane.STANDARD]
    assert any("too small" in goal for goal in coder.goals)


def test_null_judge_accepts_by_default():
    assert NullVisionJudge().assess(_task()).acceptable is True


def test_vision_rejection_preserves_gate_history_and_informs_retry():
    # When the text gate passes but vision rejects, the real passing gate result
    # must never be overwritten with a synthetic failure (the original data-
    # integrity bug). The gate PASS stays the round's authoritative attempt and
    # the vision findings are carried into an informed retry — not injected into
    # gate_history as a fake failure.
    coder = ScriptedCoder(
        [CoderResult(changed=True, summary="1"), CoderResult(changed=True, summary="2")]
    )
    gate = ScriptedGate([_pass(), _pass()])

    class OnceRejectingJudge:
        def __init__(self):
            self.n = 0

        def assess(self, task):
            self.n += 1
            return JudgeResult(acceptable=self.n > 1, findings=() if self.n > 1 else ("too small",))

    ev = SoftLoop(coder, gate, judge=OnceRejectingJudge()).run(_task(lane=Lane.SMALL))
    assert ev.final_state is State.COMPLETED
    # every recorded gate result is a real one (all passing) — no synthetic fail
    assert all(g.passed for g in ev.gate_history)
    # and the vision findings reached the retry, not just the trail
    assert any("too small" in goal for goal in coder.goals)


# ---------------------------------------------------------------- reviewer tier
class ScriptedReviewer:
    def __init__(self, results):
        self._results = list(results)
        self.calls = 0

    def review(self, task: Task) -> ReviewResult:
        self.calls += 1
        return self._results.pop(0) if self._results else ReviewResult(approved=True)


def test_null_reviewer_approves_by_default():
    assert NullReviewer().review(_task()).approved is True


def test_local_review_approve_completes_clean():
    coder = ScriptedCoder([CoderResult(changed=True, summary="ok")])
    gate = ScriptedGate([_pass()])
    reviewer = ScriptedReviewer([ReviewResult(approved=True)])
    ev = SoftLoop(coder, gate, reviewer=reviewer).run(_task())
    assert ev.final_state is State.COMPLETED
    assert ev.review_findings == ()
    assert reviewer.calls == 1
    assert any("local review acceptable" in line for line in ev.trail)


def test_local_review_revise_then_fix_then_approve():
    # Gate passes; reviewer says REVISE once, a fix pass runs, re-review approves.
    coder = ScriptedCoder(
        [CoderResult(changed=True, summary="v1"), CoderResult(changed=True, summary="review-fix")]
    )
    gate = ScriptedGate([_pass()])  # gate passes throughout
    reviewer = ScriptedReviewer(
        [ReviewResult(approved=False, findings=("rename x",)), ReviewResult(approved=True)]
    )
    ev = SoftLoop(coder, gate, reviewer=reviewer, budget=Budget(max_review_revisions=1)).run(
        _task()
    )
    assert ev.final_state is State.COMPLETED
    assert ev.review_findings == ()  # resolved
    assert any("review-fix pass 1" in line for line in ev.trail)
    assert reviewer.calls == 2


def test_local_review_residue_handed_up_when_revisions_exhausted():
    # Reviewer keeps saying REVISE; after the capped fix pass, the run completes
    # (gate-verified) and the residual findings ride along for the PR-gate tier.
    coder = ScriptedCoder([CoderResult(changed=True, summary=f"v{i}") for i in range(5)])
    gate = ScriptedGate([_pass()])
    reviewer = ScriptedReviewer(
        [ReviewResult(approved=False, findings=("nit a",)) for _ in range(5)]
    )
    ev = SoftLoop(coder, gate, reviewer=reviewer, budget=Budget(max_review_revisions=1)).run(
        _task()
    )
    assert ev.final_state is State.COMPLETED
    assert ev.review_findings == ("nit a",)  # surfaced up, not silently dropped
    assert any("handed to PR-gate review" in line for line in ev.trail)


def test_judge_fires_at_most_once_and_findings_inform_the_retry():
    # Top lane, single stubborn violation, vision keeps rejecting: JUDGE fires
    # once, its findings are carried into exactly one informed retry, then the
    # run stops at review rather than re-consulting the judge forever.
    coder = ScriptedCoder([CoderResult(changed=True, summary=f"a{i}") for i in range(6)])
    gate = ScriptedGate([_fail("stubborn")])  # always fails
    judge = RejectingJudge(findings=("still off",))
    ev = SoftLoop(coder, gate, judge=judge, budget=Budget(max_rounds=10)).run(_task(lane=Lane.DEEP))
    assert ev.final_state is State.FAILED
    assert judge.calls == 1  # consulted exactly once, never in a loop
    assert any("ladder=judge" in line for line in ev.trail)
    # the vision findings actually reached the coder's retry, not just the trail
    assert any("still off" in goal for goal in coder.goals)


# ------------------------------------------------------------------- evidence
def test_evidence_carries_full_ordered_history_and_decisions():
    coder = ScriptedCoder(
        [CoderResult(changed=True, summary="1"), CoderResult(changed=True, summary="2")]
    )
    gate = ScriptedGate([_fail("v"), _pass()])  # fail, retry, pass
    ev = SoftLoop(coder, gate).run(_task())
    assert ev.final_state is State.COMPLETED
    assert len(ev.gate_history) == 2  # both attempts recorded, in order
    assert ev.gate_history[0].passed is False and ev.gate_history[1].passed is True
    assert any("retry" in d for d in ev.decisions)


def test_evidence_counts_unnetted_changes():
    # A coder that changes code but leaves no rewind tag is flagged, not failed.
    coder = ScriptedCoder([CoderResult(changed=True, summary="edited", net_tag=None)])
    gate = ScriptedGate([_pass()])
    ev = SoftLoop(coder, gate).run(_task())
    assert ev.final_state is State.COMPLETED
    assert ev.unnetted_changes == 1
    assert ev.net_tags == ()


# ------------------------------------------------------- split re-verify (no waste)
def test_split_reverify_uses_no_extra_parent_coder_round():
    # After splitting 2 defects, the parent gate is re-verified directly — the
    # coder is called exactly 2 (initial+retry) + 2 (focused) times, not +1 more
    # for a wasted parent round (CodeRabbit #5).
    class CountingBench(Workbench):
        def __init__(self, defects):
            super().__init__(defects)
            self.runs = 0

        def run(self, task):
            self.runs += 1
            return super().run(task)

    bench = CountingBench(["alpha", "beta"])
    ev = SoftLoop(bench, bench).run(_task(goal="widen it", lane=Lane.STANDARD))
    assert ev.final_state is State.COMPLETED
    # 1 initial + 1 retry (parent, still failing) + 2 focused fixes = 4; no 5th parent round.
    assert bench.runs == 4
    assert any("post-split re-verify" in line for line in ev.trail)


# ------------------------------------------------------------------- receipts
def test_receipts_and_net_tags_flow_into_evidence():
    coder = ScriptedCoder(
        [CoderResult(changed=True, summary="ok", net_tag="pxx-pre/T", receipts=("R-1",))]
    )
    gate = ScriptedGate([_pass()])
    ev = SoftLoop(coder, gate).run(_task())
    assert ev.receipts == ("R-1",)
    assert ev.net_tags == ("pxx-pre/T",)
