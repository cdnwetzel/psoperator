"""SoftLoop — the deterministic driver that walks WORKFLOW.md's states.

It is the harness a local model runs *inside*: the model writes code (Coder)
and the harness decides — from gate results and the escalation ladder — what
happens next. No planner output can change control flow; the state machine and
the ladder own that. This is the sovereign, Claude-not-driving version of what
was done by hand: build → check → escalate on failure → stop at review.

Worked example (harmless by design): a temperature-converter GUI. The Coder
implements ``build_app``; the Gate runs pytest + an on-screen acceptance check;
the VisionJudge (optional) confirms the widgets are actually visible and
readable. Every widget-too-small finding becomes a violation the ladder acts
on, exactly as a person iterating would.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from psoperator.harness.ladder import Attempt, EscalationLadder, Rung
from psoperator.harness.model import (
    TERMINAL_STATES,
    CoderResult,
    Evidence,
    GateResult,
    Lane,
    State,
    Task,
)
from psoperator.harness.protocols import (
    Coder,
    Gate,
    NullReviewer,
    NullVisionJudge,
    Reviewer,
    VisionJudge,
)


@dataclass
class Budget:
    """Hard ceilings; hitting one ends the run at ``reviewing`` with evidence."""

    max_rounds: int = 12
    max_splits: int = 8
    # How many times a REVISE from the local reviewer may trigger a fix pass
    # before the run completes and hands the residual findings up a tier.
    max_review_revisions: int = 1


@dataclass
class _Run:
    """Mutable bookkeeping for one task; never seen by the model."""

    task: Task
    history: list[Attempt] = field(default_factory=list)
    trail: list[str] = field(default_factory=list)
    receipts: list[str] = field(default_factory=list)
    net_tags: list[str] = field(default_factory=list)
    decisions: list[str] = field(default_factory=list)
    review_findings: tuple[str, ...] = ()  # open local-review findings at finish
    unnetted: int = 0  # coder rounds that changed code with no rewind tag
    rounds: int = 0

    def note(self, state: State, detail: str) -> None:
        self.trail.append(f"{state.value}: {detail}")


class SoftLoop:
    """Drive one task to a terminal state through the workflow states.

    Seams are injected; with fakes this is fully unit-testable and needs no
    pxx or model. ``split_tasks`` turns a multi-violation gate into atomic
    sub-tasks (the caller supplies the split — the harness owns *when*, the
    adapter owns *how*, since phrasing a sub-task is coder-specific).
    """

    def __init__(
        self,
        coder: Coder,
        gate: Gate,
        *,
        judge: VisionJudge | None = None,
        reviewer: Reviewer | None = None,
        budget: Budget | None = None,
    ) -> None:
        self._coder = coder
        self._gate = gate
        self._judge = judge or NullVisionJudge()
        self._reviewer = reviewer or NullReviewer()
        self._budget = budget or Budget()
        self._ladder = EscalationLadder(vision_enabled=not isinstance(self._judge, NullVisionJudge))

    def run(self, task: Task) -> Evidence:
        run = _Run(task=task)
        state = State.IDLE
        lane = task.lane
        splits = 0
        judged = False  # has the vision judge been consulted for this task?
        review_revisions = 0  # local-review fix passes spent so far
        reverify_changed: bool | None = None  # set after a split: skip next coder call

        run.note(state, f"goal={task.goal!r} scope={task.scope!r} lane={lane.value}")
        state = State.PLANNING
        run.note(state, "spec accepted (gate command present)")

        while state not in TERMINAL_STATES:
            # A pending post-split re-verify is free (no coder round) — let it run
            # before enforcing the budget, so a split that spent the last round on
            # its focused edits still gets to see whether the parent now passes.
            if reverify_changed is None and run.rounds >= self._budget.max_rounds:
                run.note(State.REVIEWING, f"budget: max_rounds={self._budget.max_rounds}")
                return self._to_review(run, state=State.FAILED)

            # --- executing: one coder attempt on the current lane -----------
            # After a split, the focused edits already ran and were counted, so
            # re-verify the parent gate directly rather than burning another
            # parent coder round (CodeRabbit #5).
            state = State.EXECUTING
            attempt_task = task.with_lane(lane)
            if reverify_changed is not None:
                changed = reverify_changed
                reverify_changed = None
                run.note(state, f"post-split re-verify (no coder round); changed={changed}")
            else:
                coder_result = self._coder.run(attempt_task)
                run.rounds += 1
                self._absorb(run, coder_result)
                changed = coder_result.changed
                run.note(
                    state,
                    f"lane={lane.value} changed={changed} diff_lines={coder_result.diff_lines}",
                )

            # --- verifying: the gate is authoritative -----------------------
            state = State.VERIFYING
            gate_result = self._gate.check(attempt_task)
            run.history.append(Attempt(lane=lane, changed=changed, gate=gate_result))
            run.note(state, _gate_detail(gate_result))

            if gate_result.passed:
                assessed = self._judge.assess(attempt_task)
                if assessed.acceptable:
                    # --- reviewing: cheap local review tier (pxx review) --------
                    state = State.REVIEWING
                    review = self._reviewer.review(attempt_task)
                    if review.approved:
                        run.review_findings = ()
                        run.note(state, "gate + vision + local review acceptable")
                        return self._finish(run, State.COMPLETED)
                    run.review_findings = review.findings
                    run.note(state, "local review REVISE: " + "; ".join(review.findings))
                    if (
                        review_revisions >= self._budget.max_review_revisions
                        or run.rounds >= self._budget.max_rounds
                    ):
                        # Bounded: hand the residue up to the PR-gate tier + human
                        # rather than nitpick-loop. The change is gate-verified;
                        # remaining review findings ride along in the evidence.
                        run.note(
                            state,
                            f"local review residue ({len(review.findings)}) "
                            "handed to PR-gate review",
                        )
                        return self._finish(run, State.COMPLETED)
                    review_revisions += 1
                    fix_task = self._derive_task(
                        task, lane, f"Address local review findings: {'; '.join(review.findings)}"
                    )
                    fixed = self._coder.run(fix_task)
                    run.rounds += 1
                    self._absorb(run, fixed)
                    run.note(
                        State.EXECUTING,
                        f"review-fix pass {review_revisions}: changed={fixed.changed}",
                    )
                    reverify_changed = fixed.changed  # re-verify gate, no fresh parent round
                    continue
                # Vision found what the text gate could not. The gate PASS stays
                # this round's single authoritative attempt (already in history) —
                # do NOT synthesize a failing gate or append a duplicate. Carry
                # the findings into a bounded informed retry (like the review
                # path), on the same lane, and leave `judged` untouched so the
                # ladder's JUDGE rung can still fire on a genuine gate failure.
                run.note(state, "vision rejected a passing gate: " + "; ".join(assessed.findings))
                if run.rounds >= self._budget.max_rounds:
                    return self._to_review(run, state=State.FAILED)
                vision_fix = self._derive_task(
                    task,
                    lane,
                    f"{task.goal} (address vision findings: {'; '.join(assessed.findings)})",
                )
                fixed = self._coder.run(vision_fix)
                run.rounds += 1
                self._absorb(run, fixed)
                run.note(State.EXECUTING, f"vision-fix pass: changed={fixed.changed}")
                reverify_changed = fixed.changed  # re-verify gate, no fresh parent round
                continue

            # --- escalation ladder decides the next move --------------------
            decision = self._ladder.decide(tuple(run.history), judged=judged)
            run.decisions.append(f"{decision.rung.value}: {decision.reason}")
            run.note(
                State.REVIEWING if decision.rung is Rung.REVIEW else state,
                f"ladder={decision.rung.value}: {decision.reason}",
            )

            if decision.rung is Rung.REVIEW:
                return self._to_review(run, state=State.FAILED)
            if decision.rung is Rung.ESCALATE:
                lane = decision.lane
                continue
            if decision.rung is Rung.JUDGE:
                judged = True
                assessed = self._judge.assess(attempt_task)
                if assessed.acceptable:
                    # Eyes say the screen is fine though the text gate fails —
                    # surface to a human rather than loop; the gate/spec is suspect.
                    run.note(state, "vision accepts but gate fails — spec/gate mismatch")
                    return self._to_review(run, state=State.FAILED)
                # Carry the eyes' findings into exactly one informed retry (like
                # the review-fix path); a blind retry just repeats the round and
                # trips the stall detector. judged=True stops JUDGE re-firing.
                run.note(state, "vision findings: " + "; ".join(assessed.findings))
                if run.rounds >= self._budget.max_rounds:
                    # No budget for another coder round — stop here rather than
                    # overrun by one (matches the vision-fix and review-fix paths).
                    return self._to_review(run, state=State.FAILED)
                judge_fix = self._derive_task(
                    task,
                    lane,
                    f"{task.goal} (address vision findings: {'; '.join(assessed.findings)})",
                )
                fixed = self._coder.run(judge_fix)
                run.rounds += 1
                self._absorb(run, fixed)
                run.note(State.EXECUTING, f"vision-fix pass: changed={fixed.changed}")
                reverify_changed = fixed.changed  # re-verify gate, no fresh parent round
                continue
            if decision.rung is Rung.SPLIT:
                subtasks = self.split_tasks(task, gate_result)
                if not subtasks or splits >= self._budget.max_splits:
                    return self._to_review(run, state=State.FAILED)
                splits += 1
                # One focused edit per collected violation, then re-verify the
                # PARENT gate once. A collect-all gate stays red until every
                # sibling defect is fixed, so a per-defect gate would never go
                # green in isolation — the honest move is fix-all-then-reverify.
                any_changed = False
                for sub in subtasks:
                    if run.rounds >= self._budget.max_rounds:
                        break
                    focused = self._coder.run(sub.with_lane(lane))
                    run.rounds += 1
                    self._absorb(run, focused)
                    any_changed = any_changed or focused.changed
                    run.note(State.EXECUTING, f"split-fix {sub.goal!r} changed={focused.changed}")
                reverify_changed = any_changed  # next iteration re-verifies without a coder round
                continue
            # Rung.RETRY: loop again on the same lane.

        return self._finish(run, state)

    # ------------------------------------------------------------------ split
    def split_tasks(self, task: Task, gate: GateResult) -> list[Task]:
        """One atomic sub-task per collected violation (whack-a-mole fix).

        Sub-tasks inherit scope/lane and carry a per-violation gate command:
        by default the same command (the collected gate re-run still covers
        the sub-goal). Adapters may override to target a single check.
        """
        subtasks: list[Task] = []
        for violation in gate.violations:
            subtasks.append(
                Task(
                    goal=f"Fix: {violation}",
                    scope=task.scope,
                    gate_command=task.gate_command,
                    lane=task.lane,
                    parent=task.goal,
                )
            )
        return subtasks

    # ------------------------------------------------------------- internals
    def _derive_task(self, base: Task, lane: Lane, goal: str) -> Task:
        """A follow-up task (review-fix / vision-fix / judge-fix) inheriting the
        parent's scope and gate command, on the given lane."""
        return Task(
            goal=goal,
            scope=base.scope,
            gate_command=base.gate_command,
            lane=lane,
            parent=base.goal,
        )

    def _absorb(self, run: _Run, result: CoderResult) -> None:
        run.receipts.extend(result.receipts)
        if result.net_tag:
            run.net_tags.append(result.net_tag)
        elif result.changed:
            # Changed code with no rewind tag — allowed, but surfaced for review.
            run.unnetted += 1

    def _finish(self, run: _Run, state: State) -> Evidence:
        return Evidence(
            task_goal=run.task.goal,
            final_state=state,
            rounds=run.rounds,
            trail=tuple(run.trail),
            last_violations=run.history[-1].gate.violations if run.history else (),
            receipts=tuple(run.receipts),
            net_tags=tuple(run.net_tags),
            gate_history=tuple(a.gate for a in run.history),
            decisions=tuple(run.decisions),
            unnetted_changes=run.unnetted,
            review_findings=run.review_findings,
        )

    def _to_review(self, run: _Run, *, state: State) -> Evidence:
        """Terminal FAILED with the evidence bundle a human reviews."""
        return self._finish(run, state)


def _gate_detail(gate: GateResult) -> str:
    if gate.passed:
        return "gate PASS"
    if not gate.violations:
        return "gate FAIL (no structured violations)"
    return f"gate FAIL ({len(gate.violations)}): " + "; ".join(gate.violations)
