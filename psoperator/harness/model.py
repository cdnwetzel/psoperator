"""Value types for the SoftLoop harness.

These are the data that cross the harness seams. Everything here is a frozen
dataclass or enum: the harness state machine is deterministic and the model
never sees these objects, so they carry no behaviour a planner could subvert.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum


class State(str, Enum):
    """The workflow states, mirroring ``WORKFLOW.md``.

    The harness is the runtime that walks these; ``pxx workflow validate``
    validates the same names in the repo contract. ``COMPLETED`` and
    ``FAILED`` are terminal.
    """

    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    REVIEWING = "reviewing"
    COMPLETED = "completed"
    FAILED = "failed"


TERMINAL_STATES: frozenset[State] = frozenset({State.COMPLETED, State.FAILED})


class Lane(str, Enum):
    """Model lanes ordered by capability, cheapest first.

    The ladder escalates along this order. Values are logical lane names, not
    model ids; the operator maps them to endpoints/models in a ``LanePolicy``
    (endpoints stay out of tracked config — they are a data-egress surface).
    """

    SMALL = "small"  # 1-2 line edits; e.g. a 14B instruct
    STANDARD = "standard"  # functions / multi-line; e.g. a 20-30B coder
    DEEP = "deep"  # hardest edits / whole components; largest local model

    @property
    def rank(self) -> int:
        return _LANE_ORDER.index(self)


_LANE_ORDER: tuple[Lane, ...] = (Lane.SMALL, Lane.STANDARD, Lane.DEEP)


def next_lane(lane: Lane) -> Lane | None:
    """The next more-capable lane, or None if already at the top."""
    i = lane.rank + 1
    return _LANE_ORDER[i] if i < len(_LANE_ORDER) else None


@dataclass(frozen=True)
class Task:
    """One unit of work for the coder: a checkable spec.

    ``gate_command`` is what proves it (a test/acceptance command). Following
    the tutorial's rule: if you cannot say how you'd check it, the harness
    cannot either — a task with no gate command is refused fail-closed.
    """

    goal: str
    scope: str
    gate_command: str
    lane: Lane = Lane.STANDARD
    parent: str | None = None  # goal of the task this was split from, if any

    def __post_init__(self) -> None:
        if not self.goal.strip():
            raise ValueError("task goal must be non-empty")
        if not self.scope.strip():
            raise ValueError("task scope must be non-empty (the fence the coder may edit within)")
        if not self.gate_command.strip():
            raise ValueError(
                "task has no gate_command: 'done' must be machine-checkable "
                "(a failing test/command), else COMPLETED means nothing"
            )

    def with_lane(self, lane: Lane) -> "Task":
        return replace(self, lane=lane)


@dataclass(frozen=True)
class CoderResult:
    """Outcome of one coder invocation (e.g. a ``pxx edit``/``loop`` run)."""

    changed: bool
    summary: str
    diff_lines: int = 0
    committed: str | None = None  # commit sha, if the coder committed
    net_tag: str | None = None  # pxx safety tag to rewind to
    receipts: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GateResult:
    """Outcome of running a task's gate command.

    ``violations`` is the *complete* list of what failed, never just the first
    (today's whack-a-mole lesson: a gate that reveals one failure per round
    multiplies rounds; the harness relies on collect-all gates to split work).
    """

    passed: bool
    violations: tuple[str, ...] = field(default_factory=tuple)
    raw_tail: str = ""

    def __post_init__(self) -> None:
        if self.passed and self.violations:
            raise ValueError("a passing gate cannot carry violations")


@dataclass(frozen=True)
class JudgeResult:
    """Outcome of an optional vision judge (e.g. UI-TARS reading the screen)."""

    acceptable: bool
    findings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ReviewResult:
    """Outcome of the cheap local review tier (e.g. ``pxx review`` on the diff).

    ``approved`` mirrors pxx's APPROVE/REVISE verdict. This tier is *advisory
    and bounded*: it gets a limited number of revision passes to improve the
    diff, then whatever it still flags is handed up to the PR-gate review
    (CodeRabbit) and the human — it never blocks a gate-passing change forever.
    """

    approved: bool
    findings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Evidence:
    """The bundle handed to a human at ``reviewing`` — what a run produced.

    Deliberately boring and complete: every state entered, every gate result in
    order, every ladder decision, the coder receipts, and the rewind tags. This
    is the auditable record that substitutes for a human having watched the
    loop — so it carries the *full* ordered history, not just the last failure.
    """

    task_goal: str
    final_state: State
    rounds: int
    trail: tuple[str, ...]
    last_violations: tuple[str, ...] = field(default_factory=tuple)
    receipts: tuple[str, ...] = field(default_factory=tuple)
    net_tags: tuple[str, ...] = field(default_factory=tuple)
    gate_history: tuple[GateResult, ...] = field(default_factory=tuple)
    decisions: tuple[str, ...] = field(default_factory=tuple)
    # Count of coder rounds that changed code without leaving a rewind tag.
    # Not fatal (the Coder contract allows an un-netted backend), but a human
    # reviewing an autonomous run should see it: those changes can't be undone
    # by the safety-tag path. Zero on a well-netted coder like pxx.
    unnetted_changes: int = 0
    # Local-review (tier 1) findings still open at completion — the residue the
    # PR-gate review (CodeRabbit) and the human should look at. Empty means the
    # local reviewer approved cleanly (or none was configured).
    review_findings: tuple[str, ...] = field(default_factory=tuple)
