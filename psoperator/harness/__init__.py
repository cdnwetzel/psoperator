"""SoftLoop harness — the deterministic driver for local-model coding loops.

A state machine (``WORKFLOW.md`` states) that walks a checkable task to a
terminal state by driving three seams — a Coder (pxx), a Gate (a test/accept
command), and an optional VisionJudge — and an escalation ladder that responds
to gate failures the way a careful operator would: retry, split, escalate the
model lane, consult the eyes, then stop at human review. No planner output
changes control flow.
"""

from __future__ import annotations

from psoperator.harness.ladder import Attempt, Decision, EscalationLadder, Rung
from psoperator.harness.model import (
    CoderResult,
    Evidence,
    GateResult,
    JudgeResult,
    Lane,
    ReviewResult,
    State,
    Task,
    next_lane,
)
from psoperator.harness.protocols import (
    Coder,
    Gate,
    NullReviewer,
    NullVisionJudge,
    Reviewer,
    VisionJudge,
)
from psoperator.harness.softloop import Budget, SoftLoop

__all__ = [
    "Attempt",
    "Budget",
    "Coder",
    "CoderResult",
    "Decision",
    "EscalationLadder",
    "Evidence",
    "Gate",
    "GateResult",
    "JudgeResult",
    "Lane",
    "NullReviewer",
    "NullVisionJudge",
    "ReviewResult",
    "Reviewer",
    "Rung",
    "SoftLoop",
    "State",
    "Task",
    "VisionJudge",
    "next_lane",
]
