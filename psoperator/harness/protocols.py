"""Seams the SoftLoop drives.

Three narrow interfaces so the deterministic harness can be tested with fakes
and run for real against pxx + a gate command + a vision model. The harness
never imports pxx or an HTTP client itself; adapters live behind these.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from psoperator.harness.model import CoderResult, GateResult, JudgeResult, ReviewResult, Task


@runtime_checkable
class Coder(Protocol):
    """Runs a bounded, gated coding attempt (the pxx ``loop`` role).

    An adapter maps ``task.lane`` to a model/endpoint and shells out to pxx
    with ``--scope task.scope`` and ``PXX_TEST_COMMAND=task.gate_command``. It
    must be fenced (never edit outside scope) and netted (leave a rewindable
    tag). It returns what happened; it does not decide what happens next.
    """

    def run(self, task: Task) -> CoderResult: ...


@runtime_checkable
class Gate(Protocol):
    """Runs a task's acceptance command and reports every violation.

    An adapter runs ``task.gate_command`` and parses failures. The harness
    treats the returned violation list as authoritative for splitting work, so
    the command should collect all failures, not stop at the first.
    """

    def check(self, task: Task) -> GateResult: ...


@runtime_checkable
class VisionJudge(Protocol):
    """Optional on-screen acceptance for GUI work (a vision model reading pixels).

    Answers the questions a text gate cannot: is anything clipped, tiny, or
    duplicated on screen? Returning ``acceptable=True`` with no findings when
    unavailable keeps the harness fail-open on this *advisory* seam only.
    """

    def assess(self, task: Task) -> JudgeResult: ...


class NullVisionJudge:
    """A judge that abstains — used when no vision model is configured."""

    def assess(self, task: Task) -> JudgeResult:
        return JudgeResult(acceptable=True)


@runtime_checkable
class Reviewer(Protocol):
    """The cheap, local, unlimited review tier (the pxx ``review`` role).

    Runs *inside* the loop on a gate-passing change and returns a verdict plus
    findings. It is the rate-limiter that protects the paid PR-gate reviewer:
    only what survives here should reach CodeRabbit. Advisory and bounded — the
    harness gives it a capped number of revision passes, then hands the residue
    up. Returning ``approved=True`` with no findings when unavailable keeps this
    seam fail-open (like the vision judge; unlike the gate).
    """

    def review(self, task: Task) -> ReviewResult: ...


class NullReviewer:
    """A reviewer that abstains — used when no local reviewer is configured."""

    def review(self, task: Task) -> ReviewResult:
        return ReviewResult(approved=True)
