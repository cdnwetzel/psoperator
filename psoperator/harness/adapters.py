"""Real seam adapters: pxx as the Coder, a shell command as the Gate.

These are the only parts of the harness that touch the outside world (a
subprocess). They are import-safe with no pxx installed and are kept thin so
the state machine and ladder remain pure and unit-tested. The harness never
imports these directly — the operator wires them in at the edge.

Model-lane routing lives here, not in tracked config: endpoints are a
data-egress surface (see WORKFLOW.md), so a ``LanePolicy`` maps a logical
``Lane`` to a model id and endpoint supplied by the operator via env/CLI.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass

from psoperator.harness.model import CoderResult, GateResult, Lane, ReviewResult, Task

# pxx's summary tail, e.g.:
#   [net: pxx-pre/20260823T121231Z] [committed a4564158] (rounds=4 tokens=8056 diff_lines=2)
_NET = re.compile(r"\[net:\s*([^\]]+)\]")
_COMMITTED = re.compile(r"\[committed\s+([0-9a-f]+)\]")
_DIFF_LINES = re.compile(r"diff_lines=(\d+)")


def _last(pattern: re.Pattern, text: str) -> str | None:
    """Group(1) of the LAST match, or None. pxx's summary tail is at the end of
    the output, and model prose earlier in the stream can echo a [net: …] or
    [committed …] token — first-match would let that prose spoof the coder's own
    evidence (a fake [committed …] even flips `changed` to True)."""
    matches = pattern.findall(text)
    return matches[-1] if matches else None


@dataclass(frozen=True)
class LanePolicy:
    """Maps logical lanes to (model, endpoint). Operator-supplied, never tracked.

    Example (proven on the LAN): SMALL->qwen2.5:14b, STANDARD->gpt-oss:20b,
    DEEP->a larger local model, all on an Ollama endpoint. Only the lanes an
    operator populates are usable; an unmapped lane raises rather than guess.
    """

    models: dict[Lane, str]
    endpoint: str
    provider: str = "ollama"

    def model_for(self, lane: Lane) -> str:
        try:
            return self.models[lane]
        except KeyError as exc:
            raise ValueError(f"no model mapped for lane {lane.value!r}") from exc


class PxxCoder:
    """Drive ``pxx loop`` for one bounded, gated task.

    Fenced by ``--scope`` and gated by ``PXX_TEST_COMMAND=task.gate_command``;
    pxx nets the tree (rewindable tag) and commits on success. Parses the
    summary tail into a CoderResult. Requires the ``pxx`` binary on PATH; the
    class imports fine without it and only shells out in :meth:`run`.
    """

    def __init__(
        self,
        policy: LanePolicy,
        *,
        cwd: str,
        pxx_bin: str = "pxx",
        native_timeout_s: int = 540,
        run_timeout_s: float = 2400.0,
    ) -> None:
        self._policy = policy
        self._cwd = cwd
        self._pxx = pxx_bin
        self._native_timeout = native_timeout_s
        self._run_timeout = run_timeout_s

    def run(self, task: Task) -> CoderResult:
        try:
            model = self._policy.model_for(task.lane)
        except ValueError as exc:
            # An unmapped lane is an operator config gap, not a crash. Return a
            # no-change result so the escalation ladder can proceed to REVIEW
            # with an intact evidence bundle, rather than letting the ValueError
            # escape and kill an unattended SoftLoop.run.
            return CoderResult(changed=False, summary=f"no model mapped for lane: {exc}")
        env_overrides = {
            "PXX_PROVIDER": self._policy.provider,
            "PXX_BASE_URL": self._policy.endpoint,
            "PXX_MODEL": model,
            "PXX_TEST_COMMAND": task.gate_command,
            "PXX_NATIVE_TIMEOUT": str(self._native_timeout),
        }
        # --commit: on COMPLETED, pxx commits the session's work (undo still
        # available via the pxx-pre tag). Without it the fix lands uncommitted,
        # so an autonomous run leaves the tree dirty and the coder self-reports
        # no change even when it fixed the code — the live proof caught exactly
        # that. The gate stays authoritative either way; this makes the coder's
        # own evidence (commit sha, changed flag) accurate too.
        cmd = [
            self._pxx,
            "loop",
            "--scope",
            task.scope,
            "--commit",
            "-m",
            task.goal,
        ]
        try:
            proc = self._invoke(cmd, env_overrides)
        except subprocess.TimeoutExpired as exc:
            # A hung coder is a no-change round, not a crash; the ladder then
            # escalates or reviews. Never let an unattended run die here. But a
            # timed-out pxx run may already have created its safety tag + edits,
            # so recover the net_tag from partial output for the rewind path.
            partial = _decode(exc.output) + _decode(exc.stderr)
            net = _last(_NET, partial)
            return CoderResult(
                changed=False,
                summary=f"coder timed out after {self._run_timeout}s",
                net_tag=net.strip() if net else None,
            )
        except OSError as exc:
            return CoderResult(changed=False, summary=f"coder failed to launch: {exc}")
        return self._parse(proc.stdout + proc.stderr)

    # -- seams for tests / alternate transports ---------------------------
    def _invoke(self, cmd: list[str], env_overrides: dict[str, str]):  # pragma: no cover - I/O
        import os

        env = os.environ.copy()
        env.update(env_overrides)
        return subprocess.run(
            cmd,
            cwd=self._cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=self._run_timeout,
            check=False,
        )

    @staticmethod
    def _parse(output: str) -> CoderResult:
        # Anchor to the LAST occurrence of each marker so model prose earlier in
        # the output cannot spoof the coder's self-reported evidence.
        net = _last(_NET, output)
        committed = _last(_COMMITTED, output)
        diff = _last(_DIFF_LINES, output)
        diff_lines = int(diff) if diff else 0
        summary = output.strip().splitlines()[-1] if output.strip() else ""
        return CoderResult(
            changed=diff_lines > 0 or committed is not None,
            summary=summary[:500],
            diff_lines=diff_lines,
            committed=committed,
            net_tag=net.strip() if net else None,
        )


class CommandGate:
    """Run a shell gate command; parse its output into a violation list.

    Default parser lifts pytest ``FAILED ...`` lines (already collect-all
    friendly) plus any ``UI ACCEPTANCE FAIL`` / `` - `` bullet lines from the
    on-screen acceptance script. Non-zero exit with no parsed lines still fails
    closed with the raw tail as a single violation. A custom ``parser`` may be
    supplied for other gates.
    """

    def __init__(self, *, cwd: str, shell: bool = True, parser=None, timeout_s: float = 300.0):
        # ``shell=True`` (default) runs ``task.gate_command`` through a shell, so
        # the gate command must be an operator-configured, trusted string (it is,
        # in the SoftLoop contract — gate commands come from the operator's Task,
        # never from model output). Pass ``shell=False`` for any caller that
        # builds a gate command from non-operator input.
        self._cwd = cwd
        self._shell = shell
        self._parser = parser or _default_violations
        self._timeout = timeout_s

    def check(self, task: Task) -> GateResult:
        try:
            proc = self._invoke(task.gate_command)
        except subprocess.TimeoutExpired as exc:
            # A gate that hangs is a fail-closed verification failure, not a
            # crash — surface it as a violation so the ladder can act.
            tail = _tail(_decode(exc.output) + _decode(exc.stderr))
            return GateResult(
                passed=False,
                violations=(f"gate timed out after {self._timeout}s",),
                raw_tail=tail,
            )
        except OSError as exc:
            return GateResult(passed=False, violations=(f"gate failed to launch: {exc}",))
        output = proc.stdout + proc.stderr
        if proc.returncode == 0:
            return GateResult(passed=True, raw_tail=_tail(output))
        violations = self._parser(output)
        if not violations:
            violations = (f"gate exited {proc.returncode} with no parsed failures",)
        return GateResult(passed=False, violations=violations, raw_tail=_tail(output))

    def _invoke(self, command: str):  # pragma: no cover - I/O
        args = command if self._shell else shlex.split(command)
        return subprocess.run(
            args,
            cwd=self._cwd,
            shell=self._shell,
            capture_output=True,
            text=True,
            timeout=self._timeout,
            check=False,
        )


class PxxReviewer:
    """The local review tier: ``pxx review`` on the uncommitted diff.

    pxx exits 0 for APPROVE and 2 for REVISE (per its docs). This adapter maps
    that to a ReviewResult and lifts finding lines from the output. It runs on
    the same repo the coder just edited, needs no paid service, and is the
    filter that keeps the PR-gate reviewer's quota for changes worth its time.
    A launch/timeout failure abstains (fail-open) — the advisory tier must not
    block a gate-verified change if the local reviewer itself is broken.
    """

    def __init__(
        self,
        policy: "LanePolicy",
        *,
        cwd: str,
        pxx_bin: str = "pxx",
        lane: Lane = Lane.STANDARD,
        timeout_s: float = 600.0,
        parser=None,
    ) -> None:
        self._policy = policy
        self._cwd = cwd
        self._pxx = pxx_bin
        self._lane = lane
        self._timeout = timeout_s
        self._parser = parser or _default_review_findings

    def review(self, task: Task) -> ReviewResult:
        try:
            proc = self._invoke()
        except (subprocess.TimeoutExpired, OSError, ValueError):
            # Abstain, never abort: TimeoutExpired/OSError = a broken reviewer;
            # ValueError = an unmapped reviewer lane in a partial LanePolicy. The
            # local reviewer is a fail-open advisory seam, so a config gap here
            # must not abort a gate-passing unattended run (Greptile P1).
            return ReviewResult(approved=True)
        output = proc.stdout + proc.stderr
        if proc.returncode == 0:
            return ReviewResult(approved=True)
        if proc.returncode != 2:
            # Only exit 2 is pxx's REVISE verdict; any other nonzero is an
            # execution failure (crash, interrupt), not a revision request.
            # Abstain rather than trigger a spurious review-fix loop — this is
            # a fail-open advisory seam.
            return ReviewResult(approved=True)
        return ReviewResult(approved=False, findings=self._parser(output))

    def _invoke(self):  # pragma: no cover - I/O
        import os

        env = os.environ.copy()
        env.update(
            {
                "PXX_PROVIDER": self._policy.provider,
                "PXX_BASE_URL": self._policy.endpoint,
                "PXX_MODEL": self._policy.model_for(self._lane),
            }
        )
        return subprocess.run(
            [self._pxx, "review"],
            cwd=self._cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=self._timeout,
            check=False,
        )


def _default_review_findings(output: str) -> tuple[str, ...]:
    """Lift findings from a pxx review, format-agnostically.

    pxx review emits a terse ``verdict: APPROVE|REVISE`` and, on REVISE, its
    reasoning as prose (not always bulleted). So: prefer structured bullet /
    ``finding:`` lines when present; otherwise fall back to the actual review
    text (every non-empty line that isn't the verdict), so the evidence carries
    the real reason rather than a generic placeholder. Empty output -> a single
    honest 'REVISE (no detail)' marker.
    """
    structured: list[str] = []
    prose: list[str] = []
    for line in output.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith(("- ", "* ")):
            structured.append(s[2:].strip())
        elif s.lower().startswith("finding:"):
            structured.append(s.split(":", 1)[1].strip())
        elif not s.lower().startswith("verdict:"):
            prose.append(s)
    found = structured or prose or ["REVISE (no detail)"]
    seen: dict[str, None] = {}
    for item in found:
        seen.setdefault(item, None)
    return tuple(seen)


def _default_violations(output: str) -> tuple[str, ...]:
    found: list[str] = []
    for line in output.splitlines():
        s = line.strip()
        if s.startswith("FAILED "):
            found.append(s[len("FAILED ") :].split(" - ")[0].strip())
        elif s.startswith("- "):  # ui_acceptance.py bullet
            found.append(s[2:].strip())
    # de-dupe, preserve order
    seen: dict[str, None] = {}
    for item in found:
        seen.setdefault(item, None)
    return tuple(seen)


def _tail(output: str, lines: int = 8) -> str:
    return "\n".join(output.strip().splitlines()[-lines:])


def _decode(chunk) -> str:
    """TimeoutExpired.output/stderr may be bytes, str, or None."""
    if chunk is None:
        return ""
    return chunk.decode(errors="replace") if isinstance(chunk, bytes) else str(chunk)
