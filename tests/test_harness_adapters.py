"""Adapter parsing: pxx summary tail -> CoderResult, gate output -> violations.

Pure parser tests — no subprocess. The I/O methods (`_invoke`) are the only
uncovered lines and are exercised only against real pxx / a real shell.
"""

from __future__ import annotations

import pytest

from psoperator.harness.adapters import (
    CommandGate,
    LanePolicy,
    PxxCoder,
    _default_violations,
)
from psoperator.harness.model import Lane, Task


def _task(**kw):
    base = dict(goal="g", scope=".", gate_command="pytest -q")
    base.update(kw)
    return Task(**base)


# ------------------------------------------------------------- lane policy
def test_lane_policy_maps_and_rejects_unmapped():
    policy = LanePolicy(models={Lane.SMALL: "qwen2.5:14b"}, endpoint="http://x:11434")
    assert policy.model_for(Lane.SMALL) == "qwen2.5:14b"
    with pytest.raises(ValueError, match="no model mapped"):
        policy.model_for(Lane.DEEP)


# --------------------------------------------------------- pxx summary parse
def test_pxx_parse_committed_run():
    out = (
        "some agent chatter\n"
        "The change was made.\n"
        "[net: pxx-pre/20260823T121231Z] [committed a4564158] "
        "(rounds=4 tokens=8056 diff_lines=2)\n"
    )
    r = PxxCoder._parse(out)
    assert r.changed is True
    assert r.committed == "a4564158"
    assert r.net_tag == "pxx-pre/20260823T121231Z"
    assert r.diff_lines == 2


def test_pxx_parse_no_change_run():
    out = "tool call returned as prose\n[net: pxx-pre/T] (rounds=13 tokens=50980 diff_lines=0)\n"
    r = PxxCoder._parse(out)
    assert r.changed is False
    assert r.diff_lines == 0
    assert r.committed is None
    assert r.net_tag == "pxx-pre/T"


def test_pxx_parse_empty_output():
    r = PxxCoder._parse("")
    assert r.changed is False and r.summary == ""


def test_pxx_parse_ignores_prose_echoed_markers():
    # Model prose earlier in the stream echoes fake markers; the real summary tail
    # at the end must win — otherwise a spoofed [committed …] flips `changed`.
    out = (
        "I'll pretend the tail is [committed deadbee] [net: fake/tag] diff_lines=999\n"
        "...more model chatter...\n"
        "[net: pxx-pre/REAL] [committed a1b2c3d] (rounds=1 tokens=5 diff_lines=2)\n"
    )
    r = PxxCoder._parse(out)
    assert r.committed == "a1b2c3d"
    assert r.net_tag == "pxx-pre/REAL"
    assert r.diff_lines == 2


# ----------------------------------------------------------- gate parsing
def test_default_violations_lifts_pytest_failures():
    output = (
        "collected 13 items\n"
        "FAILED test_gui.py::test_widgets_readable - AssertionError: entry too small\n"
        "FAILED test_gui.py::test_window_sized - AssertionError: too narrow\n"
        "2 failed, 11 passed\n"
    )
    v = _default_violations(output)
    assert v == (
        "test_gui.py::test_widgets_readable",
        "test_gui.py::test_window_sized",
    )


def test_default_violations_lifts_ui_acceptance_bullets():
    output = "UI ACCEPTANCE FAIL:\n - 'F to C' not visible on screen\n - 'Convert' only 8px tall\n"
    v = _default_violations(output)
    assert v == ("'F to C' not visible on screen", "'Convert' only 8px tall")


def test_default_violations_dedupes_preserving_order():
    output = "FAILED a - x\nFAILED a - x\nFAILED b - y\n"
    assert _default_violations(output) == ("a", "b")


# ------------------------------------------------- CommandGate with fake I/O
class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _gate_with(proc):
    gate = CommandGate(cwd=".")
    gate._invoke = lambda command: proc  # type: ignore[assignment]
    return gate


def test_command_gate_pass():
    res = _gate_with(_Proc(0, "13 passed\n")).check(_task())
    assert res.passed is True and res.violations == ()


def test_command_gate_fail_parses_violations():
    proc = _Proc(1, "FAILED t::a - boom\nFAILED t::b - bang\n1 failed\n")
    res = _gate_with(proc).check(_task())
    assert res.passed is False
    assert res.violations == ("t::a", "t::b")


def test_command_gate_nonzero_without_parsed_lines_fails_closed():
    res = _gate_with(_Proc(2, "segfault, no test lines\n")).check(_task())
    assert res.passed is False
    assert len(res.violations) == 1
    assert "exited 2" in res.violations[0]


def test_command_gate_timeout_fails_closed():
    import subprocess

    def boom(command):
        raise subprocess.TimeoutExpired(cmd=command, timeout=1, output=b"partial\noutput")

    gate = CommandGate(cwd=".", timeout_s=1)
    gate._invoke = boom  # type: ignore[assignment]
    res = gate.check(_task())
    assert res.passed is False
    assert "timed out" in res.violations[0]
    assert "partial" in res.raw_tail


def test_command_gate_launch_error_fails_closed():
    gate = CommandGate(cwd=".")
    gate._invoke = lambda command: (_ for _ in ()).throw(OSError("no such file"))  # type: ignore[assignment]
    res = gate.check(_task())
    assert res.passed is False
    assert "failed to launch" in res.violations[0]


def test_pxx_coder_command_commits_and_scopes():
    from psoperator.harness.adapters import LanePolicy, PxxCoder

    policy = LanePolicy(models={Lane.STANDARD: "m"}, endpoint="http://x:11434")
    coder = PxxCoder(policy, cwd=".")
    captured = {}

    def fake_invoke(cmd, env):
        captured["cmd"] = cmd
        captured["env"] = env

        class P:
            stdout = "[committed abc1234] (rounds=1 tokens=1 diff_lines=1)"
            stderr = ""

        return P()

    coder._invoke = fake_invoke  # type: ignore[assignment]
    r = coder.run(_task(scope="pkg", gate_command="pytest -q tests/x.py", lane=Lane.STANDARD))
    assert "--commit" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("--scope") + 1] == "pkg"
    assert captured["env"]["PXX_MODEL"] == "m"
    assert captured["env"]["PXX_TEST_COMMAND"] == "pytest -q tests/x.py"
    assert r.changed is True and r.committed == "abc1234"


def test_pxx_coder_no_change_on_unmapped_lane():
    # The coder mirror of the reviewer fix: an unmapped lane returns a no-change
    # result (ladder proceeds to REVIEW), never a ValueError that aborts the run.
    from psoperator.harness.adapters import LanePolicy, PxxCoder

    policy = LanePolicy(models={Lane.SMALL: "m"}, endpoint="http://x:11434")
    coder = PxxCoder(policy, cwd=".")
    r = coder.run(_task(lane=Lane.DEEP))  # DEEP is unmapped
    assert r.changed is False
    assert "no model mapped" in r.summary


def test_pxx_coder_timeout_is_no_change_round():
    import subprocess

    from psoperator.harness.adapters import LanePolicy, PxxCoder

    policy = LanePolicy(models={Lane.SMALL: "m"}, endpoint="http://x:11434")
    coder = PxxCoder(policy, cwd=".", run_timeout_s=1)
    coder._invoke = lambda cmd, env: (_ for _ in ()).throw(  # type: ignore[assignment]
        subprocess.TimeoutExpired(cmd=cmd, timeout=1)
    )
    r = coder.run(_task(lane=Lane.SMALL))
    assert r.changed is False
    assert "timed out" in r.summary


# ---------------------------------------------------------------- PxxReviewer
def _reviewer_with(proc):
    from psoperator.harness.adapters import LanePolicy, PxxReviewer

    policy = LanePolicy(models={Lane.STANDARD: "m"}, endpoint="http://x:11434")
    rev = PxxReviewer(policy, cwd=".")
    rev._invoke = lambda: proc  # type: ignore[assignment]
    return rev


def test_pxx_reviewer_approve_on_exit_zero():
    res = _reviewer_with(_Proc(0, "verdict: APPROVE\n")).review(_task())
    assert res.approved is True and res.findings == ()


def test_pxx_reviewer_revise_lifts_structured_findings():
    out = "verdict: REVISE\n- extract the magic number\n- add a docstring\n"
    res = _reviewer_with(_Proc(2, out)).review(_task())
    assert res.approved is False
    assert res.findings == ("extract the magic number", "add a docstring")


def test_pxx_reviewer_revise_falls_back_to_prose_not_placeholder():
    # pxx review's REVISE reasoning is often prose, not bullets — the evidence
    # must carry the real text, not a generic 'see output' placeholder.
    out = "verdict: REVISE\nThe fix drops the guard clause for negative input.\n"
    res = _reviewer_with(_Proc(2, out)).review(_task())
    assert res.approved is False
    assert res.findings == ("The fix drops the guard clause for negative input.",)


def test_pxx_reviewer_revise_empty_output_marks_no_detail():
    res = _reviewer_with(_Proc(2, "verdict: REVISE\n")).review(_task())
    assert res.findings == ("REVISE (no detail)",)


def test_pxx_reviewer_abstains_on_non_revise_error_exit():
    # Only exit 2 is pxx's REVISE; exit 1/130 are execution failures, not a
    # revision request — the advisory seam abstains rather than loop.
    res = _reviewer_with(_Proc(1, "traceback: boom\n")).review(_task())
    assert res.approved is True and res.findings == ()
    res130 = _reviewer_with(_Proc(130, "interrupted\n")).review(_task())
    assert res130.approved is True and res130.findings == ()


def test_pxx_reviewer_abstains_on_launch_error():
    from psoperator.harness.adapters import LanePolicy, PxxReviewer

    policy = LanePolicy(models={Lane.STANDARD: "m"}, endpoint="http://x:11434")
    rev = PxxReviewer(policy, cwd=".")
    rev._invoke = lambda: (_ for _ in ()).throw(OSError("no pxx"))  # type: ignore[assignment]
    assert rev.review(_task()).approved is True  # fail-open advisory seam


def test_pxx_reviewer_abstains_on_unmapped_lane():
    # A partial LanePolicy (the reviewer's lane unmapped) must not abort the run:
    # model_for raises ValueError inside _invoke, and the advisory reviewer
    # abstains rather than letting it escape and kill a gate-passing run.
    # Regression for Greptile P1 (the coder fix that CodeRabbit's finding did not
    # generalize to the reviewer). Uses the real _invoke — no subprocess runs
    # because model_for raises before subprocess.run.
    from psoperator.harness.adapters import LanePolicy, PxxReviewer

    policy = LanePolicy(models={Lane.SMALL: "m"}, endpoint="http://x:11434")
    rev = PxxReviewer(policy, cwd=".", lane=Lane.DEEP)  # DEEP is unmapped
    assert rev.review(_task()).approved is True
