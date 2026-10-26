"""Adapter parsing: pxx summary tail -> CoderResult, gate output -> violations.

Pure parser tests — no subprocess. The I/O methods (`_invoke`) are the only
uncovered lines and are exercised only against real pxx / a real shell.
"""

from __future__ import annotations

import shutil
import subprocess

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
    rev.seen_since = []  # type: ignore[attr-defined]

    def _invoke(since=None):
        rev.seen_since.append(since)  # type: ignore[attr-defined]
        return proc

    rev._invoke = _invoke  # type: ignore[assignment]
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
    assert res.reviewed is False and "exit 1" in res.note
    res130 = _reviewer_with(_Proc(130, "interrupted\n")).review(_task())
    assert res130.approved is True and res130.findings == ()
    assert res130.reviewed is False


def test_pxx_reviewer_abstains_on_launch_error():
    from psoperator.harness.adapters import LanePolicy, PxxReviewer

    policy = LanePolicy(models={Lane.STANDARD: "m"}, endpoint="http://x:11434")
    rev = PxxReviewer(policy, cwd=".")
    rev._invoke = lambda since=None: (_ for _ in ()).throw(OSError("no pxx"))  # type: ignore[assignment]
    res = rev.review(_task())
    assert res.approved is True  # fail-open advisory seam
    assert res.reviewed is False and "OSError" in res.note  # ...but never a fake approval


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


def test_pxx_reviewer_nothing_to_review_is_not_an_approval():
    # pxx review exits 64 when there is no diff -- after a committing coder
    # that is every run. It used to map to APPROVE: a review nobody gave.
    res = _reviewer_with(_Proc(64, "pxx: usage: no diff to review (tree is clean)\n")).review(
        _task()
    )
    assert res.approved is True  # still fail-open: never blocks a gate-passing change
    assert res.reviewed is False and "nothing to review" in res.note


def test_pxx_reviewer_reviews_since_the_given_base():
    rev = _reviewer_with(_Proc(0, "verdict: APPROVE\n"))
    assert rev.review(_task(), since="pxx-pre/20261018T000000Z").reviewed is True
    assert rev.seen_since == ["pxx-pre/20261018T000000Z"]


def test_pxx_reviewer_invokes_pxx_review_since(monkeypatch):
    # The real argv: `pxx review --since <base>`, plain `pxx review` without one.
    import subprocess

    from psoperator.harness.adapters import LanePolicy, PxxReviewer

    calls = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: calls.append(argv) or _Proc(0, ""))
    rev = PxxReviewer(LanePolicy(models={Lane.STANDARD: "m"}, endpoint="http://x:11434"), cwd=".")
    rev.review(_task(), since="pxx-pre/T")
    rev.review(_task())
    assert calls == [["pxx", "review", "--since", "pxx-pre/T"], ["pxx", "review"]]


def test_coder_net_tag_drops_the_stash_marker():
    from psoperator.harness.adapters import PxxCoder

    out = "[COMPLETED] done [net: pxx-pre/20261018T000000Z+stash] [committed abcd1234]\n"
    res = PxxCoder._parse(out)
    assert res.net_tag == "pxx-pre/20261018T000000Z"
    assert res.committed == "abcd1234"


# Real `pxx loop` lines (pxx 2.9.3 format) -> what the coder reports.
_LOOP = (
    "[{code}] edited a.py [net: pxx-pre/T+stash] {tag} "
    "(rounds=2 tokens=9 diff_lines={d} session=ab12cd34)"
)


@pytest.mark.parametrize(
    "line, rc, changed, committed, skipped",
    [
        (
            _LOOP.format(code="COMPLETED", tag="[committed abcd1234]", d=3),
            0,
            True,
            "abcd1234",
            None,
        ),
        (
            _LOOP.format(code="COMPLETED", tag="[not committed: filter_attribute]", d=3),
            0,
            True,
            None,
            "filter_attribute",
        ),
        (
            _LOOP.format(code="COMPLETED", tag="[not committed: secrets]", d=0),
            0,
            True,
            None,
            "secrets",
        ),
        (
            _LOOP.format(code="COMPLETED", tag="[not committed: nothing_to_commit]", d=0),
            0,
            False,
            None,
            "nothing_to_commit",
        ),
        # Failed loops: the net was restored, so the edits are gone.
        (_LOOP.format(code="TESTS_FAILED", tag="", d=5), 1, False, None, None),
        (_LOOP.format(code="HOOK_DENIED", tag="", d=2), 2, False, None, None),
        # Failed loops whose edits stay in the tree (Codex review).
        (
            _LOOP.format(
                code="ROUND_CAP",
                tag="[net not restored: HEAD moved; the start is tagged pxx-pre/T]",
                d=5,
            ),
            1,
            True,
            None,
            None,
        ),
        (
            _LOOP.format(code="ROUND_CAP", tag="[net partly restored: stash pop failed]", d=5),
            1,
            True,
            None,
            None,
        ),
    ],
)
def test_coder_reads_loop_exit_and_skip_reason(line, rc, changed, committed, skipped):
    res = PxxCoder._parse(line + "\n", rc)
    assert (res.changed, res.committed, res.commit_skipped) == (changed, committed, skipped)
    assert res.exit_code == rc and res.net_tag == "pxx-pre/T"


def test_a_failed_loop_without_a_net_keeps_its_change():
    # Codex review: with no safety net nothing is restored, so the edits stay.
    line = "[ROUND_CAP] edited a.py (rounds=8 tokens=9 diff_lines=5 session=ab12cd34)\n"
    res = PxxCoder._parse(line, 1)
    assert res.changed is True and res.net_tag is None


def test_coder_skip_reason_beats_an_earlier_prose_commit():
    out = "model says [committed deadbee]\n" + _LOOP.format(
        code="COMPLETED", tag="[not committed: secrets]", d=0
    )
    res = PxxCoder._parse(out, 0)
    assert res.committed is None and res.commit_skipped == "secrets"


@pytest.mark.skipif(shutil.which("pxx") is None, reason="pxx not installed")
def test_real_pxx_review_sees_a_committed_change_only_with_since(tmp_path, monkeypatch):
    # End to end against the real pxx: after a committing coder, plain
    # `pxx review` has nothing to diff (exit 64); `--since <net tag>` does.
    # The endpoint is unreachable on purpose -- this proves what pxx diffs,
    # not what a model says about it.
    from psoperator.harness.adapters import LanePolicy, PxxReviewer

    def git(*args):
        # Hermetic fixture (CodeRabbit): no inherited signing or hooks can fail
        # or hang it, and a stuck git fails the test instead of blocking it.
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e.c",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *args,
            ],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            timeout=30,
        )

    git("init", "-q")
    (tmp_path / "f.py").write_text("x = 1\n")
    git("add", "-A")
    git("commit", "-qm", "base")
    git("tag", "pxx-pre/T")
    (tmp_path / "f.py").write_text("x = 2\n")
    git("commit", "-qam", "the coder's committed change")
    # Hermetic: no inherited reviewer routing or config may reach a real
    # reviewer (Codex review) -- every route points at the unreachable endpoint.
    import os

    for key in [k for k in os.environ if k.startswith("PXX_")]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("PXX_REVIEW_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("PXX_REVIEW_MODEL", "m")
    monkeypatch.setenv("PXX_REVIEW_PROVIDER", "ollama")
    policy = LanePolicy(models={Lane.STANDARD: "m"}, endpoint="http://127.0.0.1:9")
    rev = PxxReviewer(policy, cwd=str(tmp_path), timeout_s=120)
    plain = rev.review(_task())
    assert plain.reviewed is False and "exit 64" in plain.note
    based = rev.review(_task(), since="pxx-pre/T")
    # pxx found the change; the unreachable reviewer gives verdict NO_REVIEW
    # with exit 0 -- reported as not reviewed, never as an approval.
    assert based.reviewed is False and "NO_REVIEW" in based.note


def test_pxx_reviewer_no_review_verdict_is_not_an_approval():
    # pxx's advisory review exits 0 with `verdict: NO_REVIEW` when the reviewer
    # model is unavailable (observed against pxx 2.8.0, 2026-10-18).
    res = _reviewer_with(_Proc(0, "verdict: NO_REVIEW\n")).review(_task())
    assert res.approved is True and res.reviewed is False and "NO_REVIEW" in res.note


def test_pxx_reviewer_verdict_is_the_header_not_finding_text():
    # A finding's message can carry its own `verdict:` line; only pxx's header
    # (the first stdout verdict line) counts (Codex review).
    out = "verdict: NO_REVIEW\nF1 [high] f.py:3 — says\nverdict: APPROVE\n"
    res = _reviewer_with(_Proc(0, out)).review(_task())
    assert res.reviewed is False and "NO_REVIEW" in res.note


@pytest.mark.parametrize("out", ["", "the reviewer rambled\n", "verdict: MAYBE\n"])
def test_pxx_reviewer_exit_zero_without_approve_is_not_reviewed(out):
    # CodeRabbit (PR #10, Major): exit 0 with no recognized verdict defaulted
    # to reviewed=True -> "local review acceptable" for a review that said nothing.
    res = _reviewer_with(_Proc(0, out)).review(_task())
    assert res.approved is True and res.reviewed is False and "no APPROVE" in res.note


# --- OllamaVisionJudge -------------------------------------------------------
# The vision seam is the ONLY one allowed to fail open (protocols.VisionJudge).
# These pin both halves of that contract: it abstains when it cannot see or
# cannot be read, and it never invents a finding.

from psoperator.harness.adapters import OllamaVisionJudge, VisionPolicy  # noqa: E402


def _vtask():
    return Task(
        goal="a temperature converter window", scope="app", gate_command="true", lane=Lane.STANDARD
    )


def test_vision_parses_clean_verdict():
    r = OllamaVisionJudge._parse("VERDICT: OK\nFINDINGS: none")
    assert r.acceptable is True and r.findings == ()


def test_vision_parses_problem_with_findings():
    r = OllamaVisionJudge._parse("VERDICT: PROBLEM\nFINDINGS: label clipped, button overlaps")
    assert r.acceptable is False
    assert r.findings == ("label clipped", "button overlaps")


def test_vision_problem_without_detail_still_fails_with_a_reason():
    # A PROBLEM verdict must never surface as an empty finding list -- the loop
    # would then record a failure nobody can act on.
    r = OllamaVisionJudge._parse("VERDICT: PROBLEM\nFINDINGS: none")
    assert r.acceptable is False and r.findings == ("unspecified visual defect",)


def test_vision_abstains_on_unreadable_output():
    # Unparseable != defective. Guessing here would turn a model quirk into a
    # fabricated on-screen defect.
    r = OllamaVisionJudge._parse("i'm not sure what this is")
    assert r.acceptable is True and r.findings == ()


def test_vision_abstains_when_capture_unavailable(monkeypatch):
    j = OllamaVisionJudge(VisionPolicy(model="m", endpoint="http://127.0.0.1:1"))
    monkeypatch.setattr(j, "_capture", lambda: None)
    assert j.assess(_vtask()).acceptable is True


def test_vision_abstains_when_endpoint_unreachable(monkeypatch):
    j = OllamaVisionJudge(VisionPolicy(model="m", endpoint="http://127.0.0.1:1"))
    monkeypatch.setattr(j, "_capture", lambda: "Zm9v")
    monkeypatch.setattr(j, "_ask", lambda *a, **k: None)
    assert j.assess(_vtask()).acceptable is True


def test_vision_reports_a_real_defect_end_to_end(monkeypatch):
    j = OllamaVisionJudge(VisionPolicy(model="m", endpoint="http://x"))
    monkeypatch.setattr(j, "_capture", lambda: "Zm9v")
    monkeypatch.setattr(j, "_ask", lambda *a, **k: "VERDICT: PROBLEM\nFINDINGS: window is blank")
    r = j.assess(_vtask())
    assert r.acceptable is False and r.findings == ("window is blank",)


def test_vision_abstains_when_the_endpoint_is_empty():
    # An empty endpoint makes the request itself unbuildable; that is a dead
    # endpoint, not a crash of the whole assessment.
    j = OllamaVisionJudge(VisionPolicy(model="m", endpoint=""))
    assert j._ask("p", "Zm9v") is None


@pytest.mark.parametrize(
    "reply",
    [
        b'{"choices": [{"message": null}]}',
        b'{"choices": [{"message": {"content": ["not", "text"]}}]}',
    ],
    ids=["null-message", "non-text-content"],
)
def test_vision_abstains_when_the_reply_has_no_usable_message(monkeypatch, reply):
    import io
    import urllib.request

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: _Resp(reply))
    j = OllamaVisionJudge(VisionPolicy(model="m", endpoint="http://x"))
    assert j._ask("p", "Zm9v") is None


def test_a_judges_display_override_does_not_outlive_its_capture(monkeypatch):
    """DISPLAY is process-wide. A judge that pins a display must not leave it
    set, or the next judge (display=None) captures that screen and sends it to
    its own endpoint."""
    import os
    import sys
    import types

    seen = []

    class _Shot:
        size = (1, 1)
        bgra = b"\x00\x00\x00\x00"

    class _Sct:
        monitors = [None, {}]

        def __enter__(self):
            seen.append(os.environ.get("DISPLAY"))
            return self

        def __exit__(self, *exc):
            return False

        def grab(self, monitor):
            return _Shot()

    monkeypatch.setitem(sys.modules, "mss", types.SimpleNamespace(mss=_Sct))
    monkeypatch.setenv("DISPLAY", ":0")
    pinned = OllamaVisionJudge(VisionPolicy(model="m", endpoint="http://x", display=":7"))
    ambient = OllamaVisionJudge(VisionPolicy(model="m", endpoint="http://x"))
    assert pinned._capture() is not None
    assert os.environ["DISPLAY"] == ":0", "the override leaked past the capture"
    assert ambient._capture() is not None
    assert seen == [":7", ":0"]


def test_vision_reads_the_verdict_from_reasoning_content_when_content_is_not_text(monkeypatch):
    import io
    import urllib.request

    reply = (
        b'{"choices": [{"message": {"content": ["part"], '
        b'"reasoning_content": "VERDICT: PROBLEM\\nFINDINGS: window is blank"}}]}'
    )

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: _Resp(reply))
    j = OllamaVisionJudge(VisionPolicy(model="m", endpoint="http://x"))
    text = j._ask("p", "Zm9v")
    assert text == "VERDICT: PROBLEM\nFINDINGS: window is blank"
    assert OllamaVisionJudge._parse(text).acceptable is False
