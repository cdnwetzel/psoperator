"""R-A4 — kill-switch drills: the operator stop is exercised, not just present.

Each drill engages the stop, submits a canary that would otherwise proceed, and
requires a KILL_SWITCHED decision — proving the stop pre-empts execution, policy,
and freshness — with the decision left as a durable audit receipt. The last test
proves the drill fails loud if the stop ever stopped enforcing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

from psoperator.config import load_config
from psoperator.gatekeeper import killswitch
from psoperator.gatekeeper.drills import DrillFailed, DrillResult, kill_switch_drill
from psoperator.gatekeeper.executor import DryRunExecutor
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.perception.capture import Frame
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker


def _gk(tmp_path):
    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl",
        risk_policy_path=tmp_path / "policy.json",
        kill_switch_path=tmp_path / "STOP",
    )
    freshness = FreshnessTracker()
    freshness.observe(1)
    return config, Gatekeeper(config, freshness, executor=DryRunExecutor())


def _frame():
    return Frame.from_image(1, Image.new("RGB", (40, 30), "white"))


def _audit_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_drill_preempts_a_benign_canary_and_leaves_a_receipt(tmp_path):
    config, gk = _gk(tmp_path)
    result = kill_switch_drill(
        gk,
        config.kill_switch_path,
        action=Action(ActionKind.WAIT, 1, seconds=0.0),
        frame=_frame(),
    )
    assert result == DrillResult(preempted=True, decision_kind="kill-switched")
    # the KILL_SWITCHED decision is the receipt — a durable audit row.
    kills = [r for r in _audit_rows(config.audit_log_path) if r["decision"] == "kill-switched"]
    assert len(kills) == 1


def test_drill_preempts_a_destructive_canary_over_policy(tmp_path):
    # A T3 "delete" action would be hard-blocked by policy; the stop wins first.
    config, gk = _gk(tmp_path)
    result = kill_switch_drill(
        gk,
        config.kill_switch_path,
        action=Action(ActionKind.TYPE, 1, text="delete every record now"),
        frame=_frame(),
    )
    assert result.preempted and result.decision_kind == "kill-switched"


def test_drill_preempts_a_stale_canary_over_freshness(tmp_path):
    # A frame the tracker never saw would be REJECTED_STALE; the stop wins first.
    config, gk = _gk(tmp_path)
    stale_frame = Frame.from_image(999, Image.new("RGB", (40, 30), "black"))
    result = kill_switch_drill(
        gk,
        config.kill_switch_path,
        action=Action(ActionKind.WAIT, 999, seconds=0.0),
        frame=stale_frame,
    )
    assert result.preempted and result.decision_kind == "kill-switched"


def test_drill_restores_a_previously_disengaged_switch(tmp_path):
    config, gk = _gk(tmp_path)
    assert not killswitch.is_engaged(config.kill_switch_path)
    kill_switch_drill(
        gk, config.kill_switch_path, action=Action(ActionKind.WAIT, 1, seconds=0.0), frame=_frame()
    )
    assert not killswitch.is_engaged(config.kill_switch_path)  # drill left it as it found it


def test_drill_leaves_an_already_engaged_switch_engaged(tmp_path):
    config, gk = _gk(tmp_path)
    killswitch.engage(config.kill_switch_path)
    kill_switch_drill(
        gk, config.kill_switch_path, action=Action(ActionKind.WAIT, 1, seconds=0.0), frame=_frame()
    )
    assert killswitch.is_engaged(config.kill_switch_path)  # a real stop is not lifted by a drill


def test_drill_fails_loud_if_the_stop_does_not_preempt(tmp_path):
    # A gatekeeper that ignores the kill switch must make the drill raise, not pass.
    config, _ = _gk(tmp_path)

    class _DeafGatekeeper:
        def request_action(self, action, frame, context=None, snapshot=None):
            return SimpleNamespace(kind=DecisionKind.EXECUTED)

    try:
        kill_switch_drill(
            _DeafGatekeeper(),
            config.kill_switch_path,
            action=Action(ActionKind.WAIT, 1, seconds=0.0),
            frame=_frame(),
        )
        raised = False
    except DrillFailed:
        raised = True
    assert raised, "a stop that failed to pre-empt must fail the drill, loud"
    # and the drill still restored the switch it engaged
    assert not killswitch.is_engaged(config.kill_switch_path)


def test_drill_keeps_a_stop_an_operator_engages_while_the_canary_runs(tmp_path):
    # The switch was off when the drill began, so a drill that only remembered
    # "was it engaged?" would lift the operator's stop along with its own.
    config, gk = _gk(tmp_path)

    class _OperatorStopsMidDrill:
        def request_action(self, action, frame, context=None, snapshot=None):
            killswitch.engage(config.kill_switch_path)  # the operator's real stop
            return gk.request_action(action, frame, snapshot=snapshot)

    kill_switch_drill(
        _OperatorStopsMidDrill(),
        config.kill_switch_path,
        action=Action(ActionKind.WAIT, 1, seconds=0.0),
        frame=_frame(),
    )
    assert killswitch.is_engaged(config.kill_switch_path), "the drill lifted an operator's stop"


def test_an_unowned_stop_is_never_lifted_even_briefly(tmp_path, monkeypatch):
    # The gatekeeper checks the switch on every request, so a stop that is
    # moved aside while its owner is checked is a stop that is off for a moment.
    stop = tmp_path / "STOP"
    killswitch.engage(stop)
    engaged_at_reads = []
    real_read = Path.read_text

    def _recording_read(self, *a, **k):
        # The file itself, not is_engaged: a claim also reads as engaged, so a
        # rename-first regression would pass a logical check.
        engaged_at_reads.append(stop.is_file())
        return real_read(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", _recording_read)
    killswitch.disengage_if_owned(stop, "PSOperator kill-switch drill someone-else.\n")
    assert engaged_at_reads and all(engaged_at_reads), "the sentinel left its path"
    assert killswitch.is_engaged(stop)
    assert not list(tmp_path.glob("*.claim")), "the claimed sentinel leaked"


def test_a_stop_rewritten_mid_claim_stays_engaged_even_if_restoring_fails(tmp_path, monkeypatch):
    # The operator rewrites the drill's stop between the ownership read and the
    # claim. The claim then holds the operator's stop; if putting it back fails,
    # the switch must still end up engaged and the error must surface.
    stop = tmp_path / "STOP"
    marker = "PSOperator kill-switch drill mine.\n"
    assert killswitch.engage_exclusive(stop, marker)
    real_rename = os.rename

    def _operator_rewrites_first(src, dst):
        killswitch.engage(stop)
        real_rename(src, dst)

    def _restore_fails(src, dst):
        raise OSError("restore failed")

    monkeypatch.setattr(os, "rename", _operator_rewrites_first)
    monkeypatch.setattr(os, "replace", _restore_fails)
    with pytest.raises(OSError, match="restore failed"):
        killswitch.disengage_if_owned(stop, marker)
    assert killswitch.is_engaged(stop)


def test_a_stop_rewritten_mid_claim_is_restored_intact(tmp_path, monkeypatch):
    stop = tmp_path / "STOP"
    marker = "PSOperator kill-switch drill mine.\n"
    assert killswitch.engage_exclusive(stop, marker)
    real_rename = os.rename

    def _operator_rewrites_first(src, dst):
        killswitch.engage(stop)
        real_rename(src, dst)

    monkeypatch.setattr(os, "rename", _operator_rewrites_first)
    killswitch.disengage_if_owned(stop, marker)
    assert stop.read_text(encoding="utf-8") == "PSOperator stopped by operator.\n"
    assert not list(tmp_path.glob("*.claim")), "the claimed sentinel leaked"


def test_the_switch_stays_engaged_while_a_stop_is_claimed(tmp_path, monkeypatch):
    # An operator rewrite landing between the ownership read and the claim means
    # the claimed file is the operator's stop. Until it is put back the switch
    # must still read as engaged, or a request in that interval passes.
    stop = tmp_path / "STOP"
    marker = "PSOperator kill-switch drill mine.\n"
    assert killswitch.engage_exclusive(stop, marker)
    real_rename = os.rename
    engaged_after_claim = []

    def _operator_rewrites_first(src, dst):
        killswitch.engage(stop)
        real_rename(src, dst)
        engaged_after_claim.append(killswitch.is_engaged(stop))

    monkeypatch.setattr(os, "rename", _operator_rewrites_first)
    killswitch.disengage_if_owned(stop, marker)
    assert engaged_after_claim == [True]
    assert killswitch.is_engaged(stop)


def test_an_undecodable_stop_rewritten_mid_claim_is_put_back(tmp_path, monkeypatch):
    # An operator may write anything; bytes that are not UTF-8 are not provably
    # the drill's, so the stop goes back rather than the decode error escaping.
    stop = tmp_path / "STOP"
    marker = "PSOperator kill-switch drill mine.\n"
    assert killswitch.engage_exclusive(stop, marker)
    real_rename = os.rename

    def _operator_writes_bytes_first(src, dst):
        stop.write_bytes(b"\xff\xfe")
        real_rename(src, dst)

    monkeypatch.setattr(os, "rename", _operator_writes_bytes_first)
    killswitch.disengage_if_owned(stop, marker)
    assert killswitch.is_engaged(stop)
    assert stop.read_bytes() == b"\xff\xfe"
    assert not list(tmp_path.glob("*.claim")), "the claimed sentinel leaked"


def test_an_undecodable_stop_is_not_ours_to_lift(tmp_path):
    stop = tmp_path / "STOP"
    stop.write_bytes(b"\xff\xfe")
    killswitch.disengage_if_owned(stop, "marker\n")
    assert killswitch.is_engaged(stop)


def test_an_interrupted_claim_keeps_the_switch_engaged_until_the_operator_clears_it(tmp_path):
    # A process that dies mid-claim leaves only the claim file: still a stop.
    stop = tmp_path / "STOP"
    (tmp_path / "STOP.0123456789abcdef.claim").write_text("anything\n", encoding="utf-8")
    assert killswitch.is_engaged(stop)
    killswitch.disengage(stop)
    assert not killswitch.is_engaged(stop)


def test_an_operator_stop_landing_right_after_the_drills_create_is_not_taken_over(
    tmp_path, monkeypatch
):
    # The operator engages in the instant after the drill's file appears. The
    # drill must not end up "owning" that stop, or its cleanup would lift it.
    stop = tmp_path / "STOP"
    marker = "PSOperator kill-switch drill mine.\n"
    real_open = os.open
    fired = []

    def _operator_engages_after_create(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if not fired and flags & os.O_CREAT:
            fired.append(path)
            killswitch.engage(stop)
        return fd

    monkeypatch.setattr(os, "open", _operator_engages_after_create)
    owned = killswitch.engage_exclusive(stop, marker)
    monkeypatch.setattr(os, "open", real_open)
    if owned:
        killswitch.disengage_if_owned(stop, marker)
    assert fired, "the injected operator engagement never ran"
    assert killswitch.is_engaged(stop), "the drill lifted a stop the operator engaged"
    assert stop.read_text(encoding="utf-8") == "PSOperator stopped by operator.\n"


def test_a_failed_exclusive_engage_never_removes_an_operator_stop(tmp_path, monkeypatch):
    # The operator engages right after the drill's create, then the drill's own
    # write fails. Its cleanup may remove only what it created, never the stop.
    stop = tmp_path / "STOP"
    real_open = os.open
    fired = []

    def _operator_engages_after_create(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if not fired and flags & os.O_CREAT:
            fired.append(path)
            killswitch.engage(stop)
        return fd

    def _write_fails(*args, **kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(os, "open", _operator_engages_after_create)
    monkeypatch.setattr(os, "fdopen", _write_fails)
    monkeypatch.setattr(os, "write", _write_fails)
    with pytest.raises(OSError):
        killswitch.engage_exclusive(stop, "marker\n")
    monkeypatch.undo()
    assert fired, "the injected operator engagement never ran"
    assert stop.read_text(encoding="utf-8") == "PSOperator stopped by operator.\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["STOP"], "a temp file leaked"


@pytest.mark.parametrize("direction", ["claim-to-stop", "stop-to-claim"])
def test_one_rename_anywhere_inside_is_engaged_never_reads_as_disengaged(
    tmp_path, monkeypatch, direction
):
    """is_engaged reads the filesystem in several steps. A drill moves the stop
    between its path and a claim by one atomic rename; whichever step that rename
    lands before, the switch must still read as engaged."""
    import glob

    stop = tmp_path / "STOP"
    claim = tmp_path / "STOP.0123456789abcdef.claim"
    real_is_file = Path.is_file
    real_glob = glob.glob

    def run_with_rename_before_step(step: int) -> tuple[bool, int]:
        for leftover in (stop, claim):
            leftover.unlink(missing_ok=True)
        src, dst = (claim, stop) if direction == "claim-to-stop" else (stop, claim)
        src.write_text("PSOperator stopped by operator.\n", encoding="utf-8")
        calls = [0]

        def _maybe_rename():
            if calls[0] == step:
                os.rename(src, dst)
            calls[0] += 1

        def _is_file(self):
            _maybe_rename()
            return real_is_file(self)

        def _glob(pattern, *a, **k):
            _maybe_rename()
            return real_glob(pattern, *a, **k)

        monkeypatch.setattr(Path, "is_file", _is_file)
        monkeypatch.setattr(glob, "glob", _glob)
        try:
            engaged = killswitch.is_engaged(stop)
        finally:
            monkeypatch.setattr(Path, "is_file", real_is_file)
            monkeypatch.setattr(glob, "glob", real_glob)
        return engaged, calls[0]

    step = 0
    while True:
        engaged, steps_taken = run_with_rename_before_step(step)
        assert engaged, f"read as disengaged with the rename before step {step}"
        if step >= steps_taken:
            break  # the rename landed after the last step: every position covered
        step += 1


def test_a_failed_marker_write_leaves_no_orphan_stop(tmp_path, monkeypatch):
    stop = tmp_path / "STOP"

    def _disk_full(*a, **k):
        raise OSError("no space left on device")

    monkeypatch.setattr(os, "write", _disk_full)
    with pytest.raises(OSError):
        killswitch.engage_exclusive(stop, "marker\n")
    assert not killswitch.is_engaged(stop), "an empty stop nobody owns was left behind"
    assert not list(tmp_path.iterdir()), "the temp file leaked"


def test_engage_exclusive_does_not_take_over_an_existing_stop(tmp_path):
    stop = tmp_path / "STOP"
    killswitch.engage(stop)
    assert killswitch.engage_exclusive(stop, "marker\n") is False
    killswitch.disengage_if_owned(stop, "marker\n")
    assert killswitch.is_engaged(stop)
