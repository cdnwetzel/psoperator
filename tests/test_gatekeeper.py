"""Gatekeeper: risk tiering, hash-chain integrity, fail-closed freshness."""

from __future__ import annotations

import json

import pytest
from PIL import Image

from psoperator.config import load_config
from psoperator.gatekeeper.approval import ApprovalRequest, AutoApprove
from psoperator.gatekeeper.audit import AuditLog, verify
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.gatekeeper.risk import ActionContext, RiskTier, classify
from psoperator.perception.capture import Frame
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker


def frame(fid: int = 1) -> Frame:
    return Frame.from_image(fid, Image.new("RGB", (64, 64), (10, 20, 30)))


class DenyAll:
    name = "deny"

    def request(self, req: ApprovalRequest, timeout_s: float = 120.0) -> bool:
        return False


# ------------------------------------------------------------------ risk
class TestRiskTiering:
    def test_t0_observe_only(self):
        for a in (
            Action(ActionKind.WAIT, 1, seconds=1.0),
            Action(ActionKind.SCROLL, 1, amount=-3),
            Action(ActionKind.DONE, 1),
            Action(ActionKind.FAIL, 1, reason="x"),
        ):
            assert classify(a).tier is RiskTier.T0_READ_ONLY

    def test_t1_reversible_defaults(self):
        assert classify(Action(ActionKind.CLICK, 1, x=1, y=2)).tier is RiskTier.T1_REVERSIBLE
        assert classify(Action(ActionKind.TYPE, 1, text="hello")).tier is RiskTier.T1_REVERSIBLE
        assert (
            classify(Action(ActionKind.KEY, 1, keys=("ctrl", "s"))).tier is RiskTier.T1_REVERSIBLE
        )

    def test_t2_sensitive_keywords_in_context(self):
        ctx = ActionContext(target_text="Send message")
        assert classify(Action(ActionKind.CLICK, 1, x=1, y=2), ctx).tier is RiskTier.T2_SENSITIVE
        ctx = ActionContext(window_title="Checkout — Acme Store")
        assert classify(Action(ActionKind.CLICK, 1, x=1, y=2), ctx).tier is RiskTier.T2_SENSITIVE

    def test_t2_sensitive_typed_text(self):
        a = Action(ActionKind.TYPE, 1, text="please publish this post")
        assert classify(a).tier is RiskTier.T2_SENSITIVE

    def test_t3_destructive_keywords(self):
        ctx = ActionContext(target_text="Delete permanently")
        assert classify(Action(ActionKind.CLICK, 1, x=1, y=2), ctx).tier is RiskTier.T3_DESTRUCTIVE

    def test_t3_destructive_chord(self):
        a = Action(ActionKind.KEY, 1, keys=("shift", "delete"))
        assert classify(a).tier is RiskTier.T3_DESTRUCTIVE

    def test_t3_credential_field(self):
        ctx = ActionContext(target_text="Enter your password")
        a = Action(ActionKind.TYPE, 1, text="hunter2")
        assert classify(a, ctx).tier is RiskTier.T3_DESTRUCTIVE

    def test_policy_file_only_escalates(self, tmp_path):
        p = tmp_path / "policy.json"
        p.write_text(json.dumps({"t3": ["launch nuke"], "t2": ["order pizza"]}))
        policy = {"t2": ["order pizza"], "t3": ["launch nuke"]}
        ctx = ActionContext(target_text="launch nuke")
        assert (
            classify(Action(ActionKind.CLICK, 1, x=1, y=1), ctx, policy).tier
            is RiskTier.T3_DESTRUCTIVE
        )
        # policy cannot DE-escalate: built-in T3 stays T3 even with empty policy
        ctx = ActionContext(target_text="Delete permanently")
        assert (
            classify(Action(ActionKind.CLICK, 1, x=1, y=1), ctx, {"t2": [], "t3": []}).tier
            is RiskTier.T3_DESTRUCTIVE
        )


# -------------------------------------------------------------- gatekeeper
@pytest.fixture
def env(tmp_path):
    cfg = load_config(
        audit_log_path=tmp_path / "audit.jsonl", risk_policy_path=tmp_path / "policy.json"
    )
    fresh = FreshnessTracker()
    gate = Gatekeeper(cfg, fresh, approval_backend=AutoApprove())
    return cfg, fresh, gate


class TestGatekeeperDecisions:
    def test_t1_auto_approves_and_dry_runs(self, env):
        cfg, fresh, gate = env
        f = frame(1)
        fresh.observe(1)
        d = gate.request_action(Action(ActionKind.CLICK, 1, x=5, y=5), f)
        assert d.kind is DecisionKind.DRY_RUN and d.approved
        assert d.risk.tier is RiskTier.T1_REVERSIBLE

    def test_t2_requires_approval_and_denies_closed(self, tmp_path):
        cfg = load_config(audit_log_path=tmp_path / "a.jsonl", risk_policy_path=tmp_path / "p.json")
        fresh = FreshnessTracker()
        gate = Gatekeeper(cfg, fresh, approval_backend=DenyAll())
        f = frame(1)
        fresh.observe(1)
        ctx = ActionContext(target_text="Send message")
        d = gate.request_action(Action(ActionKind.CLICK, 1, x=5, y=5), f, ctx)
        assert d.kind is DecisionKind.DENIED and not d.approved

    def test_t3_is_hard_blocked_even_with_approver(self, env):
        cfg, fresh, gate = env
        f = frame(1)
        fresh.observe(1)
        ctx = ActionContext(target_text="Delete permanently")
        d = gate.request_action(Action(ActionKind.CLICK, 1, x=5, y=5), f, ctx)
        assert d.kind is DecisionKind.DENIED
        assert not d.approved
        assert d.risk.tier is RiskTier.T3_DESTRUCTIVE

    def test_stale_frame_id_rejected_fail_closed(self, env):
        cfg, fresh, gate = env
        fresh.observe(5)  # screen moved on to frame 5
        d = gate.request_action(Action(ActionKind.CLICK, 3, x=5, y=5), frame(3))
        assert d.kind is DecisionKind.REJECTED_STALE and not d.approved

    def test_negative_frame_id_rejected_fail_closed(self, env):
        cfg, fresh, gate = env
        fresh.observe(1)
        d = gate.request_action(Action(ActionKind.CLICK, -1, x=5, y=5), frame(1))
        assert d.kind is DecisionKind.REJECTED_STALE

    def test_no_frames_observed_rejects(self, env):
        cfg, fresh, gate = env
        d = gate.request_action(Action(ActionKind.CLICK, 1, x=5, y=5), frame(1))
        assert d.kind is DecisionKind.REJECTED_STALE

    def test_done_is_terminal_without_execution(self, env):
        cfg, fresh, gate = env
        fresh.observe(2)
        d = gate.request_action(Action(ActionKind.DONE, 2), frame(2))
        assert d.kind is DecisionKind.DONE and d.terminal


# ------------------------------------------------------------------- audit
class TestAuditChain:
    def _write_log(self, tmp_path, n=5) -> AuditLog:
        log = AuditLog(tmp_path / "audit.jsonl")
        f = frame(1)
        for i in range(n):
            log.append(
                frame_id=i + 1,
                frame_hash=f.sha256,
                action={"action": "click", "x": i, "y": i, "frame_id": i + 1},
                tier=1,
                decision="dry-run",
                approver="auto:tier<=T1",
                reason="ok",
            )
        return log

    def test_valid_chain_verifies(self, tmp_path):
        self._write_log(tmp_path)
        r = verify(tmp_path / "audit.jsonl")
        assert r.ok and r.lines_checked == 5

    def test_edited_line_is_detected(self, tmp_path):
        self._write_log(tmp_path)
        p = tmp_path / "audit.jsonl"
        lines = p.read_text().splitlines()
        e = json.loads(lines[2])
        e["action"]["x"] = 9999  # attacker rewrites history
        lines[2] = json.dumps(e, sort_keys=True)
        p.write_text("\n".join(lines) + "\n")
        r = verify(p)
        assert not r.ok and "hash mismatch" in r.error

    def test_deleted_line_is_detected(self, tmp_path):
        self._write_log(tmp_path)
        p = tmp_path / "audit.jsonl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join(lines[:2] + lines[3:]) + "\n")  # drop line 3
        r = verify(p)
        assert not r.ok

    def test_appending_after_restart_continues_chain(self, tmp_path):
        self._write_log(tmp_path, n=2)
        log2 = AuditLog(tmp_path / "audit.jsonl")  # fresh instance, same file
        log2.append(
            frame_id=3,
            frame_hash="abc",
            action={"action": "done", "frame_id": 3},
            tier=0,
            decision="done",
            approver="auto:terminal",
            reason="done",
        )
        r = verify(tmp_path / "audit.jsonl")
        assert r.ok and r.lines_checked == 3

    def test_missing_log_fails_verification(self, tmp_path):
        assert not verify(tmp_path / "nope.jsonl").ok

    def test_gatekeeper_writes_auditable_entries(self, env):
        cfg, fresh, gate = env
        fresh.observe(1)
        f = frame(1)
        gate.request_action(Action(ActionKind.CLICK, 1, x=1, y=1), f)
        gate.request_action(Action(ActionKind.CLICK, 1, x=2, y=2), f)  # fresh: 1 == latest
        r = verify(cfg.audit_log_path)
        assert r.ok and r.lines_checked == 2
