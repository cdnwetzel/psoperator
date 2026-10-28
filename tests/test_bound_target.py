"""The bound-target gate (pilot charter, "Consequences of the probe verdict").

Before a key reaches the application, all of these must hold, or the key is
refused and the refusal audited:

1. the menu path is on the allow-list, the key is the one allowed at this
   step, and the screen's window-tree signature matches the step's expected
   signature (one wrong digit in a path is a different screen, and the
   signature is what tells them apart);
2. the application is the foreground window and owns the topmost window at
   the target point, else the refusal names the blocking process;
3. the target field lies inside the visible client area of every ancestor
   (a scrolled-out Edit still reports itself visible);
4. the process instance (pid and start time) is the one bound;
5. the audit records identity, the frame hash and rectangles, never text.

Every path, hash and rectangle here is made up. The real allow-list is
private configuration and never enters the repository.
"""

from __future__ import annotations

import json
import os

import pytest
from PIL import Image

from psoperator.config import load_config
from psoperator.gatekeeper.audit import verify
from psoperator.gatekeeper.bound_target import (
    AllowedPath,
    AllowedStep,
    AllowList,
    AllowListError,
    BoundKeyRequest,
    ForegroundObservation,
    OcrBox,
    ScreenSignature,
    audit_record,
    clipping_problem,
    foreground_problem,
    signature_problem,
)
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.perception.capture import Frame
from psoperator.perception.win32_fields import Win32Field, WindowNode
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker

APP = (4242, 7)  # (pid, process start time)


def _sig(edits=5, owned=0, focus=("Edit", (40, 30, 200, 24)), paired=None, hashes=None):
    return ScreenSignature(
        visible_edits=edits,
        owned_windows=owned,
        focus_class=focus[0] if focus else None,
        focus_rect=focus[1] if focus else None,
        paired=paired,
        label_hashes=frozenset(hashes) if hashes is not None else None,
    )


HOME = _sig(edits=3, focus=("Edit", (10, 10, 24, 28)))
SEARCH = _sig(edits=4, focus=("Edit", (60, 40, 600, 28)))
REPORT = _sig(edits=5, paired=5, hashes=["aaaa", "bbbb", "cccc", "dddd", "eeee"])
# The neighbouring path's screen: same counts and focus, different labels.
NEIGHBOUR = _sig(edits=5, paired=5, hashes=["aaaa", "bbbb", "cccc", "dddd", "ffff"])

ALLOW = AllowList(
    [
        AllowedPath(
            "9-9",
            (
                AllowedStep(HOME, "9"),
                AllowedStep(SEARCH, "9"),
                AllowedStep(REPORT, "ENTER"),
            ),
        )
    ]
)


# --- signatures ---------------------------------------------------------------


def test_an_identical_signature_matches():
    assert signature_problem(REPORT, REPORT) is None


@pytest.mark.parametrize(
    "observed, expected_word",
    [
        (_sig(edits=6, paired=5, hashes=["aaaa", "bbbb", "cccc", "dddd", "eeee"]), "Edits"),
        (_sig(owned=1, paired=5, hashes=["aaaa", "bbbb", "cccc", "dddd", "eeee"]), "dialog"),
        (
            _sig(
                focus=("Button", (40, 30, 200, 24)),
                paired=5,
                hashes=["aaaa", "bbbb", "cccc", "dddd", "eeee"],
            ),
            "focus",
        ),
        (
            _sig(
                focus=("Edit", (41, 30, 200, 24)),
                paired=5,
                hashes=["aaaa", "bbbb", "cccc", "dddd", "eeee"],
            ),
            "focus",
        ),
        (_sig(focus=None, paired=5, hashes=["aaaa", "bbbb", "cccc", "dddd", "eeee"]), "focus"),
        (_sig(paired=4, hashes=["aaaa", "bbbb", "cccc", "dddd"]), "paired"),
        (NEIGHBOUR, "label"),
    ],
    ids=[
        "edit-count",
        "dialog-open",
        "focus-class",
        "focus-moved",
        "no-focus",
        "paired-count",
        "labels",
    ],
)
def test_each_difference_is_a_mismatch(observed, expected_word):
    problem = signature_problem(REPORT, observed)
    assert problem is not None and expected_word in problem


def test_unrecorded_hashes_and_pair_counts_are_not_compared():
    # A step recorded with counts and focus only still requires those to match.
    assert (
        signature_problem(
            HOME, _sig(edits=3, focus=("Edit", (10, 10, 24, 28)), paired=1, hashes=["x"])
        )
        is None
    )
    assert signature_problem(HOME, _sig(edits=4, focus=("Edit", (10, 10, 24, 28)))) is not None


def test_a_signature_carries_no_text():
    import dataclasses

    assert {f.name for f in dataclasses.fields(ScreenSignature)} == {
        "visible_edits", "owned_windows", "focus_class", "focus_rect", "paired", "label_hashes",
    }  # fmt: skip


# --- the allow-list -------------------------------------------------------------


def test_an_empty_allow_list_refuses_everything():
    problem = AllowList([]).problem("9-9", 0, "9", HOME)
    assert problem is not None and "not on the allow-list" in problem


def test_each_allowed_step_admits_only_its_key_on_its_screen():
    assert ALLOW.problem("9-9", 0, "9", HOME) is None
    assert ALLOW.problem("9-9", 1, "9", SEARCH) is None
    assert ALLOW.problem("9-9", 2, "ENTER", REPORT) is None


@pytest.mark.parametrize(
    "path, step, key, observed, word",
    [
        ("9-8", 0, "9", HOME, "not on the allow-list"),
        ("9-9", 3, "ENTER", REPORT, "no step 3"),
        ("9-9", -1, "9", HOME, "no step -1"),
        ("9-9", 0, "8", HOME, "allows only"),
        ("9-9", 2, "F1", REPORT, "allows only"),
        ("9-9", 0, "0", HOME, "allows only"),
        ("9-9", 2, "ENTER", NEIGHBOUR, "label"),
        ("9-9", 2, "ENTER", HOME, "Edits"),
    ],
    ids=["unknown-path", "past-the-end", "negative-step", "wrong-key", "wrong-key-at-enter",
         "console-key", "neighbouring-path", "wrong-screen"],
)  # fmt: skip
def test_everything_else_is_refused(path, step, key, observed, word):
    problem = ALLOW.problem(path, step, key, observed)
    assert problem is not None and word in problem


def _expect(edits, focus, **extra):
    return {
        "visible_edits": edits,
        "owned_windows": 0,
        "focus_class": "Edit",
        "focus_rect": focus,
        **extra,
    }


def _one(step):
    return {"paths": [{"path": "9-9", "steps": [step]}]}


MINIMAL = {"visible_edits": 1, "owned_windows": 0}


def test_the_allow_list_loads_from_private_json(tmp_path):
    report = _expect(
        5, [40, 30, 200, 24], paired=5, label_hashes=["aaaa", "bbbb", "cccc", "dddd", "eeee"]
    )
    data = {
        "paths": [
            {
                "path": "9-9",
                "steps": [
                    {"key": "9", "expected": _expect(3, [10, 10, 24, 28])},
                    {"key": "ENTER", "expected": report},
                ],
            }
        ]
    }
    file = tmp_path / "allow.json"
    file.write_text(json.dumps(data), encoding="utf-8")
    loaded = AllowList.load(file)
    assert loaded.problem("9-9", 0, "9", HOME) is None
    assert loaded.problem("9-9", 1, "ENTER", REPORT) is None
    assert loaded.problem("9-9", 1, "ENTER", NEIGHBOUR) is not None


_DUPLICATE = {
    "paths": [
        {"path": "9-9", "steps": [{"key": "9", "expected": MINIMAL}]},
        {"path": "9-9", "steps": [{"key": "9", "expected": MINIMAL}]},
    ]
}


@pytest.mark.parametrize(
    "content, word",
    [
        ("{not json", "unreadable"),
        (json.dumps({"paths": [{"path": "9-9", "steps": []}]}), "no steps"),
        (json.dumps(_one({"key": "9"})), "expected"),
        (json.dumps(_one({"key": "", "expected": MINIMAL})), "key"),
        (json.dumps(_DUPLICATE), "twice"),
        (json.dumps(_one({"key": "9", "expected": {**MINIMAL, "extra": 1}})), "expected"),
        (json.dumps({"pathz": []}), "paths"),
    ],
    ids=[
        "unparseable",
        "no-steps",
        "no-expected",
        "empty-key",
        "duplicate-path",
        "unknown-field",
        "no-paths",
    ],
)
def test_a_malformed_allow_list_refuses_to_load(tmp_path, content, word):
    file = tmp_path / "allow.json"
    file.write_text(content, encoding="utf-8")
    with pytest.raises(AllowListError, match=word):
        AllowList.load(file)


def test_a_missing_allow_list_refuses_to_load(tmp_path):
    with pytest.raises(AllowListError, match="unreadable"):
        AllowList.load(tmp_path / "absent.json")


# --- foreground and topmost -------------------------------------------------------


def _fg(foreground=APP, topmost=APP, fg_image="app.exe", top_image="app.exe"):
    return ForegroundObservation(
        foreground_instance=foreground,
        foreground_image=fg_image,
        topmost_instance=topmost,
        topmost_image=top_image,
    )


def test_the_app_in_front_and_on_top_passes():
    assert foreground_problem(APP, _fg()) is None


def test_another_foreground_process_is_named():
    problem = foreground_problem(APP, _fg(foreground=(77, 1), fg_image="term.exe"))
    assert problem is not None and "term.exe" in problem and "foreground" in problem


def test_a_window_on_top_at_the_point_is_named():
    problem = foreground_problem(APP, _fg(topmost=(88, 1), top_image="popup.exe"))
    assert problem is not None and "popup.exe" in problem and "covers" in problem


def test_a_restarted_process_with_the_same_pid_is_not_the_bound_instance():
    # Windows reuses pids: the start time tells two processes apart.
    problem = foreground_problem(APP, _fg(foreground=(4242, 8), topmost=(4242, 8)))
    assert problem is not None and "instance" in problem


# --- scroll clipping ----------------------------------------------------------------


def _clip_tree(edit_rect, viewport=(0, 100, 400, 200)):
    edit = WindowNode("Edit", edit_rect, hwnd=0x30, client_rect=edit_rect)
    scroller = WindowNode("wxScrolled", viewport, hwnd=0x20, client_rect=viewport, children=(edit,))
    return WindowNode(
        "wxWindowNR",
        (0, 0, 800, 600),
        hwnd=0x10,
        client_rect=(0, 0, 800, 600),
        children=(scroller,),
    )


def test_a_field_inside_its_viewport_is_visible():
    assert clipping_problem(_clip_tree((10, 120, 200, 20)), 0x30) is None


@pytest.mark.parametrize(
    "edit_rect", [(10, 320, 200, 20), (10, 290, 200, 20), (10, 90, 200, 20), (300, 120, 200, 20)],
    ids=["scrolled-below", "half-below", "half-above", "past-the-right-edge"],
)  # fmt: skip
def test_a_field_outside_its_viewport_is_refused(edit_rect):
    problem = clipping_problem(_clip_tree(edit_rect), 0x30)
    assert problem is not None and "outside" in problem


def test_an_unknown_client_area_fails_closed():
    edit = WindowNode("Edit", (10, 120, 200, 20), hwnd=0x30)
    tree = WindowNode("wxWindowNR", (0, 0, 800, 600), hwnd=0x10, children=(edit,))
    problem = clipping_problem(tree, 0x30)
    assert problem is not None and "client area" in problem


def test_a_field_not_in_the_tree_fails_closed():
    problem = clipping_problem(_clip_tree((10, 120, 200, 20)), 0x99)
    assert problem is not None and "not in the window tree" in problem


# --- the audit record --------------------------------------------------------------


FIELD = Win32Field(
    pid=4242, process_started=7, process_image="app.exe", class_path=("wxWindowNR", "Edit"),
    label_hash="ab" * 32, rect=(40, 30, 200, 24), label_rect=(10, 30, 33, 24),
    screen_rect=(140, 130, 200, 24), hwnd=0x30,
)  # fmt: skip


def test_the_audit_records_identity_frame_and_rectangles_never_text():
    record = audit_record(FIELD, "f" * 64)
    assert record == {
        "kind": "win32-field",
        "frame_hash": "f" * 64,
        "process_image": "app.exe",
        "instance": [4242, 7],
        "class_path": ["wxWindowNR", "Edit"],
        "label_hash": "ab" * 32,
        "rect": [40, 30, 200, 24],
        "label_rect": [10, 30, 33, 24],
        "screen_rect": [140, 130, 200, 24],
    }
    box = audit_record(OcrBox(rect=(5, 6, 70, 18)), "e" * 64)
    assert box == {"kind": "ocr-box", "frame_hash": "e" * 64, "rect": [5, 6, 70, 18]}


# --- the gatekeeper ------------------------------------------------------------------


def _frame(fid=1):
    return Frame.from_image(fid, Image.new("RGB", (64, 64), (10, 20, 30)))


def _gatekeeper(tmp_path):
    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl", kill_switch_path=tmp_path / "STOP"
    )
    freshness = FreshnessTracker()
    freshness.observe(1)
    return Gatekeeper(config, freshness), config


def _request(**kw):
    defaults = dict(
        action=Action(ActionKind.KEY, 1, keys=("ENTER",)),
        path="9-9",
        step=2,
        app_instance=APP,
        signature=REPORT,
        foreground=_fg(),
        target=FIELD,
        tree=_clip_tree((40, 130, 200, 24)),
    )
    defaults.update(kw)
    return BoundKeyRequest(**defaults)


def _entries(config):
    return [
        json.loads(line) for line in config.audit_log_path.read_text(encoding="utf-8").splitlines()
    ]


def test_an_allowed_key_runs_and_its_binding_is_audited(tmp_path):
    gk, config = _gatekeeper(tmp_path)
    decision = gk.request_bound_key(_request(), _frame(), ALLOW)
    assert decision.kind is DecisionKind.DRY_RUN
    entry = _entries(config)[-1]
    assert entry["action"]["binding"]["label_hash"] == "ab" * 32
    assert entry["action"]["binding"]["frame_hash"] == _frame().sha256
    assert verify(config.audit_log_path).ok


@pytest.mark.parametrize(
    "change, word",
    [
        (dict(path="9-8"), "not on the allow-list"),
        (dict(signature=NEIGHBOUR), "label"),
        (dict(action=Action(ActionKind.KEY, 1, keys=("F1",))), "allows only"),
        (dict(action=Action(ActionKind.KEY, 1, keys=("ctrl", "y"))), "one key"),
        (dict(action=Action(ActionKind.TYPE, 1, text="secret value")), "only key"),
        (dict(foreground=_fg(topmost=(88, 1), top_image="popup.exe")), "popup.exe"),
        (dict(app_instance=(4242, 8)), "instance"),
        (dict(tree=_clip_tree((40, 330, 200, 24))), "outside"),
    ],
    ids=["path", "signature", "key", "chord", "typing", "covered", "restarted", "scrolled-out"],
)  # fmt: skip
def test_a_refused_key_is_never_executed_and_is_audited_without_text(tmp_path, change, word):
    class _Recorder:
        name = "recorder"
        calls = []

        def execute(self, action):
            self.calls.append(action)
            return "sent"

    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl", kill_switch_path=tmp_path / "STOP"
    )
    freshness = FreshnessTracker()
    freshness.observe(1)
    recorder = _Recorder()
    gk = Gatekeeper(config, freshness, executor=recorder)
    decision = gk.request_bound_key(_request(**change), _frame(), ALLOW)
    assert decision.kind is DecisionKind.DENIED and word in decision.reason
    assert recorder.calls == []
    raw = config.audit_log_path.read_text(encoding="utf-8")
    assert "secret value" not in raw
    entry = _entries(config)[-1]
    assert entry["decision"] == "denied" and "binding" in entry["action"]


def test_a_target_from_another_instance_is_refused(tmp_path):
    # Everything else is the restarted instance; the field was read from the old one.
    gk, _ = _gatekeeper(tmp_path)
    restarted = (4242, 8)
    request = _request(
        app_instance=restarted, foreground=_fg(foreground=restarted, topmost=restarted)
    )
    decision = gk.request_bound_key(request, _frame(), ALLOW)
    assert decision.kind is DecisionKind.DENIED and "another process instance" in decision.reason


def test_the_kill_switch_still_wins(tmp_path):
    gk, config = _gatekeeper(tmp_path)
    config.kill_switch_path.write_text("stop", encoding="utf-8")
    decision = gk.request_bound_key(_request(), _frame(), ALLOW)
    assert decision.kind is DecisionKind.KILL_SWITCHED
    # And it is checked first: a key the gate would refuse is recorded as
    # kill-switched, not as an ordinary refusal.
    refused = gk.request_bound_key(_request(path="9-8"), _frame(), ALLOW)
    assert refused.kind is DecisionKind.KILL_SWITCHED


# --- live observation (Windows) ---------------------------------------------------

windows_only = pytest.mark.skipif(os.name != "nt", reason="reads real Win32 windows")


@windows_only
def test_the_reader_records_each_windows_client_area():
    from test_win32_fields import _OwnForm, _walk

    from psoperator.perception import win32_fields

    with _OwnForm([("internal_a", "v")]) as form:
        tree = win32_fields.read_window_tree(form.hwnd, label_class="Static")
    for node in _walk(tree):
        assert node.client_rect is not None
        cx, cy, cw, ch = node.client_rect
        x, y, w, h = node.rect
        assert x <= cx and y <= cy and cx + cw <= x + w and cy + ch <= y + h


@windows_only
def test_a_window_on_top_at_the_point_is_found_with_its_process():
    # Negative control: a window from another process covers the point, and
    # the observation names that process, not this one.
    import subprocess
    import sys
    import time

    from psoperator.perception import win32_state

    script = (
        "import ctypes,sys,time\n"
        "from ctypes import wintypes\n"
        "u=ctypes.WinDLL('user32');k=ctypes.WinDLL('kernel32')\n"
        "u.CreateWindowExW.argtypes=[wintypes.DWORD,wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.DWORD,"
        "ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,wintypes.HWND,wintypes.HMENU,wintypes.HINSTANCE,wintypes.LPVOID]\n"
        "u.CreateWindowExW.restype=wintypes.HWND\n"
        "k.GetModuleHandleW.restype=wintypes.HMODULE\n"
        "h=u.CreateWindowExW(0x8|0x80|0x08000000,'STATIC','',0x80000000|0x10000000,20,20,60,60,None,None,k.GetModuleHandleW(None),None)\n"
        "import os;print(os.getpid(),flush=True)\n"
        "sys.stdin.readline()\n"
    )  # fmt: skip
    child = subprocess.Popen(
        [sys.executable, "-c", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        # The venv's python.exe may be a launcher; the window belongs to the
        # interpreter process, which reports its own pid.
        owner = int(child.stdout.readline().strip())
        time.sleep(0.3)
        observed = win32_state.observe_foreground(point=(50, 50))
        assert observed.topmost_instance[0] == owner
        assert observed.topmost_image.lower().startswith("python")
        # Bound to whatever is in front, so the covering window is what refuses.
        problem = foreground_problem(observed.foreground_instance, observed)
        assert problem is not None and "covers" in problem and str(owner) in problem
    finally:
        child.stdin.write("\n")
        child.stdin.flush()
        child.wait(timeout=10)
