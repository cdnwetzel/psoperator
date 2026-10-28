"""The bound-target gate (pilot charter, "Consequences of the probe verdict").

A key reaches the application only through ``Gatekeeper.request_bound_key``.
The gatekeeper observes the screen itself (an injected observer), checks the
observation, and observes again immediately before sending. Every path, hash,
handle and rectangle here is made up; the real allow-list is private
configuration and never enters the repository.
"""

from __future__ import annotations

import dataclasses
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
    Code,
    Observation,
    OcrBox,
    ScreenSignature,
    audit_record,
    audited_keys,
    bound_key_problem,
    signature_of,
    signature_problem,
    unchanged,
    valid_key,
)
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.perception.capture import Frame
from psoperator.perception.win32_fields import Win32Field, WindowNode, name_hash
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker

APP = (4242, 7)  # (pid, process start time)
MAIN, SCROLLER, EDIT, OTHER = 0x10, 0x20, 0x30, 0x40
A, B, C, D, E = "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64


def _sig(owned=0, focus=("Edit", (40, 30, 200, 24)), edits=None, captions=None, labelled=None):
    return ScreenSignature(
        owned_windows=owned,
        focus_class=focus[0],
        focus_rect=focus[1],
        edit_rects=edits if edits is not None else ((40, 30, 200, 24), (40, 60, 200, 24)),
        captions=captions if captions is not None else (A, B),
        labelled=labelled
        if labelled is not None
        else ((A, (40, 30, 200, 24)), (B, (40, 60, 200, 24))),
    )


HOME = _sig(focus=("Edit", (10, 10, 24, 28)), edits=((10, 10, 24, 28),), captions=(D,), labelled=())
REPORT = _sig()
NEIGHBOUR = _sig(captions=(A, C), labelled=((A, (40, 30, 200, 24)), (C, (40, 60, 200, 24))))
SWAPPED = _sig(labelled=((B, (40, 30, 200, 24)), (A, (40, 60, 200, 24))))
# Two menu screens: no fields, same focus and counts; only their captions differ.
MENU = _sig(
    focus=("Edit", (60, 40, 600, 28)), edits=((60, 40, 600, 28),), captions=(D,), labelled=()
)
SUBMENU = _sig(
    focus=("Edit", (60, 40, 600, 28)), edits=((60, 40, 600, 28),), captions=(E,), labelled=()
)

ALLOW = AllowList([AllowedPath("9-9", (AllowedStep(HOME, "9"), AllowedStep(REPORT, "ENTER")))])

FIELD = Win32Field(
    pid=4242, process_started=7, process_image="app.exe", class_path=("wxWindowNR", "Edit"),
    label_hash=A, rect=(40, 30, 200, 24), label_rect=(10, 30, 33, 24),
    screen_rect=(140, 130, 200, 24), hwnd=EDIT,
)  # fmt: skip


def _tree(edit_rect=(140, 130, 200, 24), edit_visible=True, parent_visible=True, client=True):
    viewport = (100, 100, 400, 200)
    edit = WindowNode("Edit", edit_rect, hwnd=EDIT, visible=edit_visible, client_rect=edit_rect)
    scroller = WindowNode(
        "wxScrolled", viewport, hwnd=SCROLLER, visible=parent_visible,
        client_rect=viewport if client else None, children=(edit,),
    )  # fmt: skip
    main = (100, 100, 800, 600)
    return WindowNode("wxWindowNR", main, hwnd=MAIN, client_rect=main, children=(scroller,))


def _obs(**change) -> Observation:
    values = dict(
        at=100.0, main_hwnd=MAIN, instance=APP, foreground_hwnd=MAIN, topmost_hwnd=MAIN,
        focus_hwnd=EDIT, point=(150, 140), signature=REPORT, tree=_tree(),
    )  # fmt: skip
    values.update(change)
    return Observation(**values)


def _req(**change) -> BoundKeyRequest:
    values = dict(
        action=Action(ActionKind.KEY, 1, keys=("ENTER",)), path="9-9", step=1,
        app_instance=APP, main_hwnd=MAIN, target=FIELD,
    )  # fmt: skip
    values.update(change)
    return BoundKeyRequest(**values)


def _keys(*keys) -> BoundKeyRequest:
    return _req(action=Action(ActionKind.KEY, 1, keys=keys))


def _tgt(**change) -> BoundKeyRequest:
    return _req(target=dataclasses.replace(FIELD, **change))


TYPING = _req(action=Action(ActionKind.TYPE, 1, text="secret value"))


def _problem(req=None, obs=None, now=100.5):
    return bound_key_problem(req or _req(), ALLOW, obs or _obs(), now=now, max_age_s=1.0)


# --- keys and signatures ---------------------------------------------------------


@pytest.mark.parametrize("key", ["0", "9", "A", "ENTER", "F1", "F12", "ESC"])
def test_recognised_keys(key):
    assert valid_key(key)


@pytest.mark.parametrize("key", ["", "enter", "a", "ctrl", "F13", "10", "secret value", None, 3])
def test_unrecognised_keys(key):
    assert not valid_key(key)


@pytest.mark.parametrize(
    "change",
    [
        dict(owned=True),
        dict(owned=-1),
        dict(focus=("Edit", (1, 2, 0, 3))),
        dict(focus=("has space", (1, 2, 3, 4))),
        dict(edits=((1, 2, 3),)),
        dict(edits=[(1, 2, 3, 4)]),
        dict(labelled=(("short", (1, 2, 3, 4)),)),
        dict(labelled=((A, (1, 2, 3, -4)),)),
        dict(captions=("short",)),
        dict(captions=[A]),
    ],
    ids=["bool-count", "negative-count", "zero-size-focus", "bad-class", "short-rect",
         "list-not-tuple", "bad-hash", "negative-size", "bad-caption", "caption-list"],
)  # fmt: skip
def test_a_malformed_signature_cannot_be_built(change):
    with pytest.raises(ValueError):
        _sig(**change)


def test_a_signature_is_order_insensitive_but_position_sensitive():
    reordered = _sig(
        edits=((40, 60, 200, 24), (40, 30, 200, 24)),
        labelled=((B, (40, 60, 200, 24)), (A, (40, 30, 200, 24))),
    )
    assert reordered == REPORT
    assert signature_problem(REPORT, SWAPPED) == "labels"  # same labels, other places


@pytest.mark.parametrize(
    "observed, part",
    [
        (_sig(owned=1), "dialogs"),
        (_sig(focus=("Button", (40, 30, 200, 24))), "focus"),
        (_sig(focus=("Edit", (41, 30, 200, 24))), "focus"),
        (_sig(edits=((40, 30, 200, 24),)), "edits"),
        (_sig(edits=((40, 30, 200, 24), (40, 61, 200, 24))), "edits"),
        (_sig(captions=(A, B, C)), "captions"),
        (NEIGHBOUR, "captions"),
        (SWAPPED, "labels"),
        (_sig(labelled=((A, (40, 30, 200, 24)),)), "labels"),
    ],
    ids=["dialog", "focus-class", "focus-moved", "edit-missing", "edit-moved",
         "extra-caption", "other-captions", "swapped-labels", "label-missing"],
)  # fmt: skip
def test_each_screen_difference_is_found(observed, part):
    assert signature_problem(REPORT, observed) == part


def test_a_signature_carries_no_text():
    assert {f.name for f in dataclasses.fields(ScreenSignature)} == {
        "owned_windows", "focus_class", "focus_rect", "edit_rects", "captions", "labelled",
    }  # fmt: skip


def test_signature_of_an_observed_tree():
    panel = WindowNode("wxWindowClassNR", (110, 130, 33, 24), name_hash=name_hash("x"), hwnd=0x50)
    tree = WindowNode(
        "wxWindowNR", (100, 100, 800, 600), hwnd=MAIN,
        children=(panel, WindowNode("Edit", (140, 130, 200, 24), hwnd=EDIT)),
    )  # fmt: skip
    sig = signature_of(tree, EDIT, 0, pid=1, process_started=1, process_image="app.exe")
    assert sig.edit_rects == ((40, 30, 200, 24),)
    assert sig.labelled == ((name_hash("x"), (40, 30, 200, 24)),)
    assert sig.captions == (name_hash("x"),)
    assert (sig.focus_class, sig.focus_rect) == ("Edit", (40, 30, 200, 24))
    with pytest.raises(ValueError, match="focus"):
        signature_of(tree, OTHER, 0, pid=1, process_started=1, process_image="app.exe")


# --- the allow-list ------------------------------------------------------------------


def test_menu_screens_without_fields_are_told_apart_by_their_captions():
    assert signature_problem(MENU, SUBMENU) == "captions"
    menus = AllowList([AllowedPath("9-9", (AllowedStep(MENU, "9"),))])
    assert menus.problem("9-9", 0, "9", MENU) is None
    assert menus.problem("9-9", 0, "9", SUBMENU).code is Code.SCREEN


def test_a_step_without_screen_specific_captions_is_refused():
    with pytest.raises(AllowListError, match="screen-specific"):
        AllowedStep(_sig(captions=()), "ENTER")


def test_two_steps_expecting_the_same_screen_are_refused():
    with pytest.raises(AllowListError, match="same screen signature"):
        AllowList([AllowedPath("9-9", (AllowedStep(MENU, "9"), AllowedStep(MENU, "8")))])
    with pytest.raises(AllowListError, match="same screen signature"):
        AllowList(
            [
                AllowedPath("9-9", (AllowedStep(MENU, "9"),)),
                AllowedPath("9-8", (AllowedStep(MENU, "9"),)),
            ]
        )


def test_recorded_neighbouring_screens_must_differ_and_are_refused():
    with pytest.raises(AllowListError, match="neighbouring screen equals"):
        AllowedStep(REPORT, "ENTER", (REPORT,))
    guarded = AllowList([AllowedPath("9-9", (AllowedStep(REPORT, "ENTER", (NEIGHBOUR,)),))])
    assert guarded.problem("9-9", 0, "ENTER", REPORT) is None
    refusal = guarded.problem("9-9", 0, "ENTER", NEIGHBOUR)
    assert refusal.code is Code.SCREEN and "neighbouring" in refusal.detail


def test_an_empty_allow_list_refuses_everything():
    assert AllowList([]).problem("9-9", 0, "9", HOME).code is Code.NO_PATH


def test_each_step_admits_only_its_key_on_its_screen():
    assert ALLOW.problem("9-9", 0, "9", HOME) is None
    assert ALLOW.problem("9-9", 1, "ENTER", REPORT) is None


@pytest.mark.parametrize(
    "args, code",
    [
        (("9-8", 0, "9", HOME), Code.NO_PATH),
        (("9-9", 2, "ENTER", REPORT), Code.NO_STEP),
        (("9-9", -1, "9", HOME), Code.NO_STEP),
        (("9-9", True, "ENTER", REPORT), Code.NO_STEP),
        (("9-9", 0, "8", HOME), Code.WRONG_KEY),
        (("9-9", 0, "0", HOME), Code.WRONG_KEY),
        (("9-9", 1, "ENTER", NEIGHBOUR), Code.SCREEN),
        (("9-9", 1, "ENTER", SWAPPED), Code.SCREEN),
        (("9-9", 1, "ENTER", HOME), Code.SCREEN),
    ],
    ids=["unknown-path", "past-the-end", "negative-step", "bool-step", "wrong-key",
         "console-key", "neighbouring-screen", "swapped-labels", "wrong-screen"],
)  # fmt: skip
def test_everything_else_is_refused(args, code):
    assert ALLOW.problem(*args).code is code


@pytest.mark.parametrize(
    "build",
    [
        lambda: AllowedStep(REPORT, "enter"),
        lambda: AllowedStep("not a signature", "ENTER"),
        lambda: AllowedPath("9-9", ()),
        lambda: AllowedPath("9 9; anything", (AllowedStep(HOME, "9"),)),
        lambda: AllowedPath("9-9", [AllowedStep(HOME, "9")]),
        lambda: AllowList(["9-9"]),
        lambda: AllowList([AllowedPath("9-9", (AllowedStep(HOME, "9"),))] * 2),
    ],
    ids=["bad-key", "no-signature", "no-steps", "bad-path", "list-steps", "not-a-path", "twice"],
)
def test_the_constructor_is_as_strict_as_the_loader(build):
    with pytest.raises(AllowListError):
        build()


def _expected(**change):
    values = {
        "owned_windows": 0, "focus_class": "Edit", "focus_rect": [40, 30, 200, 24],
        "edit_rects": [[40, 30, 200, 24], [40, 60, 200, 24]],
        "captions": [A, B],
        "labelled": [[A, [40, 30, 200, 24]], [B, [40, 60, 200, 24]]],
    }  # fmt: skip
    values.update(change)
    return values


def _doc(expected=None, key="ENTER", step_extra=None, path_extra=None, root_extra=None):
    step = {"key": key, "expected": expected if expected is not None else _expected()}
    step.update(step_extra or {})
    path = {"path": "9-9", "steps": [step]}
    path.update(path_extra or {})
    doc = {"paths": [path]}
    doc.update(root_extra or {})
    return json.dumps(doc)


def test_the_allow_list_loads_from_private_json(tmp_path):
    file = tmp_path / "allow.json"
    neighbour = _expected(
        captions=[A, C], labelled=[[A, [40, 30, 200, 24]], [C, [40, 60, 200, 24]]]
    )
    file.write_text(_doc(step_extra={"neighbours": [neighbour]}), encoding="utf-8")
    loaded = AllowList.load(file)
    assert loaded.problem("9-9", 0, "ENTER", REPORT) is None
    assert loaded.problem("9-9", 0, "ENTER", NEIGHBOUR).code is Code.SCREEN


_MALFORMED = {
    "unparseable": "{not json",
    "duplicate-member": '{"paths": [], "paths": []}',
    "unknown-root-field": _doc(root_extra={"note": 1}),
    "unknown-path-field": _doc(path_extra={"note": 1}),
    "unknown-step-field": _doc(step_extra={"note": 1}),
    "no-captions": _doc(expected=_expected(captions=[])),
    "bad-caption": _doc(expected=_expected(captions=["abc"])),
    "neighbour-equals-expected": _doc(step_extra={"neighbours": [_expected()]}),
    "neighbours-not-a-list": _doc(step_extra={"neighbours": {}}),
    "missing-focus": _doc(expected={k: v for k, v in _expected().items() if k != "focus_rect"}),
    "bool-count": _doc(expected=_expected(owned_windows=False)),
    "string-count": _doc(expected=_expected(owned_windows="0")),
    "float-rect": _doc(expected=_expected(focus_rect=[40.0, 30, 200, 24])),
    "zero-size-rect": _doc(expected=_expected(edit_rects=[[40, 30, 0, 24]])),
    "bad-hash": _doc(expected=_expected(labelled=[["abc", [40, 30, 200, 24]]])),
    "labelled-shape": _doc(expected=_expected(labelled=[[A]])),
    "unrecognised-key": _doc(key="enter"),
    "no-steps": json.dumps({"paths": [{"path": "9-9", "steps": []}]}),
    "duplicate-path": json.dumps({"paths": [json.loads(_doc())["paths"][0]] * 2}),
}  # fmt: skip


@pytest.mark.parametrize("content", list(_MALFORMED.values()), ids=list(_MALFORMED))
def test_a_malformed_allow_list_refuses_to_load(tmp_path, content):
    file = tmp_path / "allow.json"
    file.write_text(content, encoding="utf-8")
    with pytest.raises(AllowListError):
        AllowList.load(file)


def test_a_missing_allow_list_refuses_to_load(tmp_path):
    with pytest.raises(AllowListError, match="unreadable"):
        AllowList.load(tmp_path / "absent.json")


# --- the gate on one observation ---------------------------------------------------------


def test_a_fully_bound_key_is_admitted():
    assert _problem() is None


EDIT_ROOT = WindowNode("Edit", (140, 130, 200, 24), hwnd=MAIN, client_rect=(140, 130, 200, 24))

_REFUSALS = {
    "typing": (dict(req=TYPING), Code.NOT_KEY),
    "chord": (dict(req=_keys("ctrl", "y")), Code.CHORD),
    "unrecognised-key": (dict(req=_keys("enter")), Code.BAD_KEY),
    "stale": (dict(now=101.5), Code.STALE),
    "from-the-future": (dict(now=99.0), Code.STALE),
    "other-instance": (dict(obs=_obs(instance=(4242, 8))), Code.INSTANCE),
    "other-main-window": (dict(obs=_obs(main_hwnd=OTHER)), Code.INSTANCE),
    "covered": (dict(obs=_obs(topmost_hwnd=OTHER)), Code.COVERED),
    "same-process-popup-in-front": (dict(obs=_obs(foreground_hwnd=OTHER)), Code.NOT_FOREGROUND),
    "neighbouring-screen": (dict(obs=_obs(signature=NEIGHBOUR)), Code.SCREEN),
    "not-allowed-path": (dict(req=_req(path="9-8")), Code.NO_PATH),
    "no-target": (dict(req=_req(target=None)), Code.NO_TARGET),
    "ocr-target": (dict(req=_req(target=OcrBox((1, 2, 3, 4)))), Code.UNSUPPORTED),
    "target-of-old-instance": (dict(req=_tgt(process_started=6)), Code.INSTANCE),
    "focus-elsewhere": (dict(obs=_obs(focus_hwnd=OTHER)), Code.NOT_FOCUSED),
    "not-in-tree": (dict(req=_tgt(hwnd=OTHER), obs=_obs(focus_hwnd=OTHER)), Code.TARGET_MISMATCH),
    "main-window": (dict(req=_tgt(hwnd=MAIN), obs=_obs(focus_hwnd=MAIN)), Code.TARGET_MISMATCH),
    # Even a main window that is itself an Edit at the target's geometry: the
    # root is the container, never the target (and has no ancestors to clip it).
    "edit-root": (
        dict(
            req=_tgt(hwnd=MAIN),
            obs=_obs(
                focus_hwnd=MAIN,
                tree=EDIT_ROOT,
            ),
        ),
        Code.TARGET_MISMATCH,
    ),
    "geometry": (dict(req=_tgt(screen_rect=(141, 130, 200, 24))), Code.TARGET_MISMATCH),
    "point-outside-field": (dict(obs=_obs(point=(90, 90))), Code.TARGET_MISMATCH),
    "target-hidden": (dict(obs=_obs(tree=_tree(edit_visible=False))), Code.HIDDEN),
    "ancestor-hidden": (dict(obs=_obs(tree=_tree(parent_visible=False))), Code.HIDDEN),
    "client-area-unknown": (dict(obs=_obs(tree=_tree(client=False))), Code.GEOMETRY),
}  # fmt: skip


@pytest.mark.parametrize("args, code", list(_REFUSALS.values()), ids=list(_REFUSALS))
def test_every_gap_is_refused(args, code):
    refusal = _problem(**args)
    assert refusal is not None and refusal.code is code


@pytest.mark.parametrize(
    "edit_rect",
    [(140, 320, 200, 24), (140, 290, 200, 24), (140, 90, 200, 24), (450, 130, 200, 24)],
    ids=["scrolled-below", "half-below", "half-above", "past-the-right-edge"],
)  # fmt: skip
def test_a_scrolled_out_field_is_refused(edit_rect):
    field = dataclasses.replace(FIELD, screen_rect=edit_rect)
    point = (edit_rect[0] + 5, edit_rect[1] + 5)
    refusal = _problem(_req(target=field), _obs(tree=_tree(edit_rect=edit_rect), point=point))
    assert refusal is not None and refusal.code is Code.CLIPPED


def test_two_observations_must_agree():
    assert unchanged(_obs(), _obs(at=100.3))
    for change in (
        dict(focus_hwnd=OTHER),
        dict(foreground_hwnd=OTHER),
        dict(topmost_hwnd=OTHER),
        dict(signature=NEIGHBOUR),
        dict(instance=(4242, 8)),
    ):
        assert not unchanged(_obs(), _obs(**change)), change


# --- the audit -------------------------------------------------------------------------


def test_the_audit_record_keeps_validated_identity_only():
    assert audit_record(FIELD, "f" * 64) == {
        "kind": "win32-field", "frame_hash": "f" * 64, "process_image": "app.exe",
        "instance": [4242, 7], "class_path": ["wxWindowNR", "Edit"], "label_hash": A,
        "rect": [40, 30, 200, 24], "label_rect": [10, 30, 33, 24],
        "screen_rect": [140, 130, 200, 24],
    }  # fmt: skip
    hostile = dataclasses.replace(
        FIELD, process_image="name with secret text", class_path=("ok", "also secret text"),
        label_hash="not a hash",
    )  # fmt: skip
    record = audit_record(hostile, "not a hash either")
    assert "secret" not in json.dumps(record) and "not a hash" not in json.dumps(record)
    assert record["process_image"] == "<invalid>" and record["label_hash"] == "<invalid>"
    assert audit_record(OcrBox((5, 6, 70, 18)), "e" * 64) == {
        "kind": "ocr-box", "frame_hash": "e" * 64, "rect": [5, 6, 70, 18],
    }  # fmt: skip
    assert audit_record(None, "e" * 64) == {"kind": "none", "frame_hash": "e" * 64}


def test_audited_keys_are_recognised_names_only():
    assert audited_keys(Action(ActionKind.KEY, 1, keys=("ENTER",))) == ["ENTER"]
    assert audited_keys(Action(ActionKind.KEY, 1, keys=("ctrl", "secret"))) == ["<invalid>"] * 2


# --- through the gatekeeper ------------------------------------------------------------


class _Recorder:
    name = "recorder"

    def __init__(self):
        self.calls = []

    def execute(self, action):
        self.calls.append(action)
        return "secret outcome text"


class _Observer:  # noqa: N801 - a callable stand-in
    """Returns the given observations in turn (the last repeats)."""

    def __init__(self, *observations, fail=False):
        self._observations = list(observations) or [_obs()]
        self.calls = 0
        self._fail = fail

    def __call__(self):
        self.calls += 1
        if self._fail:
            raise RuntimeError("secret observer text")
        index = min(self.calls - 1, len(self._observations) - 1)
        return self._observations[index]


_seq = _Observer


def _frame(fid=1):
    return Frame.from_image(fid, Image.new("RGB", (64, 64), (10, 20, 30)))


def _gatekeeper(tmp_path, **kwargs):
    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl", kill_switch_path=tmp_path / "STOP"
    )
    freshness = FreshnessTracker()
    freshness.observe(1)
    recorder = _Recorder()
    return Gatekeeper(config, freshness, executor=recorder, **kwargs), config, recorder


def _send(gk, req=None, observer=None):
    return gk.request_bound_key(
        req or _req(), _frame(), ALLOW, observer or _Observer(), clock=lambda: 100.5
    )


def _audit(config):
    lines = config.audit_log_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_an_admitted_key_is_observed_twice_executed_once_and_audited(tmp_path):
    gk, config, recorder = _gatekeeper(tmp_path)
    observer = _Observer()
    decision = _send(gk, observer=observer)
    assert decision.kind is DecisionKind.EXECUTED
    assert observer.calls == 2 and len(recorder.calls) == 1
    entry = _audit(config)[-1]
    assert entry["action"]["binding"]["label_hash"] == A
    assert entry["action"]["keys"] == ["ENTER"]
    assert entry["reason"] == "executed"
    assert "secret outcome text" not in config.audit_log_path.read_text(encoding="utf-8")
    assert verify(config.audit_log_path).ok


_GATEKEEPER_REFUSALS = {
    "typing": (dict(req=TYPING), Code.NOT_KEY),
    "hostile-key": (dict(req=_keys("secret key")), Code.BAD_KEY),
    "hostile-path": (dict(req=_req(path="secret path text")), Code.NO_PATH),
    "covered": (dict(observer=_seq(_obs(topmost_hwnd=OTHER))), Code.COVERED),
    "neighbouring-screen": (dict(observer=_seq(_obs(signature=NEIGHBOUR))), Code.SCREEN),
    "observer-fails": (dict(observer=_seq(fail=True)), Code.OBSERVE_FAILED),
    "malformed-target": (dict(req=_tgt(class_path=None)), Code.INVALID),
    "hostile-identity": (dict(req=_tgt(process_image="secret name")), Code.INVALID),
    "focus-before-send": (dict(observer=_seq(_obs(), _obs(focus_hwnd=OTHER))), Code.NOT_FOCUSED),
    "screen-before-send": (dict(observer=_seq(_obs(), _obs(signature=SWAPPED))), Code.SCREEN),
    "dialog-before-send": (
        dict(observer=_seq(_obs(), _obs(foreground_hwnd=OTHER))), Code.NOT_FOREGROUND
    ),
}  # fmt: skip


@pytest.mark.parametrize(
    "args, code", list(_GATEKEEPER_REFUSALS.values()), ids=list(_GATEKEEPER_REFUSALS)
)
def test_a_refused_key_never_executes_and_the_audit_holds_a_code_not_text(tmp_path, args, code):
    gk, config, recorder = _gatekeeper(tmp_path)
    decision = _send(gk, **args)
    assert decision.kind is DecisionKind.DENIED
    assert decision.reason.startswith(code.value)
    assert recorder.calls == []
    entry = _audit(config)[-1]
    assert entry["reason"] == code.value
    raw = config.audit_log_path.read_text(encoding="utf-8")
    assert "secret" not in raw


def test_a_change_between_check_and_send_is_refused_even_if_still_allowed(tmp_path):
    # The second observation is a valid screen too, just not the one checked.
    gk, _, recorder = _gatekeeper(tmp_path)
    moved = _obs(focus_hwnd=EDIT, point=(151, 141))
    decision = _send(gk, observer=_Observer(_obs(), moved))
    assert decision.kind is DecisionKind.DENIED and decision.reason == Code.CHANGED.value
    assert recorder.calls == []


def test_the_kill_switch_is_checked_first(tmp_path):
    gk, config, recorder = _gatekeeper(tmp_path)
    config.kill_switch_path.write_text("stop", encoding="utf-8")
    observer = _Observer()
    for req in (_req(), _req(path="9-8"), _tgt(class_path=None)):
        assert _send(gk, req, observer).kind is DecisionKind.KILL_SWITCHED
    assert observer.calls == 0 and recorder.calls == []


def test_bound_input_only_closes_the_ordinary_path(tmp_path):
    gk, config, recorder = _gatekeeper(tmp_path, bound_input_only=True)
    for action in (
        Action(ActionKind.KEY, 1, keys=("ENTER",)),
        Action(ActionKind.TYPE, 1, text="x"),
        Action(ActionKind.CLICK, 1, x=1, y=1),
    ):
        decision = gk.request_action(action, _frame())
        assert decision.kind is DecisionKind.DENIED and "bound-target gate" in decision.reason
    assert recorder.calls == []
    assert gk.request_action(Action(ActionKind.WAIT, 1, seconds=0.1), _frame()).approved
    assert _send(gk).kind is DecisionKind.EXECUTED
    assert [a.kind for a in recorder.calls] == [ActionKind.WAIT, ActionKind.KEY]


def test_without_bound_input_only_the_ordinary_path_is_unchanged(tmp_path):
    gk, config, recorder = _gatekeeper(tmp_path)
    decision = gk.request_action(Action(ActionKind.KEY, 1, keys=("ENTER",)), _frame())
    assert decision.kind is DecisionKind.EXECUTED
    entry = _audit(config)[-1]
    assert entry["reason"] == "ok" and "binding" not in entry["action"]


# --- live observation (Windows) ------------------------------------------------------------

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


def _topmost_popup(user32, kernel32, x, y, size=60):
    import ctypes
    from ctypes import wintypes

    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ]  # fmt: skip
    user32.CreateWindowExW.restype = wintypes.HWND
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    topmost, tool, no_activate = 0x8, 0x80, 0x08000000
    popup, visible, notify = 0x80000000, 0x10000000, 0x100  # SS_NOTIFY: hit-testable
    hwnd = user32.CreateWindowExW(
        topmost | tool | no_activate, "STATIC", "", popup | visible | notify,
        x, y, size, size, None, None, kernel32.GetModuleHandleW(None), None,
    )  # fmt: skip
    assert hwnd, ctypes.get_last_error()
    return int(hwnd)


@windows_only
def test_a_covering_window_is_found_whether_same_process_or_another():
    # The bound window is a topmost popup of this test (the control: it is
    # what the point shows). A second topmost popup over it, first from this
    # same process and then from another process, is what the point shows next,
    # and the gate refuses with "covered" without reaching the executor.
    import ctypes
    import subprocess
    import sys
    import time

    from psoperator.perception import win32_state
    from psoperator.perception.win32_fields import process_of

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.DestroyWindow.argtypes = [ctypes.c_void_p]
    point = (50, 50)
    bound = _topmost_popup(user32, kernel32, 20, 20)
    try:
        time.sleep(0.2)
        assert win32_state.topmost_at(point) == bound  # the control

        same = _topmost_popup(user32, kernel32, 30, 30, size=40)
        try:
            time.sleep(0.2)
            assert win32_state.topmost_at(point) == same
            assert process_of(same)[0] == os.getpid()
            refusal = _problem(obs=_obs(main_hwnd=bound, topmost_hwnd=same, foreground_hwnd=bound),
                               req=_req(main_hwnd=bound))  # fmt: skip
            assert refusal.code is Code.COVERED
        finally:
            user32.DestroyWindow(same)

        script = (
            "import ctypes,os,sys\n"
            "from ctypes import wintypes\n"
            "u=ctypes.WinDLL('user32');k=ctypes.WinDLL('kernel32')\n"
            "u.CreateWindowExW.argtypes=[wintypes.DWORD,wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.DWORD,"
            "ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,wintypes.HWND,wintypes.HMENU,"
            "wintypes.HINSTANCE,wintypes.LPVOID]\n"
            "u.CreateWindowExW.restype=wintypes.HWND\n"
            "k.GetModuleHandleW.restype=wintypes.HMODULE\n"
            "h=u.CreateWindowExW(0x8|0x80|0x08000000,'STATIC','',0x80000000|0x10000000|0x100,"
            "30,30,40,40,None,None,k.GetModuleHandleW(None),None)\n"
            "print(os.getpid() if h else 0,flush=True)\n"
            "sys.stdin.readline()\n"
        )  # fmt: skip
        child = subprocess.Popen(
            [sys.executable, "-c", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )
        try:
            owner = int(child.stdout.readline().strip())
            assert owner, "the covering window was not created"
            time.sleep(0.2)
            covering = win32_state.topmost_at(point)
            assert covering != bound and process_of(covering)[0] == owner
        finally:
            child.stdin.write("\n")
            child.stdin.flush()
            child.wait(timeout=10)
    finally:
        user32.DestroyWindow(bound)
