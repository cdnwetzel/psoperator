"""The bound-target gate (pilot charter, "Consequences of the probe verdict").

A key reaches the application only through ``Gatekeeper.request_bound_key``.
The gatekeeper is constructed with a trusted observer and clock; it observes
the screen itself, checks, and observes again immediately before sending.
Every path, hash, handle and rectangle here is made up; the real allow-list is
private configuration and never enters the repository.
"""

from __future__ import annotations

import dataclasses
import json
import os
from types import SimpleNamespace

import pytest
from PIL import Image

from psoperator.config import load_config
from psoperator.gatekeeper import gatekeeper as gatekeeper_module
from psoperator.gatekeeper.audit import verify
from psoperator.gatekeeper.bound_target import (
    AllowedPath,
    AllowedStep,
    AllowList,
    AllowListError,
    BoundKeyRequest,
    Code,
    FocusedEdit,
    Observation,
    OcrBox,
    ScreenSignature,
    audited_keys,
    bound_key_problem,
    observed_fields,
    signature_of,
    signature_problem,
    unchanged,
    unverified_record,
    valid_key,
)
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.gatekeeper.risk import RiskAssessment, RiskTier
from psoperator.perception.capture import Frame
from psoperator.perception.win32_fields import Win32Field, WindowNode
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker

APP = (4242, 7)  # (pid, process start time)
MAIN, SCROLLER, PANEL, EDIT, OTHER = 0x10, 0x20, 0x25, 0x30, 0x40
A, B, C, D, E = "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64
EDIT_RECT = (140, 130, 200, 24)


def _tree(edit_rect=EDIT_RECT, edit_visible=True, parent_visible=True, client=True, label=A):
    viewport = (100, 100, 400, 200)
    x, y, w, h = edit_rect
    panel = WindowNode("wxWindowClassNR", (x - 33, y, 33, h), name_hash=label, hwnd=PANEL)
    edit = WindowNode("Edit", edit_rect, hwnd=EDIT, visible=edit_visible, client_rect=edit_rect)
    scroller = WindowNode(
        "wxScrolled", viewport, hwnd=SCROLLER, visible=parent_visible,
        client_rect=viewport if client else None, children=(panel, edit),
    )  # fmt: skip
    main = (100, 100, 800, 600)
    return WindowNode("wxWindowNR", main, hwnd=MAIN, client_rect=main, children=(scroller,))


def _sig(focus=("Edit", (40, 30, 200, 24)), edits=((40, 30, 200, 24),), captions=None,
         labelled=None, owned=0):  # fmt: skip
    return ScreenSignature(
        owned_windows=owned,
        focus_class=focus[0],
        focus_rect=focus[1],
        edit_rects=edits,
        captions=captions if captions is not None else ((A, (7, 30, 33, 24)),),
        labelled=labelled if labelled is not None else ((A, (40, 30, 200, 24)),),
    )


REPORT = _sig()
NEIGHBOUR = _sig(captions=((C, (7, 30, 33, 24)),), labelled=((C, (40, 30, 200, 24)),))
MOVED_CAPTION = _sig(captions=((A, (7, 60, 33, 24)),))  # same hash, other place
HOME = _sig(focus=("Edit", (10, 10, 24, 28)), edits=((10, 10, 24, 28),),
            captions=((D, (0, 0, 30, 20)),), labelled=())  # fmt: skip
MENU = _sig(focus=("Edit", (60, 40, 600, 28)), edits=((60, 40, 600, 28),),
            captions=((D, (5, 5, 30, 20)),), labelled=())  # fmt: skip
SUBMENU = _sig(focus=("Edit", (60, 40, 600, 28)), edits=((60, 40, 600, 28),),
               captions=((E, (5, 5, 30, 20)),), labelled=())  # fmt: skip

ALLOW = AllowList(
    [
        AllowedPath(
            "9-9", (AllowedStep(HOME, "9", (MENU,)), AllowedStep(REPORT, "ENTER", (NEIGHBOUR,)))
        )
    ]
)

FIELD = Win32Field(
    pid=4242, process_started=7, process_image="app.exe",
    class_path=("wxWindowNR", "wxScrolled", "Edit"), label_hash=A, rect=(40, 30, 200, 24),
    label_rect=(7, 30, 33, 24), screen_rect=EDIT_RECT, hwnd=EDIT,
)  # fmt: skip


def _obs(**change) -> Observation:
    values = dict(
        at=100.0, main_hwnd=MAIN, instance=APP, image="app.exe", foreground_hwnd=MAIN,
        topmost_hwnd=MAIN, focus_hwnd=EDIT, input_clear=True, point=(240, 142),
        signature=REPORT, tree=_tree(),
    )  # fmt: skip
    values.update(change)
    return Observation(**values)


def _req(**change) -> BoundKeyRequest:
    values = dict(
        action=Action(ActionKind.KEY, 1, keys=("ENTER",)), path="9-9", step=1, target=FIELD,
    )  # fmt: skip
    values.update(change)
    return BoundKeyRequest(**values)


def _keys(*keys) -> BoundKeyRequest:
    return _req(action=Action(ActionKind.KEY, 1, keys=keys))


def _tgt(**change) -> BoundKeyRequest:
    return _req(target=dataclasses.replace(FIELD, **change))


TYPING = _req(action=Action(ActionKind.TYPE, 1, text="secret value"))
BROKEN = _req(action=SimpleNamespace(kind=ActionKind.KEY, keys=None))
MENU_STEP = AllowedStep(MENU, "9", (SUBMENU,))
MENU_STEP_8 = AllowedStep(MENU, "8", (SUBMENU,))


def _check(req=None, obs=None, now=100.5, allow=ALLOW):
    return bound_key_problem(
        req or _req(), allow, obs or _obs(), now=now, max_age_s=1.0, app_image="app.exe",
        main_hwnd=MAIN, instance=APP,
    )  # fmt: skip


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
        dict(captions=((A,),)),
        dict(captions=[(A, (1, 2, 3, 4))]),
    ],
    ids=["bool-count", "negative-count", "zero-size-focus", "bad-class", "short-rect",
         "list-not-tuple", "bad-hash", "negative-size", "caption-without-place", "caption-list"],
)  # fmt: skip
def test_a_malformed_signature_cannot_be_built(change):
    with pytest.raises(ValueError):
        _sig(**change)


def test_a_signature_is_order_insensitive_but_position_sensitive():
    two = _sig(captions=((A, (7, 30, 33, 24)), (B, (7, 60, 33, 24))))
    reordered = _sig(captions=((B, (7, 60, 33, 24)), (A, (7, 30, 33, 24))))
    assert two == reordered
    assert signature_problem(REPORT, MOVED_CAPTION) == "captions"


@pytest.mark.parametrize(
    "observed, part",
    [
        (_sig(owned=1), "dialogs"),
        (_sig(focus=("Button", (40, 30, 200, 24))), "focus"),
        (_sig(focus=("Edit", (41, 30, 200, 24))), "focus"),
        (_sig(edits=((40, 30, 200, 24), (40, 60, 200, 24))), "edits"),
        (MOVED_CAPTION, "captions"),
        (NEIGHBOUR, "captions"),
        (_sig(labelled=((A, (40, 60, 200, 24)),)), "labels"),
    ],
    ids=["dialog", "focus-class", "focus-moved", "extra-edit", "caption-moved",
         "other-captions", "label-elsewhere"],
)  # fmt: skip
def test_each_screen_difference_is_found(observed, part):
    assert signature_problem(REPORT, observed) == part


def test_a_signature_carries_no_text():
    assert {f.name for f in dataclasses.fields(ScreenSignature)} == {
        "owned_windows", "focus_class", "focus_rect", "edit_rects", "captions", "labelled",
    }  # fmt: skip


def test_the_signature_and_fields_of_an_observed_tree():
    tree = _tree()
    assert signature_of(tree, EDIT, 0, instance=APP, image="app.exe") == REPORT
    assert observed_fields(tree, APP, "app.exe") == (FIELD,)
    with pytest.raises(ValueError, match="focus"):
        signature_of(tree, OTHER, 0, instance=APP, image="app.exe")


def test_a_menu_without_fields_is_told_apart_by_its_captions():
    # A menu-shaped screen: one wide Edit (the menu's search box) and captions
    # that label no field. Only the captions' hashes and places tell menus apart.
    def menu(caption):
        heading = WindowNode("wxWindowClassNR", (105, 105, 30, 20), name_hash=caption, hwnd=PANEL)
        box = WindowNode("Edit", (160, 140, 600, 28), hwnd=EDIT, client_rect=(160, 140, 600, 28))
        main = (100, 100, 800, 600)
        return WindowNode("wxWindowNR", main, hwnd=MAIN, client_rect=main, children=(heading, box))

    assert observed_fields(menu(D), APP, "app.exe") == ()
    assert signature_of(menu(D), EDIT, 0, instance=APP, image="app.exe") == MENU
    assert signature_of(menu(E), EDIT, 0, instance=APP, image="app.exe") == SUBMENU
    assert MENU != SUBMENU


# --- the allow-list ------------------------------------------------------------------


def test_menu_screens_without_fields_are_told_apart_by_their_captions():
    assert signature_problem(MENU, SUBMENU) == "captions"
    menus = AllowList([AllowedPath("9-9", (AllowedStep(MENU, "9", (SUBMENU,)),))])
    assert menus.problem("9-9", 0, "9", MENU) is None
    assert menus.problem("9-9", 0, "9", SUBMENU).code is Code.SCREEN


@pytest.mark.parametrize(
    "build, match",
    [
        (lambda: AllowedStep(_sig(captions=()), "ENTER", (NEIGHBOUR,)), "screen-specific"),
        (lambda: AllowedStep(REPORT, "ENTER", ()), "neighbouring screen"),
        (lambda: AllowedStep(REPORT, "ENTER", [NEIGHBOUR]), "neighbouring screen"),
        (lambda: AllowedStep(REPORT, "ENTER", (REPORT,)), "equals the expected"),
        (lambda: AllowedStep(REPORT, "enter", (NEIGHBOUR,)), "recognised key"),
        (lambda: AllowedStep("not a signature", "ENTER", (NEIGHBOUR,)), "complete expected"),
        (lambda: AllowedPath("9-9", ()), "no steps"),
        (lambda: AllowedPath("9 9; anything", (AllowedStep(MENU, "9", (SUBMENU,)),)), "path code"),
        (lambda: AllowedPath("9-9", [AllowedStep(MENU, "9", (SUBMENU,))]), "no steps"),
        (lambda: AllowList(["9-9"]), "AllowedPath"),
        (lambda: AllowList([AllowedPath("9-9", (MENU_STEP,))] * 2), "twice"),
        (lambda: AllowList([AllowedPath("9-9", (MENU_STEP, MENU_STEP_8))]),
         "same screen"),
    ],
    ids=["no-captions", "no-neighbours", "neighbours-list", "neighbour-equals", "bad-key",
         "no-signature", "no-steps", "bad-path", "list-steps", "not-a-path", "twice",
         "same-screen"],
)  # fmt: skip
def test_the_constructors_are_strict(build, match):
    with pytest.raises(AllowListError, match=match):
        build()


def test_each_step_admits_only_its_key_on_its_screen():
    assert ALLOW.problem("9-9", 0, "9", HOME) is None
    assert ALLOW.problem("9-9", 1, "ENTER", REPORT) is None


@pytest.mark.parametrize(
    "args, code",
    [
        (("9-8", 0, "9", HOME), Code.NO_PATH),
        ((None, 0, "9", HOME), Code.NO_PATH),
        (("9-9", 2, "ENTER", REPORT), Code.NO_STEP),
        (("9-9", -1, "9", HOME), Code.NO_STEP),
        (("9-9", True, "ENTER", REPORT), Code.NO_STEP),
        (("9-9", 0, "8", HOME), Code.WRONG_KEY),
        (("9-9", 0, "0", HOME), Code.WRONG_KEY),
        (("9-9", 1, "ENTER", NEIGHBOUR), Code.SCREEN),
        (("9-9", 1, "ENTER", MOVED_CAPTION), Code.SCREEN),
        (("9-9", 1, "ENTER", HOME), Code.SCREEN),
    ],
    ids=["unknown-path", "no-path", "past-the-end", "negative-step", "bool-step", "wrong-key",
         "console-key", "recorded-neighbour", "caption-moved", "wrong-screen"],
)  # fmt: skip
def test_everything_else_is_refused(args, code):
    assert ALLOW.problem(*args).code is code


def test_a_recorded_neighbour_is_named():
    refusal = ALLOW.problem("9-9", 1, "ENTER", NEIGHBOUR)
    assert refusal.code is Code.SCREEN and "neighbouring" in refusal.detail


def _screen(sig):
    return {
        "owned_windows": sig.owned_windows,
        "focus_class": sig.focus_class,
        "focus_rect": list(sig.focus_rect),
        "edit_rects": [list(r) for r in sig.edit_rects],
        "captions": [[h, list(r)] for h, r in sig.captions],
        "labelled": [[h, list(r)] for h, r in sig.labelled],
    }


def _doc(expected=None, key="ENTER", neighbours=None, step_extra=None, path_extra=None,
         root_extra=None):  # fmt: skip
    step = {
        "key": key,
        "expected": expected if expected is not None else _screen(REPORT),
        "neighbours": neighbours if neighbours is not None else [_screen(NEIGHBOUR)],
    }
    step.update(step_extra or {})
    path = {"path": "9-9", "steps": [step]}
    path.update(path_extra or {})
    doc = {"paths": [path]}
    doc.update(root_extra or {})
    return json.dumps(doc)


def test_the_allow_list_loads_from_private_json(tmp_path):
    file = tmp_path / "allow.json"
    file.write_text(_doc(), encoding="utf-8")
    loaded = AllowList.load(file)
    assert loaded.problem("9-9", 0, "ENTER", REPORT) is None
    assert loaded.problem("9-9", 0, "ENTER", NEIGHBOUR).code is Code.SCREEN


def _screen_with(**change):
    screen = _screen(REPORT)
    screen.update(change)
    return screen


_MALFORMED = {
    "unparseable": "{not json",
    "duplicate-member": '{"paths": [], "paths": []}',
    "unknown-root-field": _doc(root_extra={"note": 1}),
    "unknown-path-field": _doc(path_extra={"note": 1}),
    "unknown-step-field": _doc(step_extra={"note": 1}),
    "null-step": json.dumps({"paths": [{"path": "9-9", "steps": [None]}]}),
    "missing-neighbours": json.dumps({"paths": [{"path": "9-9", "steps": [
        {"key": "ENTER", "expected": _screen(REPORT)}]}]}),
    "empty-neighbours": _doc(neighbours=[]),
    "neighbours-not-a-list": _doc(neighbours={}),
    "neighbour-equals-expected": _doc(neighbours=[_screen(REPORT)]),
    "missing-focus": _doc(expected={k: v for k, v in _screen(REPORT).items() if k != "focus_rect"}),
    "bool-count": _doc(expected=_screen_with(owned_windows=False)),
    "string-count": _doc(expected=_screen_with(owned_windows="0")),
    "float-rect": _doc(expected=_screen_with(focus_rect=[40.0, 30, 200, 24])),
    "zero-size-rect": _doc(expected=_screen_with(edit_rects=[[40, 30, 0, 24]])),
    "bad-hash": _doc(expected=_screen_with(labelled=[["abc", [40, 30, 200, 24]]])),
    "labelled-shape": _doc(expected=_screen_with(labelled=[[A]])),
    "no-captions": _doc(expected=_screen_with(captions=[])),
    "caption-without-place": _doc(expected=_screen_with(captions=[A])),
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


def test_a_fully_bound_key_is_admitted_with_observed_identity():
    identity, refusal = _check()
    assert refusal is None
    assert identity == {
        "kind": "win32-field", "class_path": ["wxWindowNR", "wxScrolled", "Edit"],
        "label_hash": A, "rect": [40, 30, 200, 24], "label_rect": [7, 30, 33, 24],
        "process_image": "app.exe", "instance": [4242, 7], "screen_rect": list(EDIT_RECT),
    }  # fmt: skip


def test_a_focused_edit_target_is_admitted_and_must_be_where_focus_is():
    identity, refusal = _check(_req(target=FocusedEdit((40, 30, 200, 24))))
    assert refusal is None and identity["kind"] == "focused-edit"
    _, refusal = _check(_req(target=FocusedEdit((40, 31, 200, 24))))
    assert refusal.code is Code.NOT_FOCUSED


FOCUSED = FocusedEdit((40, 30, 200, 24))
AT_FOCUS = _req(target=FOCUSED)
AT_ROOT = _req(target=FocusedEdit((0, 0, 200, 24)))
HIDDEN_EDIT = _tree(edit_visible=False)
HIDDEN_PARENT = _tree(parent_visible=False)
EDIT_ROOT = WindowNode("Edit", EDIT_RECT, hwnd=MAIN, client_rect=EDIT_RECT)
ROOT_FOCUS = _obs(focus_hwnd=MAIN, tree=EDIT_ROOT)

_REFUSALS = {
    "typing": (dict(req=TYPING), Code.NOT_KEY),
    "chord": (dict(req=_keys("ctrl", "y")), Code.CHORD),
    "unrecognised-key": (dict(req=_keys("enter")), Code.BAD_KEY),
    "stale": (dict(now=101.5), Code.STALE),
    "from-the-future": (dict(now=99.0), Code.STALE),
    "other-instance": (dict(obs=_obs(instance=(4242, 8))), Code.INSTANCE),
    "other-main-window": (dict(obs=_obs(main_hwnd=OTHER)), Code.INSTANCE),
    "other-application": (dict(obs=_obs(image="other.exe")), Code.WRONG_APP),
    "menu-mode": (dict(obs=_obs(input_clear=False)), Code.INPUT_MODE),
    "covered": (dict(obs=_obs(topmost_hwnd=OTHER)), Code.COVERED),
    "same-process-popup-in-front": (dict(obs=_obs(foreground_hwnd=OTHER)), Code.NOT_FOREGROUND),
    "recorded-neighbour": (dict(obs=_obs(signature=NEIGHBOUR)), Code.SCREEN),
    "not-allowed-path": (dict(req=_req(path="9-8")), Code.NO_PATH),
    "no-target": (dict(req=_req(target=None)), Code.NO_TARGET),
    "ocr-target": (dict(req=_req(target=OcrBox((1, 2, 3, 4)))), Code.UNSUPPORTED),
    "field-of-old-instance": (dict(req=_tgt(process_started=6)), Code.TARGET_MISMATCH),
    "claimed-identity": (dict(req=_tgt(process_image="claimed.exe")), Code.TARGET_MISMATCH),
    "claimed-label": (dict(req=_tgt(label_hash=B)), Code.TARGET_MISMATCH),
    "claimed-class-path": (dict(req=_tgt(class_path=("x", "Edit"))), Code.TARGET_MISMATCH),
    "claimed-geometry": (dict(req=_tgt(screen_rect=(141, 130, 200, 24))), Code.TARGET_MISMATCH),
    "focus-elsewhere": (dict(obs=_obs(focus_hwnd=PANEL)), Code.TARGET_MISMATCH),
    "focus-not-in-tree": (dict(obs=_obs(focus_hwnd=OTHER)), Code.NOT_FOCUSED),
    "field-not-focused": (dict(req=_tgt(hwnd=OTHER)), Code.NOT_FOCUSED),
    "focus-on-the-root": (dict(obs=_obs(focus_hwnd=MAIN, tree=EDIT_ROOT)), Code.NOT_FOCUSED),
    # Even a main window that is itself an Edit, aimed at as a focused Edit at
    # its own place: the root is the container, never the target.
    "root-as-focused-edit": (dict(req=AT_ROOT, obs=ROOT_FOCUS), Code.NOT_FOCUSED),
    "point-outside-field": (dict(obs=_obs(point=(90, 90))), Code.TARGET_MISMATCH),
    "target-hidden": (dict(req=AT_FOCUS, obs=_obs(tree=HIDDEN_EDIT)), Code.HIDDEN),
    "hidden-field-unseen": (dict(obs=_obs(tree=HIDDEN_EDIT)), Code.TARGET_MISMATCH),
    "ancestor-hidden": (dict(req=AT_FOCUS, obs=_obs(tree=HIDDEN_PARENT)), Code.HIDDEN),
    "client-area-unknown": (dict(obs=_obs(tree=_tree(client=False))), Code.GEOMETRY),
    "malformed-action": (dict(req=BROKEN), Code.CHORD),
}  # fmt: skip


@pytest.mark.parametrize("args, code", list(_REFUSALS.values()), ids=list(_REFUSALS))
def test_every_gap_is_refused(args, code):
    identity, refusal = _check(**args)
    assert identity is None and refusal is not None and refusal.code is code


def _allow_for(obs: Observation) -> AllowList:
    step = AllowedStep(obs.signature, "ENTER", (NEIGHBOUR,))
    return AllowList([AllowedPath("9-9", (HOME_STEP, step))])


HOME_STEP = AllowedStep(HOME, "9", (MENU,))


@pytest.mark.parametrize(
    "edit_rect",
    [(140, 320, 200, 24), (140, 290, 200, 24), (140, 90, 200, 24), (450, 130, 200, 24)],
    ids=["scrolled-below", "half-below", "half-above", "past-the-right-edge"],
)  # fmt: skip
def test_a_scrolled_out_field_is_refused(edit_rect):
    tree = _tree(edit_rect=edit_rect)
    (field,) = observed_fields(tree, APP, "app.exe")
    sig = signature_of(tree, EDIT, 0, instance=APP, image="app.exe")
    point = (edit_rect[0] + edit_rect[2] // 2, edit_rect[1] + edit_rect[3] // 2)
    obs = _obs(tree=tree, signature=sig, point=point)
    _, refusal = _check(_req(target=field), obs, allow=_allow_for(obs))
    assert refusal is not None and refusal.code is Code.CLIPPED


def test_two_observations_must_agree():
    assert unchanged(_obs(), _obs(at=100.3))
    for change in (
        dict(focus_hwnd=OTHER),
        dict(foreground_hwnd=OTHER),
        dict(topmost_hwnd=OTHER),
        dict(input_clear=False),
        dict(signature=NEIGHBOUR),
        dict(instance=(4242, 8)),
        dict(image="other.exe"),
        dict(point=(241, 142)),
    ):
        assert not unchanged(_obs(), _obs(**change)), change


# --- the audit -------------------------------------------------------------------------


def test_an_unverified_target_is_recorded_by_kind_only():
    hostile = dataclasses.replace(FIELD, process_image="secret", class_path=("secret",))
    record = unverified_record(hostile, "f" * 64)
    assert record == {"kind": "win32-field", "verified": False, "frame_hash": "f" * 64}
    assert unverified_record(OcrBox((1, 2, 3, 4)), "x")["frame_hash"] == "<invalid>"
    assert unverified_record("anything", "f" * 64)["kind"] == "none"


def test_audited_keys_are_recognised_names_only():
    assert audited_keys(Action(ActionKind.KEY, 1, keys=("ENTER",))) == ["ENTER"]
    assert audited_keys(Action(ActionKind.KEY, 1, keys=("ctrl", "secret"))) == ["<invalid>"] * 2
    assert audited_keys(SimpleNamespace(keys=None)) == ["<invalid>"]
    assert audited_keys(None) == ["<invalid>"]


# --- through the gatekeeper ------------------------------------------------------------


class _Recorder:
    name = "recorder"

    def __init__(self):
        self.calls = []

    def execute(self, action):
        self.calls.append(action)
        return "secret outcome text"


class Observer:
    """Returns the given observations in turn (the last repeats)."""

    def __init__(self, *observations, fail=False):
        self.observations = list(observations) or [_obs()]
        self.calls = []
        self._fail = fail

    def __call__(self, main_hwnd):
        self.calls.append(main_hwnd)
        if self._fail:
            raise RuntimeError("secret observer text")
        return self.observations[min(len(self.calls) - 1, len(self.observations) - 1)]


def _then(**change) -> Observer:
    """A valid first observation, then a changed one just before sending."""
    return Observer(_obs(), _obs(**change))


def _frame(fid=1):
    return Frame.from_image(fid, Image.new("RGB", (64, 64), (10, 20, 30)))


def _gatekeeper(tmp_path, observer=None, **kwargs):
    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl", kill_switch_path=tmp_path / "STOP"
    )
    freshness = FreshnessTracker()
    freshness.observe(1)
    recorder = _Recorder()
    settings = dict(
        bound_observer=observer if observer is not None else Observer(), clock=lambda: 100.5,
        bound_allow=ALLOW, bound_app_image="app.exe", bound_window=(MAIN, APP),
    )  # fmt: skip
    settings.update(kwargs)
    gk = Gatekeeper(config, freshness, executor=recorder, **settings)
    return gk, config, recorder


def _audit(config):
    lines = config.audit_log_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_an_admitted_key_is_observed_twice_executed_once_and_audited(tmp_path):
    observer = Observer()
    gk, config, recorder = _gatekeeper(tmp_path, observer)
    decision = gk.request_bound_key(_req(), _frame())
    assert decision.kind is DecisionKind.EXECUTED
    assert observer.calls == [MAIN, MAIN] and len(recorder.calls) == 1
    entry = _audit(config)[-1]
    binding = entry["action"]["binding"]
    assert binding["verified"] is True and binding["label_hash"] == A
    assert binding["process_image"] == "app.exe" and binding["frame_hash"] == _frame().sha256
    assert entry["action"]["keys"] == ["ENTER"] and entry["reason"] == "executed"
    assert "secret" not in config.audit_log_path.read_text(encoding="utf-8")
    assert verify(config.audit_log_path).ok


class _Shifting:
    """A request whose ``action`` is a different key on every read."""

    def __init__(self, *actions):
        self.actions = list(actions)
        self.reads = 0
        self.path, self.step, self.target = "9-9", 1, FIELD

    @property
    def action(self):
        self.reads += 1
        return self.actions[(self.reads - 1) % len(self.actions)]


def test_the_action_checked_is_the_action_executed(tmp_path):
    enter = Action(ActionKind.KEY, 1, keys=("ENTER",))
    chord = Action(ActionKind.KEY, 1, keys=("ctrl", "y"))
    request = _Shifting(enter, chord)
    gk, config, recorder = _gatekeeper(tmp_path)
    decision = gk.request_bound_key(request, _frame())
    assert decision.kind is DecisionKind.EXECUTED and request.reads == 1
    assert [a.keys for a in recorder.calls] == [("ENTER",)]
    assert recorder.calls[0] is not enter  # a private copy was executed
    assert _audit(config)[-1]["action"]["keys"] == ["ENTER"]
    # Read first as the chord, the same request is refused and nothing runs.
    request = _Shifting(chord, enter)
    gk, _, recorder = _gatekeeper(tmp_path)
    decision = gk.request_bound_key(request, _frame())
    assert decision.reason == Code.CHORD.value and recorder.calls == [] and request.reads == 1


class _ActionLike(Action):
    pass


@pytest.mark.parametrize(
    "request_",
    [
        SimpleNamespace(action=_ActionLike(ActionKind.KEY, 1, keys=("ENTER",)), path="9-9",
                        step=1, target=FIELD),
        SimpleNamespace(action=Action(ActionKind.KEY, 1, keys=["ENTER"]), path="9-9", step=1,
                        target=FIELD),
        SimpleNamespace(action=Action(ActionKind.KEY, 1, keys=("ENTER",)), path=["9-9"],
                        step=1, target=FIELD),
        SimpleNamespace(action=Action(ActionKind.KEY, 1, keys=("ENTER",)), path="9-9",
                        step=True, target=FIELD),
        SimpleNamespace(action=Action(ActionKind.KEY, 1, keys=("ENTER",)), path="9-9", step=1,
                        target="the field"),
    ],
    ids=["action-subclass", "keys-list", "path-list", "step-bool", "target-text"],
)  # fmt: skip
def test_a_request_that_is_not_plainly_a_key_request_is_refused(tmp_path, request_):
    gk, _, recorder = _gatekeeper(tmp_path)
    decision = gk.request_bound_key(request_, _frame())
    assert decision.reason == Code.INVALID.value and recorder.calls == []


def test_the_window_and_instance_are_fixed_at_construction(tmp_path):
    with pytest.raises(TypeError):
        BoundKeyRequest(
            action=Action(ActionKind.KEY, 1, keys=("ENTER",)), path="9-9", step=1,
            target=FIELD, main_hwnd=OTHER,
        )  # fmt: skip
    # Another window or instance of the same application, showing the same
    # signature, is refused: the gatekeeper observes only its bound window.
    for other in (_obs(main_hwnd=OTHER), _obs(instance=(4242, 8)), _obs(instance=(99, 7))):
        observer = Observer(other)
        gk, _, recorder = _gatekeeper(tmp_path, observer)
        decision = gk.request_bound_key(_req(), _frame())
        assert decision.reason == Code.INSTANCE.value and recorder.calls == []
        assert observer.calls == [MAIN]
    observer = Observer(_obs(main_hwnd=OTHER, foreground_hwnd=OTHER, topmost_hwnd=OTHER))
    gk, _, recorder = _gatekeeper(tmp_path, observer, bound_window=(OTHER, APP))
    assert gk.request_bound_key(_req(), _frame()).kind is DecisionKind.EXECUTED
    assert observer.calls == [OTHER, OTHER]


@pytest.mark.parametrize(
    "missing", ["bound_observer", "bound_allow", "bound_app_image", "bound_window"]
)
def test_without_full_configuration_nothing_is_admitted(tmp_path, missing):
    gk, _, recorder = _gatekeeper(tmp_path, **{missing: None})
    decision = gk.request_bound_key(_req(), _frame())
    assert decision.kind is DecisionKind.DENIED and decision.reason == Code.NO_OBSERVER.value
    assert recorder.calls == []


def test_the_allow_list_observer_and_clock_cannot_come_from_the_request(tmp_path):
    gk, _, recorder = _gatekeeper(tmp_path)
    permissive = AllowList([AllowedPath("9-8", (AllowedStep(REPORT, "ENTER", (NEIGHBOUR,)),))])
    with pytest.raises(TypeError):
        gk.request_bound_key(_req(path="9-8"), _frame(), permissive)
    with pytest.raises(TypeError):
        gk.request_bound_key(_req(), _frame(), allow=permissive)
    with pytest.raises(TypeError):
        gk.request_bound_key(_req(), _frame(), Observer())
    with pytest.raises(TypeError):
        gk.request_bound_key(_req(), _frame(), clock=lambda: 0.0)
    # A path only another allow-list would admit is refused by the configured one.
    decision = gk.request_bound_key(_req(path="9-8"), _frame())
    assert decision.reason == Code.NO_PATH.value and recorder.calls == []


def test_another_application_is_refused_at_the_gatekeeper(tmp_path):
    gk, _, recorder = _gatekeeper(tmp_path, Observer(_obs(image="other.exe")))
    decision = gk.request_bound_key(_req(), _frame())
    assert decision.reason == Code.WRONG_APP.value and recorder.calls == []


_GATEKEEPER_REFUSALS = {
    "typing": (dict(req=TYPING), Code.NOT_KEY),
    "hostile-key": (dict(req=_keys("secret key")), Code.BAD_KEY),
    "hostile-path": (dict(req=_req(path="secret path text")), Code.NO_PATH),
    "hostile-identity": (dict(req=_tgt(process_image="secret")), Code.TARGET_MISMATCH),
    "covered": (dict(observer=Observer(_obs(topmost_hwnd=OTHER))), Code.COVERED),
    "menu-mode": (dict(observer=Observer(_obs(input_clear=False))), Code.INPUT_MODE),
    "neighbour": (dict(observer=Observer(_obs(signature=NEIGHBOUR))), Code.SCREEN),
    "observer-fails": (dict(observer=Observer(fail=True)), Code.OBSERVE_FAILED),
    "malformed-action": (dict(req=BROKEN), Code.INVALID),
    "focus-before-send": (dict(observer=_then(focus_hwnd=OTHER)), Code.NOT_FOCUSED),
    "screen-before-send": (dict(observer=_then(signature=MOVED_CAPTION)), Code.SCREEN),
    "menu-before-send": (dict(observer=_then(input_clear=False)), Code.INPUT_MODE),
    "dialog-before-send": (dict(observer=_then(foreground_hwnd=OTHER)), Code.NOT_FOREGROUND),
}  # fmt: skip


@pytest.mark.parametrize(
    "args, code", list(_GATEKEEPER_REFUSALS.values()), ids=list(_GATEKEEPER_REFUSALS)
)
def test_a_refused_key_never_executes_and_the_audit_holds_a_code_not_text(tmp_path, args, code):
    gk, config, recorder = _gatekeeper(tmp_path, args.get("observer"))
    decision = gk.request_bound_key(args.get("req", _req()), _frame())
    assert decision.kind is DecisionKind.DENIED and decision.reason.startswith(code.value)
    assert recorder.calls == []
    entry = _audit(config)[-1]
    assert entry["reason"] == code.value
    assert "secret" not in config.audit_log_path.read_text(encoding="utf-8")


def test_a_change_between_check_and_send_is_refused_even_if_still_allowed(tmp_path):
    moved = _obs(point=(241, 142))  # still a valid observation, just not the one checked
    gk, _, recorder = _gatekeeper(tmp_path, Observer(_obs(), moved))
    decision = gk.request_bound_key(_req(), _frame())
    assert decision.kind is DecisionKind.DENIED and decision.reason == Code.CHANGED.value
    assert recorder.calls == []


def test_a_change_during_approval_is_caught_by_the_second_observation(tmp_path, monkeypatch):
    # Force approval, and let the screen change while the human decides.
    observer = Observer(_obs())
    approvals = []

    class _Approves:
        name = "approves"

        def request(self, req, timeout_s=120.0):
            approvals.append(req)
            observer.observations = [_obs(foreground_hwnd=OTHER)]
            return True

    monkeypatch.setattr(
        gatekeeper_module,
        "classify",
        lambda *a, **k: RiskAssessment(RiskTier.T2_SENSITIVE, ("forced for the test",)),
    )
    gk, _, recorder = _gatekeeper(tmp_path, observer, approval_backend=_Approves())
    decision = gk.request_bound_key(_req(), _frame())
    assert len(approvals) == 1 and len(observer.calls) == 2
    assert decision.kind is DecisionKind.DENIED and decision.reason == Code.NOT_FOREGROUND.value
    assert recorder.calls == []


class _Explodes:
    def __getattr__(self, name):
        raise RuntimeError("secret attribute text")


def test_a_kill_switch_engaged_during_approval_stops_the_key(tmp_path, monkeypatch):
    config_holder = {}

    class _EngagesThenApproves:
        name = "engages"

        def request(self, req, timeout_s=120.0):
            config_holder["config"].kill_switch_path.write_text("stop", encoding="utf-8")
            return True

    monkeypatch.setattr(
        gatekeeper_module,
        "classify",
        lambda *a, **k: RiskAssessment(RiskTier.T2_SENSITIVE, ("forced for the test",)),
    )
    gk, config, recorder = _gatekeeper(tmp_path, approval_backend=_EngagesThenApproves())
    config_holder["config"] = config
    decision = gk.request_bound_key(_req(), _frame())
    assert decision.kind is DecisionKind.KILL_SWITCHED and recorder.calls == []


def test_a_kill_switch_engaged_during_the_last_observation_stops_the_key(tmp_path):
    holder = {}

    class _EngagingObserver(Observer):
        def __call__(self, main_hwnd):
            obs = super().__call__(main_hwnd)
            if len(self.calls) == 2:
                holder["config"].kill_switch_path.write_text("stop", encoding="utf-8")
            return obs

    gk, config, recorder = _gatekeeper(tmp_path, _EngagingObserver())
    holder["config"] = config
    decision = gk.request_bound_key(_req(), _frame())
    assert decision.kind is DecisionKind.KILL_SWITCHED and recorder.calls == []


class _HostileAction:
    @property
    def kind(self):
        raise RuntimeError("secret kind text")

    @property
    def keys(self):
        raise RuntimeError("secret keys text")

    @property
    def frame_id(self):
        raise RuntimeError("secret frame text")


def test_an_action_whose_properties_raise_is_refused_and_recorded(tmp_path):
    gk, config, recorder = _gatekeeper(tmp_path)
    decision = gk.request_bound_key(_req(action=_HostileAction()), _frame())
    assert decision.kind is DecisionKind.DENIED and recorder.calls == []
    entry = _audit(config)[-1]
    assert entry["action"]["action"] == "<invalid>" and entry["action"]["keys"] == ["<invalid>"]
    assert "secret" not in config.audit_log_path.read_text(encoding="utf-8")


def test_the_kill_switch_is_checked_before_the_request_is_read(tmp_path):
    observer = Observer()
    gk, config, recorder = _gatekeeper(tmp_path, observer)
    config.kill_switch_path.write_text("stop", encoding="utf-8")
    for req in (_req(), _req(path="9-8"), _Explodes(),
                _req(action=SimpleNamespace(kind="x", keys=None))):  # fmt: skip
        assert gk.request_bound_key(req, _frame()).kind is DecisionKind.KILL_SWITCHED
    assert observer.calls == [] and recorder.calls == []
    raw = config.audit_log_path.read_text(encoding="utf-8")
    assert "secret" not in raw and all(e["decision"] == "kill-switched" for e in _audit(config))


def test_a_request_that_explodes_is_refused_and_audited(tmp_path):
    gk, config, recorder = _gatekeeper(tmp_path)
    decision = gk.request_bound_key(_Explodes(), _frame())
    assert decision.kind is DecisionKind.DENIED and recorder.calls == []
    assert "secret" not in config.audit_log_path.read_text(encoding="utf-8")


def test_bound_input_only_closes_the_ordinary_path(tmp_path):
    gk, config, recorder = _gatekeeper(tmp_path, bound_input_only=True)
    for action in (
        Action(ActionKind.KEY, 1, keys=("ENTER",)),
        Action(ActionKind.TYPE, 1, text="x"),
        Action(ActionKind.CLICK, 1, x=1, y=1),
    ):
        decision = gk.request_action(action, _frame())
        assert decision.kind is DecisionKind.DENIED and "bound-target gate" in decision.reason
    with pytest.raises(TypeError):
        gk.request_action(Action(ActionKind.KEY, 1, keys=("ENTER",)), _frame(), _bound=True)
    with pytest.raises(TypeError):
        gk.request_action(Action(ActionKind.KEY, 1, keys=("ENTER",)), _frame(), binding={})
    assert recorder.calls == []
    assert gk.request_action(Action(ActionKind.WAIT, 1, seconds=0.1), _frame()).approved
    assert gk.request_bound_key(_req(), _frame()).kind is DecisionKind.EXECUTED
    assert [a.kind for a in recorder.calls] == [ActionKind.WAIT, ActionKind.KEY]


@pytest.mark.parametrize(
    "action",
    [
        Action(ActionKind.CLICK, 1, x=1, y=1),
        Action(ActionKind.RIGHT_CLICK, 1, x=1, y=1),
        Action(ActionKind.DOUBLE_CLICK, 1, x=1, y=1),
        Action(ActionKind.TYPE, 1, text="x"),
        Action(ActionKind.KEY, 1, keys=("ENTER",)),
        Action(ActionKind.SCROLL, 1, amount=-3),
        Action(ActionKind.DRAG, 1, x=1, y=1, to_x=5, to_y=5),
    ],
    ids=lambda a: a.kind.value,
)
def test_bound_input_only_refuses_every_device_input_kind(tmp_path, action):
    gk, _, recorder = _gatekeeper(tmp_path, bound_input_only=True)
    decision = gk.request_action(action, _frame())
    assert decision.kind is DecisionKind.DENIED and "bound-target gate" in decision.reason
    assert recorder.calls == []


@pytest.mark.parametrize(
    "readings, kind",
    [
        ((True, False, False, False), DecisionKind.KILL_SWITCHED),
        ((False, True, False, False), DecisionKind.DENIED),
        ((False, False, False, False), DecisionKind.DENIED),
    ],
    ids=["on-then-off", "off-on-off", "off"],
)
def test_a_flipping_kill_switch_never_lets_unbound_input_through(
    tmp_path, monkeypatch, readings, kind
):
    # Whatever the switch reads at each check, unbound input never executes:
    # an engaged switch at the first check is recorded as such, and otherwise
    # the bound-input denial applies however the switch reads later.
    reads = list(readings)
    monkeypatch.setattr(
        gatekeeper_module.killswitch, "is_engaged", lambda path: reads.pop(0) if reads else False
    )
    gk, _, recorder = _gatekeeper(tmp_path, bound_input_only=True)
    decision = gk.request_action(Action(ActionKind.KEY, 1, keys=("ENTER",)), _frame())
    assert decision.kind is kind and recorder.calls == []


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


@windows_only
def test_observing_a_window_that_is_gone_raises():
    from psoperator.perception import win32_state
    from psoperator.perception.win32_fields import Win32FieldError

    with pytest.raises(Win32FieldError, match="no longer exists"):
        win32_state.observe(0x7FFFFFF0)


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


_COVER_SCRIPT = (
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


@windows_only
def test_a_real_covering_window_stops_the_key_at_the_gatekeeper(tmp_path):
    # The bound window is a topmost popup of this test (the control: the point
    # shows it, and the gatekeeper admits the key). Then a covering popup from
    # this same process, and one from another process: each time the
    # gatekeeper refuses with "covered" and the executor is never reached.
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

    def observe(main_hwnd):
        return _obs(
            main_hwnd=bound, foreground_hwnd=bound, topmost_hwnd=win32_state.topmost_at(point)
        )

    def send():
        gk, _, recorder = _gatekeeper(tmp_path, observe, bound_window=(bound, APP))
        decision = gk.request_bound_key(_req(), _frame())
        return decision, recorder

    try:
        time.sleep(0.2)
        decision, recorder = send()
        assert decision.kind is DecisionKind.EXECUTED and len(recorder.calls) == 1  # control

        same = _topmost_popup(user32, kernel32, 30, 30, size=40)
        try:
            time.sleep(0.2)
            assert process_of(same)[0] == os.getpid()
            decision, recorder = send()
            assert decision.reason == Code.COVERED.value and recorder.calls == []
        finally:
            user32.DestroyWindow(same)

        child = subprocess.Popen(
            [sys.executable, "-c", _COVER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True,
        )  # fmt: skip
        with child:  # closes both pipes
            try:
                owner = int(child.stdout.readline().strip())
                assert owner, "the covering window was not created"
                time.sleep(0.2)
                assert process_of(win32_state.topmost_at(point))[0] == owner
                decision, recorder = send()
                assert decision.reason == Code.COVERED.value and recorder.calls == []
            finally:
                child.stdin.write("\n")
                child.stdin.flush()
                child.wait(timeout=10)
    finally:
        user32.DestroyWindow(bound)


class _FakeUser32:
    def IsWindow(self, hwnd):
        return True


def _patched_observer(monkeypatch, recipients, owned=(0, 0), processes=None):
    """win32_state.observe with every system read replaced: the recipient
    state and dialog counts come from the given sequences, in call order."""
    from psoperator.perception import win32_state

    recipients = list(recipients)
    owned = list(owned)
    processes = list(processes or [(4242, 7, "app.exe"), (4242, 7, "app.exe")])
    monkeypatch.setattr(win32_state, "_api", lambda: (_FakeUser32(), None))
    monkeypatch.setattr(win32_state, "process_of", lambda hwnd: processes.pop(0))
    monkeypatch.setattr(win32_state, "_recipient", lambda u, i, hwnd: recipients.pop(0))
    monkeypatch.setattr(win32_state, "_owned_visible", lambda u, hwnd: owned.pop(0))
    monkeypatch.setattr(win32_state, "read_window_tree", lambda hwnd, label_class: _tree())
    return win32_state


RECIPIENT = (MAIN, EDIT, True, (240, 142), MAIN)


def test_a_consistent_live_observation_is_returned(monkeypatch):
    win32_state = _patched_observer(monkeypatch, [RECIPIENT, RECIPIENT])
    obs = win32_state.observe(MAIN)
    assert (obs.foreground_hwnd, obs.focus_hwnd, obs.input_clear) == (MAIN, EDIT, True)
    assert obs.signature == REPORT and obs.image == "app.exe"


@pytest.mark.parametrize(
    "recipients, owned, processes, match",
    [
        ([RECIPIENT, (OTHER, EDIT, True, (240, 142), MAIN)], (0, 0), None, "recipient"),
        ([RECIPIENT, (MAIN, EDIT, False, (240, 142), MAIN)], (0, 0), None, "recipient"),
        ([RECIPIENT, (MAIN, OTHER, True, (240, 142), MAIN)], (0, 0), None, "recipient"),
        ([RECIPIENT, (MAIN, EDIT, True, (240, 142), OTHER)], (0, 0), None, "recipient"),
        ([RECIPIENT, RECIPIENT], (0, 1), None, "dialogs"),
        ([RECIPIENT, RECIPIENT], (0, 0), [(4242, 7, "app.exe"), (4242, 8, "app.exe")], "process"),
    ],
    ids=["foreground-switched", "menu-opened", "focus-moved", "covered", "dialog-opened",
         "process-restarted"],
)  # fmt: skip
def test_a_change_during_the_live_observation_returns_nothing(
    monkeypatch, recipients, owned, processes, match
):
    from psoperator.perception.win32_fields import Win32FieldError

    win32_state = _patched_observer(monkeypatch, recipients, owned, processes)
    with pytest.raises(Win32FieldError, match=match):
        win32_state.observe(MAIN)


def test_the_recipient_is_read_last(monkeypatch):
    # A change that happens while the dialogs are enumerated for the second
    # time is still caught, because the recipient is read after it.
    from psoperator.perception.win32_fields import Win32FieldError

    state = {"recipient": RECIPIENT}
    win32_state = _patched_observer(monkeypatch, [], owned=())

    def owned_visible(u, hwnd):
        if owned_visible.calls == 1:
            state["recipient"] = (OTHER, EDIT, True, (240, 142), MAIN)
        owned_visible.calls += 1
        return 0

    owned_visible.calls = 0
    monkeypatch.setattr(win32_state, "_owned_visible", owned_visible)
    monkeypatch.setattr(win32_state, "_recipient", lambda u, i, hwnd: state["recipient"])
    with pytest.raises(Win32FieldError, match="recipient"):
        win32_state.observe(MAIN)


class _RecipientUser32:
    def __init__(self, foregrounds):
        self.foregrounds = list(foregrounds)

    def GetForegroundWindow(self):
        return self.foregrounds.pop(0) if len(self.foregrounds) > 1 else self.foregrounds[0]


def _patched_recipient(monkeypatch, threads, foregrounds, on_topmost=None):
    from psoperator.perception import win32_state

    threads = list(threads)

    def thread_state(u, i, hwnd):
        return threads.pop(0) if len(threads) > 1 else threads[0]

    def topmost(point):
        if on_topmost:
            on_topmost(threads)
        return MAIN

    monkeypatch.setattr(win32_state, "_thread_state", thread_state)
    monkeypatch.setattr(win32_state, "_centre", lambda u, hwnd: (240, 142))
    monkeypatch.setattr(win32_state, "topmost_at", topmost)
    return win32_state, _RecipientUser32(foregrounds)


def test_a_consistent_recipient_is_read(monkeypatch):
    win32_state, user32 = _patched_recipient(monkeypatch, [(EDIT, True)], [MAIN])
    assert win32_state._recipient(user32, None, MAIN) == (MAIN, EDIT, True, (240, 142), MAIN)


@pytest.mark.parametrize(
    "threads, foregrounds",
    [
        ([(EDIT, True), (OTHER, True)], [MAIN]),
        ([(EDIT, True), (EDIT, False)], [MAIN]),
        ([(EDIT, True)], [MAIN, OTHER]),
    ],
    ids=["focus-moved", "menu-opened", "foreground-switched"],
)
def test_a_recipient_that_changes_while_read_is_refused(monkeypatch, threads, foregrounds):
    from psoperator.perception.win32_fields import Win32FieldError

    win32_state, user32 = _patched_recipient(monkeypatch, threads, foregrounds)
    with pytest.raises(Win32FieldError, match="while it was being read"):
        win32_state._recipient(user32, None, MAIN)


def test_focus_moving_during_the_covering_check_is_refused(monkeypatch):
    # The focus moves while the top-level window at its centre is looked up:
    # the point checked belonged to a control that no longer has focus.
    from psoperator.perception.win32_fields import Win32FieldError

    def move(threads):
        threads[:] = [(OTHER, True)]

    win32_state, user32 = _patched_recipient(monkeypatch, [(EDIT, True)], [MAIN], move)
    with pytest.raises(Win32FieldError, match="while it was being read"):
        win32_state._recipient(user32, None, MAIN)


class _EnumUser32:
    def __init__(self, windows, ok=True):
        self.windows, self.ok = windows, ok

    def IsWindowVisible(self, h):
        return True

    def GetWindow(self, h, kind):
        return self.windows[h]

    def EnumWindows(self, visit, lparam):
        for h in self.windows:
            visit(h, lparam)
        return int(self.ok)


@windows_only
def test_owned_dialogs_are_counted():
    from psoperator.perception import win32_state

    assert win32_state._owned_visible(_EnumUser32({0x50: MAIN, 0x60: OTHER}), MAIN) == 1


@windows_only
def test_a_failed_window_enumeration_is_not_zero_dialogs():
    from psoperator.perception import win32_state
    from psoperator.perception.win32_fields import Win32FieldError

    failing = _EnumUser32({}, ok=False)
    with pytest.raises(Win32FieldError, match="enumerate"):
        win32_state._owned_visible(failing, MAIN)
