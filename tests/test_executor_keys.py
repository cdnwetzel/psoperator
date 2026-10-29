"""The gate's key names reach pynput as the keys they name.

The bound-target gate admits names such as ENTER, ESC and F1; pynput accepts
one character or a member of its ``Key`` enum. The executor maps one to the
other and refuses anything it cannot map, before pressing anything. The
Windows tests drive pynput's real ``press``/``release`` and resolver, with
only the last step (``_handle``, which calls SendInput) replaced by a
recorder: nothing reaches the OS.
"""

from __future__ import annotations

import os
from enum import Enum

import pytest

from psoperator.gatekeeper.bound_target import _KEYS
from psoperator.gatekeeper.executor import PynputExecutor, pynput_key
from psoperator.runtime.actions import Action, ActionKind

windows_only = pytest.mark.skipif(os.name != "nt", reason="pynput's Windows backend")

GATE_NAMES = sorted(_KEYS)


class _StandInKey(Enum):
    enter = "enter"
    esc = "esc"
    ctrl = "ctrl"
    f1 = "f1"


def test_names_map_to_members_and_characters_pass_through():
    assert pynput_key("ENTER", _StandInKey) is _StandInKey.enter
    assert pynput_key("esc", _StandInKey) is _StandInKey.esc
    assert pynput_key("F1", _StandInKey) is _StandInKey.f1
    assert pynput_key("3", _StandInKey) == "3"
    assert pynput_key("A", _StandInKey) == "A"


@pytest.mark.parametrize("name", ["", "F13", "secret value", "ENTERX", None, 3, ("ENTER",)])
def test_anything_else_is_refused(name):
    with pytest.raises(ValueError):
        pynput_key(name, _StandInKey)


def _recording_keyboard():
    from pynput import keyboard

    class _Recording(keyboard.Controller):
        def __init__(self):
            super().__init__()
            self.events = []

        def _handle(self, key, is_press):  # the step that would call SendInput
            self.events.append((key, is_press))

    return _Recording()


@windows_only
@pytest.mark.parametrize("name", GATE_NAMES)
def test_every_gate_key_name_resolves_in_pynput(name):
    from pynput.keyboard import Key

    keyboard = _recording_keyboard()
    executor = PynputExecutor(keyboard=keyboard, mouse=object())
    executor.execute(Action(ActionKind.KEY, 1, keys=(name,)))
    expected = getattr(Key, name.lower()).value
    assert keyboard.events == [(expected, True), (expected, False)]


@windows_only
def test_without_the_mapping_pynput_refuses_the_gate_name():
    # The control: pynput itself cannot press "ENTER", which is why an
    # admitted ENTER used to fail as execution-failed.
    with pytest.raises(ValueError):
        _recording_keyboard().press("ENTER")


@windows_only
def test_a_digit_is_pressed_as_its_character():
    from pynput.keyboard import KeyCode

    keyboard = _recording_keyboard()
    PynputExecutor(keyboard=keyboard, mouse=object()).execute(
        Action(ActionKind.KEY, 1, keys=("3",))
    )
    assert keyboard.events == [(KeyCode.from_char("3"), True), (KeyCode.from_char("3"), False)]


@windows_only
def test_an_unknown_name_presses_nothing():
    keyboard = _recording_keyboard()
    executor = PynputExecutor(keyboard=keyboard, mouse=object())
    with pytest.raises(ValueError):
        executor.execute(Action(ActionKind.KEY, 1, keys=("ctrl", "secret value")))
    assert keyboard.events == []


@windows_only
def test_an_admitted_enter_reaches_the_keyboard(tmp_path):
    from pynput.keyboard import Key
    from test_bound_target import _audit, _frame, _gatekeeper, _req

    from psoperator.gatekeeper.gatekeeper import DecisionKind

    keyboard = _recording_keyboard()
    executor = PynputExecutor(keyboard=keyboard, mouse=object())
    gk, config, _ = _gatekeeper(tmp_path, executor=executor)
    decision = gk.request_bound_key(_req(), _frame())
    assert decision.kind is DecisionKind.EXECUTED
    assert keyboard.events == [(Key.enter.value, True), (Key.enter.value, False)]
    assert _audit(config)[-1]["reason"] == "executed"


class _FailsOnSecondPress:
    def __init__(self):
        self.pressed, self.released = [], []

    def press(self, key):
        if self.pressed:
            raise RuntimeError("press failed")
        self.pressed.append(key)

    def release(self, key):
        self.released.append(key)


@windows_only
def test_a_failed_press_releases_every_key_whose_press_was_attempted():
    # The press that raised may still have gone down, so it is released too.
    from pynput.keyboard import Key

    keyboard = _FailsOnSecondPress()
    executor = PynputExecutor(keyboard=keyboard, mouse=object())
    with pytest.raises(RuntimeError, match="press failed"):
        executor.execute(Action(ActionKind.KEY, 1, keys=("ctrl", "s")))
    assert keyboard.pressed == [Key.ctrl] and keyboard.released == ["s", Key.ctrl]


class _GoesDownThenRaises:
    """A press that reaches the OS and then raises; releases are recorded,
    and the releases named in ``bad`` raise."""

    def __init__(self, bad=()):
        self.down, self.released, self.bad = [], [], set(bad)

    def press(self, key):
        self.down.append(key)
        if len(self.down) == 2:
            raise RuntimeError("press failed after the key went down")

    def release(self, key):
        self.released.append(key)
        if key in self.bad:
            raise OSError(f"release of {key} failed")


@windows_only
def test_a_key_that_went_down_before_its_press_raised_is_released():
    from pynput.keyboard import Key

    keyboard = _GoesDownThenRaises()
    executor = PynputExecutor(keyboard=keyboard, mouse=object())
    with pytest.raises(RuntimeError):
        executor.execute(Action(ActionKind.KEY, 1, keys=("ctrl", "s")))
    assert keyboard.down == [Key.ctrl, "s"]
    assert sorted(map(str, keyboard.released)) == sorted(map(str, keyboard.down))


@windows_only
def test_one_failed_release_does_not_skip_the_others():
    from pynput.keyboard import Key

    keyboard = _GoesDownThenRaises(bad={"s"})
    executor = PynputExecutor(keyboard=keyboard, mouse=object())
    # The press error is the one raised; every release is still attempted.
    with pytest.raises(RuntimeError, match="press failed"):
        executor.execute(Action(ActionKind.KEY, 1, keys=("ctrl", "s")))
    assert keyboard.released == ["s", Key.ctrl]


class _ReleaseFails:
    def __init__(self, bad):
        self.released, self.bad = [], bad

    def press(self, key):
        pass

    def release(self, key):
        self.released.append(key)
        if key == self.bad:
            raise OSError("release failed")


@windows_only
def test_a_failed_release_is_raised_after_every_release_is_attempted():
    from pynput.keyboard import Key

    keyboard = _ReleaseFails(bad="s")
    executor = PynputExecutor(keyboard=keyboard, mouse=object())
    with pytest.raises(OSError, match="release failed"):
        executor.execute(Action(ActionKind.KEY, 1, keys=("ctrl", "s")))
    assert keyboard.released == ["s", Key.ctrl]
