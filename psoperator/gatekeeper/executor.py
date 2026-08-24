"""Executors — the ONLY place in PSOperator allowed to touch OS input devices.

The runtime never imports pyautogui or pynput controllers; it hands an
approved Action to the gatekeeper, which hands it to an Executor.

* ``DryRunExecutor`` (default): records the action, moves nothing. Safe for
  development and for the whole test-suite.
* ``PynputExecutor``: real OS input via pynput controllers, import-guarded
  and instantiated ONLY on explicit operator opt-in.
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from psoperator.runtime.actions import Action, ActionKind


@runtime_checkable
class Executor(Protocol):
    name: str

    def execute(self, action: Action) -> str:
        """Perform the action; return a short human-readable outcome."""
        ...


class DryRunExecutor:
    """Performs nothing. Returns what it *would* have done."""

    name = "dry-run"

    def execute(self, action: Action) -> str:
        if action.kind is ActionKind.WAIT and action.seconds:
            time.sleep(min(action.seconds, 5.0))  # waits are real; they're harmless
        return f"dry-run: would execute {action.to_text()}"


class PynputExecutor:
    """Real input injection via pynput controllers.

    This is the single sanctioned input-injection site in the codebase.
    Construct it only from the gatekeeper, only after operator opt-in.
    """

    name = "pynput"

    def __init__(self) -> None:
        try:
            from pynput.keyboard import Controller as KbController
            from pynput.keyboard import Key
            from pynput.mouse import Button
            from pynput.mouse import Controller as MouseController
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pynput not installed") from e
        self._mouse = MouseController()
        self._kb = KbController()
        self._Key = Key
        self._Button = Button

    def _key(self, name: str):  # pragma: no cover - needs a display
        return getattr(self._Key, name, name)

    def execute(self, action: Action) -> str:  # pragma: no cover - needs a display
        k = action.kind
        if k is ActionKind.CLICK or k is ActionKind.RIGHT_CLICK or k is ActionKind.DOUBLE_CLICK:
            btn = self._Button.right if k is ActionKind.RIGHT_CLICK else self._Button.left
            self._mouse.position = (action.x, action.y)
            self._mouse.click(btn, 2 if k is ActionKind.DOUBLE_CLICK else 1)
            return f"clicked {btn} at ({action.x}, {action.y})"
        if k is ActionKind.TYPE:
            self._kb.type(action.text or "")
            return f"typed {len(action.text or '')} chars"
        if k is ActionKind.KEY:
            keys = [self._key(n) for n in action.keys]
            for key in keys:
                self._kb.press(key)
            for key in reversed(keys):
                self._kb.release(key)
            return f"pressed {'+'.join(action.keys)}"
        if k is ActionKind.SCROLL:
            if action.x is not None:
                self._mouse.position = (action.x, action.y)
            self._mouse.scroll(0, action.amount or 0)
            return f"scrolled {action.amount}"
        if k is ActionKind.DRAG:
            self._mouse.position = (action.x, action.y)
            self._mouse.press(self._Button.left)
            self._mouse.position = (action.to_x, action.to_y)
            self._mouse.release(self._Button.left)
            return f"dragged ({action.x},{action.y})->({action.to_x},{action.to_y})"
        if k is ActionKind.WAIT:
            time.sleep(min(action.seconds or 0.0, 30.0))
            return f"waited {action.seconds}s"
        return f"no-op for {k.value}"
