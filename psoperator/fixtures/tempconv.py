"""Temperature-converter fixture: the v1 target of the reference workflow.

The invoice form is the governance demo; this is the smallest task with an exact
pass and fail. It is a GTK port of the Tkinter converter the violoop harness
drove by pixels, because Tk exposes no AT-SPI tree on Linux and the service path
plans from accessibility elements only.

This module is the *contract*, not the UI: the accessible names the walk must
find, the conversion the app performs, and how a result is published and read
back. The GTK app in ``examples/fixtures/tempconv_form.py`` and the checker that
decides pass or fail both import it, so they cannot disagree about what
``100.0`` means or where it appears.

The result is published in the result label's *accessible name*
(``"Result: 100.0"``), because a snapshot element carries the accessible name
and not a widget's text. That lets the postcondition be read from the attested
snapshot itself, with no side channel.
"""

from __future__ import annotations

# The window title the gatekeeper binds an action to (R-301 window identity).
WINDOW_TITLE = "TempConv"

# Accessible names of the controls, as the AT-SPI walk reports them.
VALUE_NAME = "Value"
C_TO_F_NAME = "C to F"
F_TO_C_NAME = "F to C"
CONVERT_NAME = "Convert"
RESULT_PREFIX = "Result:"

# Directions, as the radio buttons select them.
C2F = "C2F"
F2C = "F2C"
DEFAULT_DIRECTION = C2F

# The text shown for input that is not a number.
ERROR_TEXT = "error"

# The v1 reference task and the only result that passes it. Converting the
# wrong way gives 413.6, typing the value twice gives 117877.8, and a
# non-numeric entry gives "error", so every common failure is distinguishable.
V1_GOAL = "Convert 212 degrees Fahrenheit to Celsius."
V1_EXPECTED = "100.0"


def convert_text(value: str, direction: str) -> str:
    """What the result label shows after Convert: one decimal, or ``error``."""
    try:
        number = float(value)
    except ValueError:
        return ERROR_TEXT
    if direction == C2F:
        converted = number * 9 / 5 + 32
    elif direction == F2C:
        converted = (number - 32) * 5 / 9
    else:
        raise ValueError(f"unknown direction {direction!r}")
    return f"{converted:.1f}"


def result_name(text: str) -> str:
    """The result label's accessible name for a shown result (empty before Convert)."""
    return f"{RESULT_PREFIX} {text}" if text else RESULT_PREFIX


def parse_result_name(name: str) -> str | None:
    """The result shown in a result label's accessible name.

    ``None`` when ``name`` is not a result label; ``""`` when Convert has not
    been pressed yet.
    """
    if name == RESULT_PREFIX:
        return ""
    if name.startswith(RESULT_PREFIX + " "):
        return name[len(RESULT_PREFIX) + 1 :]
    return None


def read_result(labels: list[str]) -> str | None:
    """The single result in a snapshot's element labels, or ``None``.

    Exactly one result label must be present. Two mean a stale window is still
    open, and the checker must not pick one.
    """
    results = [r for r in (parse_result_name(label) for label in labels) if r is not None]
    if len(results) != 1:
        return None
    return results[0]
