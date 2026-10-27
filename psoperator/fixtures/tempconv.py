"""Temperature-converter fixture: the v1 target of the reference workflow.

The invoice form is the governance demo; this is the smallest task with an exact
pass and fail. It is a GTK port of the Tkinter converter the violoop harness
drove by pixels, because Tk exposes no AT-SPI tree on Linux and the service path
plans from accessibility elements only.

This module is the *contract*, not the UI: the accessible names the walk must
find, the conversion the app performs, how a result is published, and how the
v1 checker decides pass or fail from an attested snapshot. The GTK app in
``examples/fixtures/tempconv_form.py`` and the checker both import it, so they
cannot disagree about what a result means.

A result is published in the result label's *accessible name*, together with
the exact input and direction that produced it
(``"Result: 100.0 (212 F to C)"``). A snapshot element carries the accessible
name, not the widget's text, and the number alone does not prove the task:
``211.99`` F to C and ``37.7778`` C to F also show ``100.0``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from psoperator.common.schema import MAX_ELEMENT_LABEL_CHARS, MAX_SNAPSHOT_ELEMENTS

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
_DIRECTION_TEXT = {C2F: C_TO_F_NAME, F2C: F_TO_C_NAME}

# The text shown for input that is not a number.
ERROR_TEXT = "error"

# How much of the typed input the published name repeats. Longer input is cut
# and marked, so it can never read as an exact match.
MAX_ECHOED_INPUT = 64

# The v1 reference task, and the one result-label name that passes it.
V1_GOAL = "Convert 212 degrees Fahrenheit to Celsius."
V1_INPUT = "212"
V1_EXPECTED = "100.0"


def convert_text(value: str, direction: str) -> str:
    """What the result label shows after Convert: one decimal, or ``error``."""
    if direction not in _DIRECTION_TEXT:
        raise ValueError(f"unknown direction {direction!r}")
    try:
        number = float(value)
    except ValueError:
        return ERROR_TEXT
    if direction == C2F:
        converted = number * 9 / 5 + 32
    else:
        converted = (number - 32) * 5 / 9
    return f"{converted:.1f}"


def _echo(value: str) -> str:
    if len(value) > MAX_ECHOED_INPUT:
        return value[:MAX_ECHOED_INPUT] + "…"
    return value


def result_name(shown: str = "", value: str = "", direction: str = DEFAULT_DIRECTION) -> str:
    """The result label's accessible name: empty before the first Convert, then
    the shown result with the exact input and direction that produced it."""
    if not shown:
        return RESULT_PREFIX
    if direction not in _DIRECTION_TEXT:
        raise ValueError(f"unknown direction {direction!r}")
    name = f"{RESULT_PREFIX} {shown} ({_echo(value)} {_DIRECTION_TEXT[direction]})"
    return name[:MAX_ELEMENT_LABEL_CHARS]


V1_PASS_NAME = result_name(V1_EXPECTED, V1_INPUT, F2C)


def is_result_name(name: str) -> bool:
    return name == RESULT_PREFIX or name.startswith(RESULT_PREFIX + " ")


class _Element(Protocol):
    label: str
    bbox: tuple[int, int, int, int]
    control_type: str
    source: str


def _inside(inner: tuple[int, int, int, int], outer: tuple[int, int, int, int]) -> bool:
    x, y, w, h = inner
    ox, oy, ow, oh = outer
    return ox <= x and oy <= y and x + w <= ox + ow and y + h <= oy + oh


def _scoped_result(elements: Sequence[_Element]) -> tuple[str | None, str]:
    """The one result label inside the one fixture window, or why there is none.

    Evidence must be complete and scoped before it can be read:

    - a snapshot at the element cap may have been truncated, so it cannot show
      that a window or result is the only one;
    - exactly one accessibility frame titled :data:`WINDOW_TITLE`;
    - exactly one accessibility result label inside that frame.

    OCR text and labels outside the frame are never read as the result.
    """
    if len(elements) >= MAX_SNAPSHOT_ELEMENTS:
        return None, "snapshot may be truncated; uniqueness cannot be established"
    a11y = [e for e in elements if e.source == "a11y"]
    frames = [e for e in a11y if e.control_type == "frame" and e.label == WINDOW_TITLE]
    if len(frames) != 1:
        return None, f"expected one {WINDOW_TITLE!r} window, found {len(frames)}"
    results = [
        e
        for e in a11y
        if e.control_type == "label" and is_result_name(e.label) and _inside(e.bbox, frames[0].bbox)
    ]
    if len(results) != 1:
        return None, f"expected one result label in the window, found {len(results)}"
    return results[0].label, "scoped"


def check_v1(elements: Sequence[_Element]) -> tuple[bool, str]:
    """Decide v1 from one attested snapshot's elements: ``(passed, reason)``.

    Passes only when the scoped result label equals :data:`V1_PASS_NAME`.
    """
    shown, reason = _scoped_result(elements)
    if shown is None:
        return False, reason
    if shown != V1_PASS_NAME:
        return False, f"result is {shown!r}, expected {V1_PASS_NAME!r}"
    return True, "result matches"


def check_v1_baseline(elements: Sequence[_Element]) -> tuple[bool, str]:
    """The start condition: the same scoped evidence, with no result yet shown.

    A run starts only from a freshly launched fixture, so a result left over
    from an earlier run can never be read as this run's.
    """
    shown, reason = _scoped_result(elements)
    if shown is None:
        return False, reason
    if shown != RESULT_PREFIX:
        return False, f"the window already shows {shown!r}; start from a fresh fixture"
    return True, "fresh fixture"
