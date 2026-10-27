"""The v1 reference fixture's contract, and the checker that decides v1.

The checker decides pass or fail from the result label's accessible name in an
attested snapshot, so the conversion, the name format, and what a snapshot
actually carries must agree. The walk-level tests run through the real
SnapshotBuilder with bounds, because a node without bounds never reaches a
snapshot. The GTK UI itself is validated live on the AT-SPI host.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image

from psoperator.common.schema import MAX_SNAPSHOT_ELEMENTS, UIElementRef
from psoperator.fixtures.tempconv import (
    C2F,
    C_TO_F_NAME,
    CONVERT_NAME,
    ERROR_TEXT,
    F2C,
    F_TO_C_NAME,
    MAX_ECHOED_INPUT,
    RESULT_PREFIX,
    V1_EXPECTED,
    V1_PASS_NAME,
    VALUE_NAME,
    WINDOW_TITLE,
    check_v1,
    check_v1_baseline,
    convert_text,
    result_name,
)
from psoperator.perception.a11y import AtSpiA11y
from psoperator.perception.capture import Frame
from psoperator.perception.ocr import NullOCR
from psoperator.perception.snapshot import SnapshotBuilder
from tests.test_a11y import COORD, FakeAcc, FakeExtents


@pytest.mark.parametrize(
    ("value", "direction", "shown"),
    [
        ("212", F2C, V1_EXPECTED),
        ("100", C2F, "212.0"),
        ("-40", F2C, "-40.0"),
        ("212", C2F, "413.6"),  # wrong direction
        ("212212", F2C, "117877.8"),  # typed twice
        ("211.99", F2C, V1_EXPECTED),  # same number, wrong input
        ("37.7778", C2F, V1_EXPECTED),  # same number, wrong direction
        ("abc", F2C, ERROR_TEXT),
        ("", F2C, ERROR_TEXT),
    ],
)
def test_convert_text(value, direction, shown):
    assert convert_text(value, direction) == shown


def test_unknown_direction_is_refused():
    with pytest.raises(ValueError, match="unknown direction"):
        convert_text("1", "K2C")
    with pytest.raises(ValueError, match="unknown direction"):
        result_name("1.0", "1", "K2C")


def test_result_name_carries_input_and_direction():
    assert V1_PASS_NAME == "Result: 100.0 (212 F to C)"
    assert result_name() == RESULT_PREFIX
    assert result_name("413.6", "212", C2F) == "Result: 413.6 (212 C to F)"


def test_long_input_is_cut_and_marked_so_it_cannot_match():
    name = result_name("1.0", "9" * (MAX_ECHOED_INPUT + 10), F2C)
    assert "…" in name
    assert len(name) < MAX_ECHOED_INPUT + 40


FRAME_BOX = (100, 100, 400, 250)


def _el(label, control_type, bbox, source="a11y", n=[0]):
    n[0] += 1
    return UIElementRef(
        element_id=f"e{n[0]}",
        frame_id=1,
        label=label,
        bbox=bbox,
        control_type=control_type,
        source=source,
    )


def _window(result, frame_box=FRAME_BOX):
    x, y = frame_box[0], frame_box[1]
    return [
        _el(WINDOW_TITLE, "frame", frame_box),
        _el(VALUE_NAME, "text", (x + 10, y + 10, 300, 30)),
        _el(result, "label", (x + 10, y + 120, 300, 20)),
        _el(CONVERT_NAME, "button", (x + 10, y + 150, 300, 30)),
    ]


def test_v1_passes_only_on_the_exact_result():
    assert check_v1(_window(V1_PASS_NAME)) == (True, "result matches")


@pytest.mark.parametrize(
    "result",
    [
        result_name("413.6", "212", C2F),
        result_name("117877.8", "212212", F2C),
        result_name(ERROR_TEXT, "abc", F2C),
        result_name(V1_EXPECTED, "211.99", F2C),
        result_name(V1_EXPECTED, "37.7778", C2F),
        result_name(V1_EXPECTED, "212.0", F2C),
        RESULT_PREFIX,
    ],
)
def test_v1_fails_every_other_result(result):
    passed, reason = check_v1(_window(result))
    assert not passed
    assert "expected" in reason


def test_v1_refuses_two_windows_even_if_one_result_survives():
    # A second TempConv frame whose result label was dropped from the snapshot.
    elements = _window(V1_PASS_NAME) + [_el(WINDOW_TITLE, "frame", (600, 100, 400, 250))]
    passed, reason = check_v1(elements)
    assert not passed and "found 2" in reason


def test_v1_ignores_result_text_outside_the_window_and_from_ocr():
    elements = _window(RESULT_PREFIX) + [
        _el(V1_PASS_NAME, "label", (700, 700, 200, 20)),  # another app
        _el(V1_PASS_NAME, "text", (110, 220, 300, 20), source="ocr"),
    ]
    passed, _ = check_v1(elements)
    assert not passed
    # And a matching label elsewhere does not break a correct run.
    elements = _window(V1_PASS_NAME) + [_el(V1_PASS_NAME, "label", (700, 700, 200, 20))]
    assert check_v1(elements)[0]


def test_v1_refuses_a_missing_window_or_result():
    assert not check_v1(_window(V1_PASS_NAME)[1:])[0]
    assert not check_v1([e for e in _window(V1_PASS_NAME) if e.control_type != "label"])[0]


def test_v1_refuses_a_snapshot_at_the_element_cap():
    filler = [_el(f"x{i}", "label", (0, 0, 1, 1)) for i in range(MAX_SNAPSHOT_ELEMENTS - 4)]
    passed, reason = check_v1(_window(V1_PASS_NAME) + filler)
    assert not passed and "truncated" in reason


def test_baseline_requires_a_fresh_fixture():
    assert check_v1_baseline(_window(RESULT_PREFIX))[0]
    passed, reason = check_v1_baseline(_window(V1_PASS_NAME))
    assert not passed and "fresh fixture" in reason


def _fixture_desktop(result: str):
    """A fake AT-SPI desktop shaped like the GTK fixture, with the roles and
    layout the live stack emitted for it on the work node (GTK 3.24)."""
    controls = [
        FakeAcc("text", VALUE_NAME, extents=FakeExtents(776, 438, 368, 34)),
        FakeAcc("radio button", C_TO_F_NAME, extents=FakeExtents(776, 480, 368, 21)),
        FakeAcc("radio button", F_TO_C_NAME, extents=FakeExtents(776, 509, 368, 21)),
        FakeAcc("label", result, extents=FakeExtents(776, 538, 368, 16)),
        FakeAcc("button", CONVERT_NAME, extents=FakeExtents(776, 562, 368, 34)),
    ]
    frame = FakeAcc(
        "frame", WINDOW_TITLE, children=controls, extents=FakeExtents(759, 402, 402, 275)
    )
    app = FakeAcc("application", "tempconv-fixture", children=[frame])
    return FakeAcc("desktop frame", "main", children=[app])


def _snapshot(result: str):
    builder = SnapshotBuilder(
        a11y=AtSpiA11y(desktop=_fixture_desktop(result), coord_type=COORD), ocr=NullOCR()
    )
    frame = Frame.from_image(1, Image.new("RGB", (1920, 1080), "white"))
    return builder.build(frame)


def test_the_published_result_reaches_a_snapshot_and_decides_v1():
    snapshot = _snapshot(V1_PASS_NAME)
    labels = {(e.control_type, e.label) for e in snapshot.elements}
    assert ("text", VALUE_NAME) in labels
    assert ("button", CONVERT_NAME) in labels
    assert check_v1(snapshot.elements) == (True, "result matches")
    assert not check_v1(_snapshot(result_name("413.6", "212", C2F)).elements)[0]
    assert check_v1_baseline(_snapshot(RESULT_PREFIX).elements)[0]


def test_check_mode_runs_without_a_display():
    script = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "tempconv_form.py"
    out = subprocess.run(
        [sys.executable, str(script), "--check"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert WINDOW_TITLE in out.stdout
    assert V1_PASS_NAME in out.stdout
