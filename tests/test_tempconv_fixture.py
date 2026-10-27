"""The v1 reference fixture's contract, and its agreement with the walk.

The checker decides pass or fail from the result label's accessible name in an
attested snapshot, so the conversion, the name format, and what the walk
surfaces must agree. The GTK UI itself is validated live on the AT-SPI host.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from psoperator.fixtures.tempconv import (
    C2F,
    C_TO_F_NAME,
    CONVERT_NAME,
    ERROR_TEXT,
    F2C,
    F_TO_C_NAME,
    RESULT_PREFIX,
    V1_EXPECTED,
    VALUE_NAME,
    WINDOW_TITLE,
    convert_text,
    parse_result_name,
    read_result,
    result_name,
)
from psoperator.perception.a11y import AtSpiA11y


@pytest.mark.parametrize(
    ("value", "direction", "shown"),
    [
        ("212", F2C, V1_EXPECTED),
        ("100", C2F, "212.0"),
        ("-40", F2C, "-40.0"),
        ("212", C2F, "413.6"),  # wrong direction
        ("212212", F2C, "117877.8"),  # typed twice
        ("abc", F2C, ERROR_TEXT),
        ("", F2C, ERROR_TEXT),
    ],
)
def test_convert_text(value, direction, shown):
    assert convert_text(value, direction) == shown


def test_unknown_direction_is_refused():
    with pytest.raises(ValueError, match="unknown direction"):
        convert_text("1", "K2C")


def test_result_name_round_trips():
    assert parse_result_name(result_name(V1_EXPECTED)) == V1_EXPECTED
    assert parse_result_name(result_name("")) == ""
    assert result_name("") == RESULT_PREFIX


@pytest.mark.parametrize("name", ["Convert", "Value", "Result:100.0", "Results: 1.0", ""])
def test_other_names_are_not_results(name):
    assert parse_result_name(name) is None


def test_read_result_requires_exactly_one_result_label():
    assert read_result(["Value", result_name(V1_EXPECTED), CONVERT_NAME]) == V1_EXPECTED
    assert read_result(["Value", CONVERT_NAME]) is None
    # Two windows open: refuse rather than pick one.
    assert read_result([result_name(V1_EXPECTED), result_name("413.6")]) is None


def _fixture_desktop(result: str = ""):
    """A fake AT-SPI desktop shaped like the GTK fixture, with the real roles
    the live stack emitted for this fixture on the work node (GTK 3.24)."""
    from tests.test_a11y import FakeAcc

    controls = [
        FakeAcc("text", VALUE_NAME),
        FakeAcc("radio button", C_TO_F_NAME),
        FakeAcc("radio button", F_TO_C_NAME),
        FakeAcc("label", result_name(result)),
        FakeAcc("button", CONVERT_NAME),
    ]
    frame = FakeAcc("frame", WINDOW_TITLE, children=controls)
    app = FakeAcc("application", "tempconv-fixture", children=[frame])
    return FakeAcc("desktop frame", "main", children=[app])


def test_the_walk_surfaces_every_control_and_the_result():
    prov = AtSpiA11y(desktop=_fixture_desktop(V1_EXPECTED), coord_type=None)
    assert prov.find(role="frame", name=WINDOW_TITLE) is not None
    assert prov.find(role="text", name=VALUE_NAME) is not None
    assert prov.find(name=C_TO_F_NAME) is not None
    assert prov.find(name=F_TO_C_NAME) is not None
    assert prov.find(name=CONVERT_NAME) is not None
    names = [node.name for node in prov.tree().walk()]
    assert read_result(names) == V1_EXPECTED


def test_check_mode_runs_without_a_display():
    script = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "tempconv_form.py"
    out = subprocess.run(
        [sys.executable, str(script), "--check"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert WINDOW_TITLE in out.stdout
    assert result_name(V1_EXPECTED) in out.stdout
