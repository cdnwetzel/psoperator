"""The R-304 invoice fixture's data contract, and its agreement with the walk.

The fixture UI, the AT-SPI walk, and the operator's field-level preview must
name the same fields. If they drift, the operator would approve a preview whose
labels no longer match the entries the executor drives — the exact failure the
staging layer exists to prevent. These tests pin the pure contract and prove the
walk, run over a fixture-shaped desktop, surfaces precisely the fields the
preview lists. The GTK UI itself is validated live on the AT-SPI host.
"""

from __future__ import annotations

import pytest

from psoperator.fixtures.invoice import (
    DEMO_INVOICE,
    FIELD_NAMES,
    SUBMIT_NAME,
    WINDOW_TITLE,
    Invoice,
    field_rows,
)
from psoperator.perception.a11y import AtSpiA11y


def test_field_rows_names_match_field_names_in_order():
    names = tuple(name for name, _ in field_rows(DEMO_INVOICE))
    assert names == FIELD_NAMES


def test_field_rows_carry_the_invoice_values():
    rows = dict(field_rows(DEMO_INVOICE))
    assert rows["Vendor"] == DEMO_INVOICE.vendor
    assert rows["Invoice Total"] == DEMO_INVOICE.total


def test_construction_rejects_a_row_set_that_drifts_from_field_names(monkeypatch):
    # If someone edits _rows or FIELD_NAMES inconsistently, construction must
    # fail loud rather than ship a preview that cannot name a field.
    import psoperator.fixtures.invoice as inv_mod

    monkeypatch.setattr(inv_mod, "FIELD_NAMES", ("Vendor", "Renamed", "Date", "Invoice Total"))
    with pytest.raises(ValueError, match="do not match FIELD_NAMES"):
        Invoice(vendor="a", number="b", date="c", total="d")


def _fixture_desktop():
    """A fake AT-SPI desktop shaped exactly like the GTK fixture: one app, one
    frame titled WINDOW_TITLE, an entry per FIELD_NAMES, and the submit button.
    Mirrors what build_window constructs, without needing a display."""
    from tests.test_a11y import FakeAcc

    entries = [FakeAcc("entry", name) for name in FIELD_NAMES]
    submit = FakeAcc("push button", SUBMIT_NAME)
    frame = FakeAcc("frame", WINDOW_TITLE, children=[*entries, submit])
    app = FakeAcc("application", "invoice-fixture", children=[frame])
    return FakeAcc("desktop frame", "main", children=[app])


def test_the_walk_surfaces_every_previewed_field():
    prov = AtSpiA11y(desktop=_fixture_desktop(), coord_type=None)
    for name, _ in field_rows(DEMO_INVOICE):
        node = prov.find(role="entry", name=name)
        assert node is not None, f"walk did not surface field {name!r}"
        assert node.name == name


def test_the_walk_finds_the_frame_by_window_title_and_the_submit_button():
    prov = AtSpiA11y(desktop=_fixture_desktop(), coord_type=None)
    assert prov.find(role="frame", name=WINDOW_TITLE) is not None
    assert prov.find(role="push button", name=SUBMIT_NAME) is not None


def test_check_mode_runs_without_a_display():
    # The example script's --check path must run without importing gi, and must
    # print the same field names the preview uses. Invoke the real entrypoint.
    import subprocess
    import sys
    from pathlib import Path

    script = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "invoice_form.py"
    out = subprocess.run(
        [sys.executable, str(script), "--check"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert WINDOW_TITLE in out.stdout
    for name in FIELD_NAMES:
        assert name in out.stdout
