"""The R-304 invoice fixture's data contract, and its agreement with the walk.

The fixture UI, the AT-SPI walk, and the operator's field-level preview must
name the same fields. If they drift, the operator would approve a preview whose
labels no longer match the entries the executor drives — the exact failure the
staging layer exists to prevent. These tests pin the pure contract and prove the
walk, run over a fixture-shaped desktop, surfaces precisely the fields the
preview lists. The GTK UI itself is validated live on the AT-SPI host.
"""

from __future__ import annotations

import json

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
    Uses the real AT-SPI roles the live stack emits: "text" for a GTK Entry,
    "button" for a GTK Button (psoperator #2).
    Mirrors what build_window constructs, without needing a display."""
    from tests.test_a11y import FakeAcc

    entries = [FakeAcc("text", name) for name in FIELD_NAMES]  # GTK Entry -> AT-SPI "text"
    submit = FakeAcc("button", SUBMIT_NAME)  # GTK Button -> AT-SPI "button"
    frame = FakeAcc("frame", WINDOW_TITLE, children=[*entries, submit])
    app = FakeAcc("application", "invoice-fixture", children=[frame])
    return FakeAcc("desktop frame", "main", children=[app])


def test_the_walk_surfaces_every_previewed_field():
    prov = AtSpiA11y(desktop=_fixture_desktop(), coord_type=None)
    for name, _ in field_rows(DEMO_INVOICE):
        node = prov.find(role="text", name=name)
        assert node is not None, f"walk did not surface field {name!r}"
        assert node.name == name


def test_the_walk_finds_the_frame_by_window_title_and_the_submit_button():
    prov = AtSpiA11y(desktop=_fixture_desktop(), coord_type=None)
    assert prov.find(role="frame", name=WINDOW_TITLE) is not None
    assert prov.find(role="button", name=SUBMIT_NAME) is not None


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


def test_record_starts_fresh_and_refuses_an_existing_file(tmp_path):
    from psoperator.fixtures.invoice import RecordError, SubmissionRecord, read_submissions

    path = tmp_path / "run.jsonl"
    record = SubmissionRecord(path)
    assert read_submissions(path) == []
    with pytest.raises(RecordError, match="already exists"):
        SubmissionRecord(path)
    record.close()


def test_record_round_trips_submissions_in_field_order(tmp_path):
    from psoperator.fixtures.invoice import SubmissionRecord, read_submissions

    path = tmp_path / "run.jsonl"
    record = SubmissionRecord(path)
    record.append(field_rows(DEMO_INVOICE))
    record.append(field_rows(DEMO_INVOICE))
    record.close()
    subs = read_submissions(path)
    assert len(subs) == 2
    assert tuple(subs[0]) == FIELD_NAMES
    assert subs[0]["Vendor"] == DEMO_INVOICE.vendor


def test_record_refuses_a_removed_or_replaced_file(tmp_path):
    from psoperator.fixtures.invoice import RecordError, SubmissionRecord

    path = tmp_path / "run.jsonl"
    record = SubmissionRecord(path)
    path.unlink()
    with pytest.raises(RecordError, match="is gone"):
        record.append(field_rows(DEMO_INVOICE))
    path.write_text("")  # a different file at the same path
    with pytest.raises(RecordError, match="replaced"):
        record.append(field_rows(DEMO_INVOICE))
    record.close()


def test_record_failures_are_errors_not_empty(tmp_path):
    from psoperator.fixtures.invoice import RecordError, SubmissionRecord, read_submissions

    with pytest.raises(RecordError, match="cannot read"):
        read_submissions(tmp_path / "missing.jsonl")
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"fields": {"Vendor": "x"}}\n')
    with pytest.raises(RecordError, match="does not name FIELD_NAMES"):
        read_submissions(bad)
    bad.write_text("not json\n")
    with pytest.raises(RecordError, match="malformed"):
        read_submissions(bad)
    good = tmp_path / "good.jsonl"
    record = SubmissionRecord(good)
    record.append(field_rows(DEMO_INVOICE))
    record.close()
    good.write_text(good.read_text().rstrip("\n"))  # cut mid-write
    with pytest.raises(RecordError, match="mid-line"):
        read_submissions(good)
    record = SubmissionRecord(tmp_path / "x.jsonl")
    with pytest.raises(RecordError, match="do not match FIELD_NAMES"):
        record.append([("Vendor", "x")])
    record.close()


@pytest.mark.parametrize("fault", ["short_write", "write_error", "fsync_error"])
def test_record_write_faults_raise(tmp_path, monkeypatch, fault):
    import psoperator.fixtures.invoice as inv_mod
    from psoperator.fixtures.invoice import RecordError, SubmissionRecord

    def _raise(*_args):
        raise OSError("injected")

    record = SubmissionRecord(tmp_path / "run.jsonl")
    try:
        if fault == "short_write":
            monkeypatch.setattr(inv_mod.os, "write", lambda fd, data: len(data) - 1)
        elif fault == "write_error":
            monkeypatch.setattr(inv_mod.os, "write", _raise)
        else:
            monkeypatch.setattr(inv_mod.os, "fsync", _raise)
        with pytest.raises(RecordError):
            record.append(field_rows(DEMO_INVOICE))
    finally:
        monkeypatch.undo()
        record.close()


def test_record_with_invalid_utf8_is_an_error(tmp_path):
    from psoperator.fixtures.invoice import RecordError, read_submissions

    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(b'{"fields": {"Vendor": "\xff"}}\n')
    with pytest.raises(RecordError, match="not valid UTF-8"):
        read_submissions(bad)


@pytest.mark.parametrize("value", [7, 1.5, None, True, ["x"], {"x": "y"}])
@pytest.mark.parametrize("field", FIELD_NAMES)
def test_record_with_a_non_text_value_is_an_error(tmp_path, field, value):
    from psoperator.fixtures.invoice import RecordError, read_submissions

    fields = dict(field_rows(DEMO_INVOICE))
    fields[field] = value
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"fields": fields}) + "\n")
    with pytest.raises(RecordError, match="non-text value"):
        read_submissions(bad)


def test_record_nested_too_deep_is_an_error(tmp_path):
    from psoperator.fixtures.invoice import RecordError, read_submissions

    bad = tmp_path / "deep.jsonl"
    bad.write_text('{"fields": {"Vendor": ' + "[" * 100_000 + "]" * 100_000 + "}}\n")
    with pytest.raises(RecordError, match="malformed"):
        read_submissions(bad)


@pytest.mark.parametrize("name", ["bad\x00.jsonl", "bad\ud800.jsonl"])
def test_record_with_an_invalid_path_is_an_error(tmp_path, name):
    from psoperator.fixtures.invoice import RecordError, read_submissions

    with pytest.raises(RecordError):
        read_submissions(tmp_path / name)


@pytest.mark.parametrize("name", ["bad\x00.jsonl", "bad\ud800.jsonl"])
def test_creating_a_record_at_an_invalid_path_is_an_error(tmp_path, name):
    from psoperator.fixtures.invoice import RecordError, SubmissionRecord

    with pytest.raises(RecordError, match="cannot create"):
        SubmissionRecord(tmp_path / name)


def test_a_failed_fstat_closes_the_record_and_raises(tmp_path, monkeypatch):
    import psoperator.fixtures.invoice as inv_mod
    from psoperator.fixtures.invoice import RecordError, SubmissionRecord

    closed: list[int] = []
    real_close = inv_mod.os.close

    def _fstat(_fd):
        raise OSError("injected")

    def _close(fd):
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(inv_mod.os, "fstat", _fstat)
    monkeypatch.setattr(inv_mod.os, "close", _close)
    with pytest.raises(RecordError, match="cannot create"):
        SubmissionRecord(tmp_path / "run.jsonl")
    assert len(closed) == 1


def test_a_failed_close_raises(tmp_path, monkeypatch):
    import psoperator.fixtures.invoice as inv_mod
    from psoperator.fixtures.invoice import RecordError, SubmissionRecord

    record = SubmissionRecord(tmp_path / "run.jsonl")
    fd = record._fd
    real_close = inv_mod.os.close

    def _close(_fd):
        raise OSError("injected")

    monkeypatch.setattr(inv_mod.os, "close", _close)
    try:
        with pytest.raises(RecordError, match="cannot close"):
            record.close()
    finally:
        monkeypatch.undo()
        real_close(fd)


def test_appending_after_the_path_became_invalid_raises(tmp_path):
    from psoperator.fixtures.invoice import RecordError, SubmissionRecord

    record = SubmissionRecord(tmp_path / "run.jsonl")
    record.path = tmp_path / "bad\x00.jsonl"
    try:
        with pytest.raises(RecordError):
            record.append(field_rows(DEMO_INVOICE))
    finally:
        record.path = tmp_path / "run.jsonl"
        record.close()
