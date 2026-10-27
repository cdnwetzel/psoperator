"""GTK invoice-entry form — the R-304 reference fixture's UI.

A deliberately small, native-GTK target so its AT-SPI tree is complete and
stable (never Electron, whose exposure is partial). Every editable field carries
an explicit accessible name from :data:`FIELD_NAMES`, so the walk in
``psoperator.perception.a11y`` finds exactly the fields the operator preview
names. The window title is stable (:data:`WINDOW_TITLE`) so the gatekeeper can
bind an action to this window's identity.

Run on the AT-SPI host (a real display + a11y bus required):

    python examples/fixtures/invoice_form.py
    python examples/fixtures/invoice_form.py --vendor "ACME" --total "$9.99"
    python examples/fixtures/invoice_form.py --record /tmp/run-1.jsonl   # v2 runs

With --record, each Submit appends the fields as the widgets held them. The file
must not exist yet, and a failed write stops the fixture with exit code 3, so an
unrecorded Submit never reads as no Submit.

Off a display, validate the data contract without importing GTK:

    python examples/fixtures/invoice_form.py --check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from psoperator.fixtures.invoice import (  # noqa: E402
    DEMO_INVOICE,
    SUBMIT_NAME,
    WINDOW_TITLE,
    Invoice,
    RecordError,
    SubmissionRecord,
    field_rows,
)


def _invoice_from_args(args: argparse.Namespace) -> Invoice:
    d = DEMO_INVOICE
    return Invoice(
        vendor=args.vendor or d.vendor,
        number=args.number or d.number,
        date=args.date or d.date,
        total=args.total or d.total,
    )


def build_window(
    invoice: Invoice,
    record: SubmissionRecord | None = None,
    failed: list[str] | None = None,
):
    """Build (but do not run) the GTK window. Imports gi lazily so this module
    stays importable — and --check runnable — without a GUI toolkit present."""
    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk

    win = Gtk.Window(title=WINDOW_TITLE)
    win.set_border_width(16)
    win.set_default_size(360, 0)
    win.connect("destroy", Gtk.main_quit)

    grid = Gtk.Grid(row_spacing=8, column_spacing=12)
    win.add(grid)

    entries: list[tuple[str, object]] = []
    for row, (name, value) in enumerate(field_rows(invoice)):
        label = Gtk.Label(label=name, halign=Gtk.Align.END)
        entry = Gtk.Entry(text=value, hexpand=True)
        entries.append((name, entry))
        # The load-bearing line: give the entry the exact accessible name the
        # walk and the operator preview both key on.
        entry.get_accessible().set_name(name)
        label.set_mnemonic_widget(entry)
        grid.attach(label, 0, row, 1, 1)
        grid.attach(entry, 1, row, 1, 1)

    submit = Gtk.Button(label=SUBMIT_NAME)
    submit.get_accessible().set_name(SUBMIT_NAME)

    def _say(message: str, stream=None) -> None:
        # Diagnostics only: a broken stdout/stderr must never stop recording
        # or the failure path.
        try:
            print(message, file=stream or sys.stdout, flush=True)
        except (OSError, ValueError):
            pass

    def _on_submit(_btn):
        # A visible, inert commit — the fixture never acts on its own; the
        # governed executor replays approved input against it. Record first,
        # then set the failure state, and only then print.
        if record is not None:
            try:
                record.append([(name, e.get_text()) for name, e in entries])
            except RecordError as exc:
                # An unrecorded Submit must not look like no Submit: stop, and
                # let main() exit 3 so the run's outcome reads as unknown.
                if failed is not None:
                    failed.append(str(exc))
                Gtk.main_quit()
                _say(f"[fixture] RECORD FAILED: {exc}", sys.stderr)
                return
        _say(f"[fixture] {SUBMIT_NAME} pressed for {WINDOW_TITLE}")

    submit.connect("clicked", _on_submit)
    grid.attach(submit, 0, len(field_rows(invoice)), 2, 1)

    return win


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="GTK invoice-entry reference fixture")
    ap.add_argument("--vendor")
    ap.add_argument("--number")
    ap.add_argument("--date")
    ap.add_argument("--total")
    ap.add_argument(
        "--record",
        type=Path,
        help="record each Submit as a JSON line here; the file must not exist yet",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="validate the data contract and print the preview; no display needed",
    )
    args = ap.parse_args(argv)
    invoice = _invoice_from_args(args)

    if args.check:
        print(f"window: {WINDOW_TITLE}")
        for name, value in field_rows(invoice):
            print(f"  {name}: {value}")
        print(f"submit: {SUBMIT_NAME}")
        return 0

    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk

    failed: list[str] = []
    record = None
    if args.record is not None:
        try:
            record = SubmissionRecord(args.record)
        except RecordError as exc:
            print(f"[fixture] {exc}", file=sys.stderr)
            return 3
    win = build_window(invoice, record, failed)
    win.show_all()
    try:
        Gtk.main()
    finally:
        if record is not None:
            record.close()
    return 3 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
