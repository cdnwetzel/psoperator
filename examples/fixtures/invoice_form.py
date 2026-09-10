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


def build_window(invoice: Invoice):
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

    for row, (name, value) in enumerate(field_rows(invoice)):
        label = Gtk.Label(label=name, halign=Gtk.Align.END)
        entry = Gtk.Entry(text=value, hexpand=True)
        # The load-bearing line: give the entry the exact accessible name the
        # walk and the operator preview both key on.
        entry.get_accessible().set_name(name)
        label.set_mnemonic_widget(entry)
        grid.attach(label, 0, row, 1, 1)
        grid.attach(entry, 1, row, 1, 1)

    submit = Gtk.Button(label=SUBMIT_NAME)
    submit.get_accessible().set_name(SUBMIT_NAME)

    def _on_submit(_btn):
        # A visible, inert commit — the fixture never acts on its own; the
        # governed executor replays approved input against it.
        print(f"[fixture] {SUBMIT_NAME} pressed for {WINDOW_TITLE}")

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

    win = build_window(invoice)
    win.show_all()
    Gtk.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
