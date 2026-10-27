"""GTK temperature converter — the v1 reference workflow target.

A GTK port of the Tkinter converter the violoop harness drove by pixels. Tk
exposes no AT-SPI tree on Linux, so the service path, which plans from
accessibility elements, could not find its entry field. Every control here
carries an explicit accessible name from :mod:`psoperator.fixtures.tempconv`,
and the result label republishes its accessible name on every Convert, so the
result can be read from an attested snapshot.

Run on the AT-SPI host (a real display + a11y bus required):
    python examples/fixtures/tempconv_form.py

Off a display, validate the contract without importing GTK:
    python examples/fixtures/tempconv_form.py --check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from psoperator.fixtures.tempconv import (  # noqa: E402
    C2F,
    C_TO_F_NAME,
    CONVERT_NAME,
    DEFAULT_DIRECTION,
    F2C,
    F_TO_C_NAME,
    V1_EXPECTED,
    V1_GOAL,
    VALUE_NAME,
    WINDOW_TITLE,
    convert_text,
    result_name,
)


def build_window():
    """Build (but do not run) the GTK window. Imports gi lazily so this module
    stays importable — and --check runnable — without a GUI toolkit present."""
    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk

    win = Gtk.Window(title=WINDOW_TITLE)
    win.set_border_width(16)
    win.set_default_size(400, 250)
    win.connect("destroy", Gtk.main_quit)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    win.add(box)

    entry = Gtk.Entry()
    entry.get_accessible().set_name(VALUE_NAME)
    box.pack_start(entry, False, False, 0)

    c_to_f = Gtk.RadioButton.new_with_label(None, C_TO_F_NAME)
    f_to_c = Gtk.RadioButton.new_with_label_from_widget(c_to_f, F_TO_C_NAME)
    c_to_f.get_accessible().set_name(C_TO_F_NAME)
    f_to_c.get_accessible().set_name(F_TO_C_NAME)
    (c_to_f if DEFAULT_DIRECTION == C2F else f_to_c).set_active(True)
    box.pack_start(c_to_f, False, False, 0)
    box.pack_start(f_to_c, False, False, 0)

    result = Gtk.Label(label="")
    result.get_accessible().set_name(result_name(""))
    box.pack_start(result, False, False, 0)

    convert = Gtk.Button(label=CONVERT_NAME)
    convert.get_accessible().set_name(CONVERT_NAME)

    def _on_convert(_btn):
        shown = convert_text(entry.get_text(), F2C if f_to_c.get_active() else C2F)
        result.set_text(shown)
        # The load-bearing line: the checker reads the result from the
        # snapshot, which carries accessible names, not widget text.
        result.get_accessible().set_name(result_name(shown))
        print(f"[fixture] {CONVERT_NAME}: {shown}", flush=True)

    convert.connect("clicked", _on_convert)
    box.pack_start(convert, False, False, 0)
    return win


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="GTK temperature-converter reference fixture")
    ap.add_argument(
        "--check",
        action="store_true",
        help="validate the contract and print the v1 task; no display needed",
    )
    args = ap.parse_args(argv)

    if args.check:
        print(f"window: {WINDOW_TITLE}")
        print(f"controls: {VALUE_NAME}, {C_TO_F_NAME}, {F_TO_C_NAME}, {CONVERT_NAME}")
        print(f"v1 goal: {V1_GOAL}")
        print(f"v1 pass: {result_name(V1_EXPECTED)}")
        return 0

    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk

    win = build_window()
    win.show_all()
    Gtk.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
