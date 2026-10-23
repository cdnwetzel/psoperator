"""Invoice-entry reference fixture: the domain-shaped target for R-304.

A GNOME-Settings toggle demonstrates the a11y ladder but tells a governance
audience nothing — there is no story in flipping a switch. An invoice form makes
the field-level preview the operator signs (vendor, total, date) legible as a
decision with consequence, which is the whole point of the staging layer.

This module is the *contract*, not the UI: the accessible names the AT-SPI walk
must find, the window identity the gatekeeper binds, and the field-level preview
the operator reviews — all pure, importable without a display, and shared by the
GTK app in ``examples/fixtures/invoice_form.py`` and the demo harness. If the two
drift, a field the operator approves would not be the field that executes; the
tests here pin them together.
"""

from __future__ import annotations

from dataclasses import dataclass

# The window title the gatekeeper binds an action to (R-301 window identity).
WINDOW_TITLE = "Invoice Entry"

# The accessible name of the commit control.
SUBMIT_NAME = "Submit"

# The editable fields, in display order. These are the exact ATK/AT-SPI
# accessible names the walk locates and the operator preview labels — one list,
# used by the UI, the walk, and the preview, so they cannot disagree.
FIELD_NAMES: tuple[str, ...] = ("Vendor", "Invoice Number", "Date", "Invoice Total")


@dataclass(frozen=True)
class Invoice:
    """One invoice's field values. Field order matches FIELD_NAMES."""

    vendor: str
    number: str
    date: str
    total: str

    def __post_init__(self) -> None:
        # A frozen fixture with a field the preview cannot name is a silent
        # drift hazard; fail loud at construction instead.
        missing = [n for n, _ in _rows(self)]
        if tuple(missing) != FIELD_NAMES:
            raise ValueError(f"invoice rows {missing} do not match FIELD_NAMES {FIELD_NAMES}")


def _rows(inv: "Invoice") -> list[tuple[str, str]]:
    return [
        ("Vendor", inv.vendor),
        ("Invoice Number", inv.number),
        ("Date", inv.date),
        ("Invoice Total", inv.total),
    ]


def field_rows(inv: Invoice) -> list[tuple[str, str]]:
    """The field-level preview: (accessible name, value) for every field.

    This is exactly what the operator reviews before signing — the diff, not a
    summary. The demo builds its preview from this, and the GTK app labels its
    entries from the same names, so the reviewed field is the executed field.
    """
    return _rows(inv)


# The canonical demo invoice. A plausible, specific record — not "test/123" —
# because the demo's credibility rests on it reading like real work.
DEMO_INVOICE = Invoice(
    vendor="Northwind Traders LLC",
    number="INV-2026-0417",
    date="2026-09-10",
    total="$12,480.00",
)
