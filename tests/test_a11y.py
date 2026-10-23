"""AT-SPI tree walk (R-303) and the cross-platform A11yNode contract.

The live provider needs pyatspi and a running AT-SPI desktop, neither of which
exists off-Linux or in CI. So the walk reads only a small, fake-able slice of
the AT-SPI surface (``getRoleName``, ``name``, ``childCount``,
``getChildAtIndex``, ``queryComponent().getExtents``) and these tests drive it
through :class:`AtSpiA11y`'s injected-desktop seam with fakes that implement
exactly that slice. The live path is validated on the AT-SPI host separately;
what is pinned here is the conversion logic, the node budget, and the
robustness guards — the parts that must not drift.
"""

from __future__ import annotations

from psoperator.perception.a11y import (
    AtSpiA11y,
    StubA11yProvider,
    default_a11y,
)

# A sentinel coordinate type: the walk passes it straight to getExtents, so any
# non-None value exercises the bounds path without needing pyatspi's constant.
COORD = object()


class FakeExtents:
    def __init__(self, x, y, w, h):
        self.x, self.y, self.width, self.height = x, y, w, h


class FakeComponent:
    def __init__(self, extents):
        self._extents = extents

    def getExtents(self, coord_type):
        assert coord_type is COORD  # the walk must pass the configured type
        return self._extents


class FakeAcc:
    """A fake AT-SPI accessible implementing only what the walk reads."""

    def __init__(self, role, name, children=(), extents=None):
        self._role = role
        self.name = name
        self._children = list(children)
        self._extents = extents

    def getRoleName(self):
        return self._role

    @property
    def childCount(self):
        return len(self._children)

    def getChildAtIndex(self, i):
        return self._children[i]

    def queryComponent(self):
        if self._extents is None:
            raise RuntimeError("no component interface")
        return FakeComponent(self._extents)


def _invoice_desktop():
    """A desktop whose one app holds an invoice-entry frame — the demo shape."""
    # Real AT-SPI roles, validated live on the AT-SPI host (2026-09-11): a
    # Gtk.Entry exposes role "text", a Gtk.Button exposes "button" — not
    # "entry"/"push button" (psoperator #2). The fakes mirror the real writer.
    vendor = FakeAcc("text", "Vendor", extents=FakeExtents(10, 40, 200, 24))
    total = FakeAcc("text", "Invoice Total", extents=FakeExtents(10, 70, 200, 24))
    submit = FakeAcc("button", "Submit", extents=FakeExtents(10, 110, 80, 30))
    frame = FakeAcc("frame", "Invoice Entry", children=[vendor, total, submit])
    app = FakeAcc("application", "invoice-fixture", children=[frame])
    return FakeAcc("desktop frame", "main", children=[app])


def _provider(desktop, coord_type=COORD):
    return AtSpiA11y(desktop=desktop, coord_type=coord_type)


def test_walk_builds_the_synthetic_root_over_the_live_apps():
    tree = _provider(_invoice_desktop()).tree()
    # Synthetic root mirrors WinAutoA11y: role "desktop", name "root".
    assert tree.role == "desktop" and tree.name == "root"
    # Its children are the live application accessibles, not the desktop itself.
    assert [c.role for c in tree.children] == ["application"]
    assert tree.children[0].name == "invoice-fixture"


def test_roles_are_lowercased_and_names_preserved():
    tree = _provider(_invoice_desktop()).tree()
    frame = tree.children[0].children[0]
    assert frame.role == "frame"  # "frame" already lower; role is casefolded
    roles = {n.role for n in frame.walk()}
    assert {"text", "button"} <= roles  # the real GTK-fixture roles (psoperator #2)
    names = {n.name for n in frame.walk()}
    assert {"Vendor", "Invoice Total", "Submit"} <= names


def test_a_spaced_role_is_lowercased_intact():
    # AT-SPI has spaced role names ("page tab", "menu item", "check box");
    # getRoleName() may return them mixed-case, and the walk must lowercase
    # without dropping the space.
    tab = FakeAcc("Page Tab", "Details")
    app = FakeAcc("application", "app", children=[FakeAcc("frame", "f", children=[tab])])
    node = _provider(FakeAcc("desktop frame", "d", children=[app])).find(name="Details")
    assert node is not None and node.role == "page tab"


def test_bounds_come_from_getextents_in_the_configured_coords():
    total = _provider(_invoice_desktop()).find(role="text", name="Invoice Total")
    assert total is not None
    assert total.bounds == (10, 70, 200, 24)


def test_bounds_are_none_without_a_coord_type():
    # No coordinate type configured -> the walk never calls getExtents.
    tree = AtSpiA11y(desktop=_invoice_desktop(), coord_type=None).tree()
    assert all(n.bounds is None for n in tree.walk())


def test_bounds_are_none_when_the_element_has_no_component():
    # A label with no component interface must not crash the walk.
    label = FakeAcc("label", "Amount due")  # extents=None -> queryComponent raises
    app = FakeAcc("application", "app", children=[FakeAcc("frame", "f", children=[label])])
    desktop = FakeAcc("desktop frame", "d", children=[app])
    node = _provider(desktop).find(role="label", name="Amount due")
    assert node is not None and node.bounds is None


def test_find_locates_a_field_through_the_real_walk():
    prov = _provider(_invoice_desktop())
    submit = prov.find(role="button", name="submit")  # find casefolds name
    assert submit is not None and submit.name == "Submit"
    assert prov.find(role="button", name="nonexistent") is None


def test_max_nodes_budget_truncates_like_the_windows_walk():
    # The invoice desktop has 5 conv'd nodes (app, frame, 3 fields). A budget of
    # 3 keeps the app + frame + first field, and breaks the sibling loop.
    tree = _provider(_invoice_desktop()).tree(max_nodes=3)
    counted = [n for n in tree.walk() if n.role != "desktop"]  # exclude synthetic root
    assert len(counted) == 3
    # The break happened at a sibling boundary: the frame kept only its first child.
    frame = tree.children[0].children[0]
    assert [c.name for c in frame.children] == ["Vendor"]


def test_a_child_that_raises_on_access_is_skipped_not_fatal():
    class ExplodingChildAcc(FakeAcc):
        def getChildAtIndex(self, i):
            if i == 1:
                raise RuntimeError("gone")
            return super().getChildAtIndex(i)

    a = FakeAcc("entry", "A")
    b = FakeAcc("entry", "B")  # index 1 -> raises, must be skipped
    c = FakeAcc("entry", "C")
    frame = ExplodingChildAcc("frame", "f", children=[a, b, c])
    app = FakeAcc("application", "app", children=[frame])
    desktop = FakeAcc("desktop frame", "d", children=[app])
    names = {n.name for n in _provider(desktop).tree().walk()}
    assert "A" in names and "C" in names and "B" not in names


def test_a_name_access_that_raises_yields_empty_string():
    class NamelessAcc(FakeAcc):
        @property
        def name(self):
            raise RuntimeError("name unavailable")

        @name.setter
        def name(self, v):
            pass

    frame = NamelessAcc("frame", "", children=[])
    app = FakeAcc("application", "app", children=[frame])
    desktop = FakeAcc("desktop frame", "d", children=[app])
    node = _provider(desktop).find(role="frame")
    assert node is not None and node.name == ""


def test_default_a11y_falls_back_to_the_stub_off_linux():
    # Off a live desktop, the factory must degrade to the honest empty stub
    # rather than raise (a missing provider is not a crash).
    prov = default_a11y()
    assert prov.tree() is None or isinstance(prov, StubA11yProvider)
