"""Read-only Win32 field identity (pilot charter: Win32 binding plus OCR reading).

A field is an ``Edit`` identified by the label panel directly to its left: the
panel's internal name (kept only as a SHA-256), both rectangles, the class
path and the process. Control ids and window text are never used; an Edit's
text is never read at all.

The pairing runs on recorded window trees on every platform. The trees here
are synthetic, shaped like the probe's record screen (a label panel left of
each Edit on shared rows) but carrying no real names, values or geometry. One
Windows-only test reads a window the test creates itself, never the
application, and checks that no input reaches it and focus does not move.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os

import pytest

from psoperator.perception.win32_fields import (
    FieldScan,
    Win32Field,
    WindowNode,
    name_hash,
    pair_fields,
)

PANEL = "wxWindowClassNR"


def _panel(x, y, w=60, h=20, name="label", **kw) -> WindowNode:
    return WindowNode(PANEL, (x, y, w, h), name_hash=name_hash(name) if name else None, **kw)


def _edit(x, y, w=120, h=20, **kw) -> WindowNode:
    return WindowNode("Edit", (x, y, w, h), **kw)


def _form(*children: WindowNode) -> WindowNode:
    body = WindowNode("wxWindowNR", (0, 0, 800, 600), children=tuple(children))
    return WindowNode("wxWindowNR", (0, 0, 800, 600), children=(body,))


def _scan(root: WindowNode, **kw) -> FieldScan:
    return pair_fields(root, pid=4242, process_image="app.exe", **kw)


def test_name_hash_is_sha256_of_the_utf8_text():
    assert name_hash("fld_a") == hashlib.sha256(b"fld_a").hexdigest()


def test_each_edit_pairs_with_the_panel_directly_to_its_left():
    root = _form(
        _panel(10, 10, name="a"),
        _edit(75, 10),
        _panel(10, 40, name="b"),
        _edit(75, 40),
    )
    scan = _scan(root)
    assert scan.unpaired == 0
    assert [f.label_hash for f in scan.fields] == [name_hash("a"), name_hash("b")]
    first = scan.fields[0]
    assert first.rect == (75, 10, 120, 20) and first.label_rect == (10, 10, 60, 20)
    assert first.class_path == ("wxWindowNR", "wxWindowNR", "Edit")
    assert (first.pid, first.process_image) == (4242, "app.exe")


def test_the_nearest_left_panel_wins_on_a_shared_row():
    # Two fields on one row: the second Edit pairs with the panel between them,
    # not with the first label or anything to its right.
    root = _form(
        _panel(10, 10, name="left"),
        _edit(75, 10, w=100),
        _panel(180, 10, name="middle"),
        _edit(245, 10, w=100),
        _panel(350, 10, name="right"),
    )
    scan = _scan(root)
    assert [f.label_hash for f in scan.fields] == [name_hash("left"), name_hash("middle")]


@pytest.mark.parametrize(
    "panel_y, paired",
    [(10, True), (17, True), (3, True), (18, False), (2, False)],
    ids=["same-row", "below-within", "above-within", "below-outside", "above-outside"],
)
def test_the_row_tolerance_is_under_eight_pixels(panel_y, paired):
    # Centres must differ by less than 8 px, the probe's rule.
    scan = _scan(_form(_panel(10, panel_y, name="a"), _edit(75, 10)))
    assert (len(scan.fields) == 1) is paired
    assert scan.unpaired == (0 if paired else 1)


@pytest.mark.parametrize(
    "panel_x, paired",
    [(15, True), (19, True), (20, False)],
    ids=["touching", "overlap-4", "overlap-5"],
)
def test_a_panel_may_overlap_the_edit_by_four_pixels_at_most(panel_x, paired):
    # The panel's right edge may sit at most 4 px past the Edit's left edge.
    scan = _scan(_form(_panel(panel_x, 10, w=60, name="a"), _edit(75, 10)))
    assert (len(scan.fields) == 1) is paired


def test_invisible_windows_are_ignored():
    hidden_edit = _scan(_form(_panel(10, 10, name="a"), _edit(75, 10, visible=False)))
    assert hidden_edit.fields == () and hidden_edit.unpaired == 0
    hidden_panel = _scan(_form(_panel(10, 10, name="a", visible=False), _edit(75, 10)))
    assert hidden_panel.fields == () and hidden_panel.unpaired == 1


def test_a_hidden_parent_hides_its_children():
    hidden = WindowNode(
        "wxWindowNR", (0, 0, 800, 600), visible=False,
        children=(_panel(10, 10, name="a"), _edit(75, 10)),
    )  # fmt: skip
    scan = _scan(WindowNode("wxWindowNR", (0, 0, 800, 600), children=(hidden,)))
    assert scan.fields == () and scan.unpaired == 0


def test_an_unnamed_nearest_panel_leaves_the_edit_unpaired():
    # Never fall back to a farther panel: that would bind the wrong label.
    root = _form(_panel(10, 10, w=20, name="far"), _panel(40, 10, w=30, name=""), _edit(75, 10))
    scan = _scan(root)
    assert scan.fields == () and scan.unpaired == 1


def test_two_equally_near_panels_leave_the_edit_unpaired():
    root = _form(_panel(10, 10, name="a"), _panel(10, 14, name="b"), _edit(75, 10))
    scan = _scan(root)
    assert scan.fields == () and scan.unpaired == 1


def test_an_edit_with_no_panel_is_counted_not_dropped_silently():
    scan = _scan(_form(_edit(75, 10), _panel(10, 40, name="a"), _edit(75, 40)))
    assert len(scan.fields) == 1 and scan.unpaired == 1


def test_only_the_label_class_counts_as_a_label():
    other = WindowNode("Static", (10, 10, 60, 20), name_hash=name_hash("a"))
    scan = _scan(_form(other, _edit(75, 10)))
    assert scan.fields == () and scan.unpaired == 1
    assert len(_scan(_form(other, _edit(75, 10)), label_class="Static").fields) == 1


def test_fields_come_in_reading_order():
    root = _form(
        _panel(180, 40, name="d"), _edit(245, 40),
        _panel(10, 40, name="c"), _edit(75, 40),
        _panel(180, 10, name="b"), _edit(245, 10),
        _panel(10, 10, name="a"), _edit(75, 10),
    )  # fmt: skip
    assert [f.label_hash for f in _scan(root).fields] == [name_hash(n) for n in "abcd"]


def test_a_record_shaped_screen_pairs_every_field():
    # 17 rows, up to four fields a row: the shape of the probe's record
    # screen, with synthetic names and a grid of its own.
    children = []
    for row in range(17):
        for column in range(4 if row < 16 else 0):
            x, y = 10 + column * 190, 10 + row * 28
            children += [_panel(x, y, name=f"r{row}c{column}"), _edit(x + 65, y, w=110)]
    scan = _scan(_form(*children))
    assert len(scan.fields) == 64 and scan.unpaired == 0
    assert len({f.identity for f in scan.fields}) == 64


def test_identity_holds_across_handles_and_excludes_them():
    a = _scan(_form(_panel(10, 10, name="a", hwnd=0x10), _edit(75, 10, hwnd=0x11))).fields[0]
    b = _scan(_form(_panel(10, 10, name="a", hwnd=0x90), _edit(75, 10, hwnd=0x91))).fields[0]
    assert a.hwnd != b.hwnd
    assert a.identity == b.identity and a == b
    moved = _scan(_form(_panel(10, 10, name="a"), _edit(76, 10))).fields[0]
    renamed = _scan(_form(_panel(10, 10, name="z"), _edit(75, 10))).fields[0]
    assert moved.identity != a.identity and renamed.identity != a.identity


def test_a_field_carries_no_text():
    names = {f.name for f in dataclasses.fields(Win32Field)}
    assert names == {
        "pid",
        "process_image",
        "class_path",
        "label_hash",
        "rect",
        "label_rect",
        "hwnd",
    }
    names = {f.name for f in dataclasses.fields(WindowNode)}
    assert names == {"class_name", "rect", "visible", "name_hash", "hwnd", "children"}


# --- a real window the test makes itself (Windows) ---------------------------


class _OwnForm:
    """A top-level window this test creates, with a Static label left of each
    Edit. It is placed off-screen and never activated, so it cannot take
    focus or cover anything; the application is never touched."""

    def __init__(self, rows: list[tuple[str, str]]) -> None:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
        ]  # fmt: skip
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.GetForegroundWindow.restype = wintypes.HWND
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        self._user32 = user32
        instance = kernel32.GetModuleHandleW(None)
        popup, visible, child = 0x80000000, 0x10000000, 0x40000000
        tool, no_activate = 0x00000080, 0x08000000
        self.hwnd = user32.CreateWindowExW(
            tool | no_activate, "STATIC", "", popup | visible,
            -32000, -32000, 600, 40 + 30 * len(rows), None, None, instance, None,
        )  # fmt: skip
        assert self.hwnd, ctypes.get_last_error()
        for i, (label, value) in enumerate(rows):
            y = 10 + 30 * i
            for cls, text, x, w in (("STATIC", label, 10, 60), ("EDIT", value, 75, 120)):
                made = user32.CreateWindowExW(
                    0, cls, text, child | visible, x, y, w, 20, self.hwnd, None, instance, None
                )
                assert made, ctypes.get_last_error()

    def foreground(self) -> int:
        return self._user32.GetForegroundWindow()

    def __enter__(self) -> "_OwnForm":
        return self

    def __exit__(self, *exc) -> None:
        self._user32.DestroyWindow(self.hwnd)


@pytest.mark.skipif(os.name != "nt", reason="reads real Win32 windows")
def test_a_real_window_is_read_without_its_text_or_focus():
    from psoperator.perception import win32_fields

    rows = [("internal_a", "typed value one"), ("internal_b", "typed value two")]
    with _OwnForm(rows) as form:
        foreground = form.foreground()
        scan = win32_fields.scan_window(form.hwnd, label_class="Static")
        assert form.foreground() == foreground, "reading the window moved focus"
    assert scan.unpaired == 0
    assert [f.label_hash for f in scan.fields] == [name_hash("internal_a"), name_hash("internal_b")]
    field = scan.fields[0]
    assert field.pid == os.getpid()
    assert field.process_image.lower().startswith("python")
    assert field.class_path == ("Static", "Edit")
    assert "typed value" not in repr(scan)


@pytest.mark.skipif(os.name != "nt", reason="reads real Win32 windows")
def test_only_label_windows_have_their_text_read(monkeypatch):
    # The text reader is called for label-class windows and nothing else, so
    # an Edit's text is never read, whatever the pairing does later.
    from psoperator.perception import win32_fields

    read: list[int] = []
    real = win32_fields._label_name_hash

    def _spy(user32, hwnd):
        read.append(int(hwnd))
        return real(user32, hwnd)

    monkeypatch.setattr(win32_fields, "_label_name_hash", _spy)
    with _OwnForm([("internal_a", "typed value one")]) as form:
        tree = win32_fields.read_window_tree(form.hwnd, label_class="Static")
    classes = {node.hwnd: node.class_name for node in _walk(tree)}
    assert read and all(classes[h] == "Static" for h in read)
    assert sum(1 for c in classes.values() if c == "Edit") == 1


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


@pytest.mark.skipif(os.name == "nt", reason="the non-Windows refusal")
def test_off_windows_reading_a_window_refuses():
    from psoperator.perception import win32_fields

    with pytest.raises(win32_fields.Win32FieldError, match="only available on Windows"):
        win32_fields.read_window_tree(1)


@pytest.mark.skipif(os.name != "nt", reason="reads real Win32 windows")
def test_a_tree_larger_than_the_cap_is_refused_not_truncated():
    from psoperator.perception import win32_fields

    with _OwnForm([("internal_a", "v"), ("internal_b", "v")]) as form:
        assert len(list(_walk(win32_fields.read_window_tree(form.hwnd, max_nodes=5)))) == 5
        with pytest.raises(win32_fields.Win32FieldError, match="refusing to truncate"):
            win32_fields.read_window_tree(form.hwnd, max_nodes=4)
