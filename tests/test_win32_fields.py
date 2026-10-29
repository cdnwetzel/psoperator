"""Read-only Win32 field identity (pilot charter: Win32 binding plus OCR reading).

A field is an ``Edit`` identified by the label panel directly to its left: the
panel's internal name (kept only as a SHA-256), both rectangles, the class
path and the process image; the running process instance is bound
separately. Control ids and window text are never used; an Edit's text is
never read at all.

The pairing runs on recorded window trees on every platform. The trees here
are synthetic, shaped like the probe's record screen (a label panel left of
each Edit on shared rows) but carrying no real names, values or geometry. The
Windows-only tests read a window the test creates itself, never the
application, and check that reading it sends no message and moves no focus.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os

import pytest

from psoperator.perception.win32_fields import (
    FieldScan,
    Win32Field,
    Win32FieldError,
    WindowNode,
    name_hash,
    pair_fields,
)

PANEL = "wxWindowClassNR"


def _panel(x, y, w=60, h=20, name="label", **kw) -> WindowNode:
    return WindowNode(PANEL, (x, y, w, h), name_hash=name_hash(name) if name else None, **kw)


def _edit(x, y, w=120, h=20, **kw) -> WindowNode:
    return WindowNode("Edit", (x, y, w, h), **kw)


def _box(*children: WindowNode, cls="wxWindowNR") -> WindowNode:
    return WindowNode(cls, (0, 0, 800, 600), children=tuple(children))


def _form(*children: WindowNode) -> WindowNode:
    return _box(_box(*children))


def _scan(root: WindowNode, **kw) -> FieldScan:
    return pair_fields(root, pid=4242, process_started=7, process_image="app.exe", **kw)


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
    assert first.instance == (4242, 7) and first.process_image == "app.exe"


def test_the_recorded_layout_pairs():
    # Every recorded label overlaps its Edit by 3 px on a shared centre.
    scan = _scan(_form(_panel(10, 10, w=68, name="a"), _edit(75, 10)))
    assert len(scan.fields) == 1 and scan.fields[0].label_rect == (10, 10, 68, 20)


def test_the_nearest_left_panel_wins_on_a_shared_row():
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
    scan = _scan(_form(_panel(10, panel_y, name="a"), _edit(75, 10)))
    assert (len(scan.fields) == 1) is paired
    assert scan.unpaired == (0 if paired else 1)


@pytest.mark.parametrize(
    "right_edge, paired",
    [(66, False), (67, True), (75, True), (79, True), (80, False)],
    ids=["gap-9", "gap-8", "touching", "overlap-4", "overlap-5"],
)
def test_the_panel_edge_must_lie_from_eight_left_to_four_past_the_edit(right_edge, paired):
    # A panel farther away is not this Edit's label, however it is nested.
    scan = _scan(_form(_panel(right_edge - 60, 10, w=60, name="a"), _edit(75, 10)))
    assert (len(scan.fields) == 1) is paired


def test_a_distant_panel_in_another_container_is_not_borrowed():
    # The Edit's own label is missing; an unrelated panel on the same row, in
    # another container, sits too far left to count.
    other = _box(_panel(10, 10, name="someone-elses"), cls="wxPanel")
    mine = _box(_edit(200, 10), cls="wxPanel")
    scan = _scan(_box(other, mine))
    assert scan.fields == () and scan.unpaired == 1


def test_one_panel_nearest_to_two_edits_pairs_neither():
    # A shared nearest panel means the layout is not the one recorded; binding
    # either Edit to it could bind the wrong field.
    root = _form(_panel(10, 10, name="a"), _edit(72, 10, w=40), _edit(74, 10, w=40))
    scan = _scan(root)
    assert scan.fields == () and scan.unpaired == 2


def test_identical_subtrees_expose_no_field():
    # Two copies of one form at the same place: every panel ties, so no
    # identity is exposed twice.
    form = _box(_panel(10, 10, name="a"), _edit(75, 10))
    scan = _scan(_box(form, form))
    assert scan.fields == () and scan.unpaired == 2


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
    scan = _scan(_box(hidden))
    assert scan.fields == () and scan.unpaired == 0


def test_an_unnamed_nearest_panel_leaves_the_edit_unpaired():
    # Never fall back to the farther, named panel: that would bind the wrong label.
    root = _form(_panel(10, 10, w=58, name="far"), _panel(40, 10, w=30, name=""), _edit(75, 10))
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


def test_an_edit_cannot_be_the_root():
    with pytest.raises(Win32FieldError, match="must be a container"):
        _scan(WindowNode("Edit", (0, 0, 100, 20)))


def test_a_root_of_the_label_class_is_a_container_never_a_label():
    # The application's own top-level window has the label panels' class
    # (observed 2026-10-28). It must be accepted as the container and never
    # chosen as a label, even with a name and a rectangle a label would have.
    root = WindowNode(
        PANEL, (0, 0, 70, 20), name_hash=name_hash("the-window"),
        children=(_panel(10, 40, name="a"), _edit(75, 40), _edit(75, 0)),
    )  # fmt: skip
    scan = _scan(root)
    assert [f.label_hash for f in scan.fields] == [name_hash("a")]
    assert scan.unpaired == 1  # the Edit beside the root's own rectangle
    assert scan.fields[0].class_path == (PANEL, "Edit")


def test_fields_come_in_reading_order():
    root = _form(
        _panel(180, 40, name="d"), _edit(245, 40),
        _panel(10, 40, name="c"), _edit(75, 40),
        _panel(180, 10, name="b"), _edit(245, 10),
        _panel(10, 10, name="a"), _edit(75, 10),
    )  # fmt: skip
    assert [f.label_hash for f in _scan(root).fields] == [name_hash(n) for n in "abcd"]


def test_a_record_shaped_screen_pairs_every_field():
    # 16 rows of four fields: the shape of the probe's record screen, with
    # synthetic names and a grid of its own.
    children = []
    for row in range(16):
        for column in range(4):
            x, y = 10 + column * 190, 10 + row * 28
            children += [_panel(x, y, w=68, name=f"r{row}c{column}"), _edit(x + 65, y, w=110)]
    scan = _scan(_form(*children))
    assert len(scan.fields) == 64 and scan.unpaired == 0
    assert len({f.identity for f in scan.fields}) == 64


def test_identity_holds_across_handles_and_instances():
    a = _scan(_form(_panel(10, 10, name="a", hwnd=0x10), _edit(75, 10, hwnd=0x11))).fields[0]
    b = _scan(_form(_panel(10, 10, name="a", hwnd=0x90), _edit(75, 10, hwnd=0x91))).fields[0]
    assert a.hwnd != b.hwnd and a == b
    restarted = pair_fields(
        _form(_panel(10, 10, name="a"), _edit(75, 10)),
        pid=4242, process_started=8, process_image="app.exe",
    ).fields[0]  # fmt: skip
    # The same field in a new process: identity holds, the instance does
    # not, and the two fields are not equal (a binding must match both).
    assert restarted.identity == a.identity
    assert restarted.instance != a.instance and restarted != a
    moved = _scan(_form(_panel(10, 10, name="a"), _edit(76, 10))).fields[0]
    renamed = _scan(_form(_panel(10, 10, name="z"), _edit(75, 10))).fields[0]
    assert moved.identity != a.identity and renamed.identity != a.identity


def _at(node: WindowNode, dx: int, dy: int) -> WindowNode:
    x, y, w, h = node.rect
    return dataclasses.replace(
        node, rect=(x + dx, y + dy, w, h), children=tuple(_at(c, dx, dy) for c in node.children)
    )


def test_identity_is_relative_to_the_window_so_a_move_keeps_it():
    # The screen rectangle is for acting; identity must survive moving or
    # restoring the window.
    form = _form(_panel(10, 10, name="a"), _edit(75, 10))
    here = _scan(form).fields[0]
    moved = _scan(_at(form, 500, 300)).fields[0]
    assert moved.identity == here.identity and moved == here
    assert moved.rect == (75, 10, 120, 20) and moved.label_rect == (10, 10, 60, 20)
    assert moved.screen_rect == (575, 310, 120, 20) != here.screen_rect
    # The control: a field moved within the window is a different field.
    shifted = _scan(_form(_panel(10, 10, name="a"), _edit(76, 10))).fields[0]
    assert shifted.identity != here.identity


def test_a_tree_too_large_or_too_deep_is_refused_not_truncated():
    wide = _box(*[_box() for _ in range(30)])
    assert _scan(wide, max_nodes=30).fields == ()
    with pytest.raises(Win32FieldError, match="exceeds 29 windows"):
        _scan(wide, max_nodes=29)
    deep = _edit(75, 10)
    for _ in range(10):
        deep = _box(deep)
    _scan(_box(deep), max_depth=11)
    with pytest.raises(Win32FieldError, match="deeper than 10"):
        _scan(_box(deep), max_depth=10)


def test_a_field_carries_no_text():
    names = {f.name for f in dataclasses.fields(Win32Field)}
    assert names == {
        "pid", "process_started", "process_image", "class_path",
        "label_hash", "rect", "label_rect", "screen_rect", "hwnd",
    }  # fmt: skip
    names = {f.name for f in dataclasses.fields(WindowNode)}
    assert names == {
        "class_name", "rect", "visible", "name_hash", "hwnd", "children", "client_rect",
    }  # fmt: skip


@pytest.mark.skipif(os.name == "nt", reason="the non-Windows refusal")
def test_off_windows_reading_a_window_refuses():
    from psoperator.perception import win32_fields

    with pytest.raises(Win32FieldError, match="only available on Windows"):
        win32_fields.read_window_tree(1)


# --- a real window the test makes itself (Windows) ---------------------------


def _foreground() -> int:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32")
    user32.GetForegroundWindow.restype = wintypes.HWND
    return user32.GetForegroundWindow() or 0


class _OwnForm:
    """A top-level window this test creates: a group box holding a Static
    label left of each Edit. It is placed off-screen and never activated, so
    it cannot take focus or cover anything; the application is never touched."""

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
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        self._user32 = user32
        instance = kernel32.GetModuleHandleW(None)
        popup, visible, child, group_box = 0x80000000, 0x10000000, 0x40000000, 0x7
        tool, no_activate = 0x00000080, 0x08000000
        self.hwnd = user32.CreateWindowExW(
            tool | no_activate, "BUTTON", "", popup | visible | group_box,
            -32000, -32000, 600, 40 + 30 * len(rows), None, None, instance, None,
        )  # fmt: skip
        assert self.hwnd, ctypes.get_last_error()
        for i, (label, value) in enumerate(rows):
            y = 10 + 30 * i
            for cls, text, x, w in (("STATIC", label, 10, 68), ("EDIT", value, 75, 120)):
                made = user32.CreateWindowExW(
                    0, cls, text, child | visible, x, y, w, 20, self.hwnd, None, instance, None
                )
                assert made, ctypes.get_last_error()

    def __enter__(self) -> "_OwnForm":
        return self

    def __exit__(self, *exc) -> None:
        self._user32.DestroyWindow(self.hwnd)


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


windows_only = pytest.mark.skipif(os.name != "nt", reason="reads real Win32 windows")


@windows_only
def test_a_real_window_is_read_without_its_text_or_focus():
    from psoperator.perception import win32_fields

    rows = [("internal_a", "typed value one"), ("internal_b", "typed value two")]
    foreground = _foreground()  # taken before the window exists
    with _OwnForm(rows) as form:
        assert _foreground() == foreground, "creating the test window moved focus"
        scan = win32_fields.scan_window(form.hwnd, label_class="Static")
        again = win32_fields.scan_window(form.hwnd, label_class="Static")
        assert _foreground() == foreground, "reading the window moved focus"
    assert scan.unpaired == 0
    assert [f.label_hash for f in scan.fields] == [name_hash("internal_a"), name_hash("internal_b")]
    field = scan.fields[0]
    assert field.pid == os.getpid() and field.process_started > 0
    assert field.process_image.lower().startswith("python")
    assert field.class_path == ("Button", "Edit")
    assert field.rect == (75, 10, 120, 20)  # relative to the test window
    assert field.screen_rect == (-32000 + 75, -32000 + 10, 120, 20)
    assert scan == again
    assert "typed value" not in repr(scan)


@windows_only
def test_reading_sends_no_message_and_reads_only_label_captions(monkeypatch):
    # Every user32 call the reader makes is recorded. None of them sends the
    # window a message (GetWindowText, GetWindowTextLength and SendMessage
    # would), and captions are read only from label windows below the root.
    from psoperator.perception import win32_fields

    calls: list[tuple[str, int]] = []
    real = win32_fields._user32

    class _Recorder:
        def __init__(self) -> None:
            self._inner = real()

        def __getattr__(self, name):
            func = getattr(self._inner, name)

            def call(*args):
                calls.append((name, int(args[0] or 0) if args else 0))
                return func(*args)

            return call

    monkeypatch.setattr(win32_fields, "_user32", _Recorder)
    with _OwnForm([("internal_a", "typed value one")]) as form:
        tree = win32_fields.read_window_tree(form.hwnd, label_class="Static")
    used = {name for name, _ in calls}
    assert used <= {
        "IsWindow", "GetWindow", "GetClassNameW", "GetWindowRect",
        "IsWindowVisible", "InternalGetWindowText", "GetClientRect", "ClientToScreen",
    }, used  # fmt: skip
    classes = {node.hwnd: node.class_name for node in _walk(tree)}
    captions = [hwnd for name, hwnd in calls if name == "InternalGetWindowText"]
    assert captions and all(classes[h] == "Static" for h in captions)
    assert tree.hwnd not in captions
    assert sum(1 for c in classes.values() if c == "Edit") == 1
    # The root is the container: even when its class is the label class, its
    # caption is not read.
    calls.clear()
    with _OwnForm([("internal_a", "typed value one")]) as form:
        tree = win32_fields.read_window_tree(form.hwnd, label_class="Button")
    assert tree.name_hash is None
    assert ("InternalGetWindowText", tree.hwnd) not in calls


@windows_only
def test_a_real_tree_larger_than_the_cap_is_refused_not_truncated():
    from psoperator.perception import win32_fields

    with _OwnForm([("internal_a", "v"), ("internal_b", "v")]) as form:
        assert len(list(_walk(win32_fields.read_window_tree(form.hwnd, max_nodes=5)))) == 5
        with pytest.raises(Win32FieldError, match="refusing to truncate"):
            win32_fields.read_window_tree(form.hwnd, max_nodes=4)
        with pytest.raises(Win32FieldError, match="deeper than 0"):
            win32_fields.read_window_tree(form.hwnd, max_depth=0)
