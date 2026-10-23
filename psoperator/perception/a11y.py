"""Accessibility-tree providers.

The a11y tree is the L1 grounding source: structured, exact, and far cheaper
than asking a VLM where a button is. Platform impls (pywinauto/uia on
Windows, pyatspi/AT-SPI on Linux, AX API on macOS via pyobjc) are OPTIONAL
and import-guarded; this PoC ships the protocol, thin wrappers, and a stub.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

MAX_A11Y_DEPTH = 64


@dataclass(frozen=True)
class A11yNode:
    role: str  # e.g. "button", "textfield", "menuitem"
    name: str
    bounds: tuple[int, int, int, int] | None = None  # x, y, w, h if on screen
    children: tuple["A11yNode", ...] = field(default_factory=tuple)

    def walk(self) -> "list[A11yNode]":
        out = [self]
        for c in self.children:
            out.extend(c.walk())
        return out


@runtime_checkable
class A11yProvider(Protocol):
    def tree(self, max_nodes: int | None = None) -> A11yNode | None: ...

    def find(self, role: str | None = None, name: str | None = None) -> A11yNode | None: ...


class StubA11yProvider:
    """Honest stub: reports an empty tree. Lets the grounding ladder exercise
    its L1 rung without a real desktop session."""

    def tree(self, max_nodes: int | None = None) -> A11yNode | None:
        return None

    def find(self, role: str | None = None, name: str | None = None) -> A11yNode | None:
        return None


def _find_in(node: A11yNode | None, role: str | None, name: str | None) -> A11yNode | None:
    if node is None:
        return None
    name_cf = name.casefold() if name else None
    for n in node.walk():
        if role and n.role != role:
            continue
        if name_cf and name_cf not in n.name.casefold():
            continue
        return n
    return None


class WinAutoA11y:
    """Windows UIAutomation via pywinauto. Import-guarded; untested here."""

    def __init__(self) -> None:
        try:
            from pywinauto import Desktop
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pywinauto not installed") from e
        self._desktop = Desktop(backend="uia")

    def tree(self, max_nodes: int | None = None) -> A11yNode | None:
        remaining = max_nodes

        def conv(w, depth: int) -> A11yNode | None:
            nonlocal remaining
            if remaining is not None:
                if remaining <= 0:
                    return None
                remaining -= 1
            try:
                r = w.rectangle()
                bounds = (r.left, r.top, r.width(), r.height())
            except Exception:
                bounds = None
            children = []
            if depth < MAX_A11Y_DEPTH:
                for child in w.children():
                    converted = conv(child, depth + 1)
                    if converted is None:
                        break
                    children.append(converted)
            return A11yNode(
                role=(w.friendly_class_name() or "").lower(),
                name=w.window_text() or "",
                bounds=bounds,
                children=tuple(children),
            )

        children = []
        for window in self._desktop.windows():
            converted = conv(window, 1)
            if converted is None:
                break
            children.append(converted)
        return A11yNode(role="desktop", name="root", children=tuple(children))

    def find(
        self, role: str | None = None, name: str | None = None
    ) -> A11yNode | None:  # pragma: no cover
        return _find_in(self.tree(), role, name)


def _atspi_extents(acc, coord_type) -> tuple[int, int, int, int] | None:
    """Best-effort on-screen bounds for one AT-SPI accessible; None if the
    element is not on screen or exposes no component interface."""
    if coord_type is None:
        return None
    try:
        ext = acc.queryComponent().getExtents(coord_type)
        return (int(ext.x), int(ext.y), int(ext.width), int(ext.height))
    except Exception:
        return None


def _atspi_tree(desktop, coord_type, max_nodes: int | None) -> A11yNode:
    """Walk an AT-SPI desktop into an :class:`A11yNode` tree.

    Mirrors :meth:`WinAutoA11y.tree`'s contract exactly: a synthetic root
    (``role="desktop"``, ``name="root"``) whose children are the live
    application accessibles, converted depth-first under the same per-tree node
    budget (``max_nodes``) and :data:`MAX_A11Y_DEPTH` cap. An exhausted budget
    returns ``None`` from ``conv`` and breaks the sibling loop, so the two
    platforms truncate identically. Reads only the AT-SPI surface a fake can
    also implement, which is what lets the walk be unit-tested off-Linux.
    """
    remaining = max_nodes

    def role_of(acc) -> str:
        try:
            return (acc.getRoleName() or "").lower()
        except Exception:
            return ""

    def name_of(acc) -> str:
        try:
            return acc.name or ""
        except Exception:
            return ""

    def child_count(acc) -> int:
        try:
            return int(acc.childCount)
        except Exception:
            return 0

    def conv(acc, depth: int) -> A11yNode | None:
        nonlocal remaining
        if remaining is not None:
            if remaining <= 0:
                return None
            remaining -= 1
        children: list[A11yNode] = []
        if depth < MAX_A11Y_DEPTH:
            for i in range(child_count(acc)):
                try:
                    child = acc.getChildAtIndex(i)
                except Exception:
                    continue
                if child is None:
                    continue
                converted = conv(child, depth + 1)
                if converted is None:
                    break
                children.append(converted)
        return A11yNode(
            role=role_of(acc),
            name=name_of(acc),
            bounds=_atspi_extents(acc, coord_type),
            children=tuple(children),
        )

    apps: list[A11yNode] = []
    for i in range(child_count(desktop)):
        try:
            app = desktop.getChildAtIndex(i)
        except Exception:
            continue
        if app is None:
            continue
        converted = conv(app, 1)
        if converted is None:
            break
        apps.append(converted)
    return A11yNode(role="desktop", name="root", children=tuple(apps))


class AtSpiA11y:
    """Linux AT-SPI provider via pyatspi (R-303).

    The live path reads ``pyatspi.Registry.getDesktop(0)`` and walks it with
    :func:`_atspi_tree`. The walk touches only ``getRoleName``, ``name``,
    ``childCount``, ``getChildAtIndex`` and ``queryComponent().getExtents`` —
    the AT-SPI methods a fake accessible can implement — so it is unit-tested
    off-Linux against fakes and validated live on the AT-SPI host. Bounds are
    read in absolute desktop coordinates so they compose with the frame the
    observer attests.
    """

    def __init__(self, desktop=None, coord_type=None) -> None:
        if desktop is not None:
            # Injected root: tests, or a caller that already holds a desktop
            # accessible. No pyatspi import on this path.
            self._desktop = desktop
            self._coord_type = coord_type
            return
        try:
            import pyatspi
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pyatspi not installed") from e
        self._desktop = pyatspi.Registry.getDesktop(0)
        self._coord_type = getattr(pyatspi, "DESKTOP_COORDS", None)

    def tree(self, max_nodes: int | None = None) -> A11yNode | None:
        return _atspi_tree(self._desktop, self._coord_type, max_nodes)

    def find(self, role: str | None = None, name: str | None = None) -> A11yNode | None:
        return _find_in(self.tree(), role, name)


def default_a11y() -> A11yProvider:
    """Best-effort factory by platform; falls back to the stub."""
    import sys

    try:
        if sys.platform == "win32":
            return WinAutoA11y()
        if sys.platform == "linux":
            return AtSpiA11y()
    except RuntimeError:
        pass
    return StubA11yProvider()
