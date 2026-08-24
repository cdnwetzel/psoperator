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


class AtSpiA11y:
    """Linux AT-SPI via pyatspi. Import-guarded; untested here."""

    def __init__(self) -> None:
        try:
            import pyatspi
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pyatspi not installed") from e
        self._pyatspi = pyatspi

    def tree(self, max_nodes: int | None = None) -> A11yNode | None:  # pragma: no cover
        # TODO(prod): walk pyatspi.Registry.getDesktop(0) children,
        # mapping getRoleName()/getName()/getExtents() onto A11yNode.
        raise NotImplementedError("AT-SPI walk is stubbed in this PoC")

    def find(
        self, role: str | None = None, name: str | None = None
    ) -> A11yNode | None:  # pragma: no cover
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
