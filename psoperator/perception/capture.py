"""Screen capture.

``ScreenCapture`` is the protocol the rest of the agent depends on.
``MSSCapture`` is the reference cross-platform implementation (mss).

Production implementations intended behind the same protocol:
  * Windows : DXGI Desktop Duplication (dirty rects + move rects for free)
  * macOS   : ScreenCaptureKit (SCStream, per-frame damage regions)
  * Linux   : PipeWire / XDG portal screencast (Wayland-safe)

Those are NOT implemented in this PoC; only mss ships here.
"""

from __future__ import annotations

import hashlib
import itertools
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

import numpy as np
from PIL import Image

# A hook that, given the newest frame, returns pixel-space dirty rectangles
# [(x, y, w, h), ...] the OS reported as damaged since the previous frame.
# DXGI/ScreenCaptureKit/PipeWire can provide these natively; mss cannot, so
# MSSCapture leaves the hook None and diff.py recomputes regions in software.
DirtyRegionHook = Callable[["Frame"], list[tuple[int, int, int, int]]]


@dataclass(frozen=True)
class Frame:
    """One captured screen frame. ``frame_id`` is the freshness token that
    every downstream action must echo (see runtime/freshness.py)."""

    frame_id: int
    image: Image.Image  # RGB
    captured_at: float
    sha256: str
    dirty_regions: list[tuple[int, int, int, int]] = field(default_factory=list)

    @classmethod
    def from_image(
        cls, frame_id: int, image: Image.Image, captured_at: float | None = None
    ) -> "Frame":
        rgb = image.convert("RGB")
        digest = hashlib.sha256(rgb.tobytes()).hexdigest()
        return cls(
            frame_id=frame_id,
            image=rgb,
            captured_at=captured_at if captured_at is not None else time.time(),
            sha256=digest,
        )

    def to_array(self) -> np.ndarray:
        return np.asarray(self.image, dtype=np.uint8)


@runtime_checkable
class ScreenCapture(Protocol):
    """Anything that yields monotonically-id'd Frames."""

    dirty_region_hook: DirtyRegionHook | None

    def grab(self) -> Frame: ...

    def close(self) -> None: ...


class MSSCapture:
    """Cross-platform capture via mss. Works headless nowhere — needs a real
    display (X11/Wayland-XDG/macOS/Windows desktop session)."""

    def __init__(self, monitor: int = 1, dirty_region_hook: DirtyRegionHook | None = None) -> None:
        import mss  # local import so headless CI can import this module

        self._sct = mss.mss()
        if monitor < 1 or monitor >= len(self._sct.monitors):
            raise ValueError(f"monitor {monitor} out of range; have {len(self._sct.monitors) - 1}")
        self._monitor = self._sct.monitors[monitor]
        self._ids = itertools.count(1)
        self.dirty_region_hook = dirty_region_hook

    def grab(self) -> Frame:
        shot = self._sct.grab(self._monitor)
        img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        frame = Frame.from_image(next(self._ids), img)
        if self.dirty_region_hook is not None:
            object.__setattr__(frame, "dirty_regions", self.dirty_region_hook(frame))
        return frame

    def close(self) -> None:
        self._sct.close()


class StaticCapture:
    """Test/demo double: replays a fixed sequence of images, then repeats the
    last one. Lets the whole loop run without a display."""

    def __init__(self, images: list[Image.Image]) -> None:
        if not images:
            raise ValueError("StaticCapture needs at least one image")
        self._images = images
        self._ids = itertools.count(1)
        self.dirty_region_hook = None

    def grab(self) -> Frame:
        idx = min(next(self._ids) - 1, len(self._images) - 1)
        return Frame.from_image(idx + 1, self._images[idx].copy())

    def close(self) -> None: ...
