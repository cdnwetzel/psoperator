"""UVC capture backend — Topology B (crash-cart / out-of-band mode).

In Topology B the agent machine watches a *different* (target) machine
through a USB HDMI capture card, which shows up as a standard UVC webcam
(``/dev/video0`` on Linux). ``UVCCapture`` implements the same
``ScreenCapture`` protocol as ``MSSCapture``, so the diff pipeline,
keyframe filter, and agent loop consume it unchanged.

OpenCV (``cv2``) is NOT a required dependency: it is imported lazily and a
missing install raises a clear error pointing at the ``uvc`` extra.
"""

from __future__ import annotations

import itertools

import numpy as np
from PIL import Image

from psoperator.perception.capture import DirtyRegionHook, Frame


def _import_cv2():
    """Lazy import guard: cv2 is optional (``pip install -e .[uvc]``)."""
    try:
        import cv2
    except ImportError as e:
        raise RuntimeError(
            "UVCCapture needs opencv-python (cv2), which is not installed. "
            "Install it with: pip install -e .[uvc]"
        ) from e
    return cv2


class UVCCapture:
    """Capture from a UVC device (USB HDMI capture card) via cv2.VideoCapture.

    Requests MJPG compression (the only way cheap HDMI capture dongles reach
    1080p over USB 2.0) and the configured resolution; the driver may clamp
    both to whatever the card actually supports. Frame ids are monotonic
    starting at 1, identical semantics to ``MSSCapture``.
    """

    def __init__(
        self,
        device_index: int = 0,
        width: int = 1920,
        height: int = 1080,
        dirty_region_hook: DirtyRegionHook | None = None,
    ) -> None:
        cv2 = _import_cv2()
        self._cv2 = cv2
        self._cap = cv2.VideoCapture(device_index)
        if not self._cap.isOpened():
            self._cap.release()
            raise RuntimeError(
                f"cannot open UVC device index {device_index} "
                f"(expected e.g. /dev/video{device_index}); is the capture card "
                "plugged in and are you in the 'video' group?"
            )
        self._cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
        self._cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
        self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
        self._ids = itertools.count(1)
        self.dirty_region_hook = dirty_region_hook

    @property
    def resolution(self) -> tuple[int, int]:
        """What the driver actually granted (may differ from the request)."""
        return (
            int(self._cap.get(self._cv2.CAP_PROP_FRAME_WIDTH)),
            int(self._cap.get(self._cv2.CAP_PROP_FRAME_HEIGHT)),
        )

    def grab(self) -> Frame:
        ok, bgr = self._cap.read()
        if not ok or bgr is None:
            raise RuntimeError(
                "UVC capture card returned no frame — target machine asleep, "
                "HDMI unplugged, or device lost?"
            )
        rgb = self._cv2.cvtColor(np.asarray(bgr), self._cv2.COLOR_BGR2RGB)
        img = Image.fromarray(rgb, "RGB")
        frame = Frame.from_image(next(self._ids), img)
        if self.dirty_region_hook is not None:
            object.__setattr__(frame, "dirty_regions", self.dirty_region_hook(frame))
        return frame

    def close(self) -> None:
        self._cap.release()
