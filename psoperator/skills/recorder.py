"""Event recorder -> raw trajectory JSONL.

pynput LISTENERS (read-only observation of input events — not controllers,
so this does not violate the runtime input-injection invariant) are merged
with synchronized frame captures: each input event is stamped with the id
and hash of the frame visible at that moment. The raw trajectory is later
compiled (by hand or by the model) into a Skill (skills/schema.py).

Requires a real desktop session; unit tests do not cover it.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from psoperator.perception.capture import Frame, ScreenCapture


@dataclass(frozen=True)
class TrajectoryEvent:
    ts: float
    kind: str  # click | scroll | key_press | key_release | type_char
    detail: dict
    frame_id: int
    frame_hash: str


class Recorder:
    """Records input events + the frame each one happened against."""

    def __init__(self, capture: ScreenCapture, poll_s: float = 0.25) -> None:
        self._capture = capture
        self._poll_s = poll_s
        self._events: list[TrajectoryEvent] = []
        self._current: Frame | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ------------------------------------------------------------- capture
    def _capture_worker(self) -> None:
        while not self._stop.is_set():
            frame = self._capture.grab()
            with self._lock:
                self._current = frame
            time.sleep(self._poll_s)

    def _stamp(self) -> tuple[int, str]:
        with self._lock:
            if self._current is None:
                return (-1, "")
            return (self._current.frame_id, self._current.sha256)

    def _log(self, kind: str, detail: dict) -> None:
        fid, fhash = self._stamp()
        self._events.append(TrajectoryEvent(time.time(), kind, detail, fid, fhash))

    # ------------------------------------------------------------- session
    def record(self, duration_s: float | None = None) -> list[TrajectoryEvent]:
        """Block and record until duration elapses or Ctrl+C."""
        from pynput import keyboard, mouse

        ml = mouse.Listener(
            on_click=lambda x, y, b, p: (
                p and self._log("click", {"x": x, "y": y, "button": str(b)})
            ),
            on_scroll=lambda x, y, dx, dy: self._log("scroll", {"x": x, "y": y, "dy": dy}),
        )
        kl = keyboard.Listener(
            on_press=lambda k: self._log("key_press", {"key": str(k)}),
            on_release=lambda k: self._log("key_release", {"key": str(k)}),
        )
        worker = threading.Thread(target=self._capture_worker, daemon=True)

        ml.start()
        kl.start()
        worker.start()
        try:
            if duration_s is None:
                while True:
                    time.sleep(0.5)
            else:
                time.sleep(duration_s)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            ml.stop()
            kl.stop()
        return self._events

    def save_jsonl(self, path: Path) -> None:
        with Path(path).open("w", encoding="utf-8") as f:
            for e in self._events:
                f.write(json.dumps(asdict(e)) + "\n")
