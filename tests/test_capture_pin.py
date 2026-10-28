"""The frame-hash contract on the capture path (roadmap D-01).

A frame's hash is SHA-256 over its RGB bytes, made from the mss BGRA buffer
exactly as ``MSSCapture`` makes them. The observer signs that hash and the
gatekeeper binds targets to it, so any reader of the same pixels (another
process decoding the PNG, or an independent byte reorder) must arrive at the
same digest. The conversion is pinned to a fixed buffer on every platform;
on Windows a real desktop grab is checked against an independent reader of
the same shot. Pixels and hashes stay in memory; nothing is written or printed.
"""

from __future__ import annotations

import hashlib
import io
import os

import numpy as np
import pytest
from PIL import Image

from psoperator.perception.capture import Frame, MSSCapture

# A 5x3 BGRA buffer with distinct values in every channel, alpha included, so
# a channel swap, a dropped or kept alpha, or a row-order change all move the
# digest.
_SIZE = (5, 3)
_BGRA = bytes(
    (7 * i + 3) % 256 if i % 4 != 3 else (11 * i) % 256 for i in range(_SIZE[0] * _SIZE[1] * 4)
)
#: SHA-256 of the RGB bytes of _BGRA. A change here is a change to the frame
#: hash contract, which every signed envelope and bound target depends on.
_PINNED = "c1413210a0da75e0b92bac8bcdbf6a2c1ab28724ce57bd76608609f419230e28"


def _independent_rgb(bgra: bytes, size: tuple[int, int]) -> bytes:
    """RGB bytes from BGRA without Pillow: reorder the channels, drop alpha."""
    pixels = np.frombuffer(bgra, dtype=np.uint8).reshape(size[1], size[0], 4)
    return pixels[:, :, [2, 1, 0]].tobytes()


def _png_round_trip(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return Image.open(io.BytesIO(buffer.getvalue())).convert("RGB").tobytes()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Shot:
    def __init__(self, bgra: bytes, size: tuple[int, int]) -> None:
        self.bgra, self.size = bgra, size


class _FakeMss:
    """Stands in for mss.mss(): one monitor, one fixed shot."""

    def __init__(self) -> None:
        self.monitors = [{}, {"left": 0, "top": 0, "width": _SIZE[0], "height": _SIZE[1]}]

    def grab(self, monitor):
        return _Shot(_BGRA, _SIZE)

    def close(self) -> None: ...


def test_the_conversion_is_pinned():
    image = Image.frombytes("RGB", _SIZE, _BGRA, "raw", "BGRX")
    assert _sha(image.tobytes()) == _PINNED
    assert _sha(_independent_rgb(_BGRA, _SIZE)) == _PINNED


def test_mss_capture_hashes_the_pinned_bytes(monkeypatch):
    import mss

    monkeypatch.setattr(mss, "mss", _FakeMss)
    grabber = MSSCapture(monitor=1)
    try:
        frame = grabber.grab()
    finally:
        grabber.close()
    assert frame.sha256 == _PINNED
    assert frame.image.mode == "RGB" and frame.image.size == _SIZE
    assert frame.frame_id == 1


def test_a_png_reader_gets_the_same_hash():
    frame = Frame.from_image(1, Image.frombytes("RGB", _SIZE, _BGRA, "raw", "BGRX"))
    assert _sha(_png_round_trip(frame.image)) == frame.sha256 == _PINNED


def test_the_hash_is_over_rgb_whatever_mode_the_image_arrives_in():
    # The digest is taken after conversion to RGB, so the same pixels handed
    # over with an alpha channel hash the same, and the stored image is RGB.
    rgba = Image.frombytes("RGBA", _SIZE, _BGRA, "raw", "BGRA")
    frame = Frame.from_image(1, rgba)
    assert frame.image.mode == "RGB"
    assert frame.sha256 == _PINNED


def test_a_changed_pixel_changes_the_hash():
    # The negative control: one byte of one channel is enough.
    changed = bytearray(_BGRA)
    changed[0] ^= 1
    image = Image.frombytes("RGB", _SIZE, bytes(changed), "raw", "BGRX")
    assert Frame.from_image(1, image).sha256 != _PINNED
    # Alpha is not part of the frame: changing it leaves the hash alone.
    alpha_only = bytearray(_BGRA)
    alpha_only[3] ^= 0xFF
    image = Image.frombytes("RGB", _SIZE, bytes(alpha_only), "raw", "BGRX")
    assert Frame.from_image(1, image).sha256 == _PINNED


@pytest.mark.skipif(os.name != "nt", reason="a real Windows desktop grab")
def test_a_real_windows_grab_matches_an_independent_reader(monkeypatch):
    # The same shot MSSCapture hashed, read back without Pillow and through a
    # PNG round trip, must give the frame's own digest.
    import mss

    shots: list[_Shot] = []
    real_mss = mss.mss

    class _Recording:
        def __init__(self) -> None:
            self._inner = real_mss()
            self.monitors = self._inner.monitors

        def grab(self, monitor):
            shot = self._inner.grab(monitor)
            shots.append(_Shot(bytes(shot.bgra), tuple(shot.size)))
            return shot

        def close(self) -> None:
            self._inner.close()

    monkeypatch.setattr(mss, "mss", _Recording)
    from mss.exception import ScreenShotError

    try:
        grabber = MSSCapture(monitor=1)
    except ScreenShotError:  # mss's own error: no interactive desktop
        pytest.skip("no desktop to capture")
    try:
        frame = grabber.grab()
    finally:
        grabber.close()
    (shot,) = shots
    assert frame.image.size == shot.size and frame.image.mode == "RGB"
    assert frame.sha256 == _sha(frame.image.tobytes())
    assert frame.sha256 == _sha(_independent_rgb(shot.bgra, shot.size))
    assert frame.sha256 == _sha(_png_round_trip(frame.image))
