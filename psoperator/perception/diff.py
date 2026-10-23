"""Frame diffing + keyframe filter.

Decides *whether* the VLM is called at all for a new frame. Two gates:

1. Tile diff: split the frame into ``tile_size`` squares, count tiles whose
   mean absolute pixel delta exceeds a noise floor. If the changed fraction
   is below ``diff_threshold`` the screen is "static" → skip the model.
2. Perceptual-hash keyframe filter (imagehash, optional): even when tiles
   changed, if the phash hamming distance to the last *keyframe* is within
   ``phash_threshold`` we consider it the same scene (blinking caret, clock
   tick, video playback) → skip the model.

Cheap and fully local: numpy + (optionally) imagehash.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from PIL import Image

try:  # optional; falls back to tile-diff-only mode
    import imagehash

    _HAS_IMAGEHASH = True
except ImportError:  # pragma: no cover - exercised when imagehash absent
    imagehash = None  # type: ignore[assignment]
    _HAS_IMAGEHASH = False

NOISE_FLOOR = 8  # mean abs delta below this per tile is compression/caret noise


@dataclass(frozen=True)
class DiffResult:
    changed_tiles: int
    total_tiles: int
    fraction_changed: float
    dirty_regions: list[tuple[int, int, int, int]]  # pixel-space (x, y, w, h)


def _tiles(arr: np.ndarray, tile: int) -> np.ndarray:
    """(H, W, C) -> (n_tiles, tile*tile*C), zero-padded on the edges."""
    h, w, c = arr.shape
    pad_h = (-h) % tile
    pad_w = (-w) % tile
    arr = np.pad(arr, ((0, pad_h), (0, pad_w), (0, 0)))
    rows = np.split(arr, arr.shape[0] // tile, axis=0)
    blocks = [np.split(r, r.shape[1] // tile, axis=1) for r in rows]
    return np.stack([b.reshape(-1) for row in blocks for b in row])


def tile_diff(a: Image.Image, b: Image.Image, tile_size: int = 32) -> DiffResult:
    """Tile-based diff of two equally-sized images."""
    if a.size != b.size:
        b = b.resize(a.size)
    ta = _tiles(np.asarray(a.convert("RGB"), dtype=np.int16), tile_size)
    tb = _tiles(np.asarray(b.convert("RGB"), dtype=np.int16), tile_size)
    deltas = np.abs(ta - tb).mean(axis=1)
    changed = np.flatnonzero(deltas > NOISE_FLOOR)

    w, h = a.size
    cols = max(1, -(-w // tile_size))
    regions = [
        (int(i % cols) * tile_size, int(i // cols) * tile_size, tile_size, tile_size)
        for i in changed
    ]
    return DiffResult(
        changed_tiles=int(changed.size),
        total_tiles=int(ta.shape[0]),
        fraction_changed=float(changed.size) / float(ta.shape[0]),
        dirty_regions=regions,
    )


def phash_distance(a: Image.Image, b: Image.Image) -> int | None:
    """Hamming distance of perceptual hashes; None if imagehash is absent."""
    if not _HAS_IMAGEHASH:
        return None
    return int(imagehash.phash(a) - imagehash.phash(b))


@dataclass
class KeyframeFilter:
    """Stateful decider: feed frames, get True (call the VLM) / False (skip)."""

    diff_threshold: float = 0.01
    phash_threshold: int = 6
    tile_size: int = 32
    _last_frame: Image.Image | None = field(default=None, repr=False)
    _last_keyframe: Image.Image | None = field(default=None, repr=False)
    stats: dict = field(default_factory=lambda: {"frames": 0, "model_calls": 0})

    def should_query(self, frame: Image.Image) -> bool:
        self.stats["frames"] += 1
        if self._last_frame is None:
            return self._keyframe(frame)  # first frame is always a keyframe

        diff = tile_diff(self._last_frame, frame, self.tile_size)
        self._last_frame = frame
        if diff.fraction_changed < self.diff_threshold:
            return False  # screen static

        if self._last_keyframe is not None:
            dist = phash_distance(self._last_keyframe, frame)
            if dist is not None and dist <= self.phash_threshold:
                return False  # same scene, minor churn (caret, clock, video)

        return self._keyframe(frame)

    def _keyframe(self, frame: Image.Image) -> bool:
        self._last_frame = frame
        self._last_keyframe = frame
        self.stats["model_calls"] += 1
        return True
