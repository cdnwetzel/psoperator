"""Diff/keyframe logic: identical frames skip the model, real changes don't."""

from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

from psoperator.perception.diff import KeyframeFilter, phash_distance, tile_diff


def img(color: tuple[int, int, int], size=(128, 96)) -> Image.Image:
    return Image.new("RGB", size, color)


def with_patch(base: Image.Image, box=(10, 10, 42, 42), color=(255, 255, 255)) -> Image.Image:
    a = np.asarray(base).copy()
    a[box[1] : box[3], box[0] : box[2]] = color
    return Image.fromarray(a)


def scene(seed: int, size=(128, 96), n_blocks=8) -> Image.Image:
    """Textured, UI-like scene (gradient + blocks). Solid-color images defeat
    perceptual hashing — DCTs of flat frames all look alike — so tests use
    these instead."""
    rng = np.random.default_rng(seed)
    h, w = size
    x = np.linspace(0, 40, w)[None, :, None]
    y = np.linspace(0, 25, h)[:, None, None]
    arr = np.broadcast_to(
        (x + y + rng.integers(0, 15, 3)[None, None, :]).astype(np.uint8), (h, w, 3)
    ).copy()
    for _ in range(n_blocks):
        bh, bw = rng.integers(10, 25, 2)
        by, bx = rng.integers(0, h - bh), rng.integers(0, w - bw)
        arr[by : by + bh, bx : bx + bw] = rng.integers(0, 255, 3)
    return Image.fromarray(arr)


class TestTileDiff:
    def test_identical_frames_have_zero_changed_tiles(self):
        r = tile_diff(img((0, 0, 0)), img((0, 0, 0)))
        assert r.changed_tiles == 0
        assert r.fraction_changed == 0.0
        assert r.dirty_regions == []

    def test_changed_tile_is_detected_and_located(self):
        a, b = img((0, 0, 0)), with_patch(img((0, 0, 0)))
        r = tile_diff(a, b, tile_size=32)
        assert r.changed_tiles >= 1
        assert 0 < r.fraction_changed < 1
        x, y, w, h = r.dirty_regions[0]
        assert (x, y) == (0, 0) and w == h == 32

    def test_noise_below_floor_is_ignored(self):
        a = np.asarray(img((100, 100, 100)), dtype=np.int16)
        b = Image.fromarray((a + 3).astype(np.uint8))  # tiny global jitter
        assert tile_diff(img((100, 100, 100)), b).changed_tiles == 0

    def test_mismatched_sizes_are_resized_not_crash(self):
        r = tile_diff(img((0, 0, 0)), img((10, 10, 10), size=(64, 64)))
        assert r.total_tiles > 0


class TestPhash:
    def test_identical_images_distance_zero(self):
        d = phash_distance(img((50, 60, 70)), img((50, 60, 70)))
        if d is not None:  # imagehash may be absent; both modes are valid
            assert d == 0

    def test_distant_scenes_differ(self):
        d = phash_distance(scene(1), scene(2))
        if d is not None:
            assert d > 6


class TestKeyframeFilter:
    def test_first_frame_is_always_keyframe(self):
        kf = KeyframeFilter()
        assert kf.should_query(img((0, 0, 0))) is True
        assert kf.stats["model_calls"] == 1

    def test_static_screen_skips_model(self):
        kf = KeyframeFilter(diff_threshold=0.01)
        kf.should_query(img((0, 0, 0)))
        for _ in range(5):
            assert kf.should_query(img((0, 0, 0))) is False
        assert kf.stats["model_calls"] == 1  # only the first frame

    def test_large_scene_change_triggers_model(self):
        kf = KeyframeFilter(diff_threshold=0.01, phash_threshold=6, tile_size=32)
        kf.should_query(scene(1))
        assert kf.should_query(scene(2)) is True  # different layout entirely

    def test_small_change_below_threshold_skips(self):
        kf = KeyframeFilter(diff_threshold=0.10, tile_size=32)
        kf.should_query(scene(1))
        tiny = with_patch(scene(1), box=(0, 0, 32, 32))  # 1 of 12 tiles ≈ 8% < 10%
        assert kf.should_query(tiny) is False

    @pytest.mark.skipif(
        __import__("psoperator.perception.diff", fromlist=["_HAS_IMAGEHASH"])._HAS_IMAGEHASH
        is False,
        reason="imagehash not installed",
    )
    def test_minor_churn_in_same_scene_skips(self):
        kf = KeyframeFilter(diff_threshold=0.001, phash_threshold=6, tile_size=16)
        base = scene(1)
        kf.should_query(base)
        churn = with_patch(base, box=(72, 70, 74, 78))  # thin blinking caret, same scene
        assert kf.should_query(churn) is False
