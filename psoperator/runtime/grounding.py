"""Cheapest-first grounding ladder.

Turning "the Save button" into something executable costs very different
amounts depending on the source. We always try the cheapest rung first:

    L0  hotkey    — a keypress sidesteps grounding entirely (Ctrl+S)
    L1  a11y      — accessibility tree: exact bounds, zero model cost
    L2  OCR text  — local OCR finds the label, click its center   (PoC)
    L4  image     — template match of a cropped reference image   (stub)
    L5  VLM       — ask the GUI model for coordinates             (expensive)

Only L0/L1/L2/L5 are even partially live in this PoC; L4 is a marked stub.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Protocol

from PIL import Image

from psoperator.perception.a11y import A11yProvider
from psoperator.perception.ocr import OCRProvider


class LocatorLayer(IntEnum):
    L0_HOTKEY = 0
    L1_A11Y = 1
    L2_TEXT = 2
    L4_IMAGE = 4
    L5_VLM = 5


@dataclass(frozen=True)
class GroundedTarget:
    layer: LocatorLayer
    # exactly one of these is meaningful per layer:
    keys: tuple[str, ...] = ()  # L0
    point: tuple[int, int] | None = None  # L1/L2/L4/L5
    note: str = ""


class VLMGroundFn(Protocol):
    """(frame, natural-language target) -> (x, y) or None."""

    def __call__(self, frame: Image.Image, target: str) -> tuple[int, int] | None: ...


@dataclass
class Grounder:
    a11y: A11yProvider
    ocr: OCRProvider
    vlm_ground: VLMGroundFn | None = None
    # template_match(frame, template_path) -> point | None  (L4, stubbed)
    template_match: Callable[[Image.Image, str], tuple[int, int] | None] | None = None

    def resolve(
        self, frame: Image.Image, locators: dict[LocatorLayer, str]
    ) -> GroundedTarget | None:
        """Walk the ladder; return the first successful grounding."""
        if LocatorLayer.L0_HOTKEY in locators:
            keys = tuple(k.strip().lower() for k in locators[LocatorLayer.L0_HOTKEY].split("+"))
            return GroundedTarget(LocatorLayer.L0_HOTKEY, keys=keys)

        if LocatorLayer.L1_A11Y in locators:
            node = self.a11y.find(name=locators[LocatorLayer.L1_A11Y])
            if node and node.bounds:
                x, y, w, h = node.bounds
                return GroundedTarget(LocatorLayer.L1_A11Y, point=(x + w // 2, y + h // 2))

        if LocatorLayer.L2_TEXT in locators:
            box = self.ocr.find(frame, locators[LocatorLayer.L2_TEXT])
            if box:
                return GroundedTarget(LocatorLayer.L2_TEXT, point=box.center)

        if LocatorLayer.L4_IMAGE in locators and self.template_match is not None:
            # STUB: production impl = OpenCV template matching / feature match
            pt = self.template_match(frame, locators[LocatorLayer.L4_IMAGE])
            if pt:
                return GroundedTarget(LocatorLayer.L4_IMAGE, point=pt)

        if LocatorLayer.L5_VLM in locators and self.vlm_ground is not None:
            pt = self.vlm_ground(frame, locators[LocatorLayer.L5_VLM])
            if pt:
                return GroundedTarget(
                    LocatorLayer.L5_VLM, point=pt, note="model-grounded; low trust"
                )

        return None
