"""OCR fast path.

Cheap local OCR runs *before* the VLM whenever a skill step can be resolved
by on-screen text (e.g. find the "Save" button). Protocol + optional RapidOCR
implementation (onnxruntime, fully local). Everything degrades to NullOCR.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
from typing import Protocol, runtime_checkable

from PIL import Image


@dataclass(frozen=True)
class TextBox:
    text: str
    box: tuple[int, int, int, int]  # x, y, w, h
    confidence: float

    @property
    def center(self) -> tuple[int, int]:
        x, y, w, h = self.box
        return (x + w // 2, y + h // 2)


@runtime_checkable
class OCRProvider(Protocol):
    def extract(self, image: Image.Image, max_results: int | None = None) -> list[TextBox]: ...

    def find(self, image: Image.Image, needle: str) -> TextBox | None: ...


class RapidOCRProvider:
    """RapidOCR (onnxruntime) implementation. Import-guarded."""

    def __init__(self) -> None:
        try:
            from rapidocr import RapidOCR
        except ImportError as e:  # pragma: no cover - depends on env
            raise RuntimeError(
                "rapidocr not installed; `pip install psoperator[perception]`"
            ) from e
        self._ocr = RapidOCR()

    def extract(self, image: Image.Image, max_results: int | None = None) -> list[TextBox]:
        import numpy as np

        output = self._ocr(np.asarray(image.convert("RGB")))
        if isinstance(output, tuple):
            # rapidocr 1.x: (list of (points, text, confidence), elapse)
            items = output[0] or ()
        else:
            # rapidocr >= 2.0: RapidOCROutput with boxes/txts/scores, None when empty
            detected = getattr(output, "boxes", None)
            items = () if detected is None else zip(detected, output.txts, output.scores)
        boxes: list[TextBox] = []
        if max_results is not None:
            items = islice(items, max_results)
        for pts, text, conf in items:
            xs = [p[0] for p in pts]
            ys = [p[1] for p in pts]
            boxes.append(
                TextBox(
                    text=text,
                    box=(
                        int(min(xs)),
                        int(min(ys)),
                        int(max(xs) - min(xs)),
                        int(max(ys) - min(ys)),
                    ),
                    confidence=float(conf),
                )
            )
        return boxes

    def find(self, image: Image.Image, needle: str) -> TextBox | None:
        needle = needle.casefold()
        for tb in self.extract(image):
            if needle in tb.text.casefold():
                return tb
        return None


class NullOCR:
    """Fallback when RapidOCR is unavailable: sees nothing, finds nothing."""

    def extract(self, image: Image.Image, max_results: int | None = None) -> list[TextBox]:
        return []

    def find(self, image: Image.Image, needle: str) -> TextBox | None:
        return None


def default_ocr() -> OCRProvider:
    """Best-effort factory: RapidOCR if installed, else NullOCR."""
    try:
        return RapidOCRProvider()
    except RuntimeError:
        return NullOCR()
