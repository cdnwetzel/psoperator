"""Unifies accessibility and OCR observations into frame-bound elements."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from inspect import Parameter, signature
from itertools import islice

from pydantic import ValidationError

from psoperator.common.schema import (
    MAX_CONTROL_TYPE_CHARS,
    MAX_ELEMENT_LABEL_CHARS,
    MAX_SNAPSHOT_ELEMENTS,
    PerceptionSnapshot,
    UIElementRef,
)
from psoperator.perception.a11y import A11yNode, A11yProvider, default_a11y
from psoperator.perception.capture import Frame
from psoperator.perception.ocr import OCRProvider, default_ocr


def _element_id(
    frame_id: int,
    frame_hash: str,
    source: str,
    label: str,
    bbox: tuple[int, int, int, int],
    ordinal: int,
) -> str:
    """Derive an id from the exact frame evidence, not only its restart-local sequence."""
    raw = f"{frame_id}|{frame_hash}|{source}|{label}|{bbox}|{ordinal}".encode("utf-8")
    return f"{source}-{hashlib.sha256(raw).hexdigest()[:24]}"


def _walk_bounded(root: A11yNode) -> Iterator[A11yNode]:
    """Walk without materializing an unbounded accessibility tree list."""
    pending = [iter((root,))]
    while pending:
        try:
            node = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        yield node
        pending.append(iter(node.children))


def _bounded_text(value: str, limit: int) -> str:
    return value[:limit]


def _accepts_keyword(method, name: str) -> bool:
    """Preserve compatibility with providers written before bounded hints."""
    try:
        parameters = signature(method).parameters
    except (TypeError, ValueError):
        return True
    return name in parameters or any(
        parameter.kind is Parameter.VAR_KEYWORD for parameter in parameters.values()
    )


class SnapshotBuilder:
    """Accessibility-first perception with OCR as a complementary fallback."""

    def __init__(
        self,
        a11y: A11yProvider | None = None,
        ocr: OCRProvider | None = None,
        max_elements: int = MAX_SNAPSHOT_ELEMENTS,
    ) -> None:
        if not 1 <= max_elements <= MAX_SNAPSHOT_ELEMENTS:
            raise ValueError(f"max_elements must be between 1 and {MAX_SNAPSHOT_ELEMENTS}")
        self._a11y = a11y or default_a11y()
        self._ocr = ocr or default_ocr()
        self._max_elements = max_elements
        self._a11y_accepts_limit = _accepts_keyword(self._a11y.tree, "max_nodes")
        self._ocr_accepts_limit = _accepts_keyword(self._ocr.extract, "max_results")

    def build(self, frame: Frame) -> PerceptionSnapshot:
        elements: list[UIElementRef] = []
        element_ids: set[str] = set()

        def append(element: UIElementRef) -> None:
            if len(elements) >= self._max_elements:
                return
            if element.element_id in element_ids:
                raise RuntimeError("duplicate element id generated for one snapshot")
            elements.append(element)
            element_ids.add(element.element_id)

        try:
            tree = (
                self._a11y.tree(max_nodes=self._max_elements)
                if self._a11y_accepts_limit
                else self._a11y.tree()
            )
        except (RuntimeError, NotImplementedError):
            tree = None
        if tree is not None:
            for node in islice(_walk_bounded(tree), self._max_elements):
                if node.bounds is None or node.bounds[2] <= 0 or node.bounds[3] <= 0:
                    continue
                label = _bounded_text(node.name, MAX_ELEMENT_LABEL_CHARS)
                try:
                    append(
                        UIElementRef(
                            element_id=_element_id(
                                frame.frame_id,
                                frame.sha256,
                                "a11y",
                                label,
                                node.bounds,
                                len(elements),
                            ),
                            frame_id=frame.frame_id,
                            label=label,
                            bbox=node.bounds,
                            control_type=_bounded_text(node.role, MAX_CONTROL_TYPE_CHARS),
                            source="a11y",
                        )
                    )
                except (TypeError, ValidationError, ValueError):
                    continue

        seen = {(item.label.casefold(), item.bbox) for item in elements}
        if len(elements) < self._max_elements:
            remaining = self._max_elements - len(elements)
            try:
                text_boxes = (
                    self._ocr.extract(frame.image, max_results=remaining)
                    if self._ocr_accepts_limit
                    else self._ocr.extract(frame.image)
                )
            except RuntimeError:
                text_boxes = []
            for text_box in islice(text_boxes, remaining):
                label = _bounded_text(text_box.text, MAX_ELEMENT_LABEL_CHARS)
                key = (label.casefold(), text_box.box)
                if key in seen or text_box.box[2] <= 0 or text_box.box[3] <= 0:
                    continue
                try:
                    append(
                        UIElementRef(
                            element_id=_element_id(
                                frame.frame_id,
                                frame.sha256,
                                "ocr",
                                label,
                                text_box.box,
                                len(elements),
                            ),
                            frame_id=frame.frame_id,
                            label=label,
                            bbox=text_box.box,
                            control_type="text",
                            source="ocr",
                            confidence=text_box.confidence,
                        )
                    )
                except (TypeError, ValidationError, ValueError):
                    continue
                seen.add(key)

        return PerceptionSnapshot(
            frame_id=frame.frame_id,
            captured_at=frame.captured_at,
            frame_hash=frame.sha256,
            screen_size=frame.image.size,
            elements=tuple(elements),
        )
