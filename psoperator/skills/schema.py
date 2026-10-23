"""Skill schema.

A Skill is a recorded, parameterized procedure. Each step carries *layered
locators* so replay can fall back down the grounding ladder when the cheap
source no longer resolves:

    L0 hotkey   ("ctrl+s")          — no grounding needed
    L1 selector (a11y name/role)    — exact, structured
    L2 text     ("Save")            — OCR fast path
    L4 image    (crop path)         — template match (stubbed)
    L5 vlm      ("the blue save button") — last resort, costs a model call

Waits are *learned* from the recording (observed inter-event gaps, padded),
not fixed sleeps. Preconditions/postconditions are cheap checks the replay
engine verifies before starting / after finishing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from psoperator.runtime.actions import ActionKind
from psoperator.runtime.grounding import LocatorLayer


class Locator(BaseModel):
    layer: LocatorLayer
    value: str  # "ctrl+s" / a11y name / visible text / image path / NL description


class Wait(BaseModel):
    """Learned wait: observed gap in the recording plus a safety pad."""

    after_ms: int = 0
    pad_ms: int = 200

    @property
    def seconds(self) -> float:
        return (self.after_ms + self.pad_ms) / 1000.0


class Condition(BaseModel):
    """Cheap check: text (OCR) present/absent on screen."""

    kind: str = Field(pattern="^(text_present|text_absent)$")
    value: str


class Step(BaseModel):
    action: ActionKind
    locators: list[Locator] = Field(default_factory=list)  # ordered cheap→expensive
    # raw coordinates/keys captured at record time (L5 fallback seed):
    x: int | None = None
    y: int | None = None
    to_x: int | None = None
    to_y: int | None = None
    text: str | None = None  # may contain {param} placeholders
    keys: list[str] = Field(default_factory=list)
    wait: Wait = Field(default_factory=Wait)


class Skill(BaseModel):
    name: str
    description: str = ""
    params: dict[str, str] = Field(default_factory=dict)  # name -> default
    preconditions: list[Condition] = Field(default_factory=list)
    steps: list[Step]
    postconditions: list[Condition] = Field(default_factory=list)
    version: int = 1

    # ------------------------------------------------------------- helpers
    def bind(self, **params: str) -> "Skill":
        """Substitute {param} placeholders in step text."""
        merged = {**self.params, **params}
        for step in self.steps:
            if step.text:
                for k, v in merged.items():
                    step.text = step.text.replace("{" + k + "}", v)
        return self

    def to_json_file(self, path: Path) -> None:
        Path(path).write_text(self.model_dump_json(indent=2))

    @classmethod
    def from_json_file(cls, path: Path) -> "Skill":
        return cls.model_validate_json(Path(path).read_text())

    def summary(self) -> dict[str, Any]:
        layers = sorted({loc.layer for s in self.steps for loc in s.locators})
        return {
            "name": self.name,
            "steps": len(self.steps),
            "locator_layers": [layer.name for layer in layers],
        }
