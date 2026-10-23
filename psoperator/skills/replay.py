"""Layered-fallback replay engine.

For each recorded step we walk the locator ladder cheap→expensive
(L0 hotkey -> L1 a11y -> L2 OCR text -> L4 image -> L5 VLM), ground the
target, build an Action bound to the CURRENT frame id, and submit it through
the gatekeeper like any model-proposed action. Skills get no back door:
freshness, risk tiering, approval, and audit all apply.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from psoperator.gatekeeper.gatekeeper import Decision, Gatekeeper
from psoperator.gatekeeper.risk import ActionContext
from psoperator.perception.capture import ScreenCapture
from psoperator.perception.ocr import OCRProvider
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker
from psoperator.runtime.grounding import GroundedTarget, Grounder, LocatorLayer
from psoperator.skills.schema import Skill, Step


@dataclass
class ReplayResult:
    skill: str
    steps_run: int
    decisions: list[Decision] = field(default_factory=list)
    ok: bool = False
    error: str = ""


class ReplayEngine:
    def __init__(
        self,
        capture: ScreenCapture,
        gatekeeper: Gatekeeper,
        grounder: Grounder,
        ocr: OCRProvider,
        freshness: FreshnessTracker,
    ) -> None:
        self._capture = capture
        self._gate = gatekeeper
        self._grounder = grounder
        self._ocr = ocr
        self._fresh = freshness

    # ------------------------------------------------------------ conditions
    def _check(self, conditions, frame) -> str | None:
        for c in conditions:
            found = self._ocr.find(frame.image, c.value) is not None
            if c.kind == "text_present" and not found:
                return f"precondition failed: text {c.value!r} not on screen"
            if c.kind == "text_absent" and found:
                return f"precondition failed: text {c.value!r} unexpectedly present"
        return None

    # ------------------------------------------------------------------ steps
    def _ground_step(self, step: Step, frame) -> GroundedTarget | None:
        locators = {loc.layer: loc.value for loc in step.locators}
        # try the structured/cheap layers first, without any VLM fallback
        g = self._grounder.resolve(
            frame.image, {k: v for k, v in locators.items() if k != LocatorLayer.L5_VLM}
        )
        if g is None and step.x is not None and step.y is not None:
            # last resort: raw coordinates captured at record time
            g = GroundedTarget(
                LocatorLayer.L5_VLM,
                point=(step.x, step.y),
                note="recorded coordinates; nothing re-grounded",
            )
        return g

    def _to_action(self, step: Step, g: GroundedTarget | None, frame_id: int) -> Action:
        k = step.action
        if k is ActionKind.KEY:
            keys = tuple(step.keys) or (g.keys if g else ())
            return Action(kind=k, frame_id=frame_id, keys=keys)
        if k is ActionKind.TYPE:
            return Action(kind=k, frame_id=frame_id, text=step.text or "")
        pt = g.point if g else None
        if pt is None:
            raise RuntimeError(f"step {step.action.value} could not be grounded on any layer")
        if k is ActionKind.DRAG:
            return Action(
                kind=k, frame_id=frame_id, x=pt[0], y=pt[1], to_x=step.to_x, to_y=step.to_y
            )
        return Action(kind=k, frame_id=frame_id, x=pt[0], y=pt[1])

    # ------------------------------------------------------------------- run
    def replay(
        self, skill: Skill, context: ActionContext | None = None, **params: str
    ) -> ReplayResult:
        skill = skill.bind(**params)
        result = ReplayResult(skill=skill.name, steps_run=0)

        frame = self._capture.grab()
        self._fresh.observe(frame.frame_id)
        if err := self._check(skill.preconditions, frame):
            result.error = err
            return result

        for step in skill.steps:
            frame = self._capture.grab()
            self._fresh.observe(frame.frame_id)
            try:
                target = self._ground_step(step, frame)
                action = self._to_action(step, target, frame.frame_id)
            except RuntimeError as e:
                result.error = str(e)
                return result

            decision = self._gate.request_action(action, frame, context)
            result.decisions.append(decision)
            result.steps_run += 1
            if not decision.approved:
                result.error = f"gatekeeper refused step {result.steps_run}: {decision.reason}"
                return result
            time.sleep(step.wait.seconds)

        frame = self._capture.grab()
        self._fresh.observe(frame.frame_id)
        if err := self._check(skill.postconditions, frame):
            result.error = err
            return result
        result.ok = True
        return result
