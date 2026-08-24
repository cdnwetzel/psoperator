"""The agent loop: observe -> think -> act -> verify.

Each iteration:
    observe : grab a frame; the keyframe filter decides if we even need the model
    think   : send task + history + screenshot to the local OpenAI-compatible
              endpoint (llama.cpp / vLLM serving a local GUI model)
    act     : parse the single action, hand it to the gatekeeper (which owns
              freshness, risk, approval, execution, and the audit trail)
    verify  : grab a fresh frame so the next model call sees consequences

Fully local: the ONLY network call is to ``config.model_endpoint``. If no
endpoint is reachable, the loop degrades gracefully (VLMUnavailable) instead
of crashing.
"""

from __future__ import annotations

import base64
import io
import time
from dataclasses import dataclass, field

import httpx
from PIL import Image

from psoperator.common.schema import PerceptionSnapshot
from psoperator.config import PSOperatorConfig
from psoperator.gatekeeper.gatekeeper import Decision, DecisionKind, Gatekeeper
from psoperator.gatekeeper.risk import ActionContext
from psoperator.perception.capture import Frame, ScreenCapture
from psoperator.perception.diff import KeyframeFilter
from psoperator.perception.snapshot import SnapshotBuilder
from psoperator.runtime.actions import ActionParseError, parse_action
from psoperator.runtime.freshness import FreshnessTracker

SYSTEM_PROMPT = """You are a desktop-automation agent. You see one screenshot per turn.
Reply with EXACTLY ONE action as JSON, echoing the frame_id you were given:
{"action":"click","target_element_id":"id-from-elements","frame_id":N}
{"action":"click","x":int,"y":int,"frame_id":N}
{"action":"type","text":"...","frame_id":N}
{"action":"key","keys":["ctrl","s"],"frame_id":N}
{"action":"scroll","amount":int,"frame_id":N}
{"action":"drag","x":int,"y":int,"to_x":int,"to_y":int,"frame_id":N}
{"action":"wait","seconds":float,"frame_id":N}
{"action":"done","frame_id":N}   when the task is complete
{"action":"fail","reason":"...","frame_id":N}   when the task is impossible
Prefer a target_element_id from the supplied element list over coordinates.
Never invent an element id. Coordinates are absolute pixels. No prose."""


class VLMUnavailable(RuntimeError):
    """Raised/caught internally when the local endpoint is not reachable."""


@dataclass
class LoopResult:
    steps: int
    finished: bool  # done/fail, vs. hit max_steps / degraded
    final: Decision | None
    history: list[Decision] = field(default_factory=list)
    model_calls: int = 0
    skipped_frames: int = 0
    degraded: str = ""  # non-empty when the loop bailed early (e.g. no endpoint)


class AgentLoop:
    def __init__(
        self,
        config: PSOperatorConfig,
        capture: ScreenCapture,
        gatekeeper: Gatekeeper,
        freshness: FreshnessTracker | None = None,
        snapshot_builder: SnapshotBuilder | None = None,
    ) -> None:
        self._cfg = config
        self._capture = capture
        self._gate = gatekeeper
        self._fresh = freshness or FreshnessTracker()
        self._snapshots = snapshot_builder or SnapshotBuilder()
        self._kf = KeyframeFilter(
            diff_threshold=config.diff_threshold,
            phash_threshold=config.phash_threshold,
            tile_size=config.tile_size,
        )
        self._client = httpx.Client(
            base_url=config.model_endpoint,
            timeout=config.model_timeout_s,
            headers={"Authorization": f"Bearer {config.model_api_key}"},
        )

    # ------------------------------------------------------------------ model
    def _png_b64(self, img: Image.Image) -> str:
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()

    def think(
        self,
        task: str,
        frame: Frame,
        history: list[Decision],
        snapshot: PerceptionSnapshot,
    ) -> str:
        """One chat-completion call to the local endpoint. Raises VLMUnavailable."""
        hist = "\n".join(
            f"step {i + 1}: {d.action.to_text()} -> {d.kind.value}"
            for i, d in enumerate(history[-6:])
        )
        visible = [
            {
                "id": item.element_id,
                "label": item.label,
                "role": item.control_type,
                "bbox": item.bbox,
                "source": item.source,
            }
            for item in snapshot.elements[:200]
        ]
        user = (
            f"Task: {task}\nframe_id: {frame.frame_id}\n"
            f"Screenshot size: {frame.image.size[0]}x{frame.image.size[1]}\n"
            f"Visible elements: {visible}\n"
            + (f"Recent steps:\n{hist}\n" if hist else "")
            + "Emit the next single action."
        )
        payload = {
            "model": self._cfg.model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": user},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{self._png_b64(frame.image)}"
                            },
                        },
                    ],
                },
            ],
            "max_tokens": 256,
            "temperature": 0.0,
        }
        try:
            r = self._client.post("/chat/completions", json=payload)
            r.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            raise VLMUnavailable(str(e)) from e
        return r.json()["choices"][0]["message"]["content"]

    # ------------------------------------------------------------------- loop
    def run(
        self, task: str, max_steps: int = 20, context: ActionContext | None = None
    ) -> LoopResult:
        history: list[Decision] = []
        model_calls = 0
        skipped = 0

        for step in range(1, max_steps + 1):
            frame = self._capture.grab()
            self._fresh.observe(frame.frame_id)

            # observe-gate: skip the model entirely if nothing meaningful changed
            if not self._kf.should_query(frame.image):
                skipped += 1
                time.sleep(0.05)
                continue

            snapshot = self._snapshots.build(frame)

            # think
            try:
                raw = self.think(task, frame, history, snapshot)
                model_calls += 1
            except VLMUnavailable as e:
                # Graceful degradation: no local endpoint running.
                return LoopResult(
                    steps=step,
                    finished=False,
                    final=None,
                    history=history,
                    model_calls=model_calls,
                    skipped_frames=skipped,
                    degraded=f"model endpoint unavailable: {e}",
                )

            # parse
            try:
                action = parse_action(raw, current_frame_id=frame.frame_id)
            except ActionParseError as e:
                history.append(self._synthetic_fail(frame, f"unparseable model output: {e}"))
                continue

            # act (gatekeeper owns freshness/risk/approval/execution/audit)
            decision = self._gate.request_action(action, frame, context, snapshot)
            history.append(decision)

            if decision.terminal or decision.kind in (
                DecisionKind.REJECTED_STALE,
                DecisionKind.REJECTED_TARGET,
                DecisionKind.KILL_SWITCHED,
            ):
                return LoopResult(
                    step,
                    finished=decision.terminal,
                    final=decision,
                    history=history,
                    model_calls=model_calls,
                    skipped_frames=skipped,
                )

            # verify happens implicitly: next iteration's frame reflects the action
            time.sleep(0.05)

        return LoopResult(
            max_steps,
            finished=False,
            final=history[-1] if history else None,
            history=history,
            model_calls=model_calls,
            skipped_frames=skipped,
        )

    def _synthetic_fail(self, frame: Frame, reason: str) -> Decision:
        from psoperator.runtime.actions import Action, ActionKind

        a = Action(kind=ActionKind.FAIL, frame_id=frame.frame_id, reason=reason)
        return self._gate.request_action(a, frame)

    def close(self) -> None:
        self._client.close()
        self._capture.close()
