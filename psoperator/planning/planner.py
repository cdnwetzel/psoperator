"""Element-aware planners that can propose actions but cannot execute them."""

from __future__ import annotations

import json
from typing import Protocol

import httpx

from psoperator.common.schema import PerceptionSnapshot
from psoperator.runtime.actions import Action, ActionKind, parse_action


class Planner(Protocol):
    def plan(self, snapshot: PerceptionSnapshot, goal: str) -> Action: ...


class RuleBasedPlanner:
    """Deterministic planner useful for isolation and end-to-end smoke tests."""

    def plan(self, snapshot: PerceptionSnapshot, goal: str) -> Action:
        needle = goal.casefold()
        for element in snapshot.elements:
            if needle in element.label.casefold():
                return Action(
                    kind=ActionKind.CLICK,
                    frame_id=snapshot.frame_id,
                    target_element_id=element.element_id,
                )
        return Action(
            kind=ActionKind.FAIL,
            frame_id=snapshot.frame_id,
            reason=f"no visible element matched {goal!r}",
        )


class LocalElementPlanner:
    """Planner for a local OpenAI-compatible text endpoint.

    Only structured element metadata crosses this boundary. A screenshot-aware
    GUI model is handled by :class:`psoperator.runtime.loop.AgentLoop`.
    """

    def __init__(
        self,
        endpoint: str,
        model: str,
        api_key: str = "not-needed",
        timeout_s: float = 30.0,
    ) -> None:
        self._model = model
        self._client = httpx.Client(
            base_url=endpoint,
            timeout=timeout_s,
            headers={"Authorization": f"Bearer {api_key}"},
        )

    def plan(self, snapshot: PerceptionSnapshot, goal: str) -> Action:
        elements = [
            {
                "id": item.element_id,
                "label": item.label,
                "role": item.control_type,
            }
            for item in snapshot.elements
        ]
        payload = {
            "model": self._model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return exactly one JSON action. Prefer click with a supplied "
                        "target_element_id; never invent an id. Echo frame_id."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {"goal": goal, "frame_id": snapshot.frame_id, "elements": elements}
                    ),
                },
            ],
            "temperature": 0.0,
            "max_tokens": 256,
        }
        response = self._client.post("/chat/completions", json=payload)
        response.raise_for_status()
        raw = response.json()["choices"][0]["message"]["content"]
        action = parse_action(raw)
        if action.target_element_id and snapshot.find(action.target_element_id) is None:
            raise ValueError("planner proposed an element id absent from the snapshot")
        return action

    def close(self) -> None:
        self._client.close()
