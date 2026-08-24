"""Submit one element-bound action through the separated gatekeeper service."""

from __future__ import annotations

import argparse

from psoperator.common.ipc import request
from psoperator.config import load_config
from psoperator.planning.planner import LocalElementPlanner, RuleBasedPlanner
from psoperator.services.observer_client import ObserverClient, ObserverUnavailable


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("goal", nargs="?", default="Save")
    parser.add_argument("--llm", action="store_true", help="use the configured local planner")
    args = parser.parse_args()

    config = load_config()
    observer = ObserverClient(
        config.observer_host,
        config.observer_port,
        timeout=config.observer_timeout_s,
    )
    planner = (
        LocalElementPlanner(
            config.model_endpoint,
            config.model_name,
            config.model_api_key,
            config.model_timeout_s,
        )
        if args.llm
        else RuleBasedPlanner()
    )

    try:
        attestation = observer.observe()
        snapshot = attestation.snapshot
        action = planner.plan(snapshot, args.goal)
        response = request(
            config.gatekeeper_host,
            config.gatekeeper_port,
            {
                "action": action.to_dict(),
                "attestation": attestation.model_dump(mode="json"),
                "context": {},
            },
        )
        print(response)
        return 0 if response.get("ok") else 1
    except ObserverUnavailable as exc:
        print(exc)
        return 2
    finally:
        close = getattr(planner, "close", None)
        if close is not None:
            close()


if __name__ == "__main__":
    raise SystemExit(main())
