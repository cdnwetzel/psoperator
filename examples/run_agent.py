"""Demo: "open notepad and type hello" against a local model endpoint.

Prereqs:
    1. A local OpenAI-compatible server serving a GUI model, e.g.
         llama-server -m ui-tars-1.5-7b-q4_k_m.gguf --port 8000
       or vLLM serving Holo3.1-4B. Default endpoint: http://localhost:8000/v1
    2. A real desktop session (mss needs a display).

Run:
    python examples/run_agent.py
    python examples/run_agent.py --real-input   # DANGEROUS: pynput executor

Without an endpoint the loop degrades gracefully and says so.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from psoperator.config import load_config
from psoperator.gatekeeper.approval import CLIApproval
from psoperator.gatekeeper.executor import DryRunExecutor, PynputExecutor
from psoperator.gatekeeper.gatekeeper import Gatekeeper
from psoperator.perception.capture import MSSCapture
from psoperator.runtime.freshness import FreshnessTracker
from psoperator.runtime.loop import AgentLoop


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", default="open notepad and type hello")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument(
        "--real-input", action="store_true", help="use the real pynput executor instead of dry-run"
    )
    ap.add_argument(
        "--static",
        action="store_true",
        help="headless smoke-test: use a static frame instead of mss",
    )
    args = ap.parse_args()

    cfg = load_config()
    if args.static:
        from PIL import Image

        from psoperator.perception.capture import StaticCapture

        capture = StaticCapture([Image.new("RGB", (1280, 720), (25, 28, 35))])
    else:
        try:
            capture = MSSCapture(monitor=cfg.monitor)
        except Exception as e:
            print(f"no usable display for mss capture ({e}); this demo needs a desktop session")
            return 2
    freshness = FreshnessTracker()
    executor = PynputExecutor() if args.real_input else DryRunExecutor()
    gate = Gatekeeper(cfg, freshness, approval_backend=CLIApproval(), executor=executor)
    loop = AgentLoop(cfg, capture, gate, freshness)

    print(f"task     : {args.task}")
    print(f"endpoint : {cfg.model_endpoint} (model {cfg.model_name})")
    print(f"executor : {executor.name}")
    print(f"audit    : {cfg.audit_log_path}\n")

    try:
        result = loop.run(args.task, max_steps=args.max_steps)
    finally:
        loop.close()

    if result.degraded:
        print(f"\nDEGRADED: {result.degraded}")
        print("Start a local server (llama.cpp/vLLM) and retry.")
        return 2
    print(
        f"\nsteps={result.steps} finished={result.finished} "
        f"model_calls={result.model_calls} skipped_frames={result.skipped_frames}"
    )
    for i, d in enumerate(result.history, 1):
        tier = d.risk.tier.name if d.risk else "-"
        print(f"  {i:>2}. [{tier}] {d.action.to_text()} -> {d.kind.value} ({d.reason})")
    return 0 if result.finished else 1


if __name__ == "__main__":
    raise SystemExit(main())
