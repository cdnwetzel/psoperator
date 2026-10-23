"""Demo: Topology B — crash-cart / out-of-band mode.

The agent machine watches the *target* machine's HDMI output through a USB
capture card and injects input through a CH9329 serial-to-USB-HID cable.
Nothing runs on the target: no agent, no driver, no accessibility API — it
can be at a BIOS screen, a locked session, or an OS without Python.

    target machine ──HDMI──> capture card ──USB──> agent machine (/dev/video0)
    agent machine (/dev/ttyUSB0) ──serial──> CH9329 cable ──USB HID──> target

Prereqs:
    pip install -e .[uvc,ch9329]
    # Linux: user must be in 'video' (capture card) and 'dialout' (serial):
    sudo usermod -aG video,dialout $USER   # then log out and back in

Run:
    python examples/run_crashcart.py --task "..."
    PSOPERATOR_CAPTURE_BACKEND=uvc \
      PSOPERATOR_EXECUTOR_BACKEND=ch9329 \
      python examples/run_crashcart.py

The CH9329 chip ships at 9600 baud; the default here matches. Only raise
PSOPERATOR_CH9329_BAUDRATE after the chip itself has been reconfigured.

Without the hardware the demo degrades gracefully: it prints a checklist and
falls back to a static frame + dry-run executor so the loop mechanics stay
exercisable. The gatekeeper/audit path is identical either way.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from psoperator.config import PSOperatorConfig, load_config
from psoperator.gatekeeper.approval import CLIApproval
from psoperator.gatekeeper.executor import DryRunExecutor
from psoperator.gatekeeper.gatekeeper import Gatekeeper
from psoperator.runtime.freshness import FreshnessTracker
from psoperator.runtime.loop import AgentLoop

CHECKLIST = """\
Topology B hardware checklist:
  [ ] HDMI capture card on the agent machine   -> /dev/video{uvc} (group: video)
  [ ] CH9329 HID cable on the agent machine    -> {port} (group: dialout)
  [ ] target HDMI out -> capture card; CH9329 USB plug -> target USB port
  [ ] baud rate matches the chip (factory default: 9600; current: {baud})
  [ ] python packages: pip install -e .[uvc,ch9329]
"""


def build_capture(cfg: PSOperatorConfig):
    """Assemble the capture backend from config ('mss' | 'uvc')."""
    if cfg.capture_backend == "uvc":
        from psoperator.perception.capture_uvc import UVCCapture

        return UVCCapture(
            device_index=cfg.uvc_device_index,
            width=cfg.uvc_width,
            height=cfg.uvc_height,
        )
    if cfg.capture_backend == "mss":
        from psoperator.perception.capture import MSSCapture

        return MSSCapture(monitor=cfg.monitor)
    raise ValueError(f"unknown capture_backend: {cfg.capture_backend!r}")


def build_executor(cfg: PSOperatorConfig):
    """Assemble the executor backend from config ('dryrun' | 'pynput' | 'ch9329')."""
    if cfg.executor_backend == "ch9329":
        from psoperator.gatekeeper.executor_ch9329 import CH9329Executor

        return CH9329Executor(
            port=cfg.ch9329_port,
            baudrate=cfg.ch9329_baudrate,
            # Absolute-mouse mapping must use the *target* screen's resolution,
            # which is what the capture card sees.
            screen_width=cfg.uvc_width,
            screen_height=cfg.uvc_height,
        )
    if cfg.executor_backend == "pynput":
        from psoperator.gatekeeper.executor import PynputExecutor

        return PynputExecutor()
    if cfg.executor_backend == "dryrun":
        return DryRunExecutor()
    raise ValueError(f"unknown executor_backend: {cfg.executor_backend!r}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", default="open the start menu and launch notepad")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument(
        "--simulate",
        action="store_true",
        help="no hardware: static frame + dry-run executor (smoke test)",
    )
    args = ap.parse_args()

    cfg = load_config(
        capture_backend="uvc" if not args.simulate else "mss",
        executor_backend="ch9329" if not args.simulate else "dryrun",
    )

    if args.simulate:
        from PIL import Image

        from psoperator.perception.capture import StaticCapture

        capture = StaticCapture([Image.new("RGB", (cfg.uvc_width, cfg.uvc_height), (25, 28, 35))])
        executor = DryRunExecutor()
        print("SIMULATE mode: no capture card, no CH9329 cable required.")
    else:
        try:
            capture = build_capture(cfg)
        except Exception as e:
            print(f"capture backend unavailable: {e}\n")
            print(
                CHECKLIST.format(
                    uvc=cfg.uvc_device_index, port=cfg.ch9329_port, baud=cfg.ch9329_baudrate
                )
            )
            return 2
        try:
            executor = build_executor(cfg)
        except Exception as e:
            capture.close()
            print(f"executor backend unavailable: {e}\n")
            print(
                CHECKLIST.format(
                    uvc=cfg.uvc_device_index, port=cfg.ch9329_port, baud=cfg.ch9329_baudrate
                )
            )
            return 2

    freshness = FreshnessTracker()
    gate = Gatekeeper(cfg, freshness, approval_backend=CLIApproval(), executor=executor)
    loop = AgentLoop(cfg, capture, gate, freshness)

    print(f"task     : {args.task}")
    if args.simulate:
        print("capture  : static  |  executor : dry-run")
    else:
        print(f"capture  : uvc /dev/video{cfg.uvc_device_index} {cfg.uvc_width}x{cfg.uvc_height}")
        print(f"executor : {executor.name} ({cfg.ch9329_port} @ {cfg.ch9329_baudrate} baud)")
    print(f"endpoint : {cfg.model_endpoint} (model {cfg.model_name})")
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
