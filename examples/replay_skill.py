"""Demo: replay a recorded Skill through the gatekeeper.

Every step is grounded via the cheapest-first ladder and submitted to the
gatekeeper exactly like a model-proposed action — freshness, risk tiering,
approval, audit all apply. Defaults to the dry-run executor.

Run:
    python examples/record_skill.py --synthetic --out skill.json
    python examples/replay_skill.py --skill skill.json
    python examples/replay_skill.py --skill skill.json --real-input  # DANGEROUS
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image

from psoperator.config import load_config
from psoperator.gatekeeper.approval import CLIApproval
from psoperator.gatekeeper.executor import DryRunExecutor, PynputExecutor
from psoperator.gatekeeper.gatekeeper import Gatekeeper
from psoperator.perception.a11y import default_a11y
from psoperator.perception.capture import MSSCapture, StaticCapture
from psoperator.perception.ocr import default_ocr
from psoperator.runtime.freshness import FreshnessTracker
from psoperator.runtime.grounding import Grounder
from psoperator.skills.replay import ReplayEngine
from psoperator.skills.schema import Skill


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill", default="skill.json")
    ap.add_argument("--real-input", action="store_true")
    ap.add_argument("--param", action="append", default=[], help="key=value override")
    args = ap.parse_args()

    params = dict(p.split("=", 1) for p in args.param)
    skill = Skill.from_json_file(Path(args.skill))
    cfg = load_config()

    try:
        capture = MSSCapture(monitor=cfg.monitor)
    except Exception:
        print("no display; using a static frame (grounding will fall back to recorded coords)")
        capture = StaticCapture([Image.new("RGB", (1920, 1080), (30, 30, 40))])

    freshness = FreshnessTracker()
    executor = PynputExecutor() if args.real_input else DryRunExecutor()
    gate = Gatekeeper(cfg, freshness, approval_backend=CLIApproval(), executor=executor)
    grounder = Grounder(a11y=default_a11y(), ocr=default_ocr())
    engine = ReplayEngine(capture, gate, grounder, default_ocr(), freshness)

    print(f"replaying skill {skill.name!r} ({len(skill.steps)} steps), executor={executor.name}")
    result = engine.replay(skill, **params)

    for i, d in enumerate(result.decisions, 1):
        tier = d.risk.tier.name if d.risk else "-"
        print(f"  {i:>2}. [{tier}] {d.action.to_text()} -> {d.kind.value}: {d.outcome or d.reason}")
    print(
        f"\nok={result.ok} steps={result.steps_run}"
        + (f" error={result.error}" if result.error else "")
    )
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
