"""Demo: record a short trajectory, compile it into a Skill JSON.

Recording needs a real desktop session (pynput listeners + mss). For a
headless demo, ``--synthetic`` fabricates the trajectory the recorder would
have produced and compiles that instead — handy on CI.

Run:
    python examples/record_skill.py --synthetic
    python examples/record_skill.py --seconds 15 --out my_skill.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from psoperator.perception.capture import MSSCapture, StaticCapture
from psoperator.runtime.actions import ActionKind
from psoperator.runtime.grounding import LocatorLayer
from psoperator.skills.schema import Locator, Skill, Step, Wait


def synthetic_skill() -> Skill:
    """What 'open notepad and type hello' looks like as a compiled skill."""
    return Skill(
        name="notepad_hello",
        description="Open notepad via the Run dialog and type a greeting.",
        params={"greeting": "hello"},
        steps=[
            Step(
                action=ActionKind.KEY,
                keys=["win", "r"],
                locators=[Locator(layer=LocatorLayer.L0_HOTKEY, value="win+r")],
                wait=Wait(after_ms=700),
            ),
            Step(action=ActionKind.TYPE, text="notepad", wait=Wait(after_ms=300)),
            Step(
                action=ActionKind.KEY,
                keys=["enter"],
                locators=[Locator(layer=LocatorLayer.L0_HOTKEY, value="enter")],
                wait=Wait(after_ms=1500),
            ),
            Step(
                action=ActionKind.TYPE,
                text="{greeting}",
                locators=[Locator(layer=LocatorLayer.L5_VLM, value="the notepad text area")],
            ),
        ],
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=None, help="record duration (Ctrl+C to stop)")
    ap.add_argument("--out", default="skill.json")
    ap.add_argument("--trajectory", default="trajectory.jsonl")
    ap.add_argument("--synthetic", action="store_true", help="skip recording; emit demo skill")
    args = ap.parse_args()

    if args.synthetic:
        skill = synthetic_skill()
        skill.to_json_file(Path(args.out))
        print(f"wrote synthetic skill -> {args.out}")
        print(skill.summary())
        return 0

    from PIL import Image

    from psoperator.skills.recorder import Recorder

    try:
        capture = MSSCapture(monitor=1)
    except Exception:
        print("no display; falling back to a static frame so listeners still record")
        capture = StaticCapture([Image.new("RGB", (1920, 1080))])

    rec = Recorder(capture)
    print("recording... perform the task, then Ctrl+C")
    events = rec.record(duration_s=args.seconds)
    rec.save_jsonl(Path(args.trajectory))
    print(f"recorded {len(events)} events -> {args.trajectory}")
    print("TODO: compile the trajectory into a Skill (by hand or with the model),")
    print(f"      then replay it: python examples/replay_skill.py --skill {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
