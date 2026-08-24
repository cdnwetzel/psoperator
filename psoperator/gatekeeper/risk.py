"""Deterministic risk classification.

Tiers:
    T0  read-only   — observe-only actions (wait, scroll, done, fail)
    T1  reversible  — clicks, typing ordinary text, navigation keys
    T2  sensitive   — message send, purchase/checkout, account changes,
                      credential-shaped typing, external sharing
    T3  destructive — delete/erase/format, financial transfer, credential
                      submission, irreversible system changes

Classification is pure pattern matching over (action kind, typed text, key
chords, and surrounding context: window title / app name / target text).
It is intentionally dumb and conservative: ambiguity escalates, never
de-escalates. The model has no say in the tier of its own action.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

from psoperator.runtime.actions import Action, ActionKind


class RiskTier(IntEnum):
    T0_READ_ONLY = 0
    T1_REVERSIBLE = 1
    T2_SENSITIVE = 2
    T3_DESTRUCTIVE = 3


@dataclass(frozen=True)
class ActionContext:
    """What we know about where the action will land. All fields optional;
    missing context never lowers a tier."""

    window_title: str = ""
    app_name: str = ""
    target_text: str = ""  # e.g. the button label / field placeholder

    def haystack(self) -> str:
        return " ".join([self.window_title, self.app_name, self.target_text]).casefold()


@dataclass(frozen=True)
class RiskAssessment:
    tier: RiskTier
    reasons: tuple[str, ...] = field(default_factory=tuple)


# --- built-in patterns (word-boundary, case-insensitive) -------------------
# These live in code, not in the model. policy.json can ADD, never remove.

_T2_PATTERNS = [
    r"\bsend\b",
    r"\bpost\b",
    r"\bshare\b",
    r"\bpublish\b",
    r"\breply\b",
    r"\bbuy\b",
    r"\bpurchase\b",
    r"\bcheckout\b",
    r"\bpay\b",
    r"\border now\b",
    r"\bsign up\b",
    r"\bsubscribe\b",
    r"\bconfirm (your )?account\b",
    r"\bchange (my )?(email|password|username)\b",
]

_T3_PATTERNS = [
    r"\bdelete\b",
    r"\berase\b",
    r"\bformat\b",
    r"\bwipe\b",
    r"\bremove permanently\b",
    r"\bempty (the )?(trash|recycle bin)\b",
    r"\brm -rf\b",
    r"\bdel /[fsq]\b",
    r"\btransfer\b",
    r"\bwire\b",
    r"\bwithdraw\b",
    r"\bcrypto\b",
    r"\bbank(ing)?\b",
    r"\benter (your )?password\b",
    r"\bconfirm (your )?password\b",
    r"\bcredit card\b",
    r"\bcvv\b",
    r"\bsecurity code\b",
    r"\bsign in\b",
    r"\blog ?in\b",
]

_CREDENTIAL_TEXT = re.compile(r"(?i)\b(password|passwd|ssn|cvv|pin)\b")
_DESTRUCTIVE_CHORDS = {("shift", "delete"), ("ctrl", "shift", "delete")}
_FINANCIAL_KEYS = re.compile(r"(?i)\b(iban|swift|routing number|card number)\b")


def _match_any(patterns: list[str], hay: str) -> list[str]:
    return [p for p in patterns if re.search(p, hay)]


def load_policy(path: Path) -> dict[str, list[str]]:
    """Optional operator-supplied extra patterns. Only escalates."""
    if not path.exists():
        return {"t2": [], "t3": []}
    data = json.loads(path.read_text())
    return {"t2": list(data.get("t2", [])), "t3": list(data.get("t3", []))}


def classify(
    action: Action, context: ActionContext | None = None, policy: dict | None = None
) -> RiskAssessment:
    """Deterministic tier assignment. Conservative on ambiguity."""
    policy = policy or {"t2": [], "t3": []}
    ctx = context or ActionContext()
    hay = ctx.haystack() + " " + (action.text or "").casefold()
    reasons: list[str] = []

    t3_hits = _match_any(_T3_PATTERNS + policy["t3"], hay)
    t2_hits = _match_any(_T2_PATTERNS + policy["t2"], hay)

    # T3: destructive chords, credential-shaped typing, T3 keywords
    if action.kind is ActionKind.KEY and tuple(action.keys) in _DESTRUCTIVE_CHORDS:
        reasons.append(f"destructive chord {'+'.join(action.keys)}")
        return RiskAssessment(RiskTier.T3_DESTRUCTIVE, tuple(reasons))
    if action.kind is ActionKind.TYPE and action.text:
        if _CREDENTIAL_TEXT.search(ctx.haystack()) or _FINANCIAL_KEYS.search(action.text):
            reasons.append("typing into a credential/financial field")
            return RiskAssessment(RiskTier.T3_DESTRUCTIVE, tuple(reasons))
    if t3_hits:
        reasons.extend(f"T3 keyword {p!r}" for p in t3_hits)
        return RiskAssessment(RiskTier.T3_DESTRUCTIVE, tuple(reasons))

    # T2: sensitive keywords in context or typed text
    if t2_hits:
        reasons.extend(f"T2 keyword {p!r}" for p in t2_hits)
        return RiskAssessment(RiskTier.T2_SENSITIVE, tuple(reasons))

    # T0: no side effects on the world
    if action.kind in (ActionKind.WAIT, ActionKind.SCROLL, ActionKind.DONE, ActionKind.FAIL):
        return RiskAssessment(RiskTier.T0_READ_ONLY, ("observe-only action",))

    # T1: clicks, ordinary typing, ordinary keys — reversible in principle
    return RiskAssessment(RiskTier.T1_REVERSIBLE, ("default reversible tier",))
