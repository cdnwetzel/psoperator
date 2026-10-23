"""Privacy gate for a public repository.

Nothing private belongs in this repo: no private-LAN addresses, no home-directory
paths, and (locally) none of the operator's real hostnames. A commit *message*
leaks as surely as a file does, so this scans both.

    python scripts/privacy_scan.py files            # every tracked file
    python scripts/privacy_scan.py text < message   # a commit message or PR body

A line carrying the marker `privacy: example` is allowed: generic sample values in
tests (e.g. a private address a bind check must refuse) need it, real ones never.

`--denylist FILE` (or $PRIVACY_DENYLIST) adds literal terms, one per line, matched
case-insensitively. Keep that file OUT of the repo (e.g.
~/.config/pxx/public-denylist): it names the real hosts, so it must never be
published. CI runs without it; the local hooks run with it.

Exit 0 when clean, 1 with one line per finding.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

ALLOW = "privacy: example"
PATTERNS = {
    "private-lan-address": re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![\d.])"
    ),
    "home-directory-path": re.compile(r"(?:/Users/|/home/)(?!runner\b)[A-Za-z][\w.-]*"),
}


def load_denylist(path: str | None) -> list[str]:
    if not path:
        return []
    p = Path(path).expanduser()
    if not p.is_file():
        return []
    terms = [line.strip() for line in p.read_text().splitlines()]
    return [t for t in terms if t and not t.startswith("#")]


def scan_lines(name: str, lines: Iterable[str], denylist: list[str]) -> list[str]:
    findings = []
    lowered = [t.lower() for t in denylist]
    for number, line in enumerate(lines, 1):
        if ALLOW in line:
            continue
        for rule, pattern in PATTERNS.items():
            for match in pattern.finditer(line):
                findings.append(f"{name}:{number}: {rule}: {match.group(0)}")
        text = line.lower()
        for term, low in zip(denylist, lowered, strict=True):
            if low in text:
                # name the rule, never echo the term: the denylist itself is private
                findings.append(f"{name}:{number}: denylist term #{denylist.index(term) + 1}")
    return findings


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.decode()
    return [root / p for p in out.split("\0") if p]


def scan_files(root: Path, denylist: list[str]) -> list[str]:
    findings = []
    for path in tracked_files(root):
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: not prose
        findings += scan_lines(str(path.relative_to(root)), text.splitlines(), denylist)
    return findings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("mode", choices=("files", "text"))
    p.add_argument("--root", type=Path, default=Path.cwd())
    p.add_argument("--name", default="message", help="label for findings in text mode")
    p.add_argument("--denylist", default=os.environ.get("PRIVACY_DENYLIST"))
    args = p.parse_args(argv)
    denylist = load_denylist(args.denylist)
    if args.mode == "files":
        findings = scan_files(args.root, denylist)
    else:
        findings = scan_lines(args.name, sys.stdin.read().splitlines(), denylist)
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
