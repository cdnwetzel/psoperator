"""Privacy gate for a public repository.

Nothing private belongs in this repo: no private-LAN addresses, no home-directory
paths, and (locally) none of the operator's real hostnames. A commit *message*
leaks as surely as a file does, so this scans both.

    python scripts/privacy_scan.py files            # every tracked file
    python scripts/privacy_scan.py staged           # what a commit would record
    python scripts/privacy_scan.py text < message   # a commit message or PR body

A line carrying the marker `privacy: example` may hold a generic sample address or
path (e.g. a private address a bind check must refuse). The marker never exempts a
denylist term: a real hostname is not an example.

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
    "home-directory-path": re.compile(
        r"(?:/Users/|/home/)(?!runner\b)[A-Za-z][\w.-]*"
        r"|[A-Za-z]:[\\/]+(?:Users|Documents and Settings)[\\/]+[A-Za-z][\w.-]*",
        re.IGNORECASE,
    ),
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

    def _shown(value: str, redacted: str) -> str:
        # A finding never echoes a denylist term, even inside a matched path or
        # a file name: the denylist itself is private.
        return redacted if any(low in value.lower() for low in lowered) else value

    name = _shown(name, "<name redacted>")
    for number, line in enumerate(lines, 1):
        if ALLOW not in line:  # the marker exempts sample values, never the denylist
            for rule, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    findings.append(
                        f"{name}:{number}: {rule}: {_shown(match.group(0), '<redacted>')}"
                    )
        text = line.lower()
        for term, low in zip(denylist, lowered, strict=True):
            if low in text:
                # name the rule, never echo the term: the denylist itself is private
                findings.append(f"{name}:{number}: denylist term #{denylist.index(term) + 1}")
    return findings


def _git(root: Path, *argv: str) -> bytes:
    return subprocess.run(["git", "-C", str(root), *argv], capture_output=True, check=True).stdout


def decode(data: bytes) -> str:
    """Text for scanning, from any bytes. Nothing is skipped as undecodable: a
    UTF-16 file is decoded as such, anything else that is not UTF-8 is read
    byte-for-byte (latin-1), so ASCII addresses and names in it still match."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def scan_files(root: Path, denylist: list[str]) -> list[str]:
    """Every tracked file as it is in the working tree."""
    findings = []
    for rel in _git(root, "ls-files", "-z").decode().split("\0"):
        path = root / rel
        if not rel or not path.is_file():
            continue
        findings += scan_lines(rel, decode(path.read_bytes()).splitlines(), denylist)
    return findings


def scan_staged(root: Path, denylist: list[str]) -> list[str]:
    """What a commit would record: each staged blob, read from the index, not
    the working tree (a leak can be staged and then edited out of the file)."""
    findings = []
    names = _git(root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    for rel in names.decode().split("\0"):
        if rel:
            blob = _git(root, "show", f":{rel}")
            findings += scan_lines(rel, decode(blob).splitlines(), denylist)
    return findings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("mode", choices=("files", "staged", "text"))
    p.add_argument("--root", type=Path, default=Path.cwd())
    p.add_argument("--name", default="message", help="label for findings in text mode")
    p.add_argument("--denylist", default=os.environ.get("PRIVACY_DENYLIST"))
    args = p.parse_args(argv)
    denylist = load_denylist(args.denylist)
    if args.mode == "files":
        findings = scan_files(args.root, denylist)
    elif args.mode == "staged":
        findings = scan_staged(args.root, denylist)
    else:
        findings = scan_lines(args.name, sys.stdin.read().splitlines(), denylist)
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
