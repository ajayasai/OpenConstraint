"""Fail when a pull-request commit lacks a DCO sign-off trailer."""

from __future__ import annotations

import re
import subprocess
import sys

SIGNOFF = re.compile(r"(?im)^Signed-off-by:\s+\S(?:.*\S)?\s+<[^<>\s]+@[^<>\s]+>\s*$")


def _git(*arguments: str) -> str:
    return subprocess.check_output(("git", *arguments), text=True, encoding="utf-8", errors="replace")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_dco.py BASE_SHA HEAD_SHA")
    base, head = sys.argv[1:]
    commits = _git("rev-list", f"{base}..{head}").splitlines()
    failures: list[str] = []
    for commit in commits:
        body = _git("show", "-s", "--format=%B", commit)
        if not SIGNOFF.search(body):
            subject = _git("show", "-s", "--format=%s", commit).strip()
            failures.append(f"{commit[:12]} {subject}")
    if failures:
        print("The following commits lack a valid 'Signed-off-by: Name <email>' trailer:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print("Amend each commit with `git commit --amend --signoff` and update the pull request.", file=sys.stderr)
        return 1
    print(f"DCO sign-off present on {len(commits)} pull-request commit(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
