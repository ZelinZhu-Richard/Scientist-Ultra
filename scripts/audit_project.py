#!/usr/bin/env python3
"""Compatibility shim for the captured-source authoritative project audit."""

from __future__ import annotations

import sys


if not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.safe_path
    and sys.flags.ignore_environment
    and sys.flags.no_user_site
    and sys.flags.dont_write_bytecode
    and sys.flags.optimize == 0
    and sys.dont_write_bytecode
):
    raise SystemExit(
        "refusing unsafe startup; invoke the pinned interpreter with -I -S -B"
    )


import os


def main() -> int:
    script = os.path.realpath(__file__)
    root = os.path.dirname(os.path.dirname(script))
    if os.path.realpath(os.getcwd()) != root:
        raise SystemExit("run from the canonical ScientistOne project root")
    launcher = os.path.join(root, "scripts", "scientist_one_cli.py")
    os.execv(
        sys.executable,
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            launcher,
            "audit-project",
        ],
    )
    raise AssertionError("exec unexpectedly returned")


if __name__ == "__main__":
    raise SystemExit(main())
