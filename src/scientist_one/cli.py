"""Composable JSON command-line interface for Scientist-One."""

from __future__ import annotations

import sys

_captured_import_capability = getattr(
    sys, "_scientist_one_captured_import_capability", None
)
_captured_import_authorized = (
    _captured_import_capability is not None
    and bool(sys.meta_path)
    and sys.meta_path[0] is _captured_import_capability
    and type(_captured_import_capability).__module__ == "__main__"
    and hasattr(_captured_import_capability, "tree")
    and hasattr(getattr(_captured_import_capability, "tree", None), "records")
    and globals().get("__loader__") is _captured_import_capability
    and getattr(globals().get("__spec__"), "loader", None)
    is _captured_import_capability
)
if not (
    _captured_import_authorized
    or getattr(sys, "_scientist_one_test_runner", False) is True
):
    raise SystemExit(
        '{"error_type":"UnsafeStartupError",'
        '"message":"refusing unisolated CLI import; use the verified '
        'python3 -I -S -B scripts/scientist_one_cli.py launcher",'
        '"status":"ERROR"}'
    )

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:
    from .orchestrator import ScientistOneOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scientist-one",
        description=(
            "Offline, custody-aware Scientist-One research controller with "
            "audited external boundaries"
        ),
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="ScientistOne project root (default: current directory)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight", help="record local hardware and resource evidence")
    subparsers.add_parser("calibrate", help="run frozen known-answer calibration")
    start = subparsers.add_parser("start", help="initialize a resumable run")
    start.add_argument("--brief", type=Path, help="project-local research brief")
    subparsers.add_parser("demo", help="execute the bounded synthetic workflow")
    research_os_fixture = subparsers.add_parser(
        "research-os-fixture",
        help="execute the integrated synthetic Research OS vNext fixture",
    )
    research_os_fixture.add_argument(
        "--run-id",
        help="optional explicit identifier for the fixture run",
    )
    research_os_fixture.add_argument(
        "--restart-from",
        dest="restart_from_run_id",
        help=(
            "start a distinct guarded run bound to an abandoned production "
            "fixture run"
        ),
    )
    status = subparsers.add_parser("status", help="show all runs or one run")
    status.add_argument("run_id", nargs="?")
    for name, description in (
        ("resume", "validate and resume a run from its safe checkpoint"),
        ("verify", "validate ledger, artifacts, and state"),
        ("reproduce", "replay the frozen primary result locally"),
        ("package", "create a human-review release candidate"),
    ):
        command = subparsers.add_parser(name, help=description)
        command.add_argument("run_id")
    return parser


def _dispatch(orchestrator: "ScientistOneOrchestrator", arguments: argparse.Namespace) -> dict[str, Any]:
    command = arguments.command
    provenance = [
        "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py", command
    ]
    run_id = getattr(arguments, "run_id", None)
    if isinstance(run_id, str):
        if command == "research-os-fixture":
            provenance.extend(("--run-id", run_id))
        else:
            provenance.append(run_id)
    restart_from_run_id = getattr(arguments, "restart_from_run_id", None)
    if isinstance(restart_from_run_id, str):
        if command != "research-os-fixture" or not isinstance(run_id, str):
            raise ValueError(
                "--restart-from requires research-os-fixture --run-id"
            )
        provenance.extend(("--restart-from", restart_from_run_id))
    if command == "start" and arguments.brief is not None:
        try:
            brief_label = arguments.brief.resolve(strict=True).relative_to(Path.cwd().resolve(strict=True)).as_posix()
        except (OSError, ValueError):
            brief_label = arguments.brief.name
        provenance.extend(("--brief", brief_label))
    orchestrator.set_command_context(provenance)
    if command == "preflight":
        return orchestrator.preflight()
    if command == "calibrate":
        return orchestrator.calibrate()
    if command == "start":
        return orchestrator.start(arguments.brief)
    if command == "demo":
        return orchestrator.demo()
    if command == "research-os-fixture":
        return orchestrator.research_os_fixture(
            arguments.run_id,
            restart_from_run_id=arguments.restart_from_run_id,
        )
    if command == "status":
        return orchestrator.status(arguments.run_id)
    if command == "resume":
        return orchestrator.resume(arguments.run_id)
    if command == "verify":
        return orchestrator.verify(arguments.run_id)
    if command == "reproduce":
        return orchestrator.reproduce(arguments.run_id)
    if command == "package":
        return orchestrator.package(arguments.run_id)
    raise ValueError(f"unsupported command: {command}")


def main(argv: Sequence[str] | None = None) -> int:
    if getattr(sys, "_scientist_one_isolated_launcher", False) is not True:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "error_type": "UnsafeStartupError",
                    "message": (
                        "refusing unisolated startup; use the verified "
                        "python3 -I -S -B scripts/scientist_one_cli.py launcher"
                    ),
                },
                sort_keys=True,
            )
        )
        return 2
    from .orchestrator import OrchestrationError, ScientistOneOrchestrator
    from .packaging import PackagingError
    from .reproduction import ReproductionError

    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        result = _dispatch(ScientistOneOrchestrator(arguments.root), arguments)
    except (OrchestrationError, PackagingError, ReproductionError, OSError, ValueError, RuntimeError) as exc:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0 if result.get("status") == "PASS" else 1


__all__ = ["build_parser", "main"]
