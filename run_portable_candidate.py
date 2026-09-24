"""Stage and run the recovered baseline as a bounded local fixture.

This runner is newly authored support.  It never imports the candidate tree;
the unchanged recovered launcher is the only process which does so.  All
paths in the frozen manifest are relative to this candidate directory.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time


BASE = Path(__file__).resolve().parent
MANIFEST_PATH = BASE / "manifest.json"
BOOTSTRAP_RELATIVE = Path("state/APP_SESSION_BOOTSTRAP.json")
FROZEN_ROOTS = ("src", "scripts", "configs", "fixtures")
TEST_ROOT = "tests"
REQUIRED_DIRS = ("state", "reports", "runs", "artifacts", ".scientist-one-build")
COMMAND = ("test-suite",)


def digest(path: Path) -> str:
    stat = path.lstat()
    if not path.is_file() or path.is_symlink() or stat.st_nlink != 1:
        raise RuntimeError(f"refusing non-private regular input: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path, relative_paths: list[str] | tuple[str, ...]) -> dict:
    result = {}
    for relative in relative_paths:
        path = root / relative
        result[relative] = {"size": path.stat().st_size, "sha256": digest(path)}
    return result


def load_manifest() -> tuple[dict, dict, dict]:
    if not MANIFEST_PATH.is_file() or MANIFEST_PATH.is_symlink():
        raise RuntimeError("candidate manifest is missing or is a symlink")
    manifest = json.loads(MANIFEST_PATH.read_bytes())
    if manifest.get("schema_version") != "PORTABLE_BASELINE_CANDIDATE_V1":
        raise RuntimeError("unsupported candidate manifest")
    frozen = manifest.get("frozen_candidate_inputs")
    historical = manifest.get("historical_identity")
    support = manifest.get("new_support_inputs")
    if not isinstance(frozen, list) or not isinstance(historical, list) or not isinstance(support, list):
        raise RuntimeError("manifest input classifications are incomplete")
    rows = {}
    for row in frozen:
        relative = row.get("path")
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise RuntimeError("manifest path is not relative")
        if relative in rows or set(row) != {"path", "size", "sha256", "classification"}:
            raise RuntimeError(f"invalid or duplicate manifest row: {relative!r}")
        if not isinstance(row["size"], int) or row["size"] < 0 or not isinstance(row["sha256"], str):
            raise RuntimeError(f"invalid manifest identity: {relative!r}")
        rows[relative] = row
    if len(rows) != 39:
        raise RuntimeError(f"expected 39 frozen candidate inputs, found {len(rows)}")
    if set(historical) | set(support) != set(rows) or set(historical) & set(support):
        raise RuntimeError("historical and support classifications do not partition inputs")
    if len(historical) != 31 or len(support) != 8:
        raise RuntimeError("unexpected historical/support input counts")
    return manifest, rows, {"historical": historical, "support": support}


def verify_candidate_inputs(rows: dict) -> None:
    observed = inventory(BASE, tuple(sorted(rows)))
    expected = {path: {key: rows[path][key] for key in ("size", "sha256")} for path in rows}
    if observed != expected:
        raise RuntimeError("candidate frozen input bytes do not match manifest")


def copy_inputs(root: Path, rows: dict) -> None:
    for relative in sorted(rows):
        source = BASE / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    actual = inventory(root, tuple(sorted(rows)))
    expected = {path: {key: rows[path][key] for key in ("size", "sha256")} for path in rows}
    if actual != expected:
        raise RuntimeError("staged input bytes do not match candidate manifest")


def write_bootstrap(root: Path, rows: dict) -> None:
    payload = {
        "app_session_bootstrap": "PASS",
        "canonical_project_root": str(root),
        "classification": "NEW_TEST_FIXTURE",
        "historical_authority": False,
        "bootstrap_checks": [{
            "check": "exact_candidate_input_hashes_and_fresh_physical_root",
            "result": "PASS",
            "classification": "NEW_TEST_FIXTURE",
            "scope": "Only local path, regular-file, and SHA-256 checks; no app, human, historical, provider, or scientific authority.",
            "input_count": len(rows),
        }],
    }
    target = root / BOOTSTRAP_RELATIVE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def expected_test_ids(rows: dict) -> tuple[str, ...]:
    """Derive unittest IDs without importing or executing any candidate test."""
    identifiers = []
    for relative in sorted(path for path in rows if path.startswith("tests/")):
        module = f"_scientist_one_tests.{Path(relative).stem}"
        tree = ast.parse((BASE / relative).read_text(encoding="utf-8"), filename=relative)
        for class_node in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            for method in (node for node in class_node.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
                if method.name.startswith("test"):
                    identifiers.append(f"{module}.{class_node.name}.{method.name}")
    result = tuple(sorted(identifiers))
    if len(result) != 146 or len(set(result)) != len(result):
        raise RuntimeError("pinned test modules do not statically derive unique 146 unittest IDs")
    return result


def output_test_ids(output: str) -> tuple[str, ...]:
    pattern = re.compile(r"^(test[^\s(]+) \(([^()]+)\) \.\.\. (?:ok|FAIL|ERROR|skipped .*)$", re.MULTILINE)
    # Captured unittest output can include the method in the parenthesized owner.
    return tuple(sorted(owner if owner.endswith("." + method) else f"{owner}.{method}"
                        for method, owner in pattern.findall(output)))


def reject_symlink_components(path: Path) -> None:
    current = path
    while True:
        if current.is_symlink():
            raise RuntimeError(f"refusing symlink output path component: {current}")
        if current == current.parent:
            return
        current = current.parent


def run(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    manifest, rows, classifications = load_manifest()
    verify_candidate_inputs(rows)
    requested_output = args.output_dir.expanduser()
    output = Path(os.path.abspath(os.fspath(requested_output)))
    reject_symlink_components(output)
    if output.exists() or output.is_symlink():
        raise RuntimeError("--output-dir target already exists; refusing to overwrite it")
    if not output.parent.is_dir():
        raise RuntimeError("--output-dir parent must be an existing directory")
    output.mkdir(mode=0o700)
    expected_ids = expected_test_ids(rows)
    parent = Path(tempfile.mkdtemp(prefix="baseline-public-candidate-", dir=output))
    root = parent / "ScientistOne"
    root.mkdir()
    if root.name != "ScientistOne" or root.is_symlink():
        raise RuntimeError("fresh physical project root identity failed")
    for name in REQUIRED_DIRS:
        (root / name).mkdir()
    copy_inputs(root, rows)
    write_bootstrap(root, rows)

    report = {
        "schema_version": "PORTABLE_BASELINE_CANDIDATE_RESULT_V1",
        "classification": "NEW_REGRESSION_TEST_AGAINST_RECOVERED_BASELINE",
        "fixture": "NEW_TEST_FIXTURE",
        "scientific_evidence": False,
        "historical_authority": False,
        "python": platform.python_version(),
        "root": str(root),
        "candidate_manifest_sha256": digest(MANIFEST_PATH),
        "runner_sha256": digest(Path(__file__)),
        "frozen_input_count": len(rows),
        "historical_identity_count": len(classifications["historical"]),
        "new_support_input_count": len(classifications["support"]),
        "commands": [],
        "status": "RUNNING",
    }
    command = [sys.executable, "-I", "-S", "-B", "scripts/scientist_one_cli.py", *COMMAND]
    try:
        started = time.monotonic()
        try:
            completed = subprocess.run(command, cwd=root, capture_output=True, check=False, timeout=300)
            stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            returncode = None
            if isinstance(stdout, str):
                stdout = stdout.encode()
            if isinstance(stderr, str):
                stderr = stderr.encode()
            (parent / "01-test-suite.stdout").write_bytes(stdout)
            (parent / "01-test-suite.stderr").write_bytes(stderr)
            report["commands"].append({
                "arguments": command,
                "returncode": returncode,
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "timeout_seconds": 300,
            })
            raise RuntimeError("captured test-suite exceeded the 300-second bound") from exc
        finally:
            elapsed = time.monotonic() - started
        (parent / "01-test-suite.stdout").write_bytes(stdout)
        (parent / "01-test-suite.stderr").write_bytes(stderr)
        report["commands"].append({
            "arguments": command,
            "returncode": returncode,
            "elapsed_seconds": round(elapsed, 6),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        })
        machine_path = root / "reports/test_results.json"
        if returncode != 0 or not machine_path.is_file():
            raise RuntimeError("captured test-suite did not produce a successful machine report")
        machine = json.loads(machine_path.read_bytes())
        report["machine_report_sha256"] = digest(machine_path)
        report["tests_run"] = machine.get("tests_run")
        report["suite_successful"] = machine.get("successful")
        report["expected_test_ids_sha256"] = hashlib.sha256("\n".join(expected_ids).encode()).hexdigest()
        observed_ids = output_test_ids(machine.get("output", ""))
        report["observed_test_ids_sha256"] = hashlib.sha256("\n".join(observed_ids).encode()).hexdigest()
        if observed_ids != expected_ids:
            raise RuntimeError("captured report output does not equal the statically derived unique unittest IDs")
        if machine.get("successful") is not True or machine.get("tests_run") != 146:
            raise RuntimeError("unexpected captured suite outcome; expected successful 146-test scoped suite")
        if machine.get("python") != platform.python_version():
            raise RuntimeError("captured report Python version differs from the executing runtime")
        if machine.get("executable") != Path(sys.executable).name:
            raise RuntimeError("captured report executable differs from the executing runtime")
        if any(machine.get(name) != 0 for name in ("failures", "errors", "skipped", "expected_failures", "unexpected_successes")):
            raise RuntimeError("captured suite contains failures, errors, skips, or unexpected outcomes")
        expected_source = {path: rows[path] for path in rows if path.startswith("src/") or path == "scripts/scientist_one_cli.py"}
        expected_tests = {path: rows[path] for path in rows if path.startswith("tests/")}
        for key, expected in (("project_source_attestation", expected_source), ("test_source_attestation", expected_tests)):
            entries = machine.get(key, {}).get("entries", [])
            if not isinstance(entries, list) or len(entries) != len(expected):
                raise RuntimeError(f"{key} has an unexpected entry count")
            observed = {
                row["path"]: {"size": row["size"], "sha256": row["sha256"]}
                for row in entries
            }
            if len(observed) != len(entries):
                raise RuntimeError(f"{key} contains duplicate paths")
            wanted = {path: {"size": row["size"], "sha256": row["sha256"]} for path, row in expected.items()}
            if observed != wanted:
                raise RuntimeError(f"{key} does not attest exactly to candidate inputs")
        verify_candidate_inputs(rows)
        staged = inventory(root, tuple(sorted(rows)))
        expected_staged = {path: {"size": row["size"], "sha256": row["sha256"]} for path, row in rows.items()}
        if staged != expected_staged:
            raise RuntimeError("staged candidate input bytes changed during captured execution")
        if digest(MANIFEST_PATH) != report["candidate_manifest_sha256"]:
            raise RuntimeError("candidate manifest changed during captured execution")
        if digest(Path(__file__)) != report["runner_sha256"]:
            raise RuntimeError("candidate runner changed during captured execution")
        report["status"] = "PASS_SCOPED_LOCAL_PORTABLE_BASELINE"
    except Exception as exc:
        report["status"] = "FAILED"
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)
    result_path = parent / "result.json"
    result_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "result": str(result_path), "root": str(root)}))
    return 0 if report["status"] == "PASS_SCOPED_LOCAL_PORTABLE_BASELINE" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(run(sys.argv[1:]))
    except Exception as exc:
        print(f"portable candidate staging failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
