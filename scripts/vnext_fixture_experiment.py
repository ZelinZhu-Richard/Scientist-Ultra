#!/usr/bin/env python3
"""Execute the deterministic vNext system fixture as an isolated child.

This program intentionally has no Scientist-One package import.  It consumes
the frozen run specification and a hash-bound synthetic dataset, writes one
result for every declared seed, and materializes every required ablation.  The
controller independently validates every byte before it can become evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _required_fd(name: str) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.isascii() or not raw.isdigit():
        raise RuntimeError(f"required descriptor {name} is absent")
    descriptor = int(raw)
    if descriptor < 3:
        raise RuntimeError(f"required descriptor {name} is invalid")
    return descriptor


def _read_held(descriptor: int, *, maximum_bytes: int) -> bytes:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > maximum_bytes
    ):
        raise RuntimeError("held input is not a bounded private regular file")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, before.st_size - offset),
            offset,
        )
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    payload = b"".join(chunks)
    after = os.fstat(descriptor)
    def stable(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
    if len(payload) != before.st_size or stable(after) != stable(before):
        raise RuntimeError("held input changed while it was read")
    return payload


def _read_named(directory_fd: int, name: str, *, maximum_bytes: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("no-follow input access is unavailable")
    descriptor = os.open(name, os.O_RDONLY | nofollow, dir_fd=directory_fd)
    try:
        return _read_held(descriptor, maximum_bytes=maximum_bytes)
    finally:
        os.close(descriptor)


def _write_new(directory_fd: int, name: str, payload: bytes) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("no-follow output creation is unavailable")
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError("created output is not a private regular file")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def main() -> int:
    expected_spec_hash = os.environ.get("SCIENTIST_ONE_SPEC_SHA256")
    expected_run_id = os.environ.get("SCIENTIST_ONE_RUN_ID")
    if not all((expected_spec_hash, expected_run_id)):
        raise RuntimeError("required Scientist-One execution boundary is absent")
    job_dir_fd = _required_fd("SCIENTIST_ONE_JOB_DIR_FD")
    if not stat.S_ISDIR(os.fstat(job_dir_fd).st_mode):
        raise RuntimeError("trusted job descriptor is not a directory")
    code_bytes = _read_held(
        _required_fd("SCIENTIST_ONE_INPUT_CODE_FD"),
        maximum_bytes=8 * 1024 * 1024,
    )
    configuration_bytes = _read_held(
        _required_fd("SCIENTIST_ONE_INPUT_CONFIGURATION_FD"),
        maximum_bytes=8 * 1024 * 1024,
    )
    dataset_bytes = _read_held(
        _required_fd("SCIENTIST_ONE_INPUT_DATA_FD"),
        maximum_bytes=8 * 1024 * 1024,
    )
    evaluator_bytes = _read_held(
        _required_fd("SCIENTIST_ONE_INPUT_EVALUATOR_FD"),
        maximum_bytes=8 * 1024 * 1024,
    )
    spec_bytes = _read_named(
        job_dir_fd,
        "frozen-run-spec.json",
        maximum_bytes=512 * 1024,
    )
    spec_value = json.loads(spec_bytes.decode("utf-8"))
    if not isinstance(spec_value, dict):
        raise ValueError("frozen run specification must be an object")
    if hashlib.sha256(_canonical(spec_value)).hexdigest() != expected_spec_hash:
        raise ValueError("frozen run specification hash mismatch")
    if spec_value.get("run_id") != expected_run_id:
        raise ValueError("run identity mismatch")
    if spec_bytes != _canonical(spec_value) + b"\n":
        raise ValueError("frozen run specification is not canonical")

    if hashlib.sha256(code_bytes).hexdigest() != spec_value.get("code_sha256"):
        raise ValueError("code identity differs from the frozen run")
    if (
        hashlib.sha256(configuration_bytes).hexdigest()
        != spec_value.get("configuration_sha256")
    ):
        raise ValueError("configuration identity differs from the frozen run")
    if hashlib.sha256(dataset_bytes).hexdigest() != spec_value.get("data_sha256"):
        raise ValueError("dataset identity differs from the frozen run")
    if hashlib.sha256(evaluator_bytes).hexdigest() != spec_value.get("evaluator_sha256"):
        raise ValueError("evaluator identity differs from the frozen run")
    configuration = json.loads(configuration_bytes.decode("utf-8"))
    dataset_value = json.loads(dataset_bytes.decode("utf-8"))
    evaluator = json.loads(evaluator_bytes.decode("utf-8"))
    if not isinstance(configuration, dict):
        raise ValueError("frozen configuration must be an object")
    threshold = configuration.get("candidate_threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("candidate_threshold must be numeric")
    threshold = float(threshold)
    evaluation_split = configuration.get("evaluation_split")
    if not isinstance(evaluation_split, str) or not evaluation_split:
        raise ValueError("evaluation_split must be non-empty text")

    if evaluator != {
        "aggregation": "arithmetic mean over all declared seeds",
        "definition": "correct development subjects divided by all development subjects",
        "fixture_notice": (
            "Synthetic integration fixture only; no publishable scientific conclusion."
        ),
        "metric_id": "subject-accuracy",
        "unit": "fraction",
        "version": "accuracy-evaluator-v1",
    }:
        raise ValueError("frozen evaluator schema is invalid")
    if not isinstance(dataset_value, dict) or not isinstance(dataset_value.get("rows"), list):
        raise ValueError("fixture dataset schema is invalid")
    rows = dataset_value["rows"]
    if not rows:
        raise ValueError("fixture dataset is empty")

    baseline_correctness: list[int] = []
    candidate_correctness: list[int] = []
    selected_rows = [row for row in rows if isinstance(row, dict) and row.get("split") == evaluation_split]
    if not selected_rows:
        raise ValueError("frozen evaluation split is empty")
    for row in selected_rows:
        if not isinstance(row, dict):
            raise ValueError("fixture row must be an object")
        label = row.get("label")
        signal = row.get("signal")
        if label not in {0, 1} or isinstance(signal, bool) or not isinstance(signal, (int, float)):
            raise ValueError("fixture row fields are invalid")
        baseline_correctness.append(int(label == 0))
        candidate_correctness.append(int((float(signal) >= threshold) == bool(label)))

    baseline_accuracy = sum(baseline_correctness) / len(baseline_correctness)
    candidate_accuracy = sum(candidate_correctness) / len(candidate_correctness)
    artifacts: list[dict[str, object]] = []
    seed_results: list[dict[str, object]] = []
    seeds = spec_value.get("seeds")
    if not isinstance(seeds, list) or not seeds:
        raise ValueError("frozen seed set is absent")
    for seed in seeds:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("frozen seed is invalid")
        result = {
            "baseline_accuracy": baseline_accuracy,
            "baseline_correctness": baseline_correctness,
            "candidate_accuracy": candidate_accuracy,
            "candidate_correctness": candidate_correctness,
            "dataset_sha256": spec_value["data_sha256"],
            "fixture_notice": "Synthetic system fixture; not a scientific result.",
            "run_id": expected_run_id,
            "seed": seed,
            "spec_sha256": expected_spec_hash,
        }
        payload = _canonical(result) + b"\n"
        relative = f"seed-{seed}.json"
        _write_new(job_dir_fd, relative, payload)
        digest = hashlib.sha256(payload).hexdigest()
        artifacts.append(
            {
                "logical_type": "seed_result",
                "path": relative,
                "sha256": digest,
                "size": len(payload),
            }
        )
        seed_results.append(
            {
                "artifact_sha256": digest,
                "metric": candidate_accuracy,
                "reason": None,
                "seed": seed,
                "status": "SUCCESS",
            }
        )

    ablations: list[dict[str, object]] = []
    required_ablations = spec_value.get("required_ablations")
    if not isinstance(required_ablations, list):
        raise ValueError("required ablation set is invalid")
    for ablation_id in required_ablations:
        if not isinstance(ablation_id, str) or not ablation_id:
            raise ValueError("required ablation identity is invalid")
        ablation = {
            "ablation_id": ablation_id,
            "accuracy": baseline_accuracy,
            "ablated_correctness": baseline_correctness,
            "dataset_sha256": spec_value["data_sha256"],
            "evaluator_sha256": spec_value["evaluator_sha256"],
            "fixture_notice": "Synthetic removal-control output.",
            "intervention": "replace candidate with frozen constant-zero baseline",
            "run_id": expected_run_id,
            "spec_sha256": expected_spec_hash,
        }
        payload = _canonical(ablation) + b"\n"
        relative = f"ablation-{ablation_id}.json"
        _write_new(job_dir_fd, relative, payload)
        digest = hashlib.sha256(payload).hexdigest()
        artifacts.append(
            {
                "logical_type": "ablation_result",
                "path": relative,
                "sha256": digest,
                "size": len(payload),
            }
        )
        ablations.append(
            {
                "ablation_id": ablation_id,
                "artifact_sha256": digest,
                "status": "PASS",
            }
        )

    manifest = {
        "ablations": ablations,
        "artifacts": artifacts,
        "code_sha256": spec_value["code_sha256"],
        "configuration_sha256": spec_value["configuration_sha256"],
        "data_sha256": spec_value["data_sha256"],
        "evaluator_sha256": spec_value["evaluator_sha256"],
        "planned_seeds": seeds,
        "run_id": expected_run_id,
        "schema_version": "SCIENTIST_ONE_OUTPUT_MANIFEST_V1",
        "seed_results": seed_results,
        "spec_sha256": expected_spec_hash,
    }
    _write_new(
        job_dir_fd,
        "output-manifest.json",
        _canonical(manifest) + b"\n",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"fixture experiment failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)
