"""Standalone stdlib-only descriptive CUDA timing evaluator, not authority.

CLI: python3 -B cuda-device-timing-evaluator.py protocol.json raw.json
Both files are bounded closed JSON. Seeds are repeat labels over one input,
not independent statistical observations. No significance or speedup is
computed. This file is also normally imported by cuda_device_timing; there
is one validation engine, with no dynamic execution of retained source text.
"""

from __future__ import annotations

import json
import math
import re
import sys


PROTOCOL_SCHEMA = "cuda-device-timing-protocol/v1"
PROFILE_ID = "cuda-u32-vector-add-events/v1"
OUTPUT_SCHEMA = "cuda-device-timing-output/v1"
EVALUATION_SCHEMA = "cuda-device-timing-evaluation/v1"
METRIC_UNIT = "MILLISECONDS"
METRIC_DIRECTION = "LOWER_IS_BETTER"
METRIC_SCOPE = "INTERMEDIATE"
METRIC_AGGREGATION = "PER_SEED_MEDIAN_ODD_MEASUREMENT_REPETITIONS"
METRIC_DEFINITION = (
    "CUDA device-event elapsed milliseconds for one uint32 vector-addition kernel "
    "on device ordinal 0 and stream 0; excludes input/output transfers, output "
    "poisoning, correctness checking and application latency. Every output of "
    "every warmup and measurement launch is checked exactly. All nonnegative "
    "samples, including zero-resolution values, are retained; report only the "
    "per-seed median of the frozen odd measurement repetitions. Seeds label "
    "repeats over the same fixed input, not independent observations."
)
MAX_ELEMENTS = 65_536
MAX_SEEDS = 24
MAX_SEED = 2**31 - 1
MAX_SAMPLES = 2 * MAX_SEEDS * (16 + 51)
MAX_ELEMENT_ADDITIONS = MAX_ELEMENTS * MAX_SAMPLES
MAX_JSON_BYTES = 1_048_576
MAX_JSON_ITEMS = 50_000
BLOCK_SIZES = (32, 64, 128, 256)
PROTOCOL_KEYS = frozenset({
    "schema_version", "profile_id", "metric_id", "baseline_id", "seeds",
    "element_count", "candidate_block_size", "baseline_block_size",
    "warmup_iterations", "repetitions",
})


class TimingValueError(ValueError):
    """A closed descriptive input is malformed; never a scientific verdict."""


def _integer(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        raise TimingValueError(f"{label} requires an exact integer in {low}..{high}")
    return value


def _text(value, label, expected=None):
    if type(value) is not str:
        raise TimingValueError(f"{label} requires exact native text")
    if expected is not None and value != expected:
        raise TimingValueError(f"{label} differs from the closed protocol")
    return value


def _object(value, keys, label):
    if type(value) is not dict or len(value) != len(keys):
        raise TimingValueError(f"{label} requires its exact native object")
    if any(type(key) is not str for key in value) or set(value) != keys:
        raise TimingValueError(f"{label} has unknown or missing fields")
    return value


def validate_protocol(value):
    """Return a detached native protocol; input shape is not prospectivity."""
    _object(value, PROTOCOL_KEYS, "protocol")
    _text(value["schema_version"], "schema_version", PROTOCOL_SCHEMA)
    _text(value["profile_id"], "profile_id", PROFILE_ID)
    for key in ("metric_id", "baseline_id"):
        text = _text(value[key], key)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", text) is None:
            raise TimingValueError(f"{key} is not a bounded identifier")
    seeds = value["seeds"]
    if type(seeds) is not list or not 1 <= len(seeds) <= MAX_SEEDS:
        raise TimingValueError("seeds require a complete bounded native list")
    for seed in seeds:
        _integer(seed, "seed", 0, MAX_SEED)
    if len(set(seeds)) != len(seeds):
        raise TimingValueError("seeds must be unique")
    _integer(value["element_count"], "element_count", 1, MAX_ELEMENTS)
    for key in ("candidate_block_size", "baseline_block_size"):
        _integer(value[key], key, 32, 256)
        if value[key] not in BLOCK_SIZES:
            raise TimingValueError("block size is not supported")
    if value["candidate_block_size"] == value["baseline_block_size"]:
        raise TimingValueError("candidate and baseline block sizes must differ")
    _integer(value["warmup_iterations"], "warmup_iterations", 1, 16)
    _integer(value["repetitions"], "repetitions", 3, 51)
    if value["repetitions"] % 2 != 1:
        raise TimingValueError("measurement repetitions must be odd")
    count = 2 * len(seeds) * (value["warmup_iterations"] + value["repetitions"])
    if count > MAX_SAMPLES or count * value["element_count"] > MAX_ELEMENT_ADDITIONS:
        raise TimingValueError("complete launch or element-work bound exceeded")
    return {key: list(seeds) if key == "seeds" else value[key] for key in value}


def expected_schedule(protocol):
    """Frozen seed-index/phase-local-iteration alternation, not seed-value parity."""
    protocol = validate_protocol(protocol)
    return tuple(
        (seed, phase, condition, repetition)
        for seed_index, seed in enumerate(protocol["seeds"])
        for phase, count in (("WARMUP", protocol["warmup_iterations"]),
                             ("MEASUREMENT", protocol["repetitions"]))
        for repetition in range(count)
        for condition in (("CANDIDATE", "BASELINE") if (seed_index + repetition) % 2 == 0
                          else ("BASELINE", "CANDIDATE"))
    )


def evaluate(protocol, raw):
    """Validate complete schedule and return detached descriptive native data."""
    protocol = validate_protocol(protocol)
    _object(raw, {"schema_version", "protocol", "metric_scope", "unit", "device", "samples"}, "raw output")
    _text(raw["schema_version"], "raw schema", OUTPUT_SCHEMA)
    observed_protocol = validate_protocol(raw["protocol"])
    if observed_protocol != protocol:
        raise TimingValueError("raw output binds another frozen protocol")
    _text(raw["metric_scope"], "metric_scope", METRIC_SCOPE)
    _text(raw["unit"], "unit", METRIC_UNIT)
    device = _object(raw["device"], {"ordinal", "name", "compute_capability_major",
                                   "compute_capability_minor", "runtime_version", "driver_version"}, "device")
    _integer(device["ordinal"], "device ordinal", 0, 0)
    name = _text(device["name"], "device name")
    if not name or len(name) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise TimingValueError("device name must be bounded nonempty display text")
    try:
        name.encode("utf-8")
    except UnicodeError as exc:
        raise TimingValueError("device name is not valid UTF-8 display text") from exc
    for key in ("compute_capability_major", "runtime_version", "driver_version"):
        _integer(device[key], key, 1, MAX_SEED)
    _integer(device["compute_capability_minor"], "compute_capability_minor", 0, MAX_SEED)
    samples = raw["samples"]
    schedule = expected_schedule(protocol)
    if type(samples) is not list or len(samples) != len(schedule):
        raise TimingValueError("raw output lacks the exact complete launch schedule")
    retained = []
    measured = {(seed, condition): [] for seed in protocol["seeds"] for condition in ("CANDIDATE", "BASELINE")}
    for sample, expected in zip(samples, schedule):
        _object(sample, {"seed", "phase", "condition", "repetition", "elapsed_ms"}, "sample")
        _integer(sample["seed"], "sample seed", 0, MAX_SEED)
        _integer(sample["repetition"], "sample repetition", 0, 50)
        _text(sample["phase"], "phase")
        _text(sample["condition"], "condition")
        identity = (sample["seed"], sample["phase"], sample["condition"], sample["repetition"])
        if identity != expected:
            raise TimingValueError("sample order or seed/phase/condition/repetition was substituted")
        elapsed = sample["elapsed_ms"]
        if type(elapsed) not in (int, float):
            raise TimingValueError("elapsed_ms requires a native finite nonnegative number")
        try:
            elapsed = float(elapsed)
        except (OverflowError, ValueError) as exc:
            raise TimingValueError("elapsed_ms is outside finite numeric capacity") from exc
        if not math.isfinite(elapsed) or elapsed < 0:
            raise TimingValueError("elapsed_ms requires a native finite nonnegative number")
        retained.append({**sample, "elapsed_ms": elapsed})
        if sample["phase"] == "MEASUREMENT":
            measured[(sample["seed"], sample["condition"])].append(elapsed)
    midpoint = protocol["repetitions"] // 2
    per_seed = [{"seed": seed,
                 "candidate_median_ms": sorted(measured[(seed, "CANDIDATE")])[midpoint],
                 "baseline_median_ms": sorted(measured[(seed, "BASELINE")])[midpoint]}
                for seed in protocol["seeds"]]
    return {"schema_version": EVALUATION_SCHEMA, "protocol": protocol,
            "metric_scope": METRIC_SCOPE, "unit": METRIC_UNIT,
            "aggregation": METRIC_AGGREGATION, "device": dict(device),
            "samples": retained, "per_seed": per_seed}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TimingValueError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(value):
    raise TimingValueError(f"nonfinite JSON constant {value}")


def parse_json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_JSON_BYTES:
        raise TimingValueError("JSON bytes exceed the closed input bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=_bad_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise TimingValueError("invalid bounded JSON") from exc
    count = 0
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_JSON_ITEMS or depth > 8:
            raise TimingValueError("JSON item or depth capacity exceeded")
        if type(item) is dict:
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is float and not math.isfinite(item):
            raise TimingValueError("nonfinite JSON number")
    return value


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if len(argv) != 2:
            raise TimingValueError("expected protocol.json and raw.json paths")
        values = []
        for path in argv:
            with open(path, "rb") as stream:
                values.append(parse_json(stream.read(MAX_JSON_BYTES + 1)))
        result = evaluate(values[0], values[1])
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
        if len(encoded) > MAX_JSON_BYTES:
            raise TimingValueError("descriptive evaluator output exceeds byte capacity")
        sys.stdout.buffer.write(encoded)
        return 0
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(f"CUDA timing evaluation refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
