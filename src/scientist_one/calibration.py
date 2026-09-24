"""Deterministic scientific-validity calibration and synthetic benchmarks.

Calibration fixtures are deliberately inert JSON.  In particular, text stored in a
research artifact is never interpreted as policy, code, a command, or a tool call.
The module uses only the Python standard library and has no network-facing code.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import itertools
import json
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence

from .errors import PathSecurityError, UnsafeSerializationError
from .security import read_confined_bytes, safe_json_loads


SCHEMA_VERSION = "1.0"
DEFAULT_CALIBRATION_SEED = 20260812
MAX_FIXTURE_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
MAX_OBSERVATIONS = 4096
MAX_COLLECTION_ITEMS = 4096
MAX_REGIMES = 32
MAX_SPLIT_ROLES = 64
MAX_SPLIT_IDS_PER_ROLE = 4096
MAX_SPLIT_PAIR_COMPARISONS = 1024
MAX_SPLIT_INTERSECTION_WORK_UNITS = 40_000
MAX_PERMUTATION_ITERATIONS = 16_384
MAX_PERMUTATION_WORK_UNITS = 20_000_000
MAX_REGIME_PERMUTATION_WORK_UNITS = 20_000_000
CALIBRATION_EVALUATOR_VERSION = "scientist_one.calibration:v3"
CALIBRATION_FIXTURE_SHA256 = "c5697cc4207bfc3c2c93287274fe0c87cfed43f74ed5f4dffe60d8c7730ef543"
WORKFLOW_FIXTURE_SHA256 = "3bef85d9e02ca5a532ecedb0bbabd7b537aeb60509f318d485d170e4e927153d"
FROZEN_CALIBRATION_REPORT_SHA256 = "34428db4cef7e70c0531ae546f424af7d7bf8ba1f1654632287482bbfed41441"
FROZEN_WORKFLOW_REPORT_SHA256 = "ffdfb300cbebbe04c8e0885a50b7b1d931afba4149d3c5f002e6d82d054ccfa7"

MANDATORY_CASE_KINDS = (
    "planted_positive",
    "true_null",
    "leakage_trap",
    "regime_reversal_shift",
    "invalid_resampling_unit",
    "multiple_comparisons",
    "baseline_implementation_mismatch",
    "corrupted_provenance",
    "unsupported_claim",
    "holdout_access_violation",
    "prompt_injection_artifact",
    "domain_invalid_permutation",
)

SYNTHETIC_WORKFLOW_SCENARIOS = (
    "signal",
    "null",
    "reversal",
    "leakage",
    "invalid-analysis",
    "corrupted-evidence",
)

_EXPECTED_WORKFLOW_DECISIONS = {
    "signal": "POSITIVE_SIGNAL",
    "null": "NEGATIVE_RESULT",
    "reversal": "SIGN_REVERSAL",
    "leakage": "INVALID_LEAKAGE",
    "invalid-analysis": "INVALID_ANALYSIS",
    "corrupted-evidence": "CORRUPTED_EVIDENCE",
}

_EXPECTED_WORKFLOW_TERMINALS = {
    "signal": "DEMO_RESEARCH_PACKAGE",
    "null": "NEGATIVE_RESULT",
    "reversal": "INCONCLUSIVE",
    "leakage": "STOP_SCIENTIFIC_INVALIDITY",
    "invalid-analysis": "STOP_SCIENTIFIC_INVALIDITY",
    "corrupted-evidence": "STOP_SCIENTIFIC_INVALIDITY",
}


class CalibrationError(ValueError):
    """Raised when calibration input is unsafe, malformed, or incomplete."""


class CalibrationGateError(RuntimeError):
    """Raised when mandatory calibration has not passed."""


@dataclass(frozen=True)
class Finding:
    """A stable, machine-readable calibration finding."""

    code: str
    severity: str
    detail: str
    location: str = "payload"

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "detail": self.detail,
            "location": self.location,
        }


@dataclass(frozen=True)
class CalibrationCase:
    """One known-answer fixture used to calibrate the evaluator."""

    case_id: str
    kind: str
    mandatory: bool
    seed: int
    expected_decision: str
    expected_finding_codes: tuple[str, ...]
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _validate_json_shape(self.payload)
        object.__setattr__(self, "payload", _deep_freeze(_json_clone(self.payload)))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CalibrationCase":
        _validate_json_shape(raw)
        required = {
            "case_id",
            "kind",
            "mandatory",
            "seed",
            "expected_decision",
            "expected_finding_codes",
            "payload",
        }
        missing = sorted(required - set(raw))
        if missing:
            raise CalibrationError(f"calibration case missing fields: {missing}")
        case_id = raw["case_id"]
        kind = raw["kind"]
        decision = raw["expected_decision"]
        if not isinstance(case_id, str) or not case_id.strip():
            raise CalibrationError("case_id must be a non-empty string")
        if kind not in MANDATORY_CASE_KINDS:
            raise CalibrationError(f"unsupported calibration kind: {kind!r}")
        if not isinstance(raw["mandatory"], bool):
            raise CalibrationError(f"{case_id}: mandatory must be boolean")
        if isinstance(raw["seed"], bool) or not isinstance(raw["seed"], int):
            raise CalibrationError(f"{case_id}: seed must be an integer")
        if not isinstance(decision, str) or not decision:
            raise CalibrationError(f"{case_id}: expected_decision must be a string")
        codes = raw["expected_finding_codes"]
        if not isinstance(codes, list) or not all(
            isinstance(code, str) and code for code in codes
        ):
            raise CalibrationError(
                f"{case_id}: expected_finding_codes must be a string list"
            )
        payload = raw["payload"]
        if not isinstance(payload, dict):
            raise CalibrationError(f"{case_id}: payload must be an object")
        return cls(
            case_id=case_id,
            kind=kind,
            mandatory=raw["mandatory"],
            seed=raw["seed"],
            expected_decision=decision,
            expected_finding_codes=tuple(codes),
            payload=_json_clone(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "mandatory": self.mandatory,
            "seed": self.seed,
            "expected_decision": self.expected_decision,
            "expected_finding_codes": list(self.expected_finding_codes),
            "payload": _json_clone(self.payload),
        }


@dataclass(frozen=True)
class CalibrationResult:
    """Actual decision for a known-answer calibration case."""

    case_id: str
    kind: str
    mandatory: bool
    seed: int
    expected_decision: str
    expected_finding_codes: tuple[str, ...]
    decision: str
    passed: bool
    findings: tuple[Finding, ...]
    statistics: Mapping[str, Any]
    fixture_sha256: str

    def __post_init__(self) -> None:
        _validate_json_shape(self.statistics)
        object.__setattr__(self, "statistics", _deep_freeze(_json_clone(self.statistics)))

    @property
    def integrity_valid(self) -> bool:
        codes = {finding.code for finding in self.findings}
        expected_pass = self.decision == self.expected_decision and set(
            self.expected_finding_codes
        ).issubset(codes)
        expected_hash = isinstance(self.fixture_sha256, str) and len(self.fixture_sha256) == 64
        return self.passed == expected_pass and expected_hash and all(
            character in "0123456789abcdef" for character in self.fixture_sha256
        ) and bool(codes or not self.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "mandatory": self.mandatory,
            "seed": self.seed,
            "expected_decision": self.expected_decision,
            "expected_finding_codes": list(self.expected_finding_codes),
            "decision": self.decision,
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
            "statistics": _json_clone(self.statistics),
            "fixture_sha256": self.fixture_sha256,
        }


@dataclass(frozen=True)
class CalibrationReport:
    """Deterministic aggregate calibration report."""

    results: tuple[CalibrationResult, ...]
    report_sha256: str

    @property
    def integrity_valid(self) -> bool:
        expected = _calibration_report_sha256(self.results)
        return (
            self.report_sha256
            == expected
            == FROZEN_CALIBRATION_REPORT_SHA256
            and all(result.integrity_valid for result in self.results)
        )

    @property
    def passed(self) -> bool:
        return self.integrity_valid and all(result.passed for result in self.results)

    @property
    def mandatory_passed(self) -> bool:
        mandatory = [result for result in self.results if result.mandatory]
        return self.integrity_valid and bool(mandatory) and all(result.passed for result in mandatory)

    @property
    def failed_case_ids(self) -> tuple[str, ...]:
        return tuple(result.case_id for result in self.results if not result.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "report_type": "scientist_one.calibration_report",
            "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
            "passed": self.passed,
            "mandatory_passed": self.mandatory_passed,
            "summary": {
                "total": len(self.results),
                "passed": sum(result.passed for result in self.results),
                "failed": sum(not result.passed for result in self.results),
                "mandatory": sum(result.mandatory for result in self.results),
            },
            "failed_case_ids": list(self.failed_case_ids),
            "results": [result.to_dict() for result in self.results],
            "report_sha256": self.report_sha256,
        }


@dataclass(frozen=True)
class SyntheticWorkflowTask:
    """A deterministic task for exercising a scientific workflow."""

    task_id: str
    scenario: str
    seed: int
    expected_decision: str
    expected_terminal_state: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _validate_json_shape(self.payload)
        object.__setattr__(self, "payload", _deep_freeze(_json_clone(self.payload)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "scenario": self.scenario,
            "seed": self.seed,
            "expected_decision": self.expected_decision,
            "expected_terminal_state": self.expected_terminal_state,
            "payload": _json_clone(self.payload),
        }


@dataclass(frozen=True)
class WorkflowTaskResult:
    task_id: str
    scenario: str
    expected_decision: str
    expected_terminal_state: str
    decision: str
    terminal_state: str
    passed: bool
    findings: tuple[Finding, ...]
    statistics: Mapping[str, Any]

    def __post_init__(self) -> None:
        _validate_json_shape(self.statistics)
        object.__setattr__(self, "statistics", _deep_freeze(_json_clone(self.statistics)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "scenario": self.scenario,
            "expected_decision": self.expected_decision,
            "expected_terminal_state": self.expected_terminal_state,
            "decision": self.decision,
            "terminal_state": self.terminal_state,
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
            "statistics": _json_clone(self.statistics),
        }


@dataclass(frozen=True)
class WorkflowBenchmarkReport:
    seed: int
    results: tuple[WorkflowTaskResult, ...]
    report_sha256: str

    @property
    def integrity_valid(self) -> bool:
        expected = _workflow_report_sha256(self.seed, self.results)
        return self.report_sha256 == expected == FROZEN_WORKFLOW_REPORT_SHA256

    @property
    def passed(self) -> bool:
        return self.integrity_valid and bool(self.results) and all(result.passed for result in self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "report_type": "scientist_one.synthetic_workflow_benchmark",
            "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
            "seed": self.seed,
            "passed": self.passed,
            "summary": {
                "total": len(self.results),
                "passed": sum(result.passed for result in self.results),
                "failed": sum(not result.passed for result in self.results),
            },
            "results": [result.to_dict() for result in self.results],
            "report_sha256": self.report_sha256,
        }


@dataclass(frozen=True)
class _DetectorOutcome:
    decision: str
    findings: tuple[Finding, ...]
    statistics: Mapping[str, Any]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _fixture_directory() -> Path:
    return _project_root() / "fixtures" / "calibration"


def _canonical_json_bytes(value: Any) -> bytes:
    _validate_json_shape(value)
    try:
        encoded = json.dumps(
            _deep_thaw(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CalibrationError(f"value is not canonical JSON: {exc}") from exc
    return encoded.encode("utf-8")


def canonical_json_sha256(value: Any) -> str:
    """Return a stable SHA-256 digest for a JSON-compatible value."""

    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _calibration_report_sha256(results: Sequence[CalibrationResult]) -> str:
    """Bind a report digest to the evaluator and exact frozen fixture bytes."""

    return canonical_json_sha256(
        {
            "schema_version": SCHEMA_VERSION,
            "report_type": "scientist_one.calibration_report",
            "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
            "fixture_file_sha256": CALIBRATION_FIXTURE_SHA256,
            "results": [result.to_dict() for result in results],
        }
    )


def _workflow_report_sha256(
    seed: int, results: Sequence[WorkflowTaskResult]
) -> str:
    """Bind a benchmark digest to its seed, evaluator, and frozen manifest."""

    return canonical_json_sha256(
        {
            "schema_version": SCHEMA_VERSION,
            "report_type": "scientist_one.synthetic_workflow_benchmark",
            "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
            "fixture_file_sha256": WORKFLOW_FIXTURE_SHA256,
            "seed": seed,
            "results": [result.to_dict() for result in results],
        }
    )


def _json_clone(value: Any) -> Any:
    return json.loads(_canonical_json_bytes(_deep_thaw(value)).decode("utf-8"))


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _deep_freeze(child) for key, child in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_deep_freeze(child) for child in value)
    return value


def _deep_thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _deep_thaw(child) for key, child in value.items()}
    if isinstance(value, tuple | list):
        return [_deep_thaw(child) for child in value]
    return value


def _validate_json_shape(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise CalibrationError(f"fixture exceeds {MAX_JSON_NODES} JSON nodes")
        if depth > MAX_JSON_DEPTH:
            raise CalibrationError(f"fixture exceeds JSON depth {MAX_JSON_DEPTH}")
        if isinstance(current, Mapping):
            if len(current) > MAX_JSON_NODES:
                raise CalibrationError(f"JSON mapping exceeds {MAX_JSON_NODES} entries")
            if not all(isinstance(key, str) for key in current):
                raise CalibrationError("JSON mapping keys must be strings")
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            if len(current) > MAX_JSON_NODES:
                raise CalibrationError(f"JSON sequence exceeds {MAX_JSON_NODES} entries")
            stack.extend((child, depth + 1) for child in current)
        elif current is not None and not isinstance(current, (str, bool, int, float)):
            raise CalibrationError(f"unsupported JSON value type: {type(current).__name__}")


def _safe_json_document(path: Path, *, expected_file_sha256: str) -> Mapping[str, Any]:
    root = _project_root().resolve(strict=True)
    if any(part == ".." for part in path.parts):
        raise CalibrationError(f"fixture traversal rejected: {path}")
    lexical = path if path.is_absolute() else Path.cwd() / path
    try:
        relative = lexical.relative_to(root)
    except ValueError as exc:
        raise CalibrationError(f"fixture must be lexically inside project root: {path}") from exc
    display_path = root / relative
    try:
        raw_bytes = read_confined_bytes(
            root,
            relative,
            reject_hardlinks=True,
            max_bytes=MAX_FIXTURE_BYTES,
        )
    except PathSecurityError as exc:
        if "hard-linked" in str(exc):
            raise CalibrationError(f"fixture hard-link count rejected: {display_path}") from exc
        if "exceeds size limit" in str(exc):
            raise CalibrationError(
                f"fixture exceeds {MAX_FIXTURE_BYTES} bytes: {display_path}"
            ) from exc
        raise CalibrationError(f"cannot safely load fixture {display_path}: {exc}") from exc
    if raw_bytes is None:  # missing_ok is false; retained as a defensive invariant.
        raise CalibrationError(f"cannot safely load fixture {display_path}: fixture is absent")
    if hashlib.sha256(raw_bytes).hexdigest() != expected_file_sha256:
        raise CalibrationError(f"frozen fixture file hash mismatch: {display_path.name}")
    try:
        document = safe_json_loads(
            raw_bytes,
            max_bytes=MAX_FIXTURE_BYTES,
            max_depth=MAX_JSON_DEPTH,
            max_items=MAX_JSON_NODES,
        )
    except UnsafeSerializationError as exc:
        if "duplicate JSON object key" in str(exc):
            raise CalibrationError("duplicate JSON key rejected") from exc
        if "non-finite JSON number" in str(exc):
            raise CalibrationError("non-finite JSON number rejected") from exc
        raise CalibrationError(f"cannot safely load fixture {display_path}: {exc}") from exc
    if not isinstance(document, dict):
        raise CalibrationError(f"fixture root must be an object: {display_path}")
    _validate_json_shape(document)
    return document


def load_calibration_cases(fixture_dir: str | Path | None = None) -> tuple[CalibrationCase, ...]:
    """Load and validate the inert known-answer calibration fixture."""

    directory = _fixture_directory() if fixture_dir is None else Path(fixture_dir)
    document = _safe_json_document(
        directory / "calibration_cases.json",
        expected_file_sha256=CALIBRATION_FIXTURE_SHA256,
    )
    if document.get("schema_version") != SCHEMA_VERSION:
        raise CalibrationError("unsupported calibration fixture schema_version")
    if document.get("fixture_type") != "scientist_one.calibration_cases":
        raise CalibrationError("unexpected calibration fixture_type")
    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list):
        raise CalibrationError("calibration fixture cases must be a list")
    cases = tuple(CalibrationCase.from_dict(raw) for raw in raw_cases if isinstance(raw, dict))
    if len(cases) != len(raw_cases):
        raise CalibrationError("every calibration case must be an object")
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise CalibrationError("calibration case_id values must be unique")
    kinds = [case.kind for case in cases if case.mandatory]
    missing = sorted(set(MANDATORY_CASE_KINDS) - set(kinds))
    duplicates = sorted(kind for kind in set(kinds) if kinds.count(kind) > 1)
    if missing or duplicates:
        raise CalibrationError(
            f"mandatory calibration coverage invalid; missing={missing}, duplicates={duplicates}"
        )
    return tuple(sorted(cases, key=lambda case: case.case_id))


def _as_float(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CalibrationError(f"{location} must be numeric")
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise CalibrationError(f"{location} must be a finite representable number") from exc
    if not math.isfinite(number):
        raise CalibrationError(f"{location} must be finite")
    return number


def _observations(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = payload.get("observations")
    if (
        not isinstance(raw, Sequence)
        or isinstance(raw, (str, bytes))
        or not raw
        or not all(isinstance(row, Mapping) for row in raw)
    ):
        raise CalibrationError("payload.observations must be a non-empty object list")
    if len(raw) > MAX_OBSERVATIONS:
        raise CalibrationError(f"payload.observations exceeds {MAX_OBSERVATIONS}")
    return list(raw)


def _mean(values: Sequence[float]) -> float:
    if not values:
        raise CalibrationError("mean requires at least one value")
    return math.fsum(values) / len(values)


def seeded_permutation_test(
    observations: Sequence[Mapping[str, Any]],
    *,
    seed: int,
    iterations: int = 4096,
    group_key: str = "group",
    outcome_key: str = "outcome",
    unit_key: str = "unit_id",
    treatment_label: str = "treatment",
    block_key: str | None = None,
) -> dict[str, Any]:
    """Run a stable two-sided Monte Carlo permutation test.

    Assignment rankings are SHA-256 derived from ``seed``, iteration, and unit ID.
    This avoids global RNG state and remains reproducible across process restarts.
    """

    if isinstance(seed, bool) or not isinstance(seed, int):
        raise CalibrationError("seed must be an integer")
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
        raise CalibrationError("iterations must be a positive integer")
    if iterations > MAX_PERMUTATION_ITERATIONS:
        raise CalibrationError(f"iterations exceeds frozen maximum {MAX_PERMUTATION_ITERATIONS}")
    if len(observations) > MAX_OBSERVATIONS:
        raise CalibrationError(f"observations exceeds frozen maximum {MAX_OBSERVATIONS}")
    if iterations * len(observations) > MAX_PERMUTATION_WORK_UNITS:
        raise CalibrationError("permutation work budget exceeded")
    parsed: list[tuple[str, str, float, str | None]] = []
    for index, row in enumerate(observations):
        if not isinstance(row, Mapping):
            raise CalibrationError(f"observations[{index}] must be an object")
        unit_id = row.get(unit_key)
        group = row.get(group_key)
        if not isinstance(unit_id, str) or not unit_id:
            raise CalibrationError(f"observations[{index}].{unit_key} must be a string")
        if not isinstance(group, str) or not group:
            raise CalibrationError(f"observations[{index}].{group_key} must be a string")
        block: str | None = None
        if block_key is not None:
            raw_block = row.get(block_key)
            if not isinstance(raw_block, str) or not raw_block:
                raise CalibrationError(f"observations[{index}].{block_key} must be a string")
            block = raw_block
        parsed.append(
            (unit_id, group, _as_float(row.get(outcome_key), f"observations[{index}].{outcome_key}"), block)
        )
    if len({unit_id for unit_id, _, _, _ in parsed}) != len(parsed):
        raise CalibrationError("permutation units must be unique")
    labels = sorted({group for _, group, _, _ in parsed})
    if len(labels) != 2 or treatment_label not in labels:
        raise CalibrationError("permutation test requires two groups including treatment_label")
    control_label = next(label for label in labels if label != treatment_label)
    treatment = [value for _, group, value, _ in parsed if group == treatment_label]
    control = [value for _, group, value, _ in parsed if group == control_label]
    if not treatment or not control:
        raise CalibrationError("both permutation groups must be non-empty")
    observed = _mean(treatment) - _mean(control)
    ordered = sorted(parsed, key=lambda item: item[0])
    treatment_count = len(treatment)
    extreme = 0
    epsilon = 1e-15
    blocks: dict[str, list[tuple[str, str, float, str | None]]] = {}
    if block_key is not None:
        for row in ordered:
            assert row[3] is not None
            blocks.setdefault(row[3], []).append(row)
        if any(
            len(rows) != 2 or {row[1] for row in rows} != {control_label, treatment_label}
            for rows in blocks.values()
        ):
            raise CalibrationError("each permutation block must contain one observation per group")
    for iteration in range(iterations):
        if block_key is None:
            ranked = sorted(
                ordered,
                key=lambda item: hashlib.sha256(
                    f"{seed}:{iteration}:{item[0]}".encode("utf-8")
                ).digest(),
            )
            permuted_treatment = {unit_id for unit_id, _, _, _ in ranked[:treatment_count]}
            perm_t = [value for unit_id, _, value, _ in ordered if unit_id in permuted_treatment]
            perm_c = [value for unit_id, _, value, _ in ordered if unit_id not in permuted_treatment]
        else:
            perm_t = []
            perm_c = []
            for block_id, rows in sorted(blocks.items()):
                by_group = {row[1]: row[2] for row in rows}
                swap = hashlib.sha256(f"{seed}:{iteration}:{block_id}".encode()).digest()[0] & 1
                if swap:
                    perm_t.append(by_group[control_label])
                    perm_c.append(by_group[treatment_label])
                else:
                    perm_t.append(by_group[treatment_label])
                    perm_c.append(by_group[control_label])
        permuted_difference = _mean(perm_t) - _mean(perm_c)
        if abs(permuted_difference) + epsilon >= abs(observed):
            extreme += 1
    p_value = (extreme + 1) / (iterations + 1)
    return {
        "method": (
            "stable_sha256_blocked_sign_flip_v1"
            if block_key is not None
            else "stable_sha256_monte_carlo_permutation_v1"
        ),
        "exchangeability_block_key": block_key,
        "seed": seed,
        "iterations": iterations,
        "extreme_count": extreme,
        "treatment_n": len(treatment),
        "control_n": len(control),
        "observed_difference": observed,
        "two_sided_p_value": p_value,
    }


def holm_adjust(p_values: Sequence[float]) -> tuple[float, ...]:
    """Return Holm-adjusted p-values in their original order."""

    parsed = [_as_float(value, f"p_values[{index}]") for index, value in enumerate(p_values)]
    if any(value < 0.0 or value > 1.0 for value in parsed):
        raise CalibrationError("p-values must be between zero and one")
    count = len(parsed)
    if not count:
        return ()
    order = sorted(range(count), key=lambda index: (parsed[index], index))
    adjusted = [0.0] * count
    previous = 0.0
    for rank, index in enumerate(order):
        candidate = min(1.0, (count - rank) * parsed[index])
        previous = max(previous, candidate)
        adjusted[index] = previous
    return tuple(adjusted)


def _permutation_block_key(payload: Mapping[str, Any]) -> str | None:
    """Return the frozen exchangeability block, if observations are paired/clustered."""
    raw = payload.get("resampling_unit")
    if raw is None or raw == "unit_id":
        return None
    if not isinstance(raw, str) or not raw:
        raise CalibrationError("resampling_unit must be a non-empty string")
    return raw


def _permutation_iterations(payload: Mapping[str, Any], default: int) -> int:
    value = payload.get("permutation_iterations", default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise CalibrationError("permutation_iterations must be an integer")
    if not 1 <= value <= MAX_PERMUTATION_ITERATIONS:
        raise CalibrationError(
            f"permutation_iterations must be in [1, {MAX_PERMUTATION_ITERATIONS}]"
        )
    return value


def _signal_detector(payload: Mapping[str, Any], seed: int) -> _DetectorOutcome:
    stats = seeded_permutation_test(
        _observations(payload),
        seed=seed,
        iterations=_permutation_iterations(payload, 4096),
        block_key=_permutation_block_key(payload),
    )
    minimum_effect = _as_float(payload.get("minimum_effect", 0.0), "minimum_effect")
    alpha = _as_float(payload.get("alpha", 0.05), "alpha")
    direction = payload.get("expected_direction", "positive")
    if minimum_effect < 0:
        raise CalibrationError("minimum_effect must be non-negative")
    if not 0.0 < alpha < 1.0:
        raise CalibrationError("alpha must be in (0, 1)")
    if direction not in {"positive", "negative"}:
        raise CalibrationError("expected_direction must be positive or negative")
    effect = stats["observed_difference"]
    direction_ok = effect > 0 if direction == "positive" else effect < 0
    recovered = direction_ok and abs(effect) >= minimum_effect and stats["two_sided_p_value"] <= alpha
    if recovered:
        return _DetectorOutcome(
            "PLANTED_SIGNAL_RECOVERED",
            (Finding("SIGNIFICANT_PLANTED_EFFECT", "info", "known effect recovered"),),
            stats,
        )
    return _DetectorOutcome(
        "SIGNAL_NOT_RECOVERED",
        (Finding("PLANTED_EFFECT_MISSED", "error", "known effect was not recovered"),),
        stats,
    )


def _null_detector(payload: Mapping[str, Any], seed: int) -> _DetectorOutcome:
    stats = seeded_permutation_test(
        _observations(payload),
        seed=seed,
        iterations=_permutation_iterations(payload, 4096),
        block_key=_permutation_block_key(payload),
    )
    maximum_effect = _as_float(payload.get("maximum_abs_effect", 0.05), "maximum_abs_effect")
    minimum_p = _as_float(payload.get("minimum_p_value", 0.5), "minimum_p_value")
    if maximum_effect < 0:
        raise CalibrationError("maximum_abs_effect must be non-negative")
    if not 0.0 <= minimum_p <= 1.0:
        raise CalibrationError("minimum_p_value must be in [0, 1]")
    retained = (
        abs(stats["observed_difference"]) <= maximum_effect
        and stats["two_sided_p_value"] >= minimum_p
    )
    if retained:
        return _DetectorOutcome(
            "TRUE_NULL_RETAINED",
            (Finding("TRUE_NULL_NOT_FALSE_POSITIVE", "info", "known null retained"),),
            stats,
        )
    return _DetectorOutcome(
        "NULL_MISCLASSIFIED",
        (Finding("FALSE_POSITIVE_ON_TRUE_NULL", "error", "known null was not retained"),),
        stats,
    )


def _leakage_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    findings: list[Finding] = []
    splits = payload.get("splits", {})
    if not isinstance(splits, Mapping):
        raise CalibrationError("payload.splits must be an object")
    if len(splits) > MAX_SPLIT_ROLES:
        raise CalibrationError(f"payload.splits exceeds {MAX_SPLIT_ROLES} roles")
    pair_comparisons = len(splits) * (len(splits) - 1) // 2
    if pair_comparisons > MAX_SPLIT_PAIR_COMPARISONS:
        raise CalibrationError("split-role pair comparison budget exceeded")
    roles: dict[str, set[str]] = {}
    for role, identifiers in splits.items():
        if not isinstance(role, str) or not isinstance(identifiers, Sequence) or isinstance(identifiers, (str, bytes)) or not all(
            isinstance(identifier, str) for identifier in identifiers
        ):
            raise CalibrationError("split roles must map to string lists")
        if not role:
            raise CalibrationError("split role names must be non-empty")
        if len(identifiers) > MAX_SPLIT_IDS_PER_ROLE:
            raise CalibrationError(
                f"split role exceeds {MAX_SPLIT_IDS_PER_ROLE} identifiers"
            )
        if len(set(identifiers)) != len(identifiers):
            raise CalibrationError("split identifiers must be unique within each role")
        roles[role] = set(identifiers)
    role_pairs = list(itertools.combinations(sorted(roles), 2))
    intersection_work_units = sum(
        min(len(roles[left]), len(roles[right])) for left, right in role_pairs
    )
    if intersection_work_units > MAX_SPLIT_INTERSECTION_WORK_UNITS:
        raise CalibrationError("split intersection work budget exceeded")
    overlaps: list[dict[str, Any]] = []
    for left, right in role_pairs:
        shared = sorted(roles[left] & roles[right])
        if shared:
            overlaps.append({"left": left, "right": right, "unit_ids": shared})
    if overlaps:
        findings.append(
            Finding("SPLIT_ID_OVERLAP", "error", "unit IDs occur in multiple data roles", "payload.splits")
        )
    forbidden_features: list[str] = []
    features = payload.get("features", [])
    if not isinstance(features, Sequence) or isinstance(features, (str, bytes)) or len(features) > MAX_COLLECTION_ITEMS or not all(isinstance(feature, Mapping) for feature in features):
        raise CalibrationError("payload.features must be an object list")
    for feature in features:
        name = feature.get("name")
        lineage = feature.get("lineage", [])
        timing = feature.get("timing")
        if not isinstance(name, str) or not isinstance(lineage, Sequence) or isinstance(lineage, (str, bytes)):
            raise CalibrationError("each feature requires name and lineage")
        if "outcome" in lineage or timing in {"post_outcome", "post_assignment_reveal"}:
            forbidden_features.append(name)
    if forbidden_features:
        findings.append(
            Finding(
                "OUTCOME_DERIVED_FEATURE",
                "error",
                "feature lineage uses an outcome or post-outcome value",
                "payload.features",
            )
        )
    stats = {"split_overlaps": overlaps, "forbidden_features": sorted(forbidden_features)}
    if findings:
        return _DetectorOutcome("LEAKAGE_DETECTED", tuple(findings), stats)
    return _DetectorOutcome("NO_LEAKAGE_DETECTED", (), stats)


def _regime_detector(payload: Mapping[str, Any], seed: int) -> _DetectorOutcome:
    regimes = payload.get("regimes")
    if not isinstance(regimes, Sequence) or isinstance(regimes, (str, bytes)) or not 2 <= len(regimes) <= MAX_REGIMES or not all(
        isinstance(regime, Mapping) for regime in regimes
    ):
        raise CalibrationError("payload.regimes must contain at least two objects")
    iterations = _permutation_iterations(payload, 2048)
    regime_names: list[str] = []
    regime_observations: dict[str, list[Mapping[str, Any]]] = {}
    for regime in regimes:
        name = regime.get("name")
        observations = regime.get("observations")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(observations, Sequence)
            or isinstance(observations, (str, bytes))
        ):
            raise CalibrationError("each regime requires a non-empty name and observations")
        regime_names.append(name)
        regime_observations[name] = _observations(regime)
    if len(regime_names) != len(set(regime_names)):
        raise CalibrationError("regime names must be unique")
    if (
        iterations * sum(len(observations) for observations in regime_observations.values())
        > MAX_REGIME_PERMUTATION_WORK_UNITS
    ):
        raise CalibrationError("regime permutation work budget exceeded")

    raw_pairs = payload.get("predeclared_regime_pairs")
    if (
        not isinstance(raw_pairs, Sequence)
        or isinstance(raw_pairs, (str, bytes))
        or not raw_pairs
        or len(raw_pairs) > MAX_COLLECTION_ITEMS
    ):
        raise CalibrationError("predeclared_regime_pairs must be a non-empty pair list")
    pairs: list[tuple[str, str]] = []
    seen_pairs: set[frozenset[str]] = set()
    known_names = set(regime_names)
    for index, pair in enumerate(raw_pairs):
        if (
            not isinstance(pair, Sequence)
            or isinstance(pair, (str, bytes))
            or len(pair) != 2
            or not all(isinstance(name, str) and name for name in pair)
        ):
            raise CalibrationError(f"predeclared_regime_pairs[{index}] must name two regimes")
        left, right = pair
        if left == right or {left, right} - known_names:
            raise CalibrationError(f"predeclared_regime_pairs[{index}] is invalid")
        identity = frozenset((left, right))
        if identity in seen_pairs:
            raise CalibrationError("predeclared regime pairs must be unique")
        seen_pairs.add(identity)
        pairs.append((left, right))

    effects: dict[str, float] = {}
    p_values: dict[str, float] = {}
    for name, observations in regime_observations.items():
        result = seeded_permutation_test(
            observations,
            seed=_derived_seed(seed, f"regime:{name}"),
            iterations=iterations,
            block_key=_permutation_block_key(payload),
        )
        effects[name] = result["observed_difference"]
        p_values[name] = result["two_sided_p_value"]
    minimum_effect = _as_float(payload.get("minimum_abs_effect", 0.1), "minimum_abs_effect")
    alpha = _as_float(payload.get("regime_alpha", 0.05), "regime_alpha")
    if minimum_effect < 0.0:
        raise CalibrationError("minimum_abs_effect must be non-negative")
    if not 0.0 < alpha < 1.0:
        raise CalibrationError("regime_alpha must be in (0, 1)")
    pair_p_values = [max(p_values[left], p_values[right]) for left, right in pairs]
    adjusted_pair_p_values = holm_adjust(pair_p_values)
    pair_results: list[dict[str, Any]] = []
    significant_pairs: list[list[str]] = []
    for (left, right), raw_p, adjusted_p in zip(
        pairs, pair_p_values, adjusted_pair_p_values, strict=True
    ):
        opposite = effects[left] * effects[right] < 0
        effect_threshold_met = (
            abs(effects[left]) >= minimum_effect and abs(effects[right]) >= minimum_effect
        )
        significant = opposite and effect_threshold_met and adjusted_p <= alpha
        pair_results.append(
            {
                "regimes": [left, right],
                "opposite_signs": opposite,
                "effect_threshold_met": effect_threshold_met,
                "intersection_union_p_value": raw_p,
                "holm_adjusted_p_value": adjusted_p,
                "significant_reversal": significant,
            }
        )
        if significant:
            significant_pairs.append([left, right])
    reversal = bool(significant_pairs)
    stats = {
        "regime_effects": effects,
        "regime_p_values": p_values,
        "regime_alpha": alpha,
        "minimum_abs_effect": minimum_effect,
        "multiplicity_method": "holm_over_predeclared_intersection_union_pairs",
        "predeclared_pair_results": pair_results,
        "significant_reversal_pairs": significant_pairs,
    }
    if reversal:
        return _DetectorOutcome(
            "REGIME_REVERSAL_DETECTED",
            (Finding("EFFECT_SIGN_REVERSAL", "error", "effect changes sign across regimes"),),
            stats,
        )
    findings = ()
    if any(item["opposite_signs"] for item in pair_results):
        findings = (
            Finding(
                "REGIME_REVERSAL_NOT_STATISTICALLY_SUPPORTED",
                "warning",
                "opposite observed signs do not both satisfy frozen effect and uncertainty thresholds",
            ),
        )
    return _DetectorOutcome("NO_REGIME_REVERSAL_DETECTED", findings, stats)


def _resampling_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    unit = payload.get("unit_of_analysis")
    resampling = payload.get("resampling_unit")
    if not isinstance(unit, str) or not isinstance(resampling, str):
        raise CalibrationError("unit_of_analysis and resampling_unit must be strings")
    observations = _observations(payload)
    unit_ids: list[str] = []
    for index, observation in enumerate(observations):
        identifier = observation.get(unit)
        if not isinstance(identifier, str) or not identifier:
            raise CalibrationError(f"observations[{index}].{unit} must be a string")
        unit_ids.append(identifier)
    repeated = sorted(identifier for identifier, count in Counter(unit_ids).items() if count > 1)
    mismatch = unit != resampling and bool(repeated)
    stats = {
        "unit_of_analysis": unit,
        "resampling_unit": resampling,
        "observation_count": len(observations),
        "unique_analysis_units": len(set(unit_ids)),
        "repeated_analysis_units": repeated,
    }
    if mismatch:
        return _DetectorOutcome(
            "INVALID_RESAMPLING_UNIT_DETECTED",
            (
                Finding(
                    "DEPENDENT_OBSERVATIONS_RESAMPLED_AS_INDEPENDENT",
                    "error",
                    "repeated analysis units would be resampled independently",
                ),
            ),
            stats,
        )
    return _DetectorOutcome("RESAMPLING_UNIT_VALID", (), stats)


def _multiplicity_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    hypotheses = payload.get("hypotheses")
    if not isinstance(hypotheses, Sequence) or isinstance(hypotheses, (str, bytes)) or not hypotheses or len(hypotheses) > MAX_COLLECTION_ITEMS or not all(
        isinstance(item, Mapping) for item in hypotheses
    ):
        raise CalibrationError("payload.hypotheses must be a non-empty object list")
    ids: list[str] = []
    p_values: list[float] = []
    for index, item in enumerate(hypotheses):
        hypothesis_id = item.get("id")
        if not isinstance(hypothesis_id, str) or not hypothesis_id:
            raise CalibrationError(f"hypotheses[{index}].id must be a string")
        ids.append(hypothesis_id)
        p_values.append(_as_float(item.get("p_value"), f"hypotheses[{index}].p_value"))
    if len(ids) != len(set(ids)):
        raise CalibrationError("hypothesis IDs must be unique")
    alpha = _as_float(payload.get("family_alpha", 0.05), "family_alpha")
    if not 0.0 < alpha < 1.0:
        raise CalibrationError("family_alpha must be in (0, 1)")
    adjusted = holm_adjust(p_values)
    raw_significant = [ids[index] for index, value in enumerate(p_values) if value <= alpha]
    holm_significant = [ids[index] for index, value in enumerate(adjusted) if value <= alpha]
    claimed = payload.get("reported_significant", [])
    if not isinstance(claimed, Sequence) or isinstance(claimed, (str, bytes)) or not all(isinstance(value, str) for value in claimed):
        raise CalibrationError("reported_significant must be a string list")
    correction = payload.get("correction_method", "none")
    unsupported = sorted(set(claimed) - set(holm_significant))
    trap = bool(unsupported)
    stats = {
        "family_size": len(ids),
        "family_alpha": alpha,
        "raw_significant": raw_significant,
        "holm_significant": holm_significant,
        "holm_adjusted_p_values": dict(zip(ids, adjusted, strict=True)),
        "unsupported_reported_discoveries": unsupported,
        "declared_correction_method": correction,
    }
    if trap:
        return _DetectorOutcome(
            "MULTIPLE_COMPARISONS_DETECTED",
            (
                Finding(
                    "UNCORRECTED_MULTIPLE_TESTING_CLAIM",
                    "error",
                    "reported discovery does not survive Holm correction",
                ),
            ),
            stats,
        )
    return _DetectorOutcome("MULTIPLICITY_HANDLED", (), stats)


def _baseline_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    baseline = payload.get("baseline")
    contender = payload.get("contender")
    required = payload.get("required_equal_dimensions")
    if not isinstance(baseline, Mapping) or not isinstance(contender, Mapping):
        raise CalibrationError("baseline and contender must be objects")
    if not isinstance(required, Sequence) or isinstance(required, (str, bytes)) or not all(isinstance(value, str) for value in required):
        raise CalibrationError("required_equal_dimensions must be a string list")
    if not required or len(set(required)) != len(required):
        raise CalibrationError("required_equal_dimensions must be non-empty and unique")
    missing_dimensions = [
        dimension for dimension in required if dimension not in baseline or dimension not in contender
    ]
    mismatches = {
        dimension: {"baseline": baseline.get(dimension), "contender": contender.get(dimension)}
        for dimension in required
        if dimension in baseline
        and dimension in contender
        and baseline.get(dimension) != contender.get(dimension)
    }
    stats = {
        "checked_dimensions": required,
        "missing_dimensions": missing_dimensions,
        "mismatches": mismatches,
    }
    if mismatches or missing_dimensions:
        return _DetectorOutcome(
            "BASELINE_MISMATCH_DETECTED",
            (
                Finding(
                    "BASELINE_COMPARABILITY_FAILURE",
                    "error",
                    "baseline and contender differ or omit required comparison dimensions",
                ),
            ),
            stats,
        )
    return _DetectorOutcome("BASELINE_EQUIVALENT", (), stats)


def _provenance_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes)) or not artifacts or len(artifacts) > MAX_COLLECTION_ITEMS or not all(
        isinstance(artifact, Mapping) for artifact in artifacts
    ):
        raise CalibrationError("payload.artifacts must be a non-empty object list")
    identifier_list = [artifact.get("artifact_id") for artifact in artifacts]
    identifiers = set(identifier_list)
    if None in identifiers or not all(isinstance(identifier, str) for identifier in identifiers):
        raise CalibrationError("each artifact requires a string artifact_id")
    duplicates = sorted(
        str(identifier) for identifier, count in Counter(identifier_list).items() if count > 1
    )
    corrupt: list[str] = []
    missing_parents: dict[str, list[str]] = {}
    actual_hashes: dict[str, str] = {}
    parent_graph: dict[str, set[str]] = {str(identifier): set() for identifier in identifiers}
    for artifact in artifacts:
        artifact_id = artifact["artifact_id"]
        declared = artifact.get("declared_sha256")
        actual = canonical_json_sha256(artifact.get("content"))
        actual_hashes[artifact_id] = actual
        if not isinstance(declared, str) or declared != actual:
            corrupt.append(artifact_id)
        parents = artifact.get("parent_artifact_ids", [])
        if not isinstance(parents, Sequence) or isinstance(parents, (str, bytes)) or not all(isinstance(parent, str) for parent in parents):
            raise CalibrationError("parent_artifact_ids must be a string list")
        absent = sorted(set(parents) - identifiers)
        parent_graph[artifact_id].update(parent for parent in parents if parent in identifiers)
        if absent:
            missing_parents[artifact_id] = absent
    findings: list[Finding] = []
    if duplicates:
        findings.append(Finding("DUPLICATE_ARTIFACT_ID", "error", "artifact IDs are not unique"))
    if corrupt:
        findings.append(
            Finding("ARTIFACT_HASH_MISMATCH", "error", "declared content hash is incorrect")
        )
    if missing_parents:
        findings.append(
            Finding("MISSING_PROVENANCE_PARENT", "error", "provenance names an absent parent")
        )
    cycle_nodes: set[str] = set()
    color: dict[str, int] = {node: 0 for node in parent_graph}
    for start in sorted(parent_graph):
        if color[start] != 0:
            continue
        stack: list[tuple[str, bool]] = [(start, False)]
        active: set[str] = set()
        while stack:
            node, exiting = stack.pop()
            if exiting:
                active.discard(node)
                color[node] = 2
                continue
            if color[node] == 2:
                continue
            if node in active:
                cycle_nodes.add(node)
                continue
            active.add(node)
            color[node] = 1
            stack.append((node, True))
            for parent in sorted(parent_graph.get(node, set()), reverse=True):
                if parent in active:
                    cycle_nodes.update({node, parent})
                elif color[parent] != 2:
                    stack.append((parent, False))
    if cycle_nodes:
        findings.append(Finding("PROVENANCE_CYCLE", "error", "provenance graph contains a cycle"))
    stats = {
        "corrupt_artifact_ids": sorted(corrupt),
        "missing_parents": missing_parents,
        "computed_sha256": actual_hashes,
        "duplicate_artifact_ids": duplicates,
        "cycle_artifact_ids": sorted(cycle_nodes),
    }
    if findings:
        return _DetectorOutcome("CORRUPTED_PROVENANCE_DETECTED", tuple(findings), stats)
    return _DetectorOutcome("PROVENANCE_VALID", (), stats)


def _claim_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    evidence = payload.get("evidence", [])
    claims = payload.get("claims", [])
    if not isinstance(evidence, Sequence) or isinstance(evidence, (str, bytes)) or len(evidence) > MAX_COLLECTION_ITEMS or not all(isinstance(item, Mapping) for item in evidence):
        raise CalibrationError("payload.evidence must be an object list")
    if not isinstance(claims, Sequence) or isinstance(claims, (str, bytes)) or not claims or len(claims) > MAX_COLLECTION_ITEMS or not all(isinstance(item, Mapping) for item in claims):
        raise CalibrationError("payload.claims must be a non-empty object list")
    eligible = {
        item.get("evidence_id")
        for item in evidence
        if isinstance(item.get("evidence_id"), str) and item.get("eligible") is True
    }
    unsupported: dict[str, list[str]] = {}
    for index, claim in enumerate(claims):
        claim_id = claim.get("claim_id")
        references = claim.get("evidence_ids")
        if not isinstance(claim_id, str) or not claim_id:
            raise CalibrationError(f"claims[{index}].claim_id must be a string")
        if not isinstance(references, Sequence) or isinstance(references, (str, bytes)) or not all(isinstance(value, str) for value in references):
            raise CalibrationError(f"claims[{index}].evidence_ids must be a string list")
        missing = sorted(set(references) - eligible)
        if not references or missing:
            unsupported[claim_id] = missing if references else ["<no-evidence>"]
    stats = {"eligible_evidence_ids": sorted(eligible), "unsupported_claims": unsupported}
    if unsupported:
        return _DetectorOutcome(
            "UNSUPPORTED_CLAIM_REJECTED",
            (
                Finding(
                    "CLAIM_LACKS_ELIGIBLE_EVIDENCE",
                    "error",
                    "claim references no eligible evidence bundle",
                ),
            ),
            stats,
        )
    return _DetectorOutcome("CLAIMS_SUPPORTED", (), stats)


def _holdout_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    protocol_frozen = payload.get("protocol_frozen")
    max_accesses = payload.get("maximum_authorized_accesses", 1)
    accesses = payload.get("accesses")
    if not isinstance(protocol_frozen, bool):
        raise CalibrationError("protocol_frozen must be boolean")
    if isinstance(max_accesses, bool) or not isinstance(max_accesses, int) or max_accesses < 0:
        raise CalibrationError("maximum_authorized_accesses must be a non-negative integer")
    if not isinstance(accesses, Sequence) or isinstance(accesses, (str, bytes)) or len(accesses) > MAX_COLLECTION_ITEMS or not all(isinstance(access, Mapping) for access in accesses):
        raise CalibrationError("accesses must be an object list")
    violations: list[dict[str, Any]] = []
    authorized_count = 0
    for index, access in enumerate(accesses):
        authorized = access.get("authorized") is True
        attempted_opt_out = access.get("requires_frozen_protocol", True) is not True
        if authorized:
            authorized_count += 1
        reasons: list[str] = []
        if not authorized:
            reasons.append("unauthorized")
        if not protocol_frozen:
            reasons.append("protocol_not_frozen")
        if attempted_opt_out:
            reasons.append("custody_policy_opt_out_rejected")
        if access.get("purpose") in {"tuning", "seed_selection", "paper_story_selection"}:
            reasons.append("forbidden_purpose")
        if reasons:
            violations.append({"access_index": index, "reasons": reasons})
    if authorized_count > max_accesses:
        violations.append(
            {
                "access_index": None,
                "reasons": ["authorized_access_count_exceeded"],
                "count": authorized_count,
            }
        )
    stats = {
        "access_count": len(accesses),
        "authorized_access_count": authorized_count,
        "maximum_authorized_accesses": max_accesses,
        "violations": violations,
    }
    if violations:
        return _DetectorOutcome(
            "HOLDOUT_ACCESS_VIOLATION_DETECTED",
            (
                Finding(
                    "HOLDOUT_CUSTODY_BREACH",
                    "error",
                    "holdout access violates frozen-custody conditions",
                ),
            ),
            stats,
        )
    return _DetectorOutcome("HOLDOUT_ACCESS_VALID", (), stats)


_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "developer message",
    "run this command",
    "execute this command",
    "tool call",
    "~/.ssh",
    "/etc/passwd",
)


def scan_untrusted_research_text(text: str) -> tuple[str, ...]:
    """Scan text as data and return marker names; never execute or interpret it."""

    if not isinstance(text, str):
        raise CalibrationError("untrusted research text must be a string")
    lowered = text.casefold()
    return tuple(marker for marker in _INJECTION_MARKERS if marker in lowered)


def _prompt_injection_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    text = payload.get("untrusted_text")
    actions = payload.get("recorded_actions", [])
    if not isinstance(text, str):
        raise CalibrationError("payload.untrusted_text must be a string")
    if not isinstance(actions, Sequence) or isinstance(actions, (str, bytes)):
        raise CalibrationError("payload.recorded_actions must be a list")
    markers = scan_untrusted_research_text(text)
    stats = {
        "detected_markers": list(markers),
        "recorded_action_count": len(actions),
        "handling": "inert_untrusted_data",
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    if markers and not actions:
        return _DetectorOutcome(
            "PROMPT_INJECTION_QUARANTINED",
            (
                Finding(
                    "PROMPT_INJECTION_PATTERN",
                    "warning",
                    "instruction-like research text retained only as inert data",
                ),
            ),
            stats,
        )
    if markers and actions:
        return _DetectorOutcome(
            "PROMPT_INJECTION_EXECUTION_ATTEMPT",
            (
                Finding(
                    "UNTRUSTED_INSTRUCTION_ACTION_RECORDED",
                    "error",
                    "an action was associated with untrusted instruction text",
                ),
            ),
            stats,
        )
    return _DetectorOutcome("NO_PROMPT_INJECTION_PATTERN", (), stats)


def _permutation_domain_detector(payload: Mapping[str, Any], _seed: int) -> _DetectorOutcome:
    exchangeability = payload.get("exchangeability")
    scheme = payload.get("proposed_permutation_scheme")
    allowed = payload.get("allowed_permutation_schemes", [])
    structure = payload.get("domain_structure")
    if not isinstance(exchangeability, bool):
        raise CalibrationError("exchangeability must be boolean")
    if not isinstance(scheme, str) or not isinstance(structure, str):
        raise CalibrationError("domain_structure and proposed_permutation_scheme must be strings")
    if not isinstance(allowed, Sequence) or isinstance(allowed, (str, bytes)) or not all(isinstance(value, str) for value in allowed):
        raise CalibrationError("allowed_permutation_schemes must be a string list")
    invalid = not exchangeability and scheme not in allowed
    stats = {
        "domain_structure": structure,
        "exchangeability": exchangeability,
        "proposed_permutation_scheme": scheme,
        "allowed_permutation_schemes": allowed,
    }
    if invalid:
        return _DetectorOutcome(
            "DOMAIN_INVALID_PERMUTATION_REJECTED",
            (
                Finding(
                    "EXCHANGEABILITY_ASSUMPTION_VIOLATED",
                    "error",
                    "global permutation is invalid for the declared domain structure",
                ),
            ),
            stats,
        )
    return _DetectorOutcome("PERMUTATION_SCHEME_DOMAIN_VALID", (), stats)


_DETECTORS: dict[str, Callable[[Mapping[str, Any], int], _DetectorOutcome]] = {
    "planted_positive": _signal_detector,
    "true_null": _null_detector,
    "leakage_trap": _leakage_detector,
    "regime_reversal_shift": _regime_detector,
    "invalid_resampling_unit": _resampling_detector,
    "multiple_comparisons": _multiplicity_detector,
    "baseline_implementation_mismatch": _baseline_detector,
    "corrupted_provenance": _provenance_detector,
    "unsupported_claim": _claim_detector,
    "holdout_access_violation": _holdout_detector,
    "prompt_injection_artifact": _prompt_injection_detector,
    "domain_invalid_permutation": _permutation_domain_detector,
}


def evaluate_case(case: CalibrationCase | Mapping[str, Any]) -> CalibrationResult:
    """Evaluate one known-answer case without mutating its payload."""

    if isinstance(case, CalibrationCase):
        parsed = case
    else:
        try:
            _validate_json_shape(case)
            parsed = CalibrationCase.from_dict(case)
        except (CalibrationError, RecursionError, TypeError, ValueError) as exc:
            return CalibrationResult(
                case_id="<invalid>",
                kind="<invalid>",
                mandatory=True,
                seed=0,
                expected_decision="CALIBRATION_CASE_VALID",
                expected_finding_codes=("MALFORMED_CALIBRATION_CASE",),
                decision="CALIBRATION_CASE_INVALID",
                passed=False,
                findings=(Finding("MALFORMED_CALIBRATION_CASE", "error", str(exc)),),
                statistics={},
                fixture_sha256="0" * 64,
            )
    fixture_hash = canonical_json_sha256(parsed.to_dict())
    try:
        outcome = _DETECTORS[parsed.kind](parsed.payload, parsed.seed)
    except (CalibrationError, KeyError, TypeError, ValueError, OverflowError) as exc:
        outcome = _DetectorOutcome(
            "CALIBRATION_CASE_INVALID",
            (Finding("MALFORMED_CALIBRATION_CASE", "error", str(exc)),),
            {},
        )
    observed_codes = {finding.code for finding in outcome.findings}
    passed = (
        outcome.decision == parsed.expected_decision
        and set(parsed.expected_finding_codes).issubset(observed_codes)
    )
    return CalibrationResult(
        case_id=parsed.case_id,
        kind=parsed.kind,
        mandatory=parsed.mandatory,
        seed=parsed.seed,
        expected_decision=parsed.expected_decision,
        expected_finding_codes=parsed.expected_finding_codes,
        decision=outcome.decision,
        passed=passed,
        findings=outcome.findings,
        statistics=outcome.statistics,
        fixture_sha256=fixture_hash,
    )


def run_calibration(
    fixture_dir: str | Path | None = None, *, mandatory_only: bool = True
) -> CalibrationReport:
    """Run the frozen known-answer calibration suite deterministically."""

    cases = load_calibration_cases(fixture_dir)
    selected = [case for case in cases if case.mandatory or not mandatory_only]
    results = tuple(evaluate_case(case) for case in selected)
    digest = _calibration_report_sha256(results)
    if digest != FROZEN_CALIBRATION_REPORT_SHA256:
        raise CalibrationGateError("frozen calibration report digest drift")
    return CalibrationReport(results, digest)


def assert_calibrated(
    report: CalibrationReport, fixture_dir: str | Path | None = None
) -> CalibrationReport:
    """Enforce the mandatory calibration gate and return the passing report."""

    if not isinstance(report, CalibrationReport):
        raise TypeError("report must be a CalibrationReport")
    if not report.integrity_valid:
        raise CalibrationGateError("calibration report integrity check failed")
    canonical = run_calibration(fixture_dir)
    if [result.to_dict() for result in report.results] != [
        result.to_dict() for result in canonical.results
    ] or report.report_sha256 != canonical.report_sha256:
        raise CalibrationGateError("calibration report does not match canonical re-evaluation")
    if not report.mandatory_passed:
        failed = ", ".join(report.failed_case_ids) or "missing mandatory cases"
        raise CalibrationGateError(f"mandatory calibration failed: {failed}")
    covered = {result.kind for result in report.results if result.mandatory}
    missing = sorted(set(MANDATORY_CASE_KINDS) - covered)
    if missing:
        raise CalibrationGateError(f"mandatory calibration coverage missing: {missing}")
    return report


def _derived_seed(seed: int, namespace: str) -> int:
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise CalibrationError("seed must be an integer")
    digest = hashlib.sha256(f"{seed}:{namespace}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _stable_noise(seed: int, namespace: str, index: int, amplitude: float = 0.2) -> float:
    digest = hashlib.sha256(f"{seed}:{namespace}:{index}".encode("utf-8")).digest()
    unit_interval = int.from_bytes(digest[:8], "big") / ((1 << 64) - 1)
    return round((2.0 * unit_interval - 1.0) * amplitude, 8)


def _paired_group_observations(seed: int, effect: float, count: int = 12) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(count):
        base = _stable_noise(seed, "paired-outcome", index)
        rows.append(
            {
                "unit_id": f"c{index:02d}",
                "pair_id": f"p{index:02d}",
                "group": "control",
                "outcome": base,
            }
        )
        rows.append(
            {
                "unit_id": f"t{index:02d}",
                "pair_id": f"p{index:02d}",
                "group": "treatment",
                "outcome": round(base + effect, 8),
            }
        )
    return rows


def generate_synthetic_workflow_tasks(
    seed: int = DEFAULT_CALIBRATION_SEED,
) -> tuple[SyntheticWorkflowTask, ...]:
    """Generate the frozen six-scenario workflow benchmark from a master seed."""

    if isinstance(seed, bool) or not isinstance(seed, int):
        raise CalibrationError("seed must be an integer")
    task_seeds = {scenario: _derived_seed(seed, scenario) for scenario in SYNTHETIC_WORKFLOW_SCENARIOS}
    tasks = (
        SyntheticWorkflowTask(
            "workflow-signal-v1",
            "signal",
            task_seeds["signal"],
            "POSITIVE_SIGNAL",
            "DEMO_RESEARCH_PACKAGE",
            {
                "alpha": 0.05,
                "minimum_effect": 0.8,
                "expected_direction": "positive",
                "permutation_iterations": 4096,
                "unit_of_analysis": "pair_id",
                "resampling_unit": "pair_id",
                "observations": _paired_group_observations(task_seeds["signal"], 1.2),
            },
        ),
        SyntheticWorkflowTask(
            "workflow-null-v1",
            "null",
            task_seeds["null"],
            "NEGATIVE_RESULT",
            "NEGATIVE_RESULT",
            {
                "maximum_abs_effect": 0.01,
                "minimum_p_value": 0.5,
                "permutation_iterations": 4096,
                "unit_of_analysis": "pair_id",
                "resampling_unit": "pair_id",
                "observations": _paired_group_observations(task_seeds["null"], 0.0),
            },
        ),
        SyntheticWorkflowTask(
            "workflow-reversal-v1",
            "reversal",
            task_seeds["reversal"],
            "SIGN_REVERSAL",
            "INCONCLUSIVE",
            {
                "minimum_abs_effect": 0.5,
                "resampling_unit": "pair_id",
                "permutation_iterations": 2048,
                "predeclared_regime_pairs": [["development", "confirmatory"]],
                "regimes": [
                    {
                        "name": "development",
                        "observations": _paired_group_observations(
                            _derived_seed(task_seeds["reversal"], "development"), 1.0, 8
                        ),
                    },
                    {
                        "name": "confirmatory",
                        "observations": _paired_group_observations(
                            _derived_seed(task_seeds["reversal"], "confirmatory"), -0.9, 8
                        ),
                    },
                ],
            },
        ),
        SyntheticWorkflowTask(
            "workflow-leakage-v1",
            "leakage",
            task_seeds["leakage"],
            "INVALID_LEAKAGE",
            "STOP_SCIENTIFIC_INVALIDITY",
            {
                "splits": {
                    "development": ["u01", "u02", "u03"],
                    "confirmatory": ["u03", "u04", "u05"],
                },
                "features": [
                    {"name": "pre_measure", "lineage": ["input"], "timing": "pre_outcome"},
                    {"name": "target_copy", "lineage": ["outcome"], "timing": "post_outcome"},
                ],
            },
        ),
        SyntheticWorkflowTask(
            "workflow-invalid-analysis-v1",
            "invalid-analysis",
            task_seeds["invalid-analysis"],
            "INVALID_ANALYSIS",
            "STOP_SCIENTIFIC_INVALIDITY",
            {
                "unit_of_analysis": "subject_id",
                "resampling_unit": "observation_id",
                "observations": [
                    {"observation_id": "o1", "subject_id": "s1", "outcome": 1.0},
                    {"observation_id": "o2", "subject_id": "s1", "outcome": 1.2},
                    {"observation_id": "o3", "subject_id": "s2", "outcome": 0.8},
                    {"observation_id": "o4", "subject_id": "s2", "outcome": 0.9},
                ],
            },
        ),
        SyntheticWorkflowTask(
            "workflow-corrupted-evidence-v1",
            "corrupted-evidence",
            task_seeds["corrupted-evidence"],
            "CORRUPTED_EVIDENCE",
            "STOP_SCIENTIFIC_INVALIDITY",
            {
                "artifacts": [
                    {
                        "artifact_id": "result-1",
                        "content": {
                            "seed": task_seeds["corrupted-evidence"],
                            "estimate": 0.75,
                        },
                        "declared_sha256": "0" * 64,
                        "parent_artifact_ids": ["missing-protocol"],
                    }
                ]
            },
        ),
    )
    return tasks


def load_synthetic_workflow_tasks(
    fixture_dir: str | Path | None = None,
) -> tuple[SyntheticWorkflowTask, ...]:
    """Load the frozen workflow manifest and materialize its deterministic tasks."""

    directory = _fixture_directory() if fixture_dir is None else Path(fixture_dir)
    document = _safe_json_document(
        directory / "synthetic_workflow_tasks.json",
        expected_file_sha256=WORKFLOW_FIXTURE_SHA256,
    )
    if document.get("schema_version") != SCHEMA_VERSION:
        raise CalibrationError("unsupported workflow fixture schema_version")
    if document.get("fixture_type") != "scientist_one.synthetic_workflow_tasks":
        raise CalibrationError("unexpected workflow fixture_type")
    if document.get("generator") != "scientist_one.calibration.generate_synthetic_workflow_tasks:v3":
        raise CalibrationError("unexpected workflow generator version")
    seed = document.get("seed")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise CalibrationError("workflow fixture seed must be an integer")
    scenarios = document.get("scenarios")
    if scenarios != list(SYNTHETIC_WORKFLOW_SCENARIOS):
        raise CalibrationError("workflow fixture must freeze the required six scenarios in order")
    expected = document.get("expected_decisions")
    if expected != _EXPECTED_WORKFLOW_DECISIONS:
        raise CalibrationError("workflow fixture expected decisions do not match benchmark contract")
    tasks = generate_synthetic_workflow_tasks(seed)
    expected_terminals = document.get("expected_terminal_states")
    if expected_terminals != _EXPECTED_WORKFLOW_TERMINALS:
        raise CalibrationError("workflow fixture terminal states do not match benchmark contract")
    task_set_sha256 = canonical_json_sha256([task.to_dict() for task in tasks])
    if document.get("task_set_sha256") != task_set_sha256:
        raise CalibrationError("workflow generated task-set hash mismatch")
    declared_digest = document.get("generator_contract_sha256")
    contract = {
        "generator": "scientist_one.calibration.generate_synthetic_workflow_tasks:v3",
        "seed": seed,
        "scenarios": list(SYNTHETIC_WORKFLOW_SCENARIOS),
        "expected_decisions": _EXPECTED_WORKFLOW_DECISIONS,
        "expected_terminal_states": _EXPECTED_WORKFLOW_TERMINALS,
        "task_set_sha256": task_set_sha256,
    }
    if declared_digest != canonical_json_sha256(contract):
        raise CalibrationError("workflow generator contract hash mismatch")
    return tasks


def evaluate_synthetic_workflow_task(task: SyntheticWorkflowTask) -> WorkflowTaskResult:
    """Evaluate one workflow task using the same calibrated deterministic checks."""

    if not isinstance(task, SyntheticWorkflowTask):
        raise TypeError("task must be a SyntheticWorkflowTask")
    if task.scenario == "signal":
        outcome = _signal_detector(task.payload, task.seed)
        decision = "POSITIVE_SIGNAL" if outcome.decision == "PLANTED_SIGNAL_RECOVERED" else "NO_SIGNAL"
    elif task.scenario == "null":
        outcome = _null_detector(task.payload, task.seed)
        decision = "NEGATIVE_RESULT" if outcome.decision == "TRUE_NULL_RETAINED" else "FALSE_POSITIVE"
    elif task.scenario == "reversal":
        outcome = _regime_detector(task.payload, task.seed)
        decision = "SIGN_REVERSAL" if outcome.decision == "REGIME_REVERSAL_DETECTED" else "NO_REVERSAL"
    elif task.scenario == "leakage":
        outcome = _leakage_detector(task.payload, task.seed)
        decision = "INVALID_LEAKAGE" if outcome.decision == "LEAKAGE_DETECTED" else "LEAKAGE_MISSED"
    elif task.scenario == "invalid-analysis":
        outcome = _resampling_detector(task.payload, task.seed)
        decision = (
            "INVALID_ANALYSIS"
            if outcome.decision == "INVALID_RESAMPLING_UNIT_DETECTED"
            else "ANALYSIS_ACCEPTED"
        )
    elif task.scenario == "corrupted-evidence":
        outcome = _provenance_detector(task.payload, task.seed)
        decision = (
            "CORRUPTED_EVIDENCE"
            if outcome.decision == "CORRUPTED_PROVENANCE_DETECTED"
            else "EVIDENCE_ACCEPTED"
        )
    else:
        raise CalibrationError(f"unsupported workflow scenario: {task.scenario!r}")
    terminal_by_decision = dict(
        zip(_EXPECTED_WORKFLOW_DECISIONS.values(), _EXPECTED_WORKFLOW_TERMINALS.values(), strict=True)
    )
    terminal_state = terminal_by_decision.get(decision, "INCONCLUSIVE")
    return WorkflowTaskResult(
        task_id=task.task_id,
        scenario=task.scenario,
        expected_decision=task.expected_decision,
        expected_terminal_state=task.expected_terminal_state,
        decision=decision,
        terminal_state=terminal_state,
        passed=(
            decision == task.expected_decision
            and terminal_state == task.expected_terminal_state
        ),
        findings=outcome.findings,
        statistics=outcome.statistics,
    )


def run_synthetic_workflow_benchmark(
    seed: int | None = None,
    fixture_dir: str | Path | None = None,
) -> WorkflowBenchmarkReport:
    """Run all six deterministic workflow scenarios and return a stable report."""

    tasks = load_synthetic_workflow_tasks(fixture_dir)
    if seed is not None and seed != DEFAULT_CALIBRATION_SEED:
        raise CalibrationError("benchmark seed differs from frozen workflow manifest")
    frozen_seed = DEFAULT_CALIBRATION_SEED
    results = tuple(evaluate_synthetic_workflow_task(task) for task in tasks)
    digest = _workflow_report_sha256(frozen_seed, results)
    if digest != FROZEN_WORKFLOW_REPORT_SHA256:
        raise CalibrationGateError("frozen workflow benchmark report digest drift")
    return WorkflowBenchmarkReport(seed=frozen_seed, results=results, report_sha256=digest)


__all__ = [
    "CalibrationCase",
    "CalibrationError",
    "CalibrationGateError",
    "CalibrationReport",
    "CalibrationResult",
    "DEFAULT_CALIBRATION_SEED",
    "Finding",
    "FROZEN_CALIBRATION_REPORT_SHA256",
    "FROZEN_WORKFLOW_REPORT_SHA256",
    "MANDATORY_CASE_KINDS",
    "SYNTHETIC_WORKFLOW_SCENARIOS",
    "SyntheticWorkflowTask",
    "WorkflowBenchmarkReport",
    "WorkflowTaskResult",
    "assert_calibrated",
    "canonical_json_sha256",
    "evaluate_case",
    "evaluate_synthetic_workflow_task",
    "generate_synthetic_workflow_tasks",
    "holm_adjust",
    "load_calibration_cases",
    "load_synthetic_workflow_tasks",
    "run_calibration",
    "run_synthetic_workflow_benchmark",
    "scan_untrusted_research_text",
    "seeded_permutation_test",
]
