"""Bounded, local-only runtime resource accounting.

The controller in this module deliberately separates *observation* from
*enforcement*.  Probes can be replaced by deterministic fakes, while every
decision retains the observations and stable reason codes that led to it.
No probe uses the network and filesystem scans never follow symbolic links.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass, fields
from enum import Enum
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import threading
import time
from typing import Any, Callable, Mapping, Sequence

from .errors import PathSecurityError, UnsafeSerializationError
from .security import read_confined_bytes, safe_json_loads


GIB = 1024**3
DEFAULT_DISK_RESERVE_BYTES = 25 * GIB
DEFAULT_CPU_WORKERS = max(1, (os.cpu_count() or 2) // 2)
MAX_RESOURCE_SCAN_ENTRIES = 100_000


class ResourceConfigError(ValueError):
    """Raised when a resource policy is malformed."""


class ResourceLimitError(RuntimeError):
    """Raised when work cannot be admitted without exceeding policy."""


def _finite_number(value: object, name: str, *, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResourceConfigError(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ResourceConfigError(f"{name} must be finite")
    if minimum is not None and result < minimum:
        raise ResourceConfigError(f"{name} must be at least {minimum}")
    return result


def _positive_int(value: object, name: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResourceConfigError(f"{name} must be an integer")
    lower = 0 if allow_zero else 1
    if value < lower:
        qualifier = "non-negative" if allow_zero else "positive"
        raise ResourceConfigError(f"{name} must be {qualifier}")
    return value


@dataclass(frozen=True)
class ResourceConfig:
    """Frozen resource policy with conservative laptop defaults."""

    schema_version: str = "1.0"
    maximum_wall_clock_seconds: float = 8 * 60 * 60
    maximum_artifact_bytes: int = 2 * GIB
    maximum_concurrent_experiments: int = 2
    cpu_worker_limit: int = DEFAULT_CPU_WORKERS
    gpu_job_limit: int = 1
    memory_soft_fraction: float = 0.60
    memory_hard_fraction: float = 0.70
    minimum_free_disk_bytes: int = DEFAULT_DISK_RESERVE_BYTES
    minimum_free_disk_fraction: float = 0.10
    checkpoint_interval_seconds: float = 5 * 60
    validity_reserve_fraction: float = 0.40
    worker_crash_limit: int = 3
    stall_timeout_seconds: float = 15 * 60
    backoff_initial_seconds: float = 1.0
    backoff_maximum_seconds: float = 60.0
    maximum_artifact_growth_bytes_per_second: float = 64 * 1024**2
    default_device: str = "auto"
    default_dtype: str = "float32"

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ResourceConfigError("schema_version must be a non-empty string")
        _finite_number(self.maximum_wall_clock_seconds, "maximum_wall_clock_seconds", minimum=1)
        _positive_int(self.maximum_artifact_bytes, "maximum_artifact_bytes")
        _positive_int(self.maximum_concurrent_experiments, "maximum_concurrent_experiments")
        _positive_int(self.cpu_worker_limit, "cpu_worker_limit")
        _positive_int(self.gpu_job_limit, "gpu_job_limit")
        soft = _finite_number(self.memory_soft_fraction, "memory_soft_fraction")
        hard = _finite_number(self.memory_hard_fraction, "memory_hard_fraction")
        if not 0 < soft < hard <= 1:
            raise ResourceConfigError(
                "memory fractions must satisfy 0 < memory_soft_fraction "
                "< memory_hard_fraction <= 1"
            )
        _positive_int(self.minimum_free_disk_bytes, "minimum_free_disk_bytes")
        disk_fraction = _finite_number(
            self.minimum_free_disk_fraction, "minimum_free_disk_fraction"
        )
        if not 0 < disk_fraction <= 1:
            raise ResourceConfigError("minimum_free_disk_fraction must be in (0, 1]")
        _finite_number(self.checkpoint_interval_seconds, "checkpoint_interval_seconds", minimum=1)
        reserve = _finite_number(self.validity_reserve_fraction, "validity_reserve_fraction")
        if not 0.30 <= reserve <= 0.50:
            raise ResourceConfigError("validity_reserve_fraction must be in [0.30, 0.50]")
        _positive_int(self.worker_crash_limit, "worker_crash_limit")
        _finite_number(self.stall_timeout_seconds, "stall_timeout_seconds", minimum=1)
        initial = _finite_number(self.backoff_initial_seconds, "backoff_initial_seconds", minimum=0.001)
        maximum = _finite_number(self.backoff_maximum_seconds, "backoff_maximum_seconds", minimum=0.001)
        if initial > maximum:
            raise ResourceConfigError("backoff_initial_seconds cannot exceed backoff_maximum_seconds")
        _finite_number(
            self.maximum_artifact_growth_bytes_per_second,
            "maximum_artifact_growth_bytes_per_second",
            minimum=1,
        )
        if self.default_device not in {"cpu", "mps", "auto"}:
            raise ResourceConfigError("default_device must be cpu, mps, or auto")
        if self.default_dtype != "float32":
            raise ResourceConfigError("default_dtype must be float32 unless separately parity-approved")

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> "ResourceConfig":
        if not isinstance(raw, Mapping):
            raise ResourceConfigError("resource configuration must be a mapping")
        allowed = {item.name for item in fields(cls)}
        unknown = sorted(repr(key) for key in raw if not isinstance(key, str) or key not in allowed)
        if unknown:
            raise ResourceConfigError(f"unknown resource configuration fields: {', '.join(unknown)}")
        return cls(**dict(raw))

    @classmethod
    def from_json(
        cls,
        path: str | os.PathLike[str],
        *,
        project_root: str | os.PathLike[str] | None = None,
        maximum_bytes: int = 1024 * 1024,
    ) -> "ResourceConfig":
        candidate = Path(path)
        if any(part == ".." for part in candidate.parts):
            raise ResourceConfigError("resource configuration path traversal is prohibited")
        # With no explicit root, the canonical current workspace is the
        # narrowest safe default; arbitrary absolute paths are never accepted.
        root = Path(project_root if project_root is not None else Path.cwd()).resolve()
        lexical = Path(os.path.abspath(candidate if candidate.is_absolute() else root / candidate))
        try:
            relative = lexical.relative_to(root)
        except ValueError as exc:
            raise ResourceConfigError("resource configuration escapes project_root") from exc
        _positive_int(maximum_bytes, "maximum_bytes")
        try:
            encoded = read_confined_bytes(
                root,
                relative,
                reject_hardlinks=True,
                max_bytes=maximum_bytes,
            )
            if encoded is None:
                raise PathSecurityError("resource configuration is absent")
            raw = safe_json_loads(encoded, max_bytes=maximum_bytes)
        except (PathSecurityError, UnsafeSerializationError) as exc:
            raise ResourceConfigError(f"cannot read resource configuration: {exc}") from exc
        return cls.from_mapping(raw)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def resource_config_sha256(config: ResourceConfig) -> str:
    """Return the canonical identity of one fully normalized resource policy."""

    if type(config) is not ResourceConfig:
        raise ResourceConfigError("resource configuration hash requires ResourceConfig")
    return hashlib.sha256(
        json.dumps(
            config.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def conservative_disk_reserve(
    total_bytes: int,
    configured_bytes: int = DEFAULT_DISK_RESERVE_BYTES,
    configured_fraction: float = 0.10,
) -> int:
    """Return max(configured bytes, ceil(fraction * total disk))."""

    total = _positive_int(total_bytes, "total_bytes")
    configured = _positive_int(configured_bytes, "configured_bytes")
    fraction = _finite_number(configured_fraction, "configured_fraction")
    if not 0 < fraction <= 1:
        raise ResourceConfigError("configured_fraction must be in (0, 1]")
    return max(configured, math.ceil(total * fraction))


def parse_vm_stat(output: str, physical_memory_bytes: int) -> MemoryObservation:
    """Parse macOS ``vm_stat`` and count safely reclaimable pages as available."""

    if not isinstance(output, str) or not output.strip():
        return MemoryObservation(
            physical_memory_bytes, None, "ERROR", "vm_stat", "empty vm_stat output"
        )
    if isinstance(physical_memory_bytes, bool) or not isinstance(physical_memory_bytes, int):
        return MemoryObservation(None, None, "ERROR", "vm_stat", "invalid physical memory")
    if physical_memory_bytes <= 0:
        return MemoryObservation(None, None, "ERROR", "vm_stat", "invalid physical memory")
    header = output.splitlines()[0]
    page_match = re.search(r"page size of\s+(\d+)\s+bytes", header)
    if page_match is None:
        return MemoryObservation(
            physical_memory_bytes, None, "ERROR", "vm_stat", "page size is missing"
        )
    page_bytes = int(page_match.group(1))
    if page_bytes <= 0:
        return MemoryObservation(
            physical_memory_bytes, None, "ERROR", "vm_stat", "invalid page size"
        )
    pages: dict[str, int] = {}
    for line in output.splitlines()[1:]:
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        match = re.fullmatch(r"\s*([0-9][0-9.]*)\.\s*", raw_value)
        if match is None:
            continue
        try:
            value = int(match.group(1).replace(".", ""))
        except ValueError:
            continue
        pages[key.strip()] = value
    # Free, inactive, speculative, and purgeable pages are reclaimable.  The
    # final clamp prevents malformed or overlapping counters from reporting
    # more available memory than the physical total.
    required = (
        "Pages free",
        "Pages inactive",
        "Pages speculative",
        "Pages purgeable",
    )
    if any(key not in pages for key in required):
        return MemoryObservation(
            physical_memory_bytes,
            None,
            "ERROR",
            "vm_stat",
            "required free/inactive/speculative/purgeable counters are missing",
        )
    available_pages = sum(pages[key] for key in required)
    available_bytes = min(physical_memory_bytes, max(0, available_pages * page_bytes))
    used_bytes = max(0, physical_memory_bytes - available_bytes)
    detail = "available=clamp(free+inactive+speculative+purgeable, physical total)"
    return MemoryObservation(
        physical_memory_bytes,
        used_bytes,
        "AVAILABLE",
        "sysconf+vm_stat",
        detail,
    )


class ResourceAction(str, Enum):
    CONTINUE = "CONTINUE"
    CHECKPOINT = "CHECKPOINT"
    PAUSE = "PAUSE"
    STOP_BUDGET = "STOP_BUDGET"


@dataclass(frozen=True)
class MemoryObservation:
    total_bytes: int | None
    used_bytes: int | None
    status: str
    source: str
    detail: str | None = None


@dataclass(frozen=True)
class PressureObservation:
    thermal: str = "unknown"
    memory: str = "unknown"
    status: str = "UNAVAILABLE"
    source: str = "none"
    detail: str | None = None


@dataclass(frozen=True)
class ResourceSnapshot:
    monotonic_time: float
    wall_elapsed_seconds: float
    artifact_bytes: int
    concurrent_experiments: int
    cpu_workers: int
    gpu_jobs: int
    physical_memory_bytes: int | None
    memory_used_bytes: int | None
    disk_total_bytes: int | None
    disk_free_bytes: int | None
    thermal_pressure: str = "unknown"
    memory_pressure: str = "unknown"
    worker_crashes: int = 0
    stalled_seconds: float = 0.0
    artifact_growth_bytes_per_second: float = 0.0
    probe_notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("monotonic_time", "wall_elapsed_seconds", "stalled_seconds"):
            _finite_number(getattr(self, name), name, minimum=0)
        _finite_number(
            self.artifact_growth_bytes_per_second,
            "artifact_growth_bytes_per_second",
            minimum=0,
        )
        for name in (
            "artifact_bytes",
            "concurrent_experiments",
            "cpu_workers",
            "gpu_jobs",
            "worker_crashes",
        ):
            _positive_int(getattr(self, name), name, allow_zero=True)
        for name in ("physical_memory_bytes", "disk_total_bytes"):
            value = getattr(self, name)
            if value is not None:
                _positive_int(value, name)
        for name in ("memory_used_bytes", "disk_free_bytes"):
            value = getattr(self, name)
            if value is not None:
                _positive_int(value, name, allow_zero=True)
        if self.physical_memory_bytes is not None and self.memory_used_bytes is not None:
            if self.memory_used_bytes > self.physical_memory_bytes:
                raise ResourceConfigError("memory_used_bytes cannot exceed physical_memory_bytes")
        if self.disk_total_bytes is not None and self.disk_free_bytes is not None:
            if self.disk_free_bytes > self.disk_total_bytes:
                raise ResourceConfigError("disk_free_bytes cannot exceed disk_total_bytes")
        allowed_pressure = {
            "unknown",
            "nominal",
            "normal",
            "moderate",
            "warning",
            "serious",
            "severe",
            "critical",
        }
        for name in ("thermal_pressure", "memory_pressure"):
            value = getattr(self, name)
            if not isinstance(value, str) or value.lower() not in allowed_pressure:
                raise ResourceConfigError(f"{name} has an unrecognized pressure status")
        if not isinstance(self.probe_notes, tuple) or any(
            not isinstance(note, str) for note in self.probe_notes
        ):
            raise ResourceConfigError("probe_notes must be a tuple of strings")

    @property
    def memory_fraction(self) -> float | None:
        if self.physical_memory_bytes is None or self.memory_used_bytes is None:
            return None
        return self.memory_used_bytes / self.physical_memory_bytes


@dataclass(frozen=True)
class ResourceDecision:
    action: ResourceAction
    reasons: tuple[str, ...]
    checkpoint_required: bool
    accept_new_work: bool
    stop_budget: bool
    backoff_seconds: float
    effective_disk_reserve_bytes: int | None
    snapshot: ResourceSnapshot

    @property
    def allowed(self) -> bool:
        return self.action in {ResourceAction.CONTINUE, ResourceAction.CHECKPOINT} and self.accept_new_work


@dataclass(frozen=True)
class ValidityBudgetSnapshot:
    total_units: int
    exploratory_limit: int
    confirmatory_reserve: int
    exploratory_used: int
    confirmatory_used: int

    @property
    def exploratory_remaining(self) -> int:
        return self.exploratory_limit - self.exploratory_used

    @property
    def confirmatory_remaining(self) -> int:
        return self.confirmatory_reserve - self.confirmatory_used


class ValidityBudget:
    """Integer accounting that prevents pilot work consuming validity reserve."""

    EXPLORATORY_STAGES = {"CALIBRATE", "IMPLEMENT", "PILOT", "EXPLORATORY"}
    CONFIRMATORY_STAGES = {"CONFIRMATORY", "CONFIRMATORY_RUN", "VALIDITY"}

    def __init__(
        self,
        total_units: int,
        reserve_fraction: float = 0.40,
        *,
        exploratory_used: int = 0,
        confirmatory_used: int = 0,
    ) -> None:
        self.total_units = _positive_int(total_units, "total_units")
        reserve = _finite_number(reserve_fraction, "reserve_fraction")
        if not 0.30 <= reserve <= 0.50:
            raise ResourceConfigError("reserve_fraction must be in [0.30, 0.50]")
        # Floor the exploratory portion so rounding always benefits the reserve.
        self.exploratory_limit = math.floor(total_units * (1.0 - reserve))
        self.confirmatory_reserve = total_units - self.exploratory_limit
        self._exploratory_used = _positive_int(
            exploratory_used, "exploratory_used", allow_zero=True
        )
        self._confirmatory_used = _positive_int(
            confirmatory_used, "confirmatory_used", allow_zero=True
        )
        if self._exploratory_used > self.exploratory_limit:
            raise ResourceConfigError("exploratory_used exceeds the exploratory limit")
        if self._confirmatory_used > self.confirmatory_reserve:
            raise ResourceConfigError("confirmatory_used exceeds the confirmatory reserve")
        self._lock = threading.Lock()

    def snapshot(self) -> ValidityBudgetSnapshot:
        with self._lock:
            return ValidityBudgetSnapshot(
                self.total_units,
                self.exploratory_limit,
                self.confirmatory_reserve,
                self._exploratory_used,
                self._confirmatory_used,
            )

    def can_charge(self, stage: str, units: int) -> bool:
        count = _positive_int(units, "units", allow_zero=True)
        label = str(stage).upper()
        snap = self.snapshot()
        if label in self.EXPLORATORY_STAGES:
            return count <= snap.exploratory_remaining
        if label in self.CONFIRMATORY_STAGES:
            return count <= snap.confirmatory_remaining
        raise ResourceConfigError(f"unknown validity-budget stage: {stage}")

    def charge(self, stage: str, units: int) -> ValidityBudgetSnapshot:
        count = _positive_int(units, "units", allow_zero=True)
        label = str(stage).upper()
        with self._lock:
            if label in self.EXPLORATORY_STAGES:
                if self._exploratory_used + count > self.exploratory_limit:
                    raise ResourceLimitError("VALIDITY_RESERVE_PROTECTED")
                self._exploratory_used += count
            elif label in self.CONFIRMATORY_STAGES:
                if self._confirmatory_used + count > self.confirmatory_reserve:
                    raise ResourceLimitError("CONFIRMATORY_BUDGET_EXHAUSTED")
                self._confirmatory_used += count
            else:
                raise ResourceConfigError(f"unknown validity-budget stage: {stage}")
            return ValidityBudgetSnapshot(
                self.total_units,
                self.exploratory_limit,
                self.confirmatory_reserve,
                self._exploratory_used,
                self._confirmatory_used,
            )


@dataclass(frozen=True)
class ResourceRuntimeState:
    """Persistable accounting state; reconstruction never replenishes budget."""

    schema_version: str
    run_id: str
    config_sha256: str
    wall_elapsed_seconds: float
    checkpoint_elapsed_seconds: float
    progress_elapsed_seconds: float
    worker_crashes: Mapping[str, int]
    wall_started_at_epoch_seconds: float
    wall_observed_at_epoch_seconds: float
    validity_total_units: int | None = None
    exploratory_used: int = 0
    confirmatory_used: int = 0

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ResourceConfigError("unsupported resource runtime-state schema")
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ResourceConfigError("runtime state run_id must be non-empty")
        if not isinstance(self.config_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.config_sha256
        ):
            raise ResourceConfigError("runtime state config_sha256 must be lowercase SHA-256")
        wall = _finite_number(self.wall_elapsed_seconds, "wall_elapsed_seconds", minimum=0)
        checkpoint = _finite_number(
            self.checkpoint_elapsed_seconds, "checkpoint_elapsed_seconds", minimum=0
        )
        progress = _finite_number(
            self.progress_elapsed_seconds, "progress_elapsed_seconds", minimum=0
        )
        if checkpoint > wall or progress > wall:
            raise ResourceConfigError("runtime checkpoint/progress elapsed time exceeds wall time")
        if not isinstance(self.worker_crashes, Mapping):
            raise ResourceConfigError("worker_crashes must be a mapping")
        for key, value in self.worker_crashes.items():
            if not isinstance(key, str) or not key:
                raise ResourceConfigError("worker crash IDs must be non-empty strings")
            _positive_int(value, f"worker_crashes[{key!r}]", allow_zero=True)
        if self.validity_total_units is None:
            if self.exploratory_used or self.confirmatory_used:
                raise ResourceConfigError("validity usage requires validity_total_units")
        else:
            _positive_int(self.validity_total_units, "validity_total_units")
        _positive_int(self.exploratory_used, "exploratory_used", allow_zero=True)
        _positive_int(self.confirmatory_used, "confirmatory_used", allow_zero=True)
        started = _finite_number(
            self.wall_started_at_epoch_seconds,
            "wall_started_at_epoch_seconds",
            minimum=0,
        )
        observed = _finite_number(
            self.wall_observed_at_epoch_seconds,
            "wall_observed_at_epoch_seconds",
            minimum=0,
        )
        if observed < started:
            raise ResourceConfigError("runtime wall-clock observation predates start")
        if not math.isclose(observed - started, wall, rel_tol=0.0, abs_tol=1e-6):
            raise ResourceConfigError("runtime wall elapsed does not match its absolute timestamps")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ResourceRuntimeState":
        if not isinstance(value, Mapping):
            raise ResourceConfigError("resource runtime state must be a mapping")
        allowed = {item.name for item in fields(cls)}
        if set(value) != allowed:
            raise ResourceConfigError("resource runtime state schema is incomplete or unknown")
        return cls(**dict(value))  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["worker_crashes"] = dict(sorted(self.worker_crashes.items()))
        return value

def _default_memory_probe() -> MemoryObservation:
    total: int | None = None
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        pages = os.sysconf("SC_PHYS_PAGES")
        if isinstance(page_size, int) and isinstance(pages, int) and page_size > 0 and pages > 0:
            total = page_size * pages
    except (AttributeError, OSError, ValueError):
        pass

    # vm_stat is a non-mutating macOS probe.  A denied or malformed result is
    # retained as unavailable rather than being converted into a safe-looking 0.
    executable = Path("/usr/bin/vm_stat")
    if executable.exists():
        try:
            result = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=3, check=False
            )
            if result.returncode == 0 and total is not None:
                vm_observation = parse_vm_stat(result.stdout, total)
                if vm_observation.status != "AVAILABLE":
                    return vm_observation
                # `memory_pressure -Q` includes reclaimable compressed/cache
                # categories not exposed as disjoint counters by vm_stat.  Use
                # the larger conservative availability estimate, never more
                # than physical memory.  Failure leaves the validated vm_stat
                # result intact rather than inventing capacity.
                pressure_executable = Path("/usr/bin/memory_pressure")
                if pressure_executable.exists():
                    try:
                        pressure_result = subprocess.run(
                            [str(pressure_executable), "-Q"],
                            capture_output=True,
                            text=True,
                            timeout=3,
                            check=False,
                        )
                        if pressure_result.returncode == 0:
                            match = re.search(
                                r"system-wide memory free percentage:\s*(\d{1,3})%",
                                pressure_result.stdout.lower(),
                            )
                            if match is not None and 0 <= int(match.group(1)) <= 100:
                                free_fraction = int(match.group(1)) / 100.0
                                pressure_used = max(
                                    0, min(total, round(total * (1 - free_fraction)))
                                )
                                vm_used = vm_observation.used_bytes
                                if vm_used is not None and pressure_used < vm_used:
                                    return MemoryObservation(
                                        total,
                                        pressure_used,
                                        "AVAILABLE",
                                        "sysconf+vm_stat+memory_pressure",
                                        (vm_observation.detail or "")
                                        + f"; memory_pressure_free={int(match.group(1))}%",
                                    )
                    except (OSError, subprocess.SubprocessError, ValueError):
                        pass
                return vm_observation
            detail = (result.stderr or result.stdout).strip()[:500] or f"exit {result.returncode}"
            status = "DENIED" if "not permitted" in detail.lower() or "denied" in detail.lower() else "ERROR"
            return MemoryObservation(total, None, status, "vm_stat", detail)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            return MemoryObservation(total, None, "ERROR", "vm_stat", str(exc))

    return MemoryObservation(total, None, "UNAVAILABLE", "stdlib", "used memory probe unavailable")


def _default_pressure_probe() -> PressureObservation:
    observations: list[str] = []

    def query(argv: Sequence[str]) -> tuple[str | None, str]:
        executable = Path(argv[0])
        if not executable.exists():
            return None, "UNAVAILABLE"
        try:
            result = subprocess.run(
                list(argv), capture_output=True, text=True, timeout=3, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            observations.append(f"{' '.join(argv)}: {type(exc).__name__}: {exc}")
            return None, "ERROR"
        combined = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        if result.returncode != 0:
            observations.append(f"{' '.join(argv)}: {combined[:300] or f'exit {result.returncode}'}")
            denied = "denied" in combined.lower() or "not permitted" in combined.lower()
            return None, "DENIED" if denied else "ERROR"
        return combined.lower(), "AVAILABLE"

    thermal_output, thermal_status = query(("/usr/bin/pmset", "-g", "therm"))
    thermal = "unknown"
    if thermal_output is not None:
        # `pmset` error prose contains phrases such as "thermal warning level";
        # parse only successful output and explicit positive state values.
        explicit = re.search(
            r"(?:thermal(?: pressure| warning)?(?: level)?|cpu[_ ]speed[_ ]limit)\s*[:=]\s*"
            r"(nominal|normal|moderate|warning|serious|critical|severe|\d+)",
            thermal_output,
        )
        value = explicit.group(1) if explicit else None
        if value in {"critical", "severe"}:
            thermal = "critical"
        elif value == "serious":
            thermal = "serious"
        elif value in {"moderate", "warning"}:
            thermal = "warning"
        elif value in {"nominal", "normal"}:
            thermal = "nominal"
        elif "no thermal warning" in thermal_output:
            thermal = "nominal"

    memory_output, memory_status = query(("/usr/bin/memory_pressure", "-Q"))
    memory = "unknown"
    if memory_output is not None:
        percentage = re.search(r"memory free percentage:\s*(\d{1,3})%", memory_output)
        if percentage is not None:
            free_percent = int(percentage.group(1))
            if 0 <= free_percent <= 100:
                # This probe is only for severe OS pressure.  Ordinary
                # utilization is enforced independently by memory fractions.
                memory = (
                    "critical"
                    if free_percent <= 5
                    else "serious"
                    if free_percent <= 10
                    else "nominal"
                )
        if memory == "unknown":
            if re.search(r"(?:state|level)\s*[:=]\s*critical", memory_output):
                memory = "critical"
            elif re.search(r"(?:state|level)\s*[:=]\s*(?:warn|serious)", memory_output):
                memory = "serious"
            elif re.search(r"(?:state|level)\s*[:=]\s*normal", memory_output):
                memory = "nominal"

    statuses = {thermal_status, memory_status}
    if "AVAILABLE" in statuses:
        status = "AVAILABLE"
    elif "DENIED" in statuses:
        status = "DENIED"
    elif "ERROR" in statuses:
        status = "ERROR"
    else:
        status = "UNAVAILABLE"
    return PressureObservation(
        thermal=thermal,
        memory=memory,
        status=status,
        source="pmset+memory_pressure",
        detail="; ".join(observations) or None,
    )


def _regular_file_bytes(project_root: Path, relative_root: Path) -> int:
    """Descriptor-walk regular files without following swapped path entries."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        current_fd = os.open(project_root, flags)
    except OSError as exc:
        raise ResourceLimitError(f"cannot pin artifact project root: {exc}") from exc
    try:
        for component in relative_root.parts:
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                return 0
            except OSError as exc:
                raise ResourceLimitError("artifact root contains a link or non-directory") from exc
            os.close(current_fd)
            current_fd = next_fd
        stack = [current_fd]
        current_fd = -1
        total = 0
        scanned_entries = 0
        try:
            while stack:
                directory_fd = stack.pop()
                try:
                    with os.scandir(directory_fd) as entries:
                        names = (entry.name for entry in entries)
                        for name in names:
                            scanned_entries += 1
                            if scanned_entries > MAX_RESOURCE_SCAN_ENTRIES:
                                raise ResourceLimitError(
                                    "artifact scan entry limit exceeded"
                                )
                            if name in {"", ".", ".."} or "/" in name:
                                raise ResourceLimitError(
                                    "artifact tree contains an unsafe name"
                                )
                            try:
                                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                            except OSError as exc:
                                raise ResourceLimitError(
                                    f"cannot inspect artifact entry: {exc}"
                                ) from exc
                            if stat.S_ISDIR(info.st_mode):
                                try:
                                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                                except OSError as exc:
                                    raise ResourceLimitError(
                                        "artifact directory changed or is unsafe"
                                    ) from exc
                                stack.append(child_fd)
                            elif stat.S_ISREG(info.st_mode):
                                total += info.st_size
                            elif stat.S_ISLNK(info.st_mode):
                                continue
                            else:
                                raise ResourceLimitError("artifact tree contains a special file")
                finally:
                    os.close(directory_fd)
        finally:
            for pending_fd in stack:
                os.close(pending_fd)
        return total
    finally:
        if current_fd >= 0:
            os.close(current_fd)

class ResourceLease(AbstractContextManager["ResourceLease"]):
    def __init__(
        self,
        controller: "ResourceController",
        experiment_id: str,
        cpu_workers: int,
        gpu_jobs: int,
        validity_stage: str | None = None,
        validity_units: int = 0,
    ) -> None:
        self._controller = controller
        self.experiment_id = experiment_id
        self.cpu_workers = cpu_workers
        self.gpu_jobs = gpu_jobs
        self.validity_stage = validity_stage
        self.validity_units = validity_units
        self._released = False

    def __enter__(self) -> "ResourceLease":
        return self

    def release(self) -> None:
        if self._released:
            raise ResourceLimitError("resource lease already released")
        self._controller._release(self)
        self._released = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if not self._released:
            self.release()


def _resource_backoff_seconds(config: ResourceConfig, attempt: int) -> float:
    count = _positive_int(attempt, "attempt", allow_zero=True)
    if count == 0:
        return 0.0
    exponent = min(count - 1, 62)
    return min(
        config.backoff_maximum_seconds,
        config.backoff_initial_seconds * (2**exponent),
    )


def _evaluate_resource_policy(
    config: ResourceConfig,
    sample: ResourceSnapshot,
    *,
    effective_cpu_worker_limit: int,
    checkpoint_elapsed: float,
    validity_budget: ValidityBudget | None,
    estimated_artifact_bytes: int = 0,
    requested_experiments: int = 0,
    requested_cpu_workers: int = 0,
    requested_gpu_jobs: int = 0,
    validity_stage: str | None = None,
    validity_units: int = 0,
) -> ResourceDecision:
    """One policy arithmetic owner; evaluation/replay perform no probes here."""
    estimate = _positive_int(estimated_artifact_bytes, "estimated_artifact_bytes", allow_zero=True)
    requested_experiments = _positive_int(
        requested_experiments, "requested_experiments", allow_zero=True
    )
    requested_cpu_workers = _positive_int(
        requested_cpu_workers, "requested_cpu_workers", allow_zero=True
    )
    requested_gpu_jobs = _positive_int(requested_gpu_jobs, "requested_gpu_jobs", allow_zero=True)
    validity_units = _positive_int(validity_units, "validity_units", allow_zero=True)

    stop_reasons: list[str] = []
    pause_reasons: list[str] = []
    checkpoint_reasons: list[str] = []
    reserve: int | None = None

    if sample.wall_elapsed_seconds >= config.maximum_wall_clock_seconds:
        stop_reasons.append("WALL_CLOCK_BUDGET_EXHAUSTED")
    if sample.artifact_bytes + estimate >= config.maximum_artifact_bytes:
        stop_reasons.append("ARTIFACT_BUDGET_EXHAUSTED")

    if sample.disk_total_bytes is None or sample.disk_free_bytes is None:
        pause_reasons.append("DISK_STATUS_UNAVAILABLE")
    else:
        reserve = conservative_disk_reserve(
            sample.disk_total_bytes,
            config.minimum_free_disk_bytes,
            config.minimum_free_disk_fraction,
        )
        if sample.disk_free_bytes - estimate <= reserve:
            stop_reasons.append("DISK_RESERVE_BREACH")

    memory_fraction = sample.memory_fraction
    if memory_fraction is None:
        pause_reasons.append("MEMORY_STATUS_UNAVAILABLE")
    elif memory_fraction >= config.memory_hard_fraction:
        pause_reasons.append("MEMORY_HARD_LIMIT_REACHED")
    elif memory_fraction >= config.memory_soft_fraction:
        pause_reasons.append("MEMORY_SOFT_LIMIT_REACHED")
    if sample.memory_pressure.lower() in {"serious", "critical", "severe", "warning"}:
        pause_reasons.append("SEVERE_MEMORY_PRESSURE")
    if sample.thermal_pressure.lower() in {"serious", "critical", "severe"}:
        pause_reasons.append("SEVERE_THERMAL_PRESSURE")
    if sample.worker_crashes >= config.worker_crash_limit:
        pause_reasons.append("REPEATED_WORKER_CRASHES")
    if sample.stalled_seconds >= config.stall_timeout_seconds:
        pause_reasons.append("WORK_STALLED")
    if (
        sample.artifact_growth_bytes_per_second
        >= config.maximum_artifact_growth_bytes_per_second
    ):
        pause_reasons.append("ABNORMAL_ARTIFACT_GROWTH")

    if (
        sample.concurrent_experiments + requested_experiments
        > config.maximum_concurrent_experiments
    ):
        pause_reasons.append("CONCURRENCY_LIMIT_REACHED")
    if sample.cpu_workers + requested_cpu_workers > effective_cpu_worker_limit:
        pause_reasons.append("CPU_WORKER_LIMIT_REACHED")
    if sample.gpu_jobs + requested_gpu_jobs > config.gpu_job_limit:
        pause_reasons.append("GPU_JOB_LIMIT_REACHED")

    if validity_units:
        if validity_budget is None or validity_stage is None:
            pause_reasons.append("VALIDITY_BUDGET_NOT_CONFIGURED")
        elif not validity_budget.can_charge(validity_stage, validity_units):
            stop_reasons.append(
                "VALIDITY_RESERVE_PROTECTED"
                if validity_stage.upper() in ValidityBudget.EXPLORATORY_STAGES
                else "CONFIRMATORY_BUDGET_EXHAUSTED"
            )

    if (
        sample.wall_elapsed_seconds >= checkpoint_elapsed
        and sample.wall_elapsed_seconds - checkpoint_elapsed
        >= config.checkpoint_interval_seconds
    ):
        checkpoint_reasons.append("CHECKPOINT_INTERVAL_REACHED")

    # Preserve every simultaneous reason while applying deterministic severity.
    reasons = tuple(dict.fromkeys(stop_reasons + pause_reasons + checkpoint_reasons))
    if stop_reasons:
        action = ResourceAction.STOP_BUDGET
        checkpoint_required = True
        accept_new_work = False
    elif pause_reasons:
        action = ResourceAction.PAUSE
        checkpoint_required = any(
            reason
            in {
                "MEMORY_HARD_LIMIT_REACHED",
                "MEMORY_SOFT_LIMIT_REACHED",
                "SEVERE_MEMORY_PRESSURE",
                "SEVERE_THERMAL_PRESSURE",
                "REPEATED_WORKER_CRASHES",
                "WORK_STALLED",
                "ABNORMAL_ARTIFACT_GROWTH",
            }
            for reason in pause_reasons
        )
        accept_new_work = False
    elif checkpoint_reasons:
        action = ResourceAction.CHECKPOINT
        checkpoint_required = True
        accept_new_work = True
    else:
        action = ResourceAction.CONTINUE
        checkpoint_required = False
        accept_new_work = True
    return ResourceDecision(
        action=action,
        reasons=reasons,
        checkpoint_required=checkpoint_required,
        accept_new_work=accept_new_work,
        stop_budget=action is ResourceAction.STOP_BUDGET,
        backoff_seconds=(_resource_backoff_seconds(config, max(1, sample.worker_crashes)) if not accept_new_work else 0.0),
        effective_disk_reserve_bytes=reserve,
        snapshot=sample,
    )


class _ResourceAdmissionRefusal(ResourceLimitError):
    """Actual acquire refusal; the immutable decision is not reconstructed."""
    def __init__(self, controller: "ResourceController", decision: ResourceDecision,
                 request: Mapping[str, object]) -> None:
        super().__init__(",".join(decision.reasons) or decision.action.value)
        self.controller = controller
        self.decision = decision
        self.observation_json = None
        if not {"WORK_STALLED", "REPEATED_WORKER_CRASHES"}.intersection(decision.reasons):
            return
        # Capture context before export can pin its epoch start earlier.
        context = {
            "monotonic_started_at": controller._started_at,
            "monotonic_observed_at": controller._last_observed_at,
            "wall_started_at_before_export": controller._wall_started_at_epoch_seconds,
            "wall_observed_at": controller._wall_observed_at_epoch_seconds,
            "effective_cpu_worker_limit": controller.effective_cpu_worker_limit,
        }
        self.observation_json = json.dumps({
            "request": dict(request), "time_context": context,
            "decision": asdict(decision),
            "runtime_state": controller.export_state().to_dict(),
        }, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _replay_resource_admission(
    config: ResourceConfig, prior: ResourceRuntimeState, observation: Mapping[str, Any],
) -> tuple[ResourceDecision, ResourceRuntimeState]:
    """Validate the saved refusal without constructing/probing a controller."""
    if set(observation) != {"request", "time_context", "decision", "runtime_state"}:
        raise ResourceConfigError("admission observation schema differs")
    request, context, raw_decision = (
        observation["request"], observation["time_context"], observation["decision"]
    )
    if set(request) != {"experiment_id", "cpu_workers", "gpu_jobs",
                        "estimated_artifact_bytes", "validity_stage", "validity_units"}:
        raise ResourceConfigError("admission request schema differs")
    if set(context) != {"monotonic_started_at", "monotonic_observed_at",
                        "wall_started_at_before_export", "wall_observed_at",
                        "effective_cpu_worker_limit"}:
        raise ResourceConfigError("admission time context schema differs")
    cap = _positive_int(context["effective_cpu_worker_limit"], "effective CPU cap")
    if cap > config.cpu_worker_limit:
        raise ResourceConfigError("effective CPU cap exceeds frozen configuration")
    start = _finite_number(context["monotonic_started_at"], "monotonic start")
    now = _finite_number(context["monotonic_observed_at"], "monotonic observation", minimum=0)
    epoch_start = _finite_number(context["wall_started_at_before_export"], "epoch start", minimum=0)
    epoch_now = _finite_number(context["wall_observed_at"], "epoch observation", minimum=0)
    runtime = ResourceRuntimeState.from_mapping(observation["runtime_state"])
    sample_value = dict(raw_decision["snapshot"])
    sample_value["probe_notes"] = tuple(sample_value["probe_notes"])
    sample = ResourceSnapshot(**sample_value)
    if (runtime.run_id != prior.run_id
            or runtime.config_sha256 != prior.config_sha256
            or runtime.config_sha256 != resource_config_sha256(config)
            or runtime.validity_total_units != prior.validity_total_units
            or runtime.exploratory_used != prior.exploratory_used
            or runtime.confirmatory_used != prior.confirmatory_used
            or runtime.worker_crashes != prior.worker_crashes
            or runtime.progress_elapsed_seconds != prior.progress_elapsed_seconds
            or runtime.checkpoint_elapsed_seconds != prior.checkpoint_elapsed_seconds
            or sample.worker_crashes != max(prior.worker_crashes.values(), default=0)
            or (sample.concurrent_experiments, sample.cpu_workers, sample.gpu_jobs) != (0, 0, 0)
            or sample.monotonic_time != now
            or epoch_start > prior.wall_started_at_epoch_seconds
            or epoch_now < prior.wall_observed_at_epoch_seconds
            or sample.wall_elapsed_seconds < prior.wall_elapsed_seconds
            or sample.wall_elapsed_seconds != max(now - start, epoch_now - epoch_start)
            or sample.stalled_seconds != max(0.0, now - start - prior.progress_elapsed_seconds)):
        raise ResourceConfigError("refusal changed prior accounting or observation context")
    # Match export's conservative max/epoch rounding, not a false equality
    # between monotonic stalled duration and rounded persisted elapsed time.
    elapsed = max(now - start, epoch_now - epoch_start,
                  prior.checkpoint_elapsed_seconds, prior.progress_elapsed_seconds)
    effective_start = epoch_now - elapsed
    if epoch_now - effective_start < elapsed:
        effective_start = math.nextafter(effective_start, -math.inf)
    expected_start = min(epoch_start, effective_start)
    if (runtime.wall_started_at_epoch_seconds != expected_start
            or runtime.wall_observed_at_epoch_seconds != epoch_now
            or runtime.wall_elapsed_seconds != epoch_now - expected_start):
        raise ResourceConfigError("refusal export time differs from observed instant")
    budget = None if prior.validity_total_units is None else ValidityBudget(
        prior.validity_total_units, config.validity_reserve_fraction,
        exploratory_used=prior.exploratory_used, confirmatory_used=prior.confirmatory_used,
    )
    decision = _evaluate_resource_policy(
        config, sample, effective_cpu_worker_limit=cap,
        checkpoint_elapsed=prior.checkpoint_elapsed_seconds, validity_budget=budget,
        requested_experiments=1, requested_cpu_workers=request["cpu_workers"],
        requested_gpu_jobs=request["gpu_jobs"],
        estimated_artifact_bytes=request["estimated_artifact_bytes"],
        validity_stage=request["validity_stage"], validity_units=request["validity_units"],
    )
    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if (encode(asdict(decision)) != encode(raw_decision)
            or decision.allowed or not decision.checkpoint_required
            or not {"WORK_STALLED", "REPEATED_WORKER_CRASHES"}.intersection(decision.reasons)):
        raise ResourceConfigError("saved refusal is not the exact qualifying policy decision")
    return decision, runtime


class ResourceController:
    """Thread-safe admission, monitoring, checkpoint, and backoff controller."""

    def __init__(
        self,
        config: ResourceConfig,
        project_root: str | os.PathLike[str],
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        disk_usage_probe: Callable[[str | os.PathLike[str]], Any] = shutil.disk_usage,
        memory_probe: Callable[[], MemoryObservation] = _default_memory_probe,
        pressure_probe: Callable[[], PressureObservation] = _default_pressure_probe,
        artifact_roots: Sequence[str | os.PathLike[str]] | None = None,
        validity_budget_units: int | None = None,
        run_id: str = "runtime",
        restored_state: ResourceRuntimeState | None = None,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        root = Path(project_root)
        if not root.exists() or not root.is_dir():
            raise ResourceConfigError("project_root must be an existing directory")
        if root.is_symlink():
            raise ResourceConfigError("project_root cannot be a symbolic link")
        self.project_root = root.resolve()
        if self.project_root == Path(self.project_root.anchor):
            raise ResourceConfigError("project_root cannot be a filesystem root")
        home = Path.home().resolve()
        if self.project_root in {home, home / "dev", Path("/Users")}:
            raise ResourceConfigError("project_root cannot be a home or broad development directory")
        if not isinstance(run_id, str) or not run_id.strip():
            raise ResourceConfigError("run_id must be a non-empty string")
        self.run_id = run_id
        self.config_sha256 = resource_config_sha256(config)
        if restored_state is not None:
            if not isinstance(restored_state, ResourceRuntimeState):
                raise ResourceConfigError("restored_state must be ResourceRuntimeState")
            if restored_state.run_id != run_id:
                raise ResourceConfigError("restored runtime state run_id mismatch")
            if restored_state.config_sha256 != self.config_sha256:
                raise ResourceConfigError("restored runtime state configuration mismatch")
            if restored_state.validity_total_units != validity_budget_units:
                raise ResourceConfigError("restored runtime validity budget mismatch")
        self._clock = clock
        self._sleeper = sleeper
        self._disk_usage_probe = disk_usage_probe
        self._memory_probe = memory_probe
        self._pressure_probe = pressure_probe
        current_clock = _finite_number(clock(), "initial monotonic clock", minimum=0)
        if not callable(wall_clock):
            raise ResourceConfigError("wall_clock must be callable")
        self._wall_clock = wall_clock
        wall_now = _finite_number(self._wall_clock(), "initial wall clock", minimum=0)
        self._last_observed_at = current_clock
        elapsed = restored_state.wall_elapsed_seconds if restored_state else 0.0
        if restored_state is not None:
            previous_wall = restored_state.wall_observed_at_epoch_seconds
            if wall_now < previous_wall:
                raise ResourceConfigError("absolute wall clock moved backwards across resume")
            elapsed += wall_now - previous_wall
        self._wall_started_at_epoch_seconds = (
            restored_state.wall_started_at_epoch_seconds
            if restored_state is not None
            else wall_now
        )
        self._wall_observed_at_epoch_seconds = wall_now
        self._started_at = current_clock - elapsed
        self._checkpoint_elapsed = (
            restored_state.checkpoint_elapsed_seconds if restored_state else 0.0
        )
        self._progress_elapsed = (
            restored_state.progress_elapsed_seconds if restored_state else 0.0
        )
        self._last_artifact_sample: tuple[float, int] | None = None
        self._leases: dict[str, ResourceLease] = {}
        self._cpu_workers = 0
        self._gpu_jobs = 0
        self._crashes: dict[str, int] = (
            dict(restored_state.worker_crashes) if restored_state else {}
        )
        self._lock = threading.RLock()
        detected_logical_cpus = os.cpu_count()
        conservative_cpu_cap = max(1, (detected_logical_cpus or 2) // 2)
        self.effective_cpu_worker_limit = min(config.cpu_worker_limit, conservative_cpu_cap)
        self.validity_budget = (
            ValidityBudget(
                validity_budget_units,
                config.validity_reserve_fraction,
                exploratory_used=(restored_state.exploratory_used if restored_state else 0),
                confirmatory_used=(restored_state.confirmatory_used if restored_state else 0),
            )
            if validity_budget_units is not None
            else None
        )
        raw_roots: Sequence[str | os.PathLike[str]] = (
            artifact_roots
            if artifact_roots is not None
            else (
                "artifacts",
                "runs",
                "reports",
                ".scientist-one-build/checkpoints",
                ".scientist-one-build/logs",
                ".scientist-one-build/quarantine",
            )
        )
        self.artifact_roots = tuple(self._confined_path(item) for item in raw_roots)

    def export_state(self, now: float | None = None) -> ResourceRuntimeState:
        # Persist the last already-observed monotonic instant by default.  No
        # clock or capacity probe occurs here.  If monotonic time is ahead of
        # epoch time, pin the earlier effective epoch start so later clock
        # catch-up or a restart cannot replenish elapsed wall budget.
        with self._lock:
            current = self._last_observed_at
            if now is not None:
                supplied = _finite_number(now, "runtime state clock", minimum=0)
                if supplied < current:
                    raise ResourceConfigError("monotonic clock moved backwards")
                if supplied != current:
                    raise ResourceConfigError(
                        "export_state cannot advance time; observe it with snapshot, "
                        "mark_checkpoint, or record_progress first"
                    )
            elapsed = current - self._started_at
            wall_observed = self._wall_observed_at_epoch_seconds
            elapsed = max(
                elapsed,
                wall_observed - self._wall_started_at_epoch_seconds,
                self._checkpoint_elapsed,
                self._progress_elapsed,
            )
            effective_start = wall_observed - elapsed
            if wall_observed - effective_start < elapsed:
                # Epoch floats have coarser spacing than monotonic durations.
                # Round the start earlier, never elapsed down or progress back,
                # so serialization cannot replenish budget or reject real work.
                effective_start = math.nextafter(effective_start, -math.inf)
            self._wall_started_at_epoch_seconds = min(
                self._wall_started_at_epoch_seconds,
                effective_start,
            )
            elapsed = wall_observed - self._wall_started_at_epoch_seconds
            validity = self.validity_budget.snapshot() if self.validity_budget else None
            crashes = dict(sorted(self._crashes.items()))
            checkpoint_elapsed = self._checkpoint_elapsed
            progress_elapsed = self._progress_elapsed
        return ResourceRuntimeState(
            schema_version="1.0",
            run_id=self.run_id,
            config_sha256=self.config_sha256,
            wall_elapsed_seconds=elapsed,
            checkpoint_elapsed_seconds=checkpoint_elapsed,
            progress_elapsed_seconds=progress_elapsed,
            worker_crashes=crashes,
            validity_total_units=validity.total_units if validity else None,
            exploratory_used=validity.exploratory_used if validity else 0,
            confirmatory_used=validity.confirmatory_used if validity else 0,
            wall_started_at_epoch_seconds=self._wall_started_at_epoch_seconds,
            wall_observed_at_epoch_seconds=wall_observed,
        )

    @classmethod
    def from_runtime_state(
        cls,
        config: ResourceConfig,
        project_root: str | os.PathLike[str],
        state: ResourceRuntimeState | Mapping[str, object],
        **kwargs: object,
    ) -> "ResourceController":
        restored = (
            state
            if isinstance(state, ResourceRuntimeState)
            else ResourceRuntimeState.from_mapping(state)
        )
        return cls(
            config,
            project_root,
            run_id=restored.run_id,
            validity_budget_units=restored.validity_total_units,
            restored_state=restored,
            **kwargs,  # type: ignore[arg-type]
        )

    def _confined_path(self, value: str | os.PathLike[str]) -> Path:
        candidate = Path(value)
        if any(part == ".." for part in candidate.parts):
            raise ResourceConfigError("path traversal is not allowed")
        if not candidate.is_absolute():
            candidate = self.project_root / candidate
        lexical = Path(os.path.abspath(candidate))
        try:
            relative = lexical.relative_to(self.project_root)
        except ValueError as exc:
            raise ResourceConfigError("path escapes project_root") from exc
        # Reject an already-present unsafe component at construction time for
        # immediate diagnostics.  The descriptor walk remains the authoritative
        # operation-time control against subsequent swaps.
        cursor = self.project_root
        for component in relative.parts:
            cursor /= component
            try:
                mode = cursor.lstat().st_mode
            except FileNotFoundError:
                break
            except OSError as exc:
                raise ResourceConfigError("cannot inspect resource path") from exc
            if stat.S_ISLNK(mode):
                raise ResourceConfigError("resource path cannot traverse a symbolic link")
        return self.project_root / relative

    def artifact_usage(self) -> int:
        return sum(
            _regular_file_bytes(self.project_root, path.relative_to(self.project_root))
            for path in self.artifact_roots
        )

    def checkpoint_due(self, now: float | None = None) -> bool:
        with self._lock:
            current = _finite_number(
                self._clock() if now is None else now,
                "monotonic checkpoint clock",
                minimum=0,
            )
            if current < self._last_observed_at:
                raise ResourceConfigError("monotonic checkpoint time moved backwards")
            self._observe_wall_clock("checkpoint-due wall clock")
            self._last_observed_at = current
            return (
                current - self._started_at - self._checkpoint_elapsed
                >= self.config.checkpoint_interval_seconds
            )

    def observe_wall_time(self) -> ResourceRuntimeState:
        """Advance only the built-in monotonic and absolute wall clocks.

        This intentionally performs no capacity, memory, disk, pressure, or
        artifact probe.  Source owners use it to commit elapsed run time
        without turning an unrelated resource probe into terminal authority.
        """

        with self._lock:
            current = _finite_number(
                self._clock(), "monotonic wall observation clock", minimum=0
            )
            if current < self._last_observed_at:
                raise ResourceConfigError("monotonic wall observation moved backwards")
            self._observe_wall_clock("resource wall observation clock")
            self._last_observed_at = current
            return self.export_state()

    def _observe_wall_clock(self, label: str) -> float:
        observed = _finite_number(self._wall_clock(), label, minimum=0)
        if observed < self._wall_observed_at_epoch_seconds:
            raise ResourceConfigError("absolute wall clock moved backwards")
        self._wall_observed_at_epoch_seconds = observed
        return observed

    def mark_checkpoint(self, now: float | None = None) -> None:
        with self._lock:
            current = _finite_number(
                self._clock() if now is None else now,
                "monotonic checkpoint clock",
                minimum=0,
            )
            if current < self._last_observed_at:
                raise ResourceConfigError("monotonic checkpoint time moved backwards")
            self._observe_wall_clock("checkpoint wall clock")
            self._checkpoint_elapsed = max(
                self._checkpoint_elapsed, current - self._started_at
            )
            self._last_observed_at = current

    def record_progress(self, now: float | None = None) -> None:
        with self._lock:
            current = _finite_number(
                self._clock() if now is None else now,
                "monotonic progress clock",
                minimum=0,
            )
            if current < self._last_observed_at:
                raise ResourceConfigError("monotonic progress time moved backwards")
            self._observe_wall_clock("progress wall clock")
            self._progress_elapsed = max(
                self._progress_elapsed, current - self._started_at
            )
            self._last_observed_at = current

    def register_worker_crash(self, worker_id: str = "default") -> int:
        if not isinstance(worker_id, str) or not worker_id.strip():
            raise ResourceConfigError("worker_id must be non-empty")
        with self._lock:
            self._crashes[worker_id] = self._crashes.get(worker_id, 0) + 1
            return self._crashes[worker_id]

    def clear_worker_crashes(self, worker_id: str = "default") -> None:
        with self._lock:
            self._crashes.pop(worker_id, None)

    def charge_validity(self, stage: str, units: int) -> ValidityBudgetSnapshot:
        """Atomically consume validity budget or fail without partial charge."""

        if self.validity_budget is None:
            raise ResourceLimitError("VALIDITY_BUDGET_NOT_CONFIGURED")
        with self._lock:
            return self.validity_budget.charge(stage, units)

    def backoff_seconds(self, attempt: int) -> float:
        return _resource_backoff_seconds(self.config, attempt)

    def sleep_backoff(self, attempt: int) -> float:
        delay = self.backoff_seconds(attempt)
        if delay > 0:
            self._sleeper(delay)
        return delay

    def _probe_disk(self) -> tuple[int | None, int | None, str | None]:
        try:
            usage = self._disk_usage_probe(self.project_root)
            total = int(usage.total)
            free = int(usage.free)
            if total <= 0 or free < 0 or free > total:
                raise ValueError("invalid disk usage values")
            return total, free, None
        except Exception as exc:
            return None, None, f"disk probe unavailable: {exc}"

    def snapshot(self, now: float | None = None) -> ResourceSnapshot:
        with self._lock:
            current = _finite_number(
                self._clock() if now is None else now,
                "monotonic snapshot clock",
                minimum=0,
            )
            if current < self._last_observed_at:
                raise ResourceConfigError("monotonic clock moved backwards")
            wall_observed = self._observe_wall_clock("snapshot wall clock")
            self._last_observed_at = current
            elapsed = max(
                current - self._started_at,
                wall_observed - self._wall_started_at_epoch_seconds,
            )
        notes: list[str] = []
        try:
            memory = self._memory_probe()
            if not isinstance(memory, MemoryObservation):
                raise TypeError("memory probe returned an invalid observation")
        except Exception as exc:
            memory = MemoryObservation(None, None, "ERROR", "memory_probe", str(exc))
        if memory.status != "AVAILABLE":
            notes.append(f"memory:{memory.status}:{memory.detail or memory.source}")
        try:
            pressure = self._pressure_probe()
            if not isinstance(pressure, PressureObservation):
                raise TypeError("pressure probe returned an invalid observation")
            if not isinstance(pressure.thermal, str) or not isinstance(pressure.memory, str):
                raise TypeError("pressure values must be strings")
        except Exception as exc:
            pressure = PressureObservation(detail=f"pressure probe failed: {exc}", status="ERROR")
        if pressure.status != "AVAILABLE":
            notes.append(f"pressure:{pressure.status}:{pressure.detail or pressure.source}")
        disk_total, disk_free, disk_note = self._probe_disk()
        if disk_note:
            notes.append(disk_note)
        try:
            artifact_bytes = self.artifact_usage()
        except (OSError, ResourceLimitError, ResourceConfigError) as exc:
            # Unknown artifact use can never be interpreted as spare capacity.
            artifact_bytes = self.config.maximum_artifact_bytes
            notes.append(f"artifacts:ERROR:{exc}")
        growth = 0.0
        if self._last_artifact_sample is not None:
            previous_time, previous_bytes = self._last_artifact_sample
            interval = current - previous_time
            if interval >= 1.0 and artifact_bytes > previous_bytes:
                growth = (artifact_bytes - previous_bytes) / interval
        self._last_artifact_sample = (current, artifact_bytes)
        with self._lock:
            crashes = max(self._crashes.values(), default=0)
            experiments = len(self._leases)
            cpu_workers = self._cpu_workers
            gpu_jobs = self._gpu_jobs
        return ResourceSnapshot(
            monotonic_time=current,
            wall_elapsed_seconds=elapsed,
            artifact_bytes=artifact_bytes,
            concurrent_experiments=experiments,
            cpu_workers=cpu_workers,
            gpu_jobs=gpu_jobs,
            physical_memory_bytes=memory.total_bytes,
            memory_used_bytes=memory.used_bytes,
            disk_total_bytes=disk_total,
            disk_free_bytes=disk_free,
            thermal_pressure=pressure.thermal.lower(),
            memory_pressure=pressure.memory.lower(),
            worker_crashes=crashes,
            stalled_seconds=max(0.0, current - self._started_at - self._progress_elapsed),
            artifact_growth_bytes_per_second=growth,
            probe_notes=tuple(notes),
        )

    def evaluate(
        self,
        snapshot: ResourceSnapshot | None = None,
        *,
        estimated_artifact_bytes: int = 0,
        requested_experiments: int = 0,
        requested_cpu_workers: int = 0,
        requested_gpu_jobs: int = 0,
        validity_stage: str | None = None,
        validity_units: int = 0,
    ) -> ResourceDecision:
        return _evaluate_resource_policy(
            self.config, snapshot or self.snapshot(),
            effective_cpu_worker_limit=self.effective_cpu_worker_limit,
            checkpoint_elapsed=self._checkpoint_elapsed,
            validity_budget=self.validity_budget,
            estimated_artifact_bytes=estimated_artifact_bytes,
            requested_experiments=requested_experiments,
            requested_cpu_workers=requested_cpu_workers,
            requested_gpu_jobs=requested_gpu_jobs,
            validity_stage=validity_stage, validity_units=validity_units,
        )

    def acquire(
        self,
        experiment_id: str,
        *,
        cpu_workers: int = 1,
        gpu_jobs: int = 0,
        estimated_artifact_bytes: int = 0,
        validity_stage: str | None = None,
        validity_units: int = 0,
    ) -> ResourceLease:
        if not isinstance(experiment_id, str) or not experiment_id.strip():
            raise ResourceConfigError("experiment_id must be non-empty")
        workers = _positive_int(cpu_workers, "cpu_workers")
        gpu = _positive_int(gpu_jobs, "gpu_jobs", allow_zero=True)
        validity_count = _positive_int(validity_units, "validity_units", allow_zero=True)
        if validity_count and not isinstance(validity_stage, str):
            raise ResourceConfigError("validity_stage is required when validity_units are requested")
        with self._lock:
            if experiment_id in self._leases:
                raise ResourceLimitError("experiment already holds a resource lease")
            decision = self.evaluate(
                estimated_artifact_bytes=estimated_artifact_bytes,
                requested_experiments=1,
                requested_cpu_workers=workers,
                requested_gpu_jobs=gpu,
                validity_stage=validity_stage,
                validity_units=validity_count,
            )
            if not decision.allowed:
                if {"WORK_STALLED", "REPEATED_WORKER_CRASHES"}.intersection(decision.reasons):
                    raise _ResourceAdmissionRefusal(self, decision, {
                        "experiment_id": experiment_id, "cpu_workers": workers,
                        "gpu_jobs": gpu, "estimated_artifact_bytes": estimated_artifact_bytes,
                        "validity_stage": validity_stage, "validity_units": validity_count,
                    })
                raise ResourceLimitError(",".join(decision.reasons) or decision.action.value)
            if validity_count:
                self.charge_validity(str(validity_stage), validity_count)
            lease = ResourceLease(
                self,
                experiment_id,
                workers,
                gpu,
                validity_stage,
                validity_count,
            )
            self._leases[experiment_id] = lease
            self._cpu_workers += workers
            self._gpu_jobs += gpu
            return lease

    def _release(self, lease: ResourceLease) -> None:
        with self._lock:
            current = self._leases.get(lease.experiment_id)
            if current is not lease:
                raise ResourceLimitError("unknown or mismatched resource lease")
            if self._cpu_workers < lease.cpu_workers or self._gpu_jobs < lease.gpu_jobs:
                raise ResourceLimitError("resource counter underflow")
            del self._leases[lease.experiment_id]
            self._cpu_workers -= lease.cpu_workers
            self._gpu_jobs -= lease.gpu_jobs


__all__ = [
    "DEFAULT_CPU_WORKERS",
    "DEFAULT_DISK_RESERVE_BYTES",
    "MemoryObservation",
    "PressureObservation",
    "ResourceAction",
    "ResourceConfig",
    "ResourceConfigError",
    "ResourceController",
    "ResourceDecision",
    "ResourceLease",
    "ResourceLimitError",
    "ResourceRuntimeState",
    "ResourceSnapshot",
    "ValidityBudget",
    "ValidityBudgetSnapshot",
    "conservative_disk_reserve",
    "parse_vm_stat",
    "resource_config_sha256",
]
