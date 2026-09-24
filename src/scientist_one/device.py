"""Conservative CPU/MPS selection and non-mutating hardware profiling.

MPS is an optimization, never an assumption.  Selection requires an installed
backend, build/runtime capability, operation support, and a finite float32
CPU-versus-MPS parity result under a frozen tolerance.  Every failure cleanly
selects CPU and remains visible as capability evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.metadata
import importlib.util
import math
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import subprocess
import sys
from typing import Any, Callable, Mapping, Protocol, Sequence

from .errors import PathSecurityError
from .security import (
    atomic_write_bytes,
    canonical_json_bytes,
    read_confined_bytes,
    safe_json_loads,
    secure_directory,
)


class DeviceConfigurationError(ValueError):
    """Raised when a requested device or numerical policy is unsafe."""


class DeviceExecutionError(RuntimeError):
    """Raised when a frozen execution cannot safely change devices."""


class DeviceBackend(Protocol):
    """Narrow adapter implemented by optional, already-installed frameworks."""

    name: str
    version: str | None

    def is_mps_built(self) -> bool: ...

    def is_mps_available(self) -> bool: ...

    def supports_operation(self, operation: str) -> bool: ...

    def run(
        self, *, device: str, operation: str, values: object, dtype: str
    ) -> object: ...


@dataclass(frozen=True)
class ParityTolerance:
    """Frozen elementwise tolerance: abs(a-b) <= atol + rtol*abs(cpu)."""

    atol: float = 1e-5
    rtol: float = 1e-5

    def __post_init__(self) -> None:
        for name, value in (("atol", self.atol), ("rtol", self.rtol)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise DeviceConfigurationError(f"{name} must be numeric")
            if not math.isfinite(float(value)) or value < 0:
                raise DeviceConfigurationError(f"{name} must be finite and non-negative")


@dataclass(frozen=True)
class DeviceCapabilities:
    framework: str | None
    framework_version: str | None
    framework_installed: bool
    mps_built: bool
    mps_available: bool
    operation: str
    operation_supported: bool
    probe_status: str
    evidence: tuple[str, ...] = ()
    reproducibility_limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["evidence"] = list(self.evidence)
        data["reproducibility_limitations"] = list(self.reproducibility_limitations)
        return data


@dataclass(frozen=True)
class ParityResult:
    passed: bool
    reason: str
    tolerance: ParityTolerance
    fixture_sha256: str
    shape: tuple[int, ...] | None
    maximum_absolute_error: float | None
    maximum_relative_error: float | None
    cpu_output_sha256: str | None = None
    mps_output_sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["shape"] = list(self.shape) if self.shape is not None else None
        return data


@dataclass(frozen=True)
class DeviceSelection:
    requested: str
    selected: str
    dtype: str
    operation: str
    parity_passed: bool
    fallback_reason: str | None
    capabilities: DeviceCapabilities
    parity: ParityResult | None
    implementation_sha256: str | None = None
    execution_binding_sha256: str | None = None

    @property
    def is_accelerated(self) -> bool:
        return self.selected == "mps"

    def to_dict(self) -> dict[str, object]:
        return {
            "requested": self.requested,
            "selected": self.selected,
            "dtype": self.dtype,
            "operation": self.operation,
            "parity_passed": self.parity_passed,
            "fallback_reason": self.fallback_reason,
            "capabilities": self.capabilities.to_dict(),
            "reproducibility_limitations": list(
                self.capabilities.reproducibility_limitations
            ),
            "parity": self.parity.to_dict() if self.parity else None,
            "implementation_sha256": self.implementation_sha256,
            "execution_binding_sha256": self.execution_binding_sha256,
        }


@dataclass(frozen=True)
class DeviceExecution:
    value: object
    device_used: str
    fallback_reason: str | None = None


def _canonical_json_bytes(value: object) -> bytes:
    return canonical_json_bytes(value)


def _immutable(value: object) -> object:
    if isinstance(value, (list, tuple)):
        return tuple(_immutable(item) for item in value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if not math.isfinite(number):
            raise DeviceConfigurationError("parity fixture values must be finite")
        return number
    raise DeviceConfigurationError("parity fixture must contain only nested numeric sequences")


def _tolist(value: object) -> object:
    current = value
    # Torch-like objects are intentionally handled by behavior, without a hard
    # framework dependency.
    for method_name in ("detach", "cpu"):
        method = getattr(current, method_name, None)
        if callable(method):
            current = method()
    method = getattr(current, "tolist", None)
    if callable(method):
        current = method()
    return current


def _shape_and_flatten(value: object) -> tuple[tuple[int, ...], tuple[float, ...]]:
    current = _tolist(value)
    if isinstance(current, bool):
        raise DeviceConfigurationError("boolean parity output is not numeric")
    if isinstance(current, (int, float)):
        number = float(current)
        if not math.isfinite(number):
            raise DeviceConfigurationError("parity output contains NaN or infinity")
        return (), (number,)
    if not isinstance(current, (list, tuple)):
        raise DeviceConfigurationError("parity output is not a numeric sequence")
    children = [_shape_and_flatten(item) for item in current]
    if not children:
        return (0,), ()
    child_shape = children[0][0]
    if any(shape != child_shape for shape, _ in children):
        raise DeviceConfigurationError("parity output is ragged")
    flattened: list[float] = []
    for _, values in children:
        flattened.extend(values)
    return (len(children),) + child_shape, tuple(flattened)


class TorchMPSBackend:
    """Optional PyTorch adapter; it never installs or downloads anything."""

    name = "torch"
    SUPPORTED_OPERATIONS = {"basic_arithmetic", "matrix_multiply"}

    def __init__(self, torch_module: object) -> None:
        self._torch = torch_module
        self.version = str(getattr(torch_module, "__version__", "unknown"))

    def is_mps_built(self) -> bool:
        mps = getattr(getattr(self._torch, "backends", None), "mps", None)
        method = getattr(mps, "is_built", None)
        return bool(method()) if callable(method) else False

    def is_mps_available(self) -> bool:
        mps = getattr(getattr(self._torch, "backends", None), "mps", None)
        method = getattr(mps, "is_available", None)
        return bool(method()) if callable(method) else False

    def supports_operation(self, operation: str) -> bool:
        return operation in self.SUPPORTED_OPERATIONS

    def run(self, *, device: str, operation: str, values: object, dtype: str) -> object:
        if dtype != "float32":
            raise DeviceConfigurationError("TorchMPSBackend only permits float32")
        tensor = self._torch.tensor(values, dtype=self._torch.float32, device=device)
        if operation == "basic_arithmetic":
            return tensor * tensor + tensor * 0.25 - 1.0
        if operation == "matrix_multiply":
            if getattr(tensor, "ndim", 0) != 2:
                raise DeviceConfigurationError("matrix_multiply parity fixture must be rank 2")
            return tensor @ tensor.transpose(0, 1)
        raise DeviceConfigurationError(f"unsupported parity operation: {operation}")


def _discover_torch_backend(
    project_root: str | os.PathLike[str] | None = None,
) -> tuple[DeviceBackend | None, tuple[str, ...]]:
    evidence: list[str] = []
    try:
        spec = importlib.util.find_spec("torch")
    except (ImportError, ValueError) as exc:
        return None, (f"torch discovery failed: {type(exc).__name__}: {exc}",)
    if spec is None:
        return None, ("torch is not installed",)
    if project_root is not None:
        root = Path(project_root).resolve()
        locations: list[Path] = []
        if spec.origin and spec.origin not in {"built-in", "frozen"}:
            locations.append(Path(spec.origin).resolve(strict=False))
        if spec.submodule_search_locations:
            locations.extend(
                Path(location).resolve(strict=False)
                for location in spec.submodule_search_locations
            )
        for location in locations:
            try:
                location.relative_to(root)
            except ValueError:
                continue
            return None, (
                "torch candidate resolves inside project_root and was rejected without import",
            )
        try:
            distribution = importlib.metadata.distribution("torch")
            installed_root = Path(distribution.locate_file(".")).resolve(strict=False)
            if not any(
                location == installed_root or installed_root in location.parents
                for location in locations
            ):
                return None, (
                    "torch import spec is not bound to installed distribution provenance",
                )
        except importlib.metadata.PackageNotFoundError:
            return None, ("torch import candidate has no installed distribution metadata",)
        except Exception as exc:
            return None, (
                f"torch distribution provenance failed: {type(exc).__name__}: {exc}",
            )
    # Discovery must never execute a project-local package.  Only adapt a
    # framework already imported by trusted application startup; callers may
    # also inject an explicit backend.  Importing by name here would reopen a
    # sys.path race after the provenance checks above.
    if "torch" not in sys.modules:
        return None, tuple(evidence) + (
            "torch is installed but not preloaded; automatic import is disabled",
        )
    try:
        module = sys.modules["torch"]
        module_origin = getattr(module, "__file__", None)
        if not isinstance(module_origin, str) or not module_origin:
            raise DeviceConfigurationError("preloaded torch has no verifiable origin")
        if project_root is not None:
            try:
                Path(module_origin).resolve(strict=False).relative_to(Path(project_root).resolve())
            except ValueError:
                pass
            else:
                raise DeviceConfigurationError("preloaded torch resolves inside project_root")
        evidence.append("torch imported from an already-installed local package")
        return TorchMPSBackend(module), tuple(evidence)
    except Exception as exc:  # optional frameworks can fail for platform reasons
        return None, (f"torch import failed: {type(exc).__name__}: {exc}",)


class DeviceManager:
    """Select cpu/mps/auto with mandatory, operation-specific parity."""

    DEFAULT_FIXTURE = ((0.0, 1.0, -2.0), (3.5, -0.25, 8.0))
    MPS_REPRODUCIBILITY_LIMITATIONS = (
        "float32 parity covers only the frozen fixture and tolerance, not every runtime input",
        "MPS kernel availability and determinism can vary with framework and macOS versions",
        "a frozen confirmatory MPS failure cannot silently fall back to CPU",
    )

    def __init__(
        self,
        preference: str = "auto",
        dtype: str = "float32",
        *,
        backend: DeviceBackend | None = None,
        tolerance: ParityTolerance = ParityTolerance(),
        project_root: str | os.PathLike[str] | None = None,
    ) -> None:
        requested = str(preference).lower()
        if requested not in {"cpu", "mps", "auto"}:
            raise DeviceConfigurationError("device must be cpu, mps, or auto; CUDA is unsupported")
        if dtype != "float32":
            raise DeviceConfigurationError(
                "float32 is required; reduced precision needs a separate equivalence protocol"
            )
        self.preference = requested
        self.dtype = dtype
        self.tolerance = tolerance
        discovery_root = (
            Path.cwd().resolve()
            if project_root is None
            else Path(project_root).resolve()
        )
        self._discovery_evidence: tuple[str, ...] = ()
        self._issued_mps_selections: list[DeviceSelection] = []
        self._prepared_executions: dict[
            int, tuple[Callable[[object], object], Callable[[object], object]]
        ] = {}
        if backend is None:
            if requested == "cpu":
                self._discovery_evidence = (
                    "CPU requested; optional accelerator framework was not imported",
                )
            else:
                backend, evidence = _discover_torch_backend(discovery_root)
                self._discovery_evidence = evidence
        self.backend = backend

    def probe_capabilities(self, operation: str = "basic_arithmetic") -> DeviceCapabilities:
        if not isinstance(operation, str) or not operation:
            raise DeviceConfigurationError("operation must be a non-empty string")
        if self.backend is None:
            return DeviceCapabilities(
                framework=None,
                framework_version=None,
                framework_installed=False,
                mps_built=False,
                mps_available=False,
                operation=operation,
                operation_supported=False,
                probe_status="UNAVAILABLE",
                evidence=self._discovery_evidence or ("no optional MPS backend installed",),
                reproducibility_limitations=self.MPS_REPRODUCIBILITY_LIMITATIONS,
            )
        evidence = list(self._discovery_evidence)
        try:
            built = bool(self.backend.is_mps_built())
            available = bool(self.backend.is_mps_available())
            supported = bool(self.backend.supports_operation(operation))
            evidence.extend(
                (
                    f"backend={self.backend.name}",
                    f"mps_built={built}",
                    f"mps_available={available}",
                    f"operation_supported={supported}",
                )
            )
            return DeviceCapabilities(
                framework=str(self.backend.name),
                framework_version=(
                    str(self.backend.version) if self.backend.version is not None else None
                ),
                framework_installed=True,
                mps_built=built,
                mps_available=available,
                operation=operation,
                operation_supported=supported,
                probe_status="AVAILABLE",
                evidence=tuple(evidence),
                reproducibility_limitations=self.MPS_REPRODUCIBILITY_LIMITATIONS,
            )
        except Exception as exc:
            evidence.append(f"capability probe failed: {type(exc).__name__}: {exc}")
            return DeviceCapabilities(
                framework=str(getattr(self.backend, "name", "unknown")),
                framework_version=(
                    str(getattr(self.backend, "version", "unknown"))
                    if getattr(self.backend, "version", None) is not None
                    else None
                ),
                framework_installed=True,
                mps_built=False,
                mps_available=False,
                operation=operation,
                operation_supported=False,
                probe_status="ERROR",
                evidence=tuple(evidence),
                reproducibility_limitations=self.MPS_REPRODUCIBILITY_LIMITATIONS,
            )

    def _parity_from_outputs(
        self,
        *,
        fixture: object,
        cpu_raw: object,
        mps_raw: object,
        tolerance: ParityTolerance,
    ) -> ParityResult:
        frozen_fixture = _immutable(fixture)
        fixture_shape, fixture_values = _shape_and_flatten(frozen_fixture)
        fixture_hash = hashlib.sha256(_canonical_json_bytes(frozen_fixture)).hexdigest()
        if not fixture_values:
            return ParityResult(
                False,
                "EMPTY_PARITY_FIXTURE",
                tolerance,
                fixture_hash,
                fixture_shape,
                None,
                None,
            )
        cpu_shape, cpu_values = _shape_and_flatten(cpu_raw)
        mps_shape, mps_values = _shape_and_flatten(mps_raw)
        cpu_hash = hashlib.sha256(_canonical_json_bytes(cpu_values)).hexdigest()
        mps_hash = hashlib.sha256(_canonical_json_bytes(mps_values)).hexdigest()
        if cpu_shape != mps_shape:
            return ParityResult(
                False,
                "OUTPUT_SHAPE_MISMATCH",
                tolerance,
                fixture_hash,
                cpu_shape,
                None,
                None,
                cpu_hash,
                mps_hash,
            )
        if not cpu_values or not mps_values:
            return ParityResult(
                False,
                "EMPTY_PARITY_OUTPUT",
                tolerance,
                fixture_hash,
                cpu_shape,
                None,
                None,
                cpu_hash,
                mps_hash,
            )
        maximum_absolute = 0.0
        maximum_relative = 0.0
        passed = True
        for cpu, mps in zip(cpu_values, mps_values, strict=True):
            absolute = abs(cpu - mps)
            relative = absolute / abs(cpu) if cpu != 0 else absolute
            maximum_absolute = max(maximum_absolute, absolute)
            maximum_relative = max(maximum_relative, relative)
            if absolute > tolerance.atol + tolerance.rtol * abs(cpu):
                passed = False
        return ParityResult(
            passed,
            "PARITY_PASSED" if passed else "NUMERICAL_TOLERANCE_EXCEEDED",
            tolerance,
            fixture_hash,
            cpu_shape,
            maximum_absolute,
            maximum_relative,
            cpu_hash,
            mps_hash,
        )

    def validate_mps_parity(
        self,
        operation: str = "basic_arithmetic",
        fixture: object = DEFAULT_FIXTURE,
        *,
        tolerance: ParityTolerance | None = None,
    ) -> ParityResult:
        frozen_fixture = _immutable(fixture)
        fixture_shape, fixture_values = _shape_and_flatten(frozen_fixture)
        fixture_hash = hashlib.sha256(_canonical_json_bytes(frozen_fixture)).hexdigest()
        accepted = tolerance or self.tolerance
        if not fixture_values:
            return ParityResult(
                False,
                "EMPTY_PARITY_FIXTURE",
                accepted,
                fixture_hash,
                fixture_shape,
                None,
                None,
            )
        if self.backend is None:
            return ParityResult(
                False,
                "MPS_BACKEND_UNAVAILABLE",
                accepted,
                fixture_hash,
                None,
                None,
                None,
            )
        try:
            cpu_raw = self.backend.run(
                device="cpu", operation=operation, values=frozen_fixture, dtype=self.dtype
            )
            mps_raw = self.backend.run(
                device="mps", operation=operation, values=frozen_fixture, dtype=self.dtype
            )
            return self._parity_from_outputs(
                fixture=frozen_fixture,
                cpu_raw=cpu_raw,
                mps_raw=mps_raw,
                tolerance=accepted,
            )
        except Exception as exc:
            return ParityResult(
                False,
                f"PARITY_EXECUTION_FAILED:{type(exc).__name__}:{exc}",
                accepted,
                fixture_hash,
                None,
                None,
                None,
            )

    def select(
        self,
        operation: str = "basic_arithmetic",
        fixture: object = DEFAULT_FIXTURE,
    ) -> DeviceSelection:
        capabilities = self.probe_capabilities(operation)
        if self.preference == "cpu":
            return DeviceSelection(
                requested="cpu",
                selected="cpu",
                dtype=self.dtype,
                operation=operation,
                parity_passed=False,
                fallback_reason=None,
                capabilities=capabilities,
                parity=None,
            )
        reason: str | None = None
        if not capabilities.framework_installed:
            reason = "MPS_BACKEND_UNAVAILABLE"
        elif capabilities.probe_status != "AVAILABLE":
            reason = "MPS_CAPABILITY_PROBE_FAILED"
        elif not capabilities.mps_built:
            reason = "MPS_NOT_BUILT"
        elif not capabilities.mps_available:
            reason = "MPS_NOT_AVAILABLE"
        elif not capabilities.operation_supported:
            reason = "MPS_OPERATION_UNSUPPORTED"
        if reason is not None:
            return DeviceSelection(
                requested=self.preference,
                selected="cpu",
                dtype=self.dtype,
                operation=operation,
                parity_passed=False,
                fallback_reason=reason,
                capabilities=capabilities,
                parity=None,
            )
        parity = self.validate_mps_parity(operation, fixture)
        if not parity.passed:
            return DeviceSelection(
                requested=self.preference,
                selected="cpu",
                dtype=self.dtype,
                operation=operation,
                parity_passed=False,
                fallback_reason=parity.reason,
                capabilities=capabilities,
                parity=parity,
            )
        selection = DeviceSelection(
            requested=self.preference,
            selected="mps",
            dtype=self.dtype,
            operation=operation,
            parity_passed=True,
            fallback_reason=None,
            capabilities=capabilities,
            parity=parity,
        )
        self._issued_mps_selections.append(selection)
        return selection

    def prepare_execution(
        self,
        operation: str,
        fixture: object,
        *,
        implementation_sha256: str,
        cpu_callable: Callable[[object], object],
        mps_callable: Callable[[object], object],
    ) -> DeviceSelection:
        """Issue MPS evidence bound to exact frozen implementation callables."""

        if not isinstance(implementation_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", implementation_sha256
        ):
            raise DeviceConfigurationError("implementation_sha256 must be lowercase SHA-256")
        if not callable(cpu_callable) or not callable(mps_callable):
            raise DeviceConfigurationError("prepared execution callables must be callable")
        frozen_fixture = _immutable(fixture)
        selection = self.select(operation, frozen_fixture)
        if selection.selected != "mps" or selection.parity is None:
            return selection
        try:
            exact_parity = self._parity_from_outputs(
                fixture=frozen_fixture,
                cpu_raw=cpu_callable(frozen_fixture),
                mps_raw=mps_callable(frozen_fixture),
                tolerance=self.tolerance,
            )
        except Exception as exc:
            exact_parity = ParityResult(
                False,
                f"PARITY_EXECUTION_FAILED:{type(exc).__name__}:{exc}",
                self.tolerance,
                hashlib.sha256(_canonical_json_bytes(frozen_fixture)).hexdigest(),
                None,
                None,
                None,
            )
        if not exact_parity.passed:
            return DeviceSelection(
                requested=selection.requested,
                selected="cpu",
                dtype=selection.dtype,
                operation=selection.operation,
                parity_passed=False,
                fallback_reason=exact_parity.reason,
                capabilities=selection.capabilities,
                parity=exact_parity,
                implementation_sha256=implementation_sha256,
            )
        binding_payload = {
            "backend": selection.capabilities.framework,
            "backend_version": selection.capabilities.framework_version,
            "operation": selection.operation,
            "dtype": selection.dtype,
            "implementation_sha256": implementation_sha256,
            "fixture_sha256": exact_parity.fixture_sha256,
            "tolerance": asdict(exact_parity.tolerance),
            "cpu_output_sha256": exact_parity.cpu_output_sha256,
            "mps_output_sha256": exact_parity.mps_output_sha256,
            "reproducibility_limitations": list(
                selection.capabilities.reproducibility_limitations
            ),
        }
        bound = DeviceSelection(
            requested=selection.requested,
            selected=selection.selected,
            dtype=selection.dtype,
            operation=selection.operation,
            parity_passed=selection.parity_passed,
            fallback_reason=selection.fallback_reason,
            capabilities=selection.capabilities,
            parity=exact_parity,
            implementation_sha256=implementation_sha256,
            execution_binding_sha256=hashlib.sha256(
                canonical_json_bytes(binding_payload)
            ).hexdigest(),
        )
        self._issued_mps_selections.append(bound)
        self._prepared_executions[id(bound)] = (cpu_callable, mps_callable)
        return bound

    def execute(
        self,
        selection: DeviceSelection,
        *,
        cpu_callable: Callable[..., object],
        mps_callable: Callable[..., object] | None = None,
        values: object | None = None,
        confirmatory: bool = False,
    ) -> DeviceExecution:
        """Execute with CPU fallback only before a frozen confirmatory run."""

        if not isinstance(selection, DeviceSelection):
            raise DeviceConfigurationError("selection must be a DeviceSelection")
        if values is not None:
            values = _immutable(values)
        if selection.selected not in {"cpu", "mps"} or selection.dtype != "float32":
            raise DeviceConfigurationError("selection contains an unsupported execution policy")
        if selection.selected == "mps" and not selection.parity_passed:
            raise DeviceConfigurationError("MPS execution requires a passing parity decision")
        if selection.selected == "mps":
            if not any(selection is issued for issued in self._issued_mps_selections):
                raise DeviceConfigurationError(
                    "MPS selection evidence was not issued by this DeviceManager"
                )
            if selection.parity is None or not selection.parity.passed:
                raise DeviceConfigurationError("MPS selection lacks passing parity evidence")
            capabilities = selection.capabilities
            if not (
                capabilities.framework_installed
                and capabilities.probe_status == "AVAILABLE"
                and capabilities.mps_built
                and capabilities.mps_available
                and capabilities.operation_supported
            ):
                raise DeviceConfigurationError("MPS selection lacks capability evidence")
            if self.backend is None or capabilities.framework != str(self.backend.name):
                raise DeviceConfigurationError("MPS selection is not bound to this backend")
            if confirmatory:
                prepared = self._prepared_executions.get(id(selection))
                if (
                    prepared is None
                    or prepared[0] is not cpu_callable
                    or prepared[1] is not mps_callable
                    or selection.implementation_sha256 is None
                    or selection.execution_binding_sha256 is None
                ):
                    raise DeviceExecutionError(
                        "confirmatory MPS execution is not bound to the parity-approved implementation"
                    )
                if values is None:
                    raise DeviceExecutionError(
                        "confirmatory prepared MPS execution requires explicit numeric input values"
                    )
        prepared_execution = self._prepared_executions.get(id(selection))

        def invoke(callable_: Callable[..., object]) -> object:
            if values is not None:
                return callable_(values)
            if prepared_execution is not None:
                raise DeviceExecutionError(
                    "prepared execution requires explicit numeric input values"
                )
            return callable_()

        if selection.selected == "cpu":
            return DeviceExecution(invoke(cpu_callable), "cpu")
        if mps_callable is None:
            if confirmatory:
                raise DeviceExecutionError(
                    "MPS callable missing during confirmatory execution; mechanical retry or new study required"
                )
            return DeviceExecution(invoke(cpu_callable), "cpu", "MPS_CALLABLE_MISSING")
        try:
            return DeviceExecution(invoke(mps_callable), "mps")
        except Exception as exc:
            if confirmatory:
                raise DeviceExecutionError(
                    "MPS failed during frozen confirmatory execution; silent CPU rerun is prohibited"
                ) from exc
            return DeviceExecution(
                invoke(cpu_callable), "cpu", f"MPS_RUNTIME_FAILURE:{type(exc).__name__}:{exc}"
            )


@dataclass(frozen=True)
class ProbeEvidence:
    value: object
    status: str
    source: str
    detail: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class HardwareProfile:
    schema_version: str
    timestamp: str
    project_root: str
    architecture: ProbeEvidence
    operating_system: ProbeEvidence
    macos_version: ProbeEvidence
    logical_cpu_count: ProbeEvidence
    physical_cpu_count: ProbeEvidence
    gpu_description: ProbeEvidence
    physical_memory_bytes: ProbeEvidence
    disk_total_bytes: ProbeEvidence
    disk_free_bytes: ProbeEvidence
    python_version: ProbeEvidence
    installed_toolchains: Mapping[str, ProbeEvidence]
    installed_numerical_libraries: Mapping[str, ProbeEvidence]
    mps_capability: Mapping[str, object]
    resource_limits: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "project_root": self.project_root,
            "architecture": self.architecture.to_dict(),
            "operating_system": self.operating_system.to_dict(),
            "macos_version": self.macos_version.to_dict(),
            "logical_cpu_count": self.logical_cpu_count.to_dict(),
            "physical_cpu_count": self.physical_cpu_count.to_dict(),
            "gpu_description": self.gpu_description.to_dict(),
            "physical_memory_bytes": self.physical_memory_bytes.to_dict(),
            "disk_total_bytes": self.disk_total_bytes.to_dict(),
            "disk_free_bytes": self.disk_free_bytes.to_dict(),
            "python_version": self.python_version.to_dict(),
            "installed_toolchains": {
                key: value.to_dict() for key, value in self.installed_toolchains.items()
            },
            "installed_numerical_libraries": {
                key: value.to_dict()
                for key, value in self.installed_numerical_libraries.items()
            },
            "mps_capability": dict(self.mps_capability),
            "resource_limits": dict(self.resource_limits),
        }


class HardwareProfiler:
    """Collect capability evidence using local, non-mutating, bounded probes."""

    TOOLCHAINS = ("python3", "git", "clang", "make", "sqlite3")
    NUMERICAL_LIBRARIES = ("numpy", "scipy", "torch", "tensorflow", "jax", "mlx")

    def __init__(
        self,
        project_root: str | os.PathLike[str],
        *,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        executable_exists: Callable[[Path], bool] = Path.exists,
        now: Callable[[], datetime] | None = None,
        device_manager_factory: Callable[[], DeviceManager] | None = None,
    ) -> None:
        root = Path(project_root)
        if not root.exists() or not root.is_dir() or root.is_symlink():
            raise DeviceConfigurationError("project_root must be an existing non-symlink directory")
        self.project_root = root.resolve()
        home = Path.home().resolve()
        if self.project_root in {
            Path(self.project_root.anchor),
            home,
            home / "dev",
            Path("/Users"),
        }:
            raise DeviceConfigurationError(
                "project_root cannot be a filesystem, home, or broad development directory"
            )
        self._runner = command_runner
        self._executable_exists = executable_exists
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._device_manager_factory = device_manager_factory or (
            lambda: DeviceManager(project_root=self.project_root)
        )

    def _run(self, argv: Sequence[str]) -> tuple[str | None, str, str | None]:
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            return None, "ERROR", "invalid command arguments"
        if not Path(argv[0]).is_absolute():
            return None, "ERROR", "probe executable must be an absolute path"
        if not self._executable_exists(Path(argv[0])):
            return None, "UNAVAILABLE", "probe executable not found"
        try:
            result = self._runner(
                list(argv), capture_output=True, text=True, timeout=8, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            detail = str(exc)
            denied = "denied" in detail.lower() or "not permitted" in detail.lower()
            return None, "DENIED" if denied else "ERROR", detail
        try:
            returncode = int(result.returncode)
            stdout = result.stdout if isinstance(result.stdout, str) else ""
            stderr = result.stderr if isinstance(result.stderr, str) else ""
        except (AttributeError, TypeError, ValueError) as exc:
            return None, "ERROR", f"malformed probe result: {exc}"
        if len(stdout) + len(stderr) > 8 * 1024**2:
            return None, "ERROR", "probe output exceeds 8 MiB safety limit"
        if returncode != 0:
            detail = (stderr or stdout).strip()[:1000] or f"exit {returncode}"
            denied = "denied" in detail.lower() or "not permitted" in detail.lower()
            return None, "DENIED" if denied else "ERROR", detail
        return stdout, "AVAILABLE", None

    def _sysctl_int(self, key: str) -> ProbeEvidence:
        output, status, detail = self._run(("/usr/sbin/sysctl", "-n", key))
        if status != "AVAILABLE" or output is None:
            return ProbeEvidence(None, status, f"sysctl {key}", detail)
        try:
            value = int(output.strip())
            if value <= 0:
                raise ValueError("non-positive value")
            return ProbeEvidence(value, "AVAILABLE", f"sysctl {key}")
        except ValueError as exc:
            return ProbeEvidence(None, "ERROR", f"sysctl {key}", f"malformed output: {exc}")

    @staticmethod
    def _recursive_values(value: object, wanted: set[str]) -> list[object]:
        found: list[object] = []
        if isinstance(value, Mapping):
            for key, child in value.items():
                normalized = str(key).lower().replace("_", " ")
                if normalized in wanted:
                    found.append(child)
                found.extend(HardwareProfiler._recursive_values(child, wanted))
        elif isinstance(value, list):
            for child in value:
                found.extend(HardwareProfiler._recursive_values(child, wanted))
        return found

    def _system_profiler(self) -> tuple[dict[str, object] | None, str, str | None]:
        output, status, detail = self._run(
            (
                "/usr/sbin/system_profiler",
                "SPHardwareDataType",
                "SPDisplaysDataType",
                "-json",
            )
        )
        if status != "AVAILABLE" or output is None:
            return None, status, detail
        try:
            parsed = safe_json_loads(output, max_bytes=8 * 1024**2)
            if not isinstance(parsed, dict):
                raise ValueError("top level is not an object")
            return parsed, "AVAILABLE", None
        except Exception as exc:
            return None, "ERROR", f"malformed system_profiler JSON: {exc}"

    def _gpu_evidence(self, profile: dict[str, object] | None, status: str, detail: str | None) -> ProbeEvidence:
        if profile is None:
            return ProbeEvidence(None, status, "system_profiler", detail)
        values = self._recursive_values(
            profile,
            {
                "chip type",
                "spdisplays chipset-model",
                "sppci model",
                "sppci cores",
                "gpu",
                "gpu cores",
            },
        )
        strings = [str(item) for item in values if item not in (None, "")]
        if not strings:
            return ProbeEvidence(None, "UNAVAILABLE", "system_profiler", "GPU field absent")
        return ProbeEvidence("; ".join(dict.fromkeys(strings)), "AVAILABLE", "system_profiler")

    @staticmethod
    def _first_positive_integer(values: Sequence[object]) -> int | None:
        for value in values:
            if isinstance(value, bool):
                continue
            if isinstance(value, int) and value > 0:
                return value
            if isinstance(value, str):
                match = re.search(r"\d+", value.replace(",", ""))
                if match is not None and int(match.group()) > 0:
                    return int(match.group())
        return None

    @staticmethod
    def _memory_bytes(values: Sequence[object]) -> int | None:
        multipliers = {
            "B": 1,
            "KB": 1024,
            "MB": 1024**2,
            "GB": 1024**3,
            "TB": 1024**4,
        }
        for value in values:
            if isinstance(value, bool):
                continue
            if isinstance(value, int) and value > 0:
                return value
            if isinstance(value, str):
                parts = value.upper().replace(",", "").split()
                if len(parts) >= 2 and parts[1] in multipliers:
                    try:
                        amount = float(parts[0])
                    except ValueError:
                        continue
                    if math.isfinite(amount) and amount > 0:
                        return int(amount * multipliers[parts[1]])
        return None

    def collect(self) -> HardwareProfile:
        profile, profiler_status, profiler_detail = self._system_profiler()
        logical = os.cpu_count()
        logical_evidence = (
            ProbeEvidence(logical, "AVAILABLE", "os.cpu_count")
            if isinstance(logical, int) and logical > 0
            else ProbeEvidence(None, "UNAVAILABLE", "os.cpu_count", "returned no positive count")
        )
        physical = self._sysctl_int("hw.physicalcpu")
        memory = self._sysctl_int("hw.memsize")
        if profile is not None and physical.status != "AVAILABLE":
            physical_fallback = self._first_positive_integer(
                self._recursive_values(
                    profile,
                    {
                        "total number of cores",
                        "number of cores",
                        "number processors",
                        "physical cpu count",
                    },
                )
            )
            if physical_fallback is not None:
                physical = ProbeEvidence(
                    physical_fallback,
                    "AVAILABLE",
                    "system_profiler",
                    f"sysctl fallback used after {physical.status}",
                )
        if profile is not None and memory.status != "AVAILABLE":
            memory_fallback = self._memory_bytes(
                self._recursive_values(
                    profile,
                    {"physical memory", "memory", "physical memory bytes"},
                )
            )
            if memory_fallback is not None:
                memory = ProbeEvidence(
                    memory_fallback,
                    "AVAILABLE",
                    "system_profiler",
                    f"sysctl fallback used after {memory.status}",
                )
        try:
            disk = shutil.disk_usage(self.project_root)
            disk_total = ProbeEvidence(int(disk.total), "AVAILABLE", "shutil.disk_usage")
            disk_free = ProbeEvidence(int(disk.free), "AVAILABLE", "shutil.disk_usage")
        except OSError as exc:
            disk_total = ProbeEvidence(None, "ERROR", "shutil.disk_usage", str(exc))
            disk_free = ProbeEvidence(None, "ERROR", "shutil.disk_usage", str(exc))

        tools: dict[str, ProbeEvidence] = {}
        for executable in self.TOOLCHAINS:
            path = shutil.which(executable)
            tools[executable] = (
                ProbeEvidence(
                    executable,
                    "AVAILABLE",
                    "PATH lookup",
                    "absolute executable path intentionally omitted",
                )
                if path
                else ProbeEvidence(None, "UNAVAILABLE", "PATH lookup", "not on supplied PATH")
            )
        libraries: dict[str, ProbeEvidence] = {}
        for package in self.NUMERICAL_LIBRARIES:
            try:
                version = importlib.metadata.version(package)
                libraries[package] = ProbeEvidence(version, "AVAILABLE", "importlib.metadata")
            except importlib.metadata.PackageNotFoundError:
                libraries[package] = ProbeEvidence(
                    None, "UNAVAILABLE", "importlib.metadata", "not installed"
                )
            except Exception as exc:
                libraries[package] = ProbeEvidence(
                    None, "ERROR", "importlib.metadata", f"{type(exc).__name__}: {exc}"
                )

        try:
            manager = self._device_manager_factory()
            capabilities = manager.probe_capabilities().to_dict()
        except Exception as exc:
            capabilities = {
                "probe_status": "ERROR",
                "evidence": [f"device capability probe failed: {type(exc).__name__}: {exc}"],
            }

        limits: dict[str, object] = {}
        for label, identifier in (
            ("address_space", resource.RLIMIT_AS),
            ("cpu", resource.RLIMIT_CPU),
            ("open_files", resource.RLIMIT_NOFILE),
        ):
            try:
                soft, hard = resource.getrlimit(identifier)
                limits[label] = {"soft": soft, "hard": hard, "status": "AVAILABLE"}
            except (OSError, ValueError) as exc:
                limits[label] = {"soft": None, "hard": None, "status": "ERROR", "detail": str(exc)}

        mac_version = platform.mac_ver()[0]
        return HardwareProfile(
            schema_version="1.0",
            timestamp=self._now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            project_root=str(self.project_root),
            architecture=ProbeEvidence(platform.machine() or None, "AVAILABLE" if platform.machine() else "UNAVAILABLE", "platform.machine"),
            operating_system=ProbeEvidence(platform.system() or None, "AVAILABLE" if platform.system() else "UNAVAILABLE", "platform.system"),
            macos_version=ProbeEvidence(
                mac_version or None,
                "AVAILABLE" if mac_version else "UNAVAILABLE",
                "platform.mac_ver",
                None if mac_version else "not running on macOS or version unavailable",
            ),
            logical_cpu_count=logical_evidence,
            physical_cpu_count=physical,
            gpu_description=self._gpu_evidence(profile, profiler_status, profiler_detail),
            physical_memory_bytes=memory,
            disk_total_bytes=disk_total,
            disk_free_bytes=disk_free,
            python_version=ProbeEvidence(sys.version.split()[0], "AVAILABLE", "sys.version"),
            installed_toolchains=tools,
            installed_numerical_libraries=libraries,
            mps_capability=capabilities,
            resource_limits=limits,
        )

    def _confined_output(self, path: str | os.PathLike[str]) -> Path:
        raw = Path(path)
        if any(part == ".." for part in raw.parts):
            raise DeviceConfigurationError("output path traversal is prohibited")
        candidate = raw if raw.is_absolute() else self.project_root / raw
        lexical = Path(os.path.abspath(candidate))
        try:
            relative = lexical.relative_to(self.project_root)
        except ValueError as exc:
            raise DeviceConfigurationError("hardware profile output escapes project_root") from exc
        return self.project_root / relative

    def write_json(
        self,
        path: str | os.PathLike[str] = "state/HARDWARE_PROFILE.json",
        profile: HardwareProfile | None = None,
    ) -> Path:
        destination = self._confined_output(path)
        relative = destination.relative_to(self.project_root)
        payload = (profile or self.collect()).to_dict()
        serialized = (
            canonical_json_bytes(payload) + b"\n"
        )
        try:
            secure_directory(self.project_root, relative.parent, create=True)
            previous = read_confined_bytes(
                self.project_root,
                relative,
                reject_hardlinks=True,
                max_bytes=8 * 1024**2,
                missing_ok=True,
            )
            if previous is not None:
                if previous == serialized:
                    return destination
                previous_hash = hashlib.sha256(previous).hexdigest()
                history_relative = (
                    Path(".scientist-one-build")
                    / "checkpoints"
                    / "hardware-profile-history"
                )
                archive_relative = history_relative / f"{destination.stem}.{previous_hash}.json"
                atomic_write_bytes(
                    self.project_root,
                    archive_relative,
                    previous,
                    immutable=True,
                    create_parents=True,
                )
            return atomic_write_bytes(
                self.project_root,
                relative,
                serialized,
                overwrite=True,
                create_parents=True,
            )
        except PathSecurityError as exc:
            raise DeviceConfigurationError(
                f"hardware profile cannot be written safely: {exc}"
            ) from exc


__all__ = [
    "DeviceBackend",
    "DeviceCapabilities",
    "DeviceConfigurationError",
    "DeviceExecution",
    "DeviceExecutionError",
    "DeviceManager",
    "DeviceSelection",
    "HardwareProfile",
    "HardwareProfiler",
    "ParityResult",
    "ParityTolerance",
    "ProbeEvidence",
    "TorchMPSBackend",
    "_discover_torch_backend",
]
