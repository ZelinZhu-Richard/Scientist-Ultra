"""Pure prospective CUDA-event protocol and retained implementation sources.

This is not a registry/ledger owner, execution receipt, capability proof or
scientific decision. The CUDA SDK is an external future toolchain: this module
neither imports it nor compiles/runs the retained .cu bytes. The independent
source owner must establish prospectivity and actual execution custody. All
seeds label repeats of the same Dataset, not independent observations.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

from . import cuda_device_timing_evaluator as _engine
from .errors import ValidationError
from .security import canonical_json_bytes


CUDA_DEVICE_TIMING_PROTOCOL_SCHEMA = _engine.PROTOCOL_SCHEMA
CUDA_DEVICE_TIMING_PROFILE_ID = _engine.PROFILE_ID
CUDA_DEVICE_TIMING_OUTPUT_SCHEMA = _engine.OUTPUT_SCHEMA
CUDA_DEVICE_TIMING_METRIC_UNIT = _engine.METRIC_UNIT
CUDA_DEVICE_TIMING_METRIC_DIRECTION = _engine.METRIC_DIRECTION
CUDA_DEVICE_TIMING_METRIC_SCOPE = _engine.METRIC_SCOPE
CUDA_DEVICE_TIMING_METRIC_DEFINITION = _engine.METRIC_DEFINITION
CUDA_DEVICE_TIMING_METRIC_AGGREGATION = _engine.METRIC_AGGREGATION
MAX_CUDA_DEVICE_TIMING_ELEMENTS = _engine.MAX_ELEMENTS
MAX_CUDA_DEVICE_TIMING_SAMPLES = _engine.MAX_SAMPLES
MAX_CUDA_DEVICE_TIMING_ELEMENT_ADDITIONS = _engine.MAX_ELEMENT_ADDITIONS
MAX_CUDA_DEVICE_TIMING_OUTPUT_BYTES = _engine.MAX_JSON_BYTES
MAX_CUDA_DEVICE_TIMING_DATASET_BYTES = 8 + 8 * MAX_CUDA_DEVICE_TIMING_ELEMENTS
MAX_CUDA_DEVICE_TIMING_INPUT_SCALAR = 1_000_000
CUDA_DEVICE_TIMING_EVALUATOR_SHA256 = "6484e4224317444a01e26eacd4198c5c4448890c30a2db50fbc5743dd78410d2"


class CudaDeviceTimingError(ValidationError):
    """A pure timing protocol, input or descriptive output is not exact."""


def _require_retained_evaluator_bytes(raw: bytes) -> bytes:
    if type(raw) is not bytes or not 0 < len(raw) <= 1_048_576:
        raise CudaDeviceTimingError("retained evaluator exceeds its exact bounded byte contract")
    if hashlib.sha256(raw).hexdigest() != CUDA_DEVICE_TIMING_EVALUATOR_SHA256:
        raise CudaDeviceTimingError("retained evaluator differs from the prospectively pinned source")
    return raw


def _read_retained_evaluator_bytes() -> bytes:
    # Fixed owned local source, imported normally above; never a caller-selected
    # path or exec/eval. Full source attestation belongs to the surrounding owner.
    with Path(__file__).with_name("cuda_device_timing_evaluator.py").open("rb") as stream:
        return _require_retained_evaluator_bytes(stream.read(1_048_577))


CUDA_DEVICE_TIMING_EVALUATOR_BYTES = _read_retained_evaluator_bytes()


@dataclass(frozen=True, slots=True)
class CudaDeviceTimingProtocol:
    metric_id: str
    baseline_id: str
    seeds: tuple[int, ...]
    element_count: int
    candidate_block_size: int
    baseline_block_size: int
    warmup_iterations: int
    repetitions: int
    schema_version: str = CUDA_DEVICE_TIMING_PROTOCOL_SCHEMA
    profile_id: str = CUDA_DEVICE_TIMING_PROFILE_ID

    def __post_init__(self) -> None:
        if type(self) is not CudaDeviceTimingProtocol:
            raise CudaDeviceTimingError("protocol requires the exact native type")
        if type(self.seeds) is not tuple or not 1 <= len(self.seeds) <= _engine.MAX_SEEDS:
            raise CudaDeviceTimingError("seeds require an exact bounded native tuple")
        try:
            _engine.validate_protocol(_protocol_fields(self))
        except _engine.TimingValueError as exc:
            raise CudaDeviceTimingError(str(exc)) from exc

    def to_dict(self) -> dict:
        _require_protocol(self)
        return _protocol_fields(self)

    @classmethod
    def from_mapping(cls, value: dict) -> CudaDeviceTimingProtocol:
        if cls is not CudaDeviceTimingProtocol:
            raise CudaDeviceTimingError("protocol requires the exact native type")
        try:
            values = _engine.validate_protocol(value)
        except _engine.TimingValueError as exc:
            raise CudaDeviceTimingError(str(exc)) from exc
        values["seeds"] = tuple(values["seeds"])
        return cls(**values)

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(CudaDeviceTimingProtocol.to_dict(self)) + b"\n"

    def expected_argv(self, executable: str = "./cuda-device-timing",
                      dataset_path: str = "cuda-device-input.bin") -> tuple[str, ...]:
        _require_protocol(self)
        for label, value in (("executable", executable), ("dataset_path", dataset_path)):
            if type(value) is not str or not 1 <= len(value) <= 4096 or "\x00" in value:
                raise CudaDeviceTimingError(f"{label} requires bounded native path text")
            try:
                encoded = value.encode("utf-8")
            except UnicodeError as exc:
                raise CudaDeviceTimingError(f"{label} requires UTF-8 path text") from exc
            if len(encoded) > 4096:
                raise CudaDeviceTimingError(f"{label} exceeds the CLI byte bound")
        return (
            executable, "--dataset", dataset_path,
            "--schema-version", self.schema_version, "--profile-id", self.profile_id,
            "--metric-id", self.metric_id, "--baseline-id", self.baseline_id,
            "--element-count", str(self.element_count),
            "--candidate-block-size", str(self.candidate_block_size),
            "--baseline-block-size", str(self.baseline_block_size),
            "--warmup-iterations", str(self.warmup_iterations),
            "--repetitions", str(self.repetitions),
            "--seeds", ",".join(str(seed) for seed in self.seeds),
        )


def _protocol_fields(protocol: CudaDeviceTimingProtocol) -> dict:
    return {"schema_version": protocol.schema_version, "profile_id": protocol.profile_id,
            "metric_id": protocol.metric_id, "baseline_id": protocol.baseline_id,
            "seeds": list(protocol.seeds), "element_count": protocol.element_count,
            "candidate_block_size": protocol.candidate_block_size,
            "baseline_block_size": protocol.baseline_block_size,
            "warmup_iterations": protocol.warmup_iterations, "repetitions": protocol.repetitions}


def _require_protocol(protocol: CudaDeviceTimingProtocol) -> None:
    if type(protocol) is not CudaDeviceTimingProtocol:
        raise CudaDeviceTimingError("protocol requires the exact native type")
    CudaDeviceTimingProtocol.__post_init__(protocol)


def validate_cuda_device_timing_dataset(protocol: CudaDeviceTimingProtocol, raw: bytes) -> None:
    """Validate exact CDT1/LE planar addition inputs; this grants no custody."""
    _require_protocol(protocol)
    if type(raw) is not bytes or len(raw) != 8 + 8 * protocol.element_count:
        raise CudaDeviceTimingError("Dataset bytes have the wrong exact bounded length")
    if raw[:4] != b"CDT1" or struct.unpack_from("<I", raw, 4)[0] != protocol.element_count:
        raise CudaDeviceTimingError("Dataset header/count differs from the frozen protocol")
    for (value,) in struct.iter_unpack("<I", memoryview(raw)[8:]):
        if value > MAX_CUDA_DEVICE_TIMING_INPUT_SCALAR:
            raise CudaDeviceTimingError("Dataset scalar exceeds the no-overflow input bound")


@dataclass(frozen=True, slots=True)
class CudaDeviceIdentity:
    ordinal: int
    name: str
    compute_capability_major: int
    compute_capability_minor: int
    runtime_version: int
    driver_version: int


@dataclass(frozen=True, slots=True)
class CudaDeviceTimingSample:
    seed: int
    phase: str
    condition: str
    repetition: int
    elapsed_ms: float


@dataclass(frozen=True, slots=True)
class CudaDeviceSeedMedians:
    seed: int
    candidate_median_ms: float
    baseline_median_ms: float


@dataclass(frozen=True, slots=True)
class CudaDeviceTimingEvaluation:
    """Immutable descriptive values only; even zero timings imply no PASS."""

    protocol: CudaDeviceTimingProtocol
    device: CudaDeviceIdentity
    samples: tuple[CudaDeviceTimingSample, ...]
    per_seed: tuple[CudaDeviceSeedMedians, ...]

    def to_dict(self) -> dict:
        return {"schema_version": _engine.EVALUATION_SCHEMA,
                "protocol": CudaDeviceTimingProtocol.to_dict(self.protocol),
                "metric_scope": CUDA_DEVICE_TIMING_METRIC_SCOPE,
                "unit": CUDA_DEVICE_TIMING_METRIC_UNIT,
                "aggregation": CUDA_DEVICE_TIMING_METRIC_AGGREGATION,
                "device": {key: getattr(self.device, key) for key in CudaDeviceIdentity.__dataclass_fields__},
                "samples": [{key: getattr(sample, key) for key in CudaDeviceTimingSample.__dataclass_fields__}
                            for sample in self.samples],
                "per_seed": [{key: getattr(item, key) for key in CudaDeviceSeedMedians.__dataclass_fields__}
                             for item in self.per_seed]}


def evaluate_cuda_device_timings(protocol: CudaDeviceTimingProtocol, raw: dict) -> CudaDeviceTimingEvaluation:
    _require_protocol(protocol)
    try:
        value = _engine.evaluate(_protocol_fields(protocol), raw)
    except _engine.TimingValueError as exc:
        raise CudaDeviceTimingError(str(exc)) from exc
    return CudaDeviceTimingEvaluation(
        protocol=protocol, device=CudaDeviceIdentity(**value["device"]),
        samples=tuple(CudaDeviceTimingSample(**item) for item in value["samples"]),
        per_seed=tuple(CudaDeviceSeedMedians(**item) for item in value["per_seed"]),
    )


# Complete future .cu translation unit; CUDA SDK compilation/execution remains
# UNTESTED. Device-event API reference: NVIDIA CUDA Runtime API, Event Management.
CUDA_DEVICE_TIMING_BENCHMARK_BYTES = rb'''// CUDA uint32 vector addition, device-event timing only. No CPU/MPS fallback.
// Future build: nvcc -std=c++14 cuda-device-timing.cu -o cuda-device-timing
// Seeds are repeat labels for the SAME input, not randomized/independent data.
#include <cuda_runtime.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr std::uint32_t MAX_N = 65536;
constexpr std::uint32_t MAX_INPUT = 1000000;
constexpr std::uint64_t MAX_SAMPLES = 3216;
constexpr std::uint64_t MAX_ADDITIONS = 210763776;
constexpr std::uint64_t MAX_OUTPUT_BYTES = 1048576;
constexpr std::uint64_t MAX_DEVICE_BYTES = 3ULL * MAX_N * sizeof(std::uint32_t);
const char* PROTOCOL = "cuda-device-timing-protocol/v1";
const char* PROFILE = "cuda-u32-vector-add-events/v1";
const char* OUTPUT = "cuda-device-timing-output/v1";

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void checked(cudaError_t value, const char* operation) {
    if (value != cudaSuccess) {
        throw std::runtime_error(std::string(operation) + ": " + cudaGetErrorString(value));
    }
}

std::uint32_t integer(const std::string& text, std::uint32_t low, std::uint32_t high) {
    require(!text.empty() && text.size() <= 10, "invalid integer length");
    require(text.size() == 1 || text[0] != '0', "noncanonical integer");
    std::uint64_t result = 0;
    for (char digit : text) {
        require(digit >= '0' && digit <= '9', "integer is not unsigned decimal");
        result = result * 10 + static_cast<unsigned>(digit - '0');
    }
    require(result >= low && result <= high, "integer is out of bounds");
    return static_cast<std::uint32_t>(result);
}

bool alphanumeric(char value) {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
        || (value >= '0' && value <= '9');
}

void identifier(const std::string& value) {
    require(!value.empty() && value.size() <= 128 && alphanumeric(value[0]), "invalid identifier");
    for (char c : value) require(alphanumeric(c) || c == '.' || c == '_' || c == ':' || c == '-', "invalid identifier");
}

std::string quote(const std::string& text) {
    const char* hex = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : text) {
        if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
        else if (c < 32 || c >= 127) {
            result += "\\u00"; result += hex[c >> 4]; result += hex[c & 15];
        } else result += static_cast<char>(c);
    }
    return result + "\"";
}

struct Config {
    std::string dataset, metric, baseline;
    std::uint32_t n, candidate_block, baseline_block, warmups, repetitions;
    std::vector<std::uint32_t> seeds;
};

Config arguments(int argc, char** argv) {
    require(argc == 23, "expected exactly eleven frozen flag/value pairs");
    // Bound every argument before creating any std::string from argv.
    for (int i = 1; i < argc; ++i) {
        std::size_t length = 0;
        while (length <= 4096 && argv[i][length] != '\0') ++length;
        require(length <= 4096, "argument exceeds byte bound");
    }
    const char* flags[] = {"--dataset", "--schema-version", "--profile-id", "--metric-id",
        "--baseline-id", "--element-count", "--candidate-block-size", "--baseline-block-size",
        "--warmup-iterations", "--repetitions", "--seeds"};
    for (int i = 0; i < 11; ++i) {
        require(std::string(argv[1 + i * 2]) == flags[i], "flags are missing, duplicated or reordered");
        require(std::string(argv[2 + i * 2]).size() <= 4096, "argument exceeds byte bound");
    }
    require(std::string(argv[4]) == PROTOCOL && std::string(argv[6]) == PROFILE, "wrong protocol/profile");
    Config c;
    c.dataset = argv[2]; c.metric = argv[8]; c.baseline = argv[10];
    require(!c.dataset.empty(), "empty dataset path");
    identifier(c.metric); identifier(c.baseline);
    c.n = integer(argv[12], 1, MAX_N);
    c.candidate_block = integer(argv[14], 32, 256);
    c.baseline_block = integer(argv[16], 32, 256);
    auto supported = [](std::uint32_t block) { return block == 32 || block == 64 || block == 128 || block == 256; };
    require(supported(c.candidate_block) && supported(c.baseline_block)
            && c.candidate_block != c.baseline_block, "blocks must be distinct supported values");
    c.warmups = integer(argv[18], 1, 16);
    c.repetitions = integer(argv[20], 3, 51);
    require(c.repetitions % 2 == 1, "measurement repetitions must be odd");
    std::string seed_text = argv[22];
    require(!seed_text.empty() && seed_text.size() <= 263, "seed vector exceeds bound");
    c.seeds.reserve(24);
    std::size_t offset = 0;
    while (true) {
        const std::size_t comma = seed_text.find(',', offset);
        const std::string part = seed_text.substr(offset, comma == std::string::npos ? comma : comma - offset);
        const std::uint32_t seed = integer(part, 0, 2147483647);
        require(c.seeds.size() < 24 && std::find(c.seeds.begin(), c.seeds.end(), seed) == c.seeds.end(), "seed count or duplicate seed");
        c.seeds.push_back(seed);
        if (comma == std::string::npos) break;
        offset = comma + 1;
    }
    return c;
}

std::uint32_t read_le(std::ifstream& stream) {
    unsigned char bytes[4];
    stream.read(reinterpret_cast<char*>(bytes), 4);
    require(static_cast<bool>(stream), "short Dataset scalar");
    return std::uint32_t(bytes[0]) | (std::uint32_t(bytes[1]) << 8)
        | (std::uint32_t(bytes[2]) << 16) | (std::uint32_t(bytes[3]) << 24);
}

__global__ void add(const std::uint32_t* lhs, const std::uint32_t* rhs,
                    std::uint32_t* output, std::uint32_t n) {
    const std::uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) output[i] = lhs[i] + rhs[i];
}

struct Sample { std::uint32_t seed, repetition; const char* phase; const char* condition; float ms; };

void protocol_json(std::ostream& out, const Config& c) {
    out << "{\"schema_version\":" << quote(PROTOCOL) << ",\"profile_id\":" << quote(PROFILE)
        << ",\"metric_id\":" << quote(c.metric) << ",\"baseline_id\":" << quote(c.baseline)
        << ",\"element_count\":" << c.n << ",\"candidate_block_size\":" << c.candidate_block
        << ",\"baseline_block_size\":" << c.baseline_block << ",\"warmup_iterations\":" << c.warmups
        << ",\"repetitions\":" << c.repetitions << ",\"seeds\":[";
    for (std::size_t i = 0; i < c.seeds.size(); ++i) { if (i) out << ','; out << c.seeds[i]; }
    out << "]}";
}

int run(int argc, char** argv) {
    const Config c = arguments(argc, argv);
    const std::uint64_t sample_count = 2ULL * c.seeds.size() * (c.warmups + c.repetitions);
    const std::uint64_t buffer_bytes = std::uint64_t(c.n) * sizeof(std::uint32_t);
    // Complete bounds precede input/vector/output allocation and ALL CUDA work.
    require(sample_count <= MAX_SAMPLES && sample_count * c.n <= MAX_ADDITIONS, "complete work bound exceeded");
    require(3 * buffer_bytes <= MAX_DEVICE_BYTES, "host/device vector allocation bound exceeded");
    const std::uint64_t output_bound = 5120 + sample_count * 192;
    require(output_bound <= MAX_OUTPUT_BYTES, "output bound exceeded");
    std::ifstream stream(c.dataset, std::ios::binary | std::ios::ate);
    require(static_cast<bool>(stream) && stream.tellg() == std::streamoff(8 + 8ULL * c.n), "Dataset has wrong exact length");
    stream.seekg(0);
    char magic[4]; stream.read(magic, 4);
    require(static_cast<bool>(stream) && std::string(magic, 4) == "CDT1", "Dataset magic differs");
    require(read_le(stream) == c.n, "Dataset count differs from protocol");
    std::vector<std::uint32_t> lhs(c.n), rhs(c.n), observed(c.n);
    for (std::uint32_t& value : lhs) { value = read_le(stream); require(value <= MAX_INPUT, "lhs exceeds no-overflow bound"); }
    for (std::uint32_t& value : rhs) { value = read_le(stream); require(value <= MAX_INPUT, "rhs exceeds no-overflow bound"); }
    require(stream.peek() == std::char_traits<char>::eof(), "Dataset has trailing bytes");
    std::vector<Sample> samples; samples.reserve(static_cast<std::size_t>(sample_count));

    int device_count = 0; checked(cudaGetDeviceCount(&device_count), "cudaGetDeviceCount");
    require(device_count > 0, "CUDA device ordinal 0 is unavailable; no fallback");
    checked(cudaSetDevice(0), "cudaSetDevice");
    cudaDeviceProp device{}; checked(cudaGetDeviceProperties(&device, 0), "cudaGetDeviceProperties");
    int runtime_version = 0, driver_version = 0;
    checked(cudaRuntimeGetVersion(&runtime_version), "cudaRuntimeGetVersion");
    checked(cudaDriverGetVersion(&driver_version), "cudaDriverGetVersion");
    std::uint32_t *d_lhs = nullptr, *d_rhs = nullptr, *d_output = nullptr;
    checked(cudaMalloc(reinterpret_cast<void**>(&d_lhs), buffer_bytes), "cudaMalloc lhs");
    checked(cudaMalloc(reinterpret_cast<void**>(&d_rhs), buffer_bytes), "cudaMalloc rhs");
    checked(cudaMalloc(reinterpret_cast<void**>(&d_output), buffer_bytes), "cudaMalloc output");
    checked(cudaMemcpy(d_lhs, lhs.data(), buffer_bytes, cudaMemcpyHostToDevice), "cudaMemcpy lhs");
    checked(cudaMemcpy(d_rhs, rhs.data(), buffer_bytes, cudaMemcpyHostToDevice), "cudaMemcpy rhs");
    cudaEvent_t start, stop;
    checked(cudaEventCreate(&start), "cudaEventCreate start");
    checked(cudaEventCreate(&stop), "cudaEventCreate stop");
    for (std::size_t seed_index = 0; seed_index < c.seeds.size(); ++seed_index) {
        for (unsigned phase = 0; phase < 2; ++phase) {
            const std::uint32_t count = phase == 0 ? c.warmups : c.repetitions;
            for (std::uint32_t repetition = 0; repetition < count; ++repetition) {
                for (unsigned order = 0; order < 2; ++order) {
                    const bool candidate = ((seed_index + repetition + order) % 2 == 0);
                    const std::uint32_t block = candidate ? c.candidate_block : c.baseline_block;
                    // UINT32_MAX cannot equal any valid sum (maximum 2,000,000).
                    // Same stream orders poison before start; poison is NOT timed.
                    checked(cudaMemset(d_output, 0xff, buffer_bytes), "cudaMemset poison");
                    checked(cudaEventRecord(start, 0), "cudaEventRecord start");
                    add<<<(c.n + block - 1) / block, block, 0, 0>>>(d_lhs, d_rhs, d_output, c.n);
                    checked(cudaGetLastError(), "kernel launch");
                    checked(cudaEventRecord(stop, 0), "cudaEventRecord stop");
                    checked(cudaEventSynchronize(stop), "cudaEventSynchronize stop");
                    float ms = 0.0f;
                    checked(cudaEventElapsedTime(&ms, start, stop), "cudaEventElapsedTime");
                    require(std::isfinite(ms) && ms >= 0.0f, "nonfinite or negative CUDA event time");
                    // EVERY warmup and measurement output is checked outside timing.
                    checked(cudaMemcpy(observed.data(), d_output, buffer_bytes, cudaMemcpyDeviceToHost), "cudaMemcpy output");
                    for (std::uint32_t i = 0; i < c.n; ++i) {
                        require(observed[i] == lhs[i] + rhs[i], "exact output correctness failed");
                    }
                    samples.push_back(Sample{c.seeds[seed_index], repetition, phase == 0 ? "WARMUP" : "MEASUREMENT",
                                             candidate ? "CANDIDATE" : "BASELINE", ms});
                }
            }
        }
    }
    require(samples.size() == sample_count, "incomplete launch coverage");
    // All CUDA failures, including cleanup failures, prevent JSON output.
    checked(cudaEventDestroy(start), "cudaEventDestroy start");
    checked(cudaEventDestroy(stop), "cudaEventDestroy stop");
    checked(cudaFree(d_output), "cudaFree output");
    checked(cudaFree(d_rhs), "cudaFree rhs");
    checked(cudaFree(d_lhs), "cudaFree lhs");
    std::size_t name_length = 0;
    while (name_length < sizeof(device.name) && device.name[name_length] != '\0') ++name_length;
    require(name_length > 0 && name_length < sizeof(device.name), "invalid bounded device name");
    require(device.major > 0 && device.minor >= 0 && runtime_version > 0 && driver_version > 0, "invalid actual device/runtime metadata");
    std::ostringstream out; out << std::setprecision(std::numeric_limits<float>::max_digits10) << std::showpoint;
    out << "{\"schema_version\":" << quote(OUTPUT) << ",\"protocol\":"; protocol_json(out, c);
    out << ",\"metric_scope\":\"INTERMEDIATE\",\"unit\":\"MILLISECONDS\",\"device\":{\"ordinal\":0,\"name\":"
        << quote(std::string(device.name, name_length)) << ",\"compute_capability_major\":" << device.major
        << ",\"compute_capability_minor\":" << device.minor << ",\"runtime_version\":" << runtime_version
        << ",\"driver_version\":" << driver_version << "},\"samples\":[";
    for (std::size_t i = 0; i < samples.size(); ++i) {
        if (i) out << ',';
        const Sample& sample = samples[i];
        out << "{\"seed\":" << sample.seed << ",\"phase\":" << quote(sample.phase)
            << ",\"condition\":" << quote(sample.condition) << ",\"repetition\":" << sample.repetition
            << ",\"elapsed_ms\":" << sample.ms << '}';
    }
    out << "]}\n";
    const std::string json = out.str();
    require(json.size() <= output_bound && json.size() <= MAX_OUTPUT_BYTES, "actual output exceeds bound");
    std::cout << json;
    std::cout.flush();
    require(static_cast<bool>(std::cout), "stdout write failed");
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    try { return run(argc, argv); }
    catch (const std::exception& error) {
        std::cerr << "CUDA timing refused: " << error.what() << '\n';
        return 2; // No usable measurement is emitted on an execution failure.
    }
}
'''
