"""Pure/synthetic timing and retained-source controls, never GPU evidence.

The standalone evaluator runs only on synthetic JSON in a temporary directory.
No CUDA compiler/runtime is invoked, no registry/ledger is used, no scientific
owner is mocked, and no positive measurement/authority is issued. C++ checks
are source-structural checks, explicitly not compilation or device validation.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import inspect
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from scientist_one import cuda_device_timing as timing
from scientist_one import cuda_device_timing_evaluator as engine
from scientist_one.security import canonical_json_bytes


def _protocol(**changes):
    values = dict(metric_id="kernel-time", baseline_id="block32", seeds=(9, 7),
                  element_count=2, candidate_block_size=64, baseline_block_size=32,
                  warmup_iterations=1, repetitions=3)
    values.update(changes)
    return timing.CudaDeviceTimingProtocol(**values)


def _raw(protocol, *, zero=False):
    samples = []
    for seed_index, seed in enumerate(protocol.seeds):
        for phase, count in (("WARMUP", protocol.warmup_iterations), ("MEASUREMENT", protocol.repetitions)):
            for repetition in range(count):
                conditions = ("CANDIDATE", "BASELINE") if (seed_index + repetition) % 2 == 0 else ("BASELINE", "CANDIDATE")
                for condition in conditions:
                    value = (3.0, 0.0, 9.0)[repetition % 3] if condition == "CANDIDATE" else (9.0, 3.0, 0.0)[repetition % 3]
                    if seed_index % 2:
                        value += 2.0 if condition == "CANDIDATE" else 4.0
                    samples.append({"seed": seed, "phase": phase, "condition": condition,
                                    "repetition": repetition,
                                    "elapsed_ms": 0.0 if zero else (100000.0 if phase == "WARMUP" else value)})
    return {"schema_version": timing.CUDA_DEVICE_TIMING_OUTPUT_SCHEMA,
            "protocol": protocol.to_dict(), "metric_scope": "INTERMEDIATE", "unit": "MILLISECONDS",
            "device": {"ordinal": 0, "name": "SYNTHETIC NO DEVICE EXECUTED", "compute_capability_major": 8,
                       "compute_capability_minor": 0, "runtime_version": 12000, "driver_version": 12000},
            "samples": samples}


class CudaDeviceTimingProtocolTests(unittest.TestCase):
    def test_closed_protocol_codec_and_every_argument_binding(self):
        protocol = _protocol()
        self.assertEqual(timing.CudaDeviceTimingProtocol.from_mapping(protocol.to_dict()), protocol)
        self.assertEqual(protocol.canonical_bytes(), canonical_json_bytes(protocol.to_dict()) + b"\n")
        self.assertEqual(protocol.expected_argv(), (
            "./cuda-device-timing", "--dataset", "cuda-device-input.bin",
            "--schema-version", "cuda-device-timing-protocol/v1", "--profile-id", "cuda-u32-vector-add-events/v1",
            "--metric-id", "kernel-time", "--baseline-id", "block32", "--element-count", "2",
            "--candidate-block-size", "64", "--baseline-block-size", "32",
            "--warmup-iterations", "1", "--repetitions", "3", "--seeds", "9,7",
        ))
        self.assertEqual(protocol.expected_argv("/bin/future-cuda", "inputs/plan.bin")[:3],
                         ("/bin/future-cuda", "--dataset", "inputs/plan.bin"))
        for path in ("", "x\x00y", "x" * 4097, "\ud800", "\u00e9" * 2049):
            with self.subTest(path_length=len(path)), self.assertRaises(timing.CudaDeviceTimingError):
                protocol.expected_argv(dataset_path=path)
        with self.assertRaises(FrozenInstanceError):
            protocol.repetitions = 5
        view = protocol.to_dict()
        view["seeds"].clear()
        self.assertEqual(protocol.seeds, (9, 7))
        for changes in ({"unknown": True}, {"schema_version": "legacy"}, {"profile_id": "other"}, {"seeds": (9, 7)}):
            with self.subTest(changes=changes), self.assertRaises(timing.CudaDeviceTimingError):
                timing.CudaDeviceTimingProtocol.from_mapping({**protocol.to_dict(), **changes})
        for missing in protocol.to_dict():
            value = protocol.to_dict()
            del value[missing]
            with self.subTest(missing=missing), self.assertRaises(timing.CudaDeviceTimingError):
                timing.CudaDeviceTimingProtocol.from_mapping(value)

    def test_all_prospective_bounds_and_distinct_supported_blocks(self):
        for changes in (
            {"element_count": 0}, {"element_count": 65537}, {"element_count": True},
            {"warmup_iterations": 0}, {"warmup_iterations": 17},
            {"repetitions": 2}, {"repetitions": 4}, {"repetitions": 53},
            {"candidate_block_size": 33}, {"candidate_block_size": 32},
            {"baseline_block_size": 512}, {"seeds": ()}, {"seeds": (9, 9)},
            {"seeds": (-1,)}, {"seeds": (2**31,)}, {"seeds": (True,)},
            {"seeds": tuple(range(25))}, {"metric_id": "bad id"}, {"baseline_id": "a" * 129},
        ):
            with self.subTest(changes=changes), self.assertRaises(timing.CudaDeviceTimingError):
                _protocol(**changes)
        for candidate in (32, 64, 128, 256):
            for baseline in (32, 64, 128, 256):
                if candidate != baseline:
                    _protocol(candidate_block_size=candidate, baseline_block_size=baseline)
        maximum = _protocol(element_count=65536, seeds=tuple(range(23)) + (2**31 - 1,),
                            warmup_iterations=16, repetitions=51)
        self.assertEqual(len(engine.expected_schedule(maximum.to_dict())), 3216)
        self.assertEqual(65536 * 3216, timing.MAX_CUDA_DEVICE_TIMING_ELEMENT_ADDITIONS)

    def test_binary_dataset_exact_little_endian_planes_and_no_overflow(self):
        protocol = _protocol()
        raw = b"CDT1" + struct.pack("<I4I", 2, 0, 1000000, 999999, 1)
        self.assertIsNone(timing.validate_cuda_device_timing_dataset(protocol, raw))
        for malformed in (raw + b"\0", raw[:-1], b"BAD1" + raw[4:],
                          b"CDT1" + struct.pack("<I4I", 1, 0, 1, 2, 3),
                          b"CDT1" + struct.pack(">I4I", 2, 0, 1, 2, 3),
                          b"CDT1" + struct.pack("<I4I", 2, 0, 1000001, 2, 3),
                          b"CDT1" + struct.pack("<I4I", 2, 0, 1, 0xffffffff, 3), bytearray(raw)):
            with self.subTest(length=len(malformed)), self.assertRaises(timing.CudaDeviceTimingError):
                timing.validate_cuda_device_timing_dataset(protocol, malformed)
        maximum = _protocol(element_count=65536)
        raw = b"CDT1" + struct.pack("<I", 65536) + struct.pack("<I", 1000000) * 131072
        self.assertEqual(len(raw), timing.MAX_CUDA_DEVICE_TIMING_DATASET_BYTES)
        timing.validate_cuda_device_timing_dataset(maximum, raw)

    def test_native_subclasses_and_mutation_reject_before_hooks(self):
        hooks = []
        class ForeignInt(int):
            def __int__(self):
                hooks.append("int")
                return 3

            def __str__(self):
                hooks.append("str")
                return "3"

        class ForeignFloat(float):
            def __float__(self):
                hooks.append("float")
                return 0.0

        class ForeignText(str):
            def __eq__(self, other):
                hooks.append("equal")
                return True

        class ForeignList(list):
            def __iter__(self):
                hooks.append("iter")
                return super().__iter__()

        for changes in ({"repetitions": ForeignInt(3)}, {"metric_id": ForeignText("metric")},
                        {"seeds": (ForeignInt(2),)}, {"seeds": ForeignList([2])}):
            with self.assertRaises(timing.CudaDeviceTimingError):
                _protocol(**changes)
        protocol = _protocol()
        raw = _raw(protocol)
        raw["samples"][0]["elapsed_ms"] = ForeignFloat(0.0)
        with self.assertRaises(timing.CudaDeviceTimingError):
            timing.evaluate_cuda_device_timings(protocol, raw)
        with self.assertRaises(timing.CudaDeviceTimingError):
            protocol.expected_argv(executable=ForeignText("binary"))
        object.__setattr__(protocol, "repetitions", ForeignInt(3))
        for action in (protocol.to_dict, protocol.expected_argv,
                       lambda: timing.evaluate_cuda_device_timings(protocol, raw)):
            with self.assertRaises(timing.CudaDeviceTimingError):
                action()
        self.assertEqual(hooks, [])


class CudaDeviceTimingEvaluationTests(unittest.TestCase):
    def test_schedule_alternates_by_index_and_retains_warmups_and_zero(self):
        protocol = _protocol()  # Both seed VALUES are odd.
        raw = _raw(protocol)
        result = timing.evaluate_cuda_device_timings(protocol, raw)
        self.assertEqual([(row.seed, row.phase, row.condition, row.repetition) for row in result.samples[:6]], [
            (9, "WARMUP", "CANDIDATE", 0), (9, "WARMUP", "BASELINE", 0),
            (9, "MEASUREMENT", "CANDIDATE", 0), (9, "MEASUREMENT", "BASELINE", 0),
            (9, "MEASUREMENT", "BASELINE", 1), (9, "MEASUREMENT", "CANDIDATE", 1),
        ])
        self.assertEqual((result.samples[8].seed, result.samples[8].condition), (7, "BASELINE"))
        self.assertEqual(len(result.samples), 16)
        self.assertEqual([(item.seed, item.candidate_median_ms, item.baseline_median_ms) for item in result.per_seed],
                         [(9, 3.0, 3.0), (7, 5.0, 7.0)])
        self.assertEqual(result.samples[0].elapsed_ms, 100000.0)
        self.assertTrue(any(sample.elapsed_ms == 0.0 for sample in result.samples))
        self.assertEqual(result.to_dict(), engine.evaluate(protocol.to_dict(), raw))
        self.assertIsInstance(result.samples, tuple)
        with self.assertRaises(FrozenInstanceError):
            result.per_seed[0].candidate_median_ms = 0.0
        raw["samples"][0]["elapsed_ms"] = 7.0
        self.assertEqual(result.samples[0].elapsed_ms, 100000.0)

    def test_zero_and_reversed_timing_effects_are_not_filtered_or_promoted(self):
        protocol = _protocol(seeds=(0,))
        for reverse in (False, True):
            raw = _raw(protocol, zero=True)
            for row in raw["samples"]:
                if reverse and row["condition"] == "CANDIDATE":
                    row["elapsed_ms"] = 10.0
            result = timing.evaluate_cuda_device_timings(protocol, raw)
            self.assertEqual(result.per_seed[0].candidate_median_ms, 10.0 if reverse else 0.0)
            self.assertEqual(result.per_seed[0].baseline_median_ms, 0.0)
            keys = set(result.to_dict())
            self.assertFalse(keys.intersection({"p_value", "speedup", "passed", "status", "scientific_evidence_eligible"}))
            self.assertEqual(result.to_dict()["metric_scope"], "INTERMEDIATE")

    def test_all_identity_omission_duplication_permutation_and_metadata_mismatches_refuse(self):
        protocol = _protocol()
        original = _raw(protocol)
        variants = []
        for key in original:
            changed = deepcopy(original)
            del changed[key]
            variants.append(changed)
        for key, value in (("schema_version", "other"), ("unit", "SECONDS"), ("metric_scope", "END_TO_END"), ("unknown", True)):
            variants.append({**original, key: value})
        for change in ({"seeds": [7, 9]}, {"metric_id": "other"}, {"baseline_id": "other"},
                       {"candidate_block_size": 128}, {"warmup_iterations": 2}, {"element_count": 3}):
            variants.append({**original, "protocol": {**original["protocol"], **change}})
        for key, value in (("ordinal", 1), ("ordinal", True), ("name", ""), ("name", "\ud800"),
                           ("runtime_version", 0), ("driver_version", -1), ("compute_capability_major", 0), ("unknown", 0)):
            variants.append({**original, "device": {**original["device"], key: value}})
        for samples in (original["samples"][:-1], original["samples"] + original["samples"][:1],
                        list(reversed(original["samples"])), original["samples"][:1] * len(original["samples"]),
                        tuple(original["samples"])):
            variants.append({**original, "samples": samples})
        for key, value in (("seed", 2), ("repetition", True), ("phase", "MEASUREMENT"),
                           ("condition", "OTHER"), ("elapsed_ms", float("nan")), ("elapsed_ms", float("inf")),
                           ("elapsed_ms", -1.0), ("elapsed_ms", True), ("elapsed_ms", 10**1000), ("unknown", 0)):
            changed = deepcopy(original)
            changed["samples"][0][key] = value
            variants.append(changed)
        for index, raw in enumerate(variants):
            with self.subTest(vector=index), self.assertRaises(timing.CudaDeviceTimingError):
                timing.evaluate_cuda_device_timings(protocol, raw)

    def test_maximum_complete_synthetic_grid_fits_all_recorded_bounds(self):
        protocol = _protocol(element_count=65536, seeds=tuple(range(24)), warmup_iterations=16, repetitions=51)
        raw = _raw(protocol, zero=True)
        wire = canonical_json_bytes(raw) + b"\n"
        self.assertLess(len(wire), timing.MAX_CUDA_DEVICE_TIMING_OUTPUT_BYTES)
        parsed = engine.parse_json(wire)
        result = timing.evaluate_cuda_device_timings(protocol, parsed)
        self.assertEqual(len(result.samples), timing.MAX_CUDA_DEVICE_TIMING_SAMPLES)
        self.assertEqual(len(result.per_seed), 24)
        self.assertLess(len(canonical_json_bytes(result.to_dict())) + 1, timing.MAX_CUDA_DEVICE_TIMING_OUTPUT_BYTES)

    def test_standalone_evaluator_actual_retained_bytes_and_refusal_exit(self):
        protocol = _protocol()
        raw = _raw(protocol)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            script, config, observed = root / "evaluator.py", root / "protocol.json", root / "raw.json"
            script.write_bytes(timing.CUDA_DEVICE_TIMING_EVALUATOR_BYTES)
            config.write_bytes(protocol.canonical_bytes())
            observed.write_bytes(canonical_json_bytes(raw) + b"\n")
            command = (sys.executable, "-I", "-S", "-B", str(script), str(config), str(observed))
            completed = subprocess.run(command, check=False, capture_output=True, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, b"")
            self.assertEqual(json.loads(completed.stdout), timing.evaluate_cuda_device_timings(protocol, raw).to_dict())
            self.assertTrue(completed.stdout.endswith(b"\n"))
            observed.write_bytes(b'{"schema_version":"x","schema_version":"x"}')
            rejected = subprocess.run(command, check=False, capture_output=True, timeout=10)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stdout, b"")
            self.assertIn(b"refused", rejected.stderr)

    def test_standalone_parser_rejects_duplicate_nonfinite_depth_and_size(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'\xff',
                    b'[' * 10 + b'0' + b']' * 10, b' ' * (engine.MAX_JSON_BYTES + 1), bytearray(b'{}')):
            with self.subTest(length=len(raw)), self.assertRaises(engine.TimingValueError):
                engine.parse_json(raw)


class CudaDeviceTimingRetainedSourceTests(unittest.TestCase):
    def test_exact_evaluator_pin_fixed_bounded_reader_and_no_dynamic_execution(self):
        source = Path(engine.__file__).read_bytes()
        self.assertEqual(source, timing.CUDA_DEVICE_TIMING_EVALUATOR_BYTES)
        self.assertEqual(hashlib.sha256(source).hexdigest(), timing.CUDA_DEVICE_TIMING_EVALUATOR_SHA256)
        for raw in (source + b"\n", b"", b"x" * 1048577, bytearray(source)):
            with self.subTest(length=len(raw)), self.assertRaises(timing.CudaDeviceTimingError):
                timing._require_retained_evaluator_bytes(raw)
        reader = inspect.getsource(timing._read_retained_evaluator_bytes)
        self.assertIn('with_name("cuda_device_timing_evaluator.py")', reader)
        self.assertIn('stream.read(1_048_577)', reader)
        self.assertEqual(tuple(inspect.signature(timing._read_retained_evaluator_bytes).parameters), ())
        for module in (timing, engine):
            tree = ast.parse(inspect.getsource(module))
            self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                                 and node.func.id in {"exec", "eval", "compile"} for node in ast.walk(tree)))
        imports = [node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.level for node in imports))
        self.assertEqual({name.name for node in imports if isinstance(node, ast.Import) for name in node.names},
                         {"json", "math", "re", "sys"})

    def test_retained_cuda_every_launch_is_poisoned_timed_and_fully_checked(self):
        source = timing.CUDA_DEVICE_TIMING_BENCHMARK_BYTES.decode("ascii")
        self.assertIn("#include <cuda_runtime.h>", source)
        expected_order = (
            'checked(cudaMemset(d_output, 0xff, buffer_bytes)',
            'checked(cudaEventRecord(start, 0)', 'add<<<(c.n + block - 1) / block, block, 0, 0>>>',
            'checked(cudaGetLastError()', 'checked(cudaEventRecord(stop, 0)',
            'checked(cudaEventSynchronize(stop)', 'checked(cudaEventElapsedTime(&ms, start, stop)',
            'checked(cudaMemcpy(observed.data(), d_output, buffer_bytes, cudaMemcpyDeviceToHost)',
            'for (std::uint32_t i = 0; i < c.n; ++i)',
            'require(observed[i] == lhs[i] + rhs[i]', 'samples.push_back(',
        )
        offsets = [source.index(value) for value in expected_order]
        self.assertEqual(offsets, sorted(offsets))
        timed = source[offsets[1]:offsets[6]]
        self.assertNotIn("cudaMemcpy", timed)
        self.assertNotIn("cudaMemset", timed)
        self.assertIn("if (i < n) output[i] = lhs[i] + rhs[i];", source)
        self.assertIn("MAX_INPUT = 1000000", source)
        self.assertIn("std::isfinite(ms) && ms >= 0.0f", source)
        self.assertIn("(seed_index + repetition + order) % 2 == 0", source)
        self.assertIn("phase == 0 ? c.warmups : c.repetitions", source)
        self.assertIn("candidate ? c.candidate_block : c.baseline_block", source)
        self.assertNotIn("c.seeds[seed_index] %", source)
        # Every error-returning CUDA call is checked, including destruction.
        for match in re.finditer(r"\b(cuda[A-Z][A-Za-z]+)\(", source):
            if match.group(1) != "cudaGetErrorString":
                self.assertTrue(source[:match.start()].endswith("checked("), match.group(1))
        self.assertLess(source.index("checked(cudaFree(d_lhs)"), source.index("std::cout << json"))
        self.assertLess(source.index("std::cout << json"), source.index("std::cout.flush();"))
        self.assertLess(source.index("std::cout.flush();"), source.index('"stdout write failed"'))
        self.assertIn('return 2; // No usable measurement', source)

    def test_retained_cuda_complete_bounds_planes_device_identity_and_frozen_flags(self):
        source = timing.CUDA_DEVICE_TIMING_BENCHMARK_BYTES.decode("ascii")
        for literal in ("sample_count <= MAX_SAMPLES", "sample_count * c.n <= MAX_ADDITIONS",
                        "3 * buffer_bytes <= MAX_DEVICE_BYTES", "output_bound <= MAX_OUTPUT_BYTES",
                        'stream.tellg() == std::streamoff(8 + 8ULL * c.n)', 'read_le(stream) == c.n'):
            self.assertLess(source.index(literal), source.index("std::vector<std::uint32_t> lhs"))
        self.assertLess(source.index("for (std::uint32_t& value : lhs)"), source.index("for (std::uint32_t& value : rhs)"))
        self.assertLess(source.index("samples.reserve("), source.index("cudaGetDeviceCount("))
        for call in ("cudaSetDevice(0)", "cudaGetDeviceProperties(&device, 0)",
                     "cudaRuntimeGetVersion(&runtime_version)", "cudaDriverGetVersion(&driver_version)"):
            self.assertIn(call, source)
        for value in (timing.CUDA_DEVICE_TIMING_PROTOCOL_SCHEMA, timing.CUDA_DEVICE_TIMING_PROFILE_ID,
                      timing.CUDA_DEVICE_TIMING_OUTPUT_SCHEMA):
            self.assertIn(value, source)
        for flag in _protocol().expected_argv()[1::2]:
            self.assertIn('"' + flag + '"', source)
        self.assertIn("argc == 23", source)
        self.assertIn("MAX_SAMPLES = 3216", source)
        self.assertIn("MAX_ADDITIONS = 210763776", source)
        self.assertEqual(timing.CUDA_DEVICE_TIMING_METRIC_UNIT, "MILLISECONDS")
        self.assertEqual(timing.CUDA_DEVICE_TIMING_METRIC_DIRECTION, "LOWER_IS_BETTER")
        self.assertEqual(timing.CUDA_DEVICE_TIMING_METRIC_SCOPE, "INTERMEDIATE")
        self.assertIn("not independent observations", timing.CUDA_DEVICE_TIMING_METRIC_DEFINITION)


if __name__ == "__main__":
    unittest.main()
