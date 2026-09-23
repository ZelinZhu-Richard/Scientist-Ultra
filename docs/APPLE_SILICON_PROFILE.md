# Apple Silicon Profile

## Recorded bootstrap hardware

`state/APP_SESSION_BOOTSTRAP.json` records the 2026-08-12 app session as:

| Property | Recorded value |
|---|---|
| Architecture | `arm64` |
| Operating system | macOS 26.5.1, build 25F80 |
| Model | MacBook Pro (`Mac16,7`) |
| Chip | Apple M4 Pro |
| CPU cores | 14 total reported by `system_profiler` |
| GPU cores | 20 |
| Physical memory | 48 GB |
| Metal support | yes |
| Python | 3.13.9 at `/opt/anaconda3/bin/python3` |
| Disk at bootstrap | 971,350,180 KiB total; 571,872,104 KiB available; 36% used |

This is evidence for one session, not a hard-coded machine requirement. Scientist-One targets Apple Silicon machines down to a conservative profile roughly equivalent to a 10-GPU-core Mac and must also run CPU-only. Direct `sysctl` queries were denied by the app sandbox during bootstrap; `system_profiler` supplied core/memory evidence. Runtime hardware profiles sanitize detected executable paths to logical basenames so evidence does not capture outside-root absolute paths; the bootstrap receipt separately records the exact interpreter selected for this app session.

## Device selection

The device API supports `cpu`, `mps`, and `auto`:

- `cpu` is the portable reference and fallback.
- `mps` is allowed only through an explicitly injected adapter or a framework already imported by a trusted application startup, for supported operations, after a small CPU/MPS parity check passes a frozen tolerance.
- `auto` prefers only a validated accelerator; otherwise it chooses CPU and records the reason.

Float32 is the default. The built-in operation-specific parity tolerance is frozen at absolute and relative `1e-5`. Mixed or reduced precision requires a separate numerical-equivalence test and is not enabled merely for speed. CUDA is never assumed. An MPS detection result is not a parity result, and Metal support in the hardware profile does not prove the Python runtime has an approved MPS adapter. Device selection parity-runs the exact prepared CPU/MPS callables, requires finite shape-preserving outputs, and binds their output hashes before confirmatory MPS use. A pilot capability/parity failure records evidence and selects CPU; a frozen confirmatory runtime failure is never silently rerun on CPU. The supported captured-source CLI uses `-S`, does not preload third-party site-packages, and supplies no accelerator adapter, so its current automatic path is CPU. This session did not have an approved physical MPS adapter; adversarial coverage uses deterministic injected fixtures and does not establish real-device parity.

The selected demonstration `run-20260812T204930Z-299b1dad55` records `requested=auto`, `selected=cpu`, `fallback_reason=MPS_BACKEND_UNAVAILABLE`, `dtype=float32`, and no parity or execution-binding hash. Its isolated preflight observed no installed Torch, MLX, JAX, TensorFlow, NumPy, or SciPy distribution in the `-S` environment. This is a truthful CPU execution record, not evidence that the host lacks Metal hardware or that MPS could never work under a separately reviewed adapter.

## Research OS vNext `LOCAL_MAC` execution profile

The vNext experiment layer adds a provider-neutral `ComputeProfile` and a separate `ResourceEstimate`. A profile binds the execution mode, accelerator, scheduler, experiment class, CPU/accelerator counts, memory and batch bounds, concurrency, checkpoint/preemption capabilities, and validation status. The estimate records expected scientific value and uncertainty reduction plus CPU, GPU, RAM, VRAM, disk, wall-clock, and monetary cost where known. An estimate is planning evidence; it neither allocates resources nor authorizes escalation.

`LOCAL_MAC` supports the resource-planning classes `SMOKE`, `PILOT`, `EXPLORATORY`, and `FINAL_LOCAL`. Local profiles require the local scheduler and either CPU or a separately validated MPS adapter. MPS still requires a bound local validation artifact; accelerator detection alone remains insufficient. The integrated Research OS fixture intentionally uses the smallest CPU `SMOKE` profile and declares its frozen runs `NON_EVIDENTIARY`.

`LocalMacBackend` admits an explicit executable/argument vector, freezes the run specification, computes a bounded adaptive execution plan, limits concurrency, supplies a scrubbed child environment, captures bounded stdout/stderr, and validates the exact output manifest and returned artifacts before collection. Its reconciliation step fails a previously successful job if captured outputs later change. Confirmatory backend fallback is prohibited; exploratory fallback requires a new explicit run.

Promotion now preserves the adaptive plan itself, not only the run specification and outputs. The controller parses the exact immutable `execution-plan.json`, requires canonical bytes, and requires its semantic plan hash to agree with both the submission receipt and collected run. The raw bytes enter the registry as a frozen, safely deduplicable `adaptive_execution_plan`. Each job also gets a frozen `adaptive_execution_plan_binding`, parented to that raw plan and the exact frozen spec, recording the backend, job, run, spec, plan, submission, and collection identities. Both records enter the run's promotion event and downstream artifact closure.

### Bounded reviewed-template implementation

The integrated vNext fixture also exercises one provider-advisory implementation path locally. A coding-provider response may select only a member of a closed, separately reviewed worker-template catalog and supply schema-bounded numeric parameters and declared evidence parents. It cannot supply source code, an executable, argv, filesystem paths, dependencies, shell policy, or network policy. Admission re-resolves provider provenance, catalog and review records, exact context, evidence, deterministic code/configuration bytes, and the frozen run descriptor before the built-in `LocalMacBackend` may execute it.

The resulting autonomous component is an exploratory `NON_EVIDENTIARY` run. Its input is deterministically derived from non-protected fixture rows, every seed output is registered, and a separate semantic-validation artifact recomputes the template metric from the frozen data and configuration. This demonstrates bounded implementation and local execution plumbing; it is not permission to execute arbitrary model-generated code and is not a scientific result.

### Explicit isolation limitation

The vNext local runner does **not** provide an OS-enforced filesystem, process, or network sandbox. An executable allowlist, confined path handling, a scrubbed environment, resource bounds, adaptive-plan custody, and output validation reduce accidental and provenance failures, but they cannot confine arbitrary or hostile child code. `LOCAL_MAC` is technically functional for the reviewed CPU fixture and its clean rerun, while scientific-result eligibility is `BLOCKED_LOCAL` until a tested backend-owned isolation boundary or equivalent reviewed executor exists. Run only reviewed local experiment programs, keep current outputs non-evidentiary, and do not treat `VALIDATED_LOCAL` as evidence of process isolation or scientific validity. This limitation is independent of the captured-source CLI boundary described elsewhere.

## `GPU_CLOUD` boundary status

The vNext layer defines replaceable CUDA, direct-remote, scheduled, and SLURM-like backend contracts with queues, checkpoints, preemption, and artifact return. Escalation records expected value, uncertainty reduction, GPU need, memory/storage/time/cost estimates, and a reason; it must preserve the same provider-neutral scientific project definition used locally. Multi-GPU profiles require an explicit rationale, and returned artifacts must re-enter the trusted registry.

Two offline boundaries are implemented. The integrated Research OS fixture uses the deterministic fake lifecycle and reports `BOUNDARY_TESTED_ONLY`. Separately, the injected `ScheduledGPUCloudBackend` binds local and cloud specs through an explicit escalation/submission plan; enforces idempotency, queue/state/attempt monotonicity, checkpoint-bound requeue and preemption lineage; and validates bounded manifest-backed artifact return before registry admission. Hostile transport, stale-attempt, checkpoint, cancellation, malformed-bundle, and artifact-substitution paths are exercised without a live provider.

Neither boundary performs a real networked GPU job. Scheduled transport status and returned artifacts remain `UNTESTED` and non-evidentiary, and no CUDA hardware, remote scheduler, queue, preemption service, credential, cost authority, remote isolation, or independent artifact-return path has been validated live. These controls must not be reported as a successful `GPU_CLOUD` run.

## Conservative resource profile

`configs/resource_limits.json` freezes:

- 28,800 seconds maximum wall clock;
- 2,147,483,648 bytes maximum project artifacts;
- two concurrent experiments maximum;
- seven CPU workers maximum for this recorded 14-core machine;
- one GPU job maximum;
- 60% memory soft and 70% hard fractions;
- minimum free disk of 26,843,545,600 bytes or 10% of total, whichever is greater;
- 300-second checkpoint interval;
- 40% scientific validity reserve; and
- a repeated-worker-crash policy threshold of three recorded crashes.

The controller also treats 15 minutes without progress as a stall and bounds exponential retry backoff from one to 60 seconds. The configured CPU ceiling is clamped to at most half the detected logical CPUs. Missing memory or disk observations pause new admissions rather than being interpreted as zero pressure.

These are controller policy/accounting rules, not proof of integrated crash
collection or a durable branch stop. The installed code has no production caller
of `register_worker_crash`; an arbitrary Python exception is not an observed OS
worker crash. Durable admission-refusal and bounded owned-PILOT failure handling
are now installed with private scoped evidence; installed combined validation
is still pending. Their
tests do not establish true OS-crash collection, every interrupted publication
path, physical containment, or actual protected-data reserve accounting.

The limits are ceilings, not allocation targets. A calibration and small pilot precede a large run. On an unknown/lower-capacity machine, runtime probes must reduce concurrency; they must not assume this M4 Pro profile. The vNext per-experiment `ComputeProfile` and `ResourceEstimate` must remain within these repository-wide ceilings; they do not supersede them.

## Pause and fallback behavior

Checkpoint and stop starting new work when memory reaches a hard threshold, free disk approaches the reserve, serious/critical thermal pressure is observable, artifact growth is abnormal, workers repeatedly fail, or wall budget expires. Do not defeat macOS thermal management and do not busy-loop while waiting. Hardware/probe evidence uses `AVAILABLE`, `UNAVAILABLE`, `DENIED`, or `ERROR`; where thermal state is not observable, its value remains `unknown` with the unavailable evidence rather than pretending to be nominal.

## Local checks

```sh
set -eu
uname -m
sw_vers
system_profiler SPHardwareDataType
df -k .
/opt/homebrew/bin/python3 --version
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py preflight
```

These commands are non-mutating except that `preflight` may record project-local state by design. Compare the resulting `state/HARDWARE_PROFILE.json` to the bootstrap receipt and investigate material differences before resuming a confirmatory run.

When a new hardware profile differs from an existing one, the profiler preserves the prior receipt by SHA-256 under `.scientist-one-build/checkpoints/hardware-profile-history/` before publishing the current profile. This records drift; it does not prove two environments are equivalent.
