# Operational Local Mac terminal capture

The opt-in Local Mac capture profile preserves actual completed or partial job
observations, including unsuccessful attempts. It is not a scientific Result,
independent execution attestation, network-isolation proof or BEST_OF_N report.
The existing registry and ledger remain the scientific authorities.

## Closed scope

The exact `local_terminal_capture` metadata marker has schema
`SCIENTIST_ONE_LOCAL_TERMINAL_CAPTURE_PROFILE_V1` and profile ID
`EXPLORATORY_BOUND_CPU_TERMINAL_V1`. Admission requires the exact built-in backend
and runner, CPU `LOCAL_MAC`, `EXPLORATORY`, `NON_EVIDENTIARY`, disabled checkpoints
and resume, and disabled isolation mode. The latter is an explicit limitation:
this profile does not claim full scientific read isolation or resource
containment. Absence of the marker preserves the prior backend route.

Captured files are limited to 2 MiB each and 4 MiB in aggregate. Execution sources
have a separate 2 MiB admission budget, including reserved binding metadata;
each log is limited to 1 MiB. Up to 128 declared output paths are observed.
The deterministic encoded envelope fits the unchanged 8 MiB canonical JSON
limit. Over-limit outputs retain a bounded identity/status without invented
bytes. Inaccessible or malformed output inventories stay explicitly unresolved.

## Observation and recovery

`collect_terminal_observation(job_id)` verifies the durable native observation
and its current source files. `recover_terminal_observation(spec,
idempotency_key=...)` reconstructs that exact observation without launching a
child. The final terminal marker is written only after captures and replay
checks; missing or incomplete publication is unresolved and cannot authorize a
fresh dispatch. Finished jobs without a marker do not report themselves as
still running.

Invocation count and successful `Popen` return count are distinct. An exception
after invocation but without a returned process handle does not prove that no
process launched. Only a zero invocation count is reported as `NOT_INVOKED`.
Partial log reads preserve available bytes with incomplete or unavailable
capture status; unknown truncation is not converted into `false`.

Nonzero exit, timeout and cancellation cannot gain an accepted output manifest,
even if the child wrote valid-looking JSON. Invalid manifests remain raw bytes.
Unsafe names are not opened; unencodable decoded names remain in the raw
manifest with unresolved inventory rather than being silently renamed. Ordinary
I/O failures retain `ERROR` or `UNAVAILABLE` observations only where the required
identity checks remain possible. File replacement or source drift refuses
replay instead of being downgraded into an ordinary execution failure.

Successful operational manifests can preserve all five declared seed statuses
and adverse numeric values. Missing batch output does not establish per-seed
failure. Prospective selection, complete admitted attempt history, retry rules
and source-owned report publication have a separate
[operational reporting candidate](OPERATIONAL_BEST_OF_N.md). Its integration and
independent verification remain unfinished.

## Confidentiality and evidentiary limits

Native captures include raw local sources, logs and outputs and may contain
confidential material. They are local run artifacts, not public-release
candidates; do not commit or upload them. The terminal DTO and runtime identity
checks do not resist an arbitrary coherent rewrite by the same local principal.
Actual network use remains `UNKNOWN_UNATTESTED`, scientific eligibility remains
false, and constructing a capture DTO grants no authority.
