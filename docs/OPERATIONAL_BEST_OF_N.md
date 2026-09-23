# Operational BEST_OF_N reporting

Status: locally integrated and independently scoped-reviewed. The frozen affected
matrix passes636/636 tests across28 full modules in905.570s, with no skips or
failures and an unchanged complete Python source/test inventory. This document
describes the closed local API, not a completed scientific workflow, an enabled
product command, final whole-goal verification or public-release approval.

## Scope and source ownership

The reporting owner in `src/scientist_one/seed_reporting.py` uses the existing
`ArtifactRegistry` and `EventLedger`. It reopens real Evaluation Contract,
per-seed plan, frozen run specification and design-freeze receipt owners. Both
the initial batch and the sole possible retry must have exact sealed design
populations before the first operational admission. A historical freeze receipt
does not by itself establish current contract-family freshness.

The initial profile exempts only the two selected, fully verified design-freeze
events from its scientific-timeline marker fence. Extra design-like declarations
or copied timeline fragments are unsupported coexistence, not proof of actual
execution or scientific invalidity. Historical design readers remain unchanged.

The closed profile is exploratory, CPU `LOCAL_MAC`, `NON_EVIDENTIARY`, and the
exact built-in backend/runner with [native terminal capture](LOCAL_TERMINAL_CAPTURE.md).
It admits one ordered cohort of 1–128 seeds, one split and one primary metric.
Both attempt identities, selection rule and retry rule are frozen in advance;
the second specification may differ only in its declared retry identity.

Isolation is disabled in this profile. Consequently, equality of declared
Dataset identifiers cannot prove that other local resources were unread.
Initial admission refuses protected scientific work or prior result-work in the
same registry/ledger population, including incomplete ownership markers.
Conversely, prospective scientific admission treats an operational reservation
as possible exposure even if no child, terminal observation or ledger event is
available. This is a conservative run-wide exclusion, not evidence that execution
or result observation occurred. Other run stores and unregistered local files
are outside this population guarantee.

## Attempt lifecycle

1. The first admission binds the exact current source map and event prefix,
   verifies input bytes and both runtime namespaces, and publishes under paired
   registry/ledger comparison-and-swap before dispatch.
2. The actual backend produces a native terminal observation. Its exact bytes
   become one registered artifact parented to the admission; they are not
   replaced by a summary or wrapped in a second provenance system.
3. Only an exact queue-timeout observation with no invocation, no proven process
   launch, no dispatch intent and no outputs permits the already-frozen second
   attempt. A process-creation exception, execution failure, timeout, cancellation
   or missing terminal does not qualify.
4. The report binds all admitted attempts and their archived terminals. The
   retry is an additional attempt, not a change to the planned number of seeds.

An interrupted admission is an unresolved reservation. Recovery can complete
only its exact record/event publication at an unchanged source prefix; it never
dispatches that recovered admission. An interrupted report can complete its
exact event only from its unchanged source population. Completed replay permits
unrelated material already present at entry, but must refuse changes during
readback. These rules preserve resumable partial writes; they are not a claim
of filesystem transactionality against arbitrary same-principal mutations.

## What the report means

The report separates the raw observed numeric distribution from the eligible
distribution. Failed and invalid rows retain their reported numeric values.
All five declared seed statuses remain visible. A failed batch without per-seed
observations does not create fictional failed seed rows. Invalid rows or absent
manifests leave explicit completeness and seed-coverage limitations, while the
exact native capture retains the original bytes.

Eligibility requires a backend-accepted successful manifest and exact declared
seed coverage. Selection follows the frozen primary-metric direction, then
frozen seed order for ties. Target-distance comparisons use exact rational
distances of the retained finite numeric values. An all-adverse cohort has no
selected result. The selected value is never a representative average.

These are operational bookkeeping claims. They do not establish metric
semantics, statistical independence, scientific adequacy, generalization,
independent execution, superiority or result-promotion authority. Existing
scientific consumers are not relaxed to accept this selected report as a
scientific Result.

## Readback and publication boundaries

`execute_operational_best_of_n` owns prospective dispatch and report publication.
`recover_operational_best_of_n` performs source-backed recovery without fresh
dispatch. `require_operational_best_of_n_report` requires an already completed
publication and rejects any replay mutation.

The passive progress descriptor operates only on its caller-selected record map
and event prefix; it does not invoke full admission owners. The negative exposure
guard also supports paired publication critical sections. It reads only exact
selected, bounded, confined metadata/content bytes without reacquiring registry
or ledger locks. Historical unsealed design replay inspects only referenced
records in its supplied event prefix, never unrelated record-only later work.

Native sources, logs, manifests and outputs can contain confidential content.
All operational captures, admissions and reports are local generated run
artifacts, not public Git candidates. No provider/network invocation, independent
scientific custody, human-only E4 approval or public-release clearance is supplied
by this profile or its tests.
