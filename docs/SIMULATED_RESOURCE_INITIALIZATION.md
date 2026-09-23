# Simulated resource initialization

This is an implemented local accounting prerequisite, not a scientific execution or confirmation result. The initializer is in `src/scientist_one/simulated_resource.py` and uses the existing artifact registry, event ledger, resource controller and external resource-history storage.

## Supported scope

The closed profile uses the existing public known-answer two-window population. A canonical run namespace is derived from that population and profile, not a caller-selected study or generation. Its original budget is 40 units with a 0.4 confirmatory reserve fraction. The actual initial protocol and resource configuration must agree on that fraction.

The inventory producer freezes the real source/configuration inventories under its own explicit simulated-initialization provenance. It does not pretend the legacy offline CLI ran, and an inventory of source bytes is not execution attestation. Initialization then binds the exact initial protocol, Evaluation Contract, population, inventories and complete pre-initialization registry/ledger population.

The native controller supplies the original runtime state. Callers cannot supply a new start time, reset counters, or replace an existing initial budget. The external resource record is published before the local initialization artifact and event. Recovery can complete only that exact interrupted suffix; it cannot allocate a second initial budget or silently accept intervening work. Returned runtime projections are detached from immutable recorded bytes.

## Reading and currentness

The public initialization reader supports the original initialization-only current population and original external head. It verifies live inventories and rechecks external history and the complete paired registry/ledger snapshot after its final live reads.

The internal historical reader resolves the earlier sealed dependencies without consulting later live configuration or treating a historical budget as current execution permission. It separately rejects competing initialization records, events and corrections in the caller-selected outer population. Unrelated later history does not retroactively rewrite the initialization. Future reserve/charge consumers must implement their own complete current-use checks; calling a historical reader is not such a check.

Historical initialization replay scans every unconsumed selected record within the existing reservation census's 2 MiB per-record bound and refuses larger unconsumed objects. This prevents renamed initialization markers from disappearing above the initializer's separate 1 MiB publication cap. Exact owned initialization/inventory records remain separately validated; unrelated supported-size notes remain readable.

These are bounded consistency checks, not an atomic transaction against arbitrary host changes after the final check. The external history survives run-directory rollback, but it is still project-local. Whole-project rollback resistance requires an independent monotonic witness that this profile does not provide.

## First confirmatory charge

`charge_simulated_confirmatory_reserve` now restores the actual original native runtime and debits the first reservation's eight members. The total remains 40, the confirmatory reserve remains 16, exploratory use remains zero, and elapsed time is never reset. The source-owned `sim-resource-charge/v1` artifact and event bind the complete I/S source population and native external authority chain. No workload or holdout release occurs.

Publication is external-first, followed by the registry record and ledger event. An interrupted exact prefix can complete its missing local suffix without restoring or charging the controller again. Substitution, corrections, unowned aliases, source drift or a later external head refuse current use. Completed historical replay is separate from current permission; the public reservation reader consumes a charge only through its complete source owner, not its family name. Event-only and oversized renamed I/Q aliases are covered by regression tests.

`require_simulated_confirmatory_charge` requires the exact current Q1 head and unchanged live source/configuration. It does not authorize release, execution, scientific evidence, independent custody, blinding or E4. Q2 and the two-release lifecycle remain unfinished.

## Verification and remaining work

The first native observation is now installed in `simulated_observation.py`.
Preparation seals exact Q1 sources; an attempt marker in the existing native
external resource-history chain consumes the one attempt before STARTED and
RELEASE without charging another validity unit. Native custody stays outside
the run tree. Run-directory rollback cannot erase that attempt or permit a
second release; whole-project rollback remains unsupported. J1 replays the
actual terminal journal and aggregate and retains explicit non-evidentiary,
non-independent, no-scientific/no-freshness/no-E4 authority flags.

The old amendment path refuses possible native attempt exposure, including
external-only attempts after run-tree rollback. It cannot silently report
unseen results. Completed pre-observation amendment replay remains historical.
Explicit observation-aware amendments and second-window allocation are installed;
the second debit/attempt/release sequence remains unfinished private work.
Generic recovery refuses this profile; only its exact owner may
reconcile supported interrupted suffixes, without retrying a consumed attempt.

The earlier installed J1/default-amendment/native-hook matrix passed517/517 tests in
630.706s, with unchanged whole Python inventory, no failures/errors/skips, clean
Ruff and closed scoped independent reviews. This supersedes the earlier Q1-only
checkpoint below; overlapping test totals are not added.

## Explicit observed-contract amendment

The existing amendment facade accepts an explicit exact one-element tuple of
`observation_artifact_sha256s` for the supported completed J1 profile. Omission
retains the legacy v1 branch; malformed or empty explicit selection refuses.
The v2 amendment fully replays J1 at its sealed source population and derives
`results_already_seen` and `requires_new_confirmatory_reserve`; J1 is not
misrepresented as a scientific result manifest. Existing hypotheses and their
promotion history are immutable; additions are secondary, post-hoc and untested.
The supported sequential chronology is J publication <= child contract freeze
<= amendment publication. The existing protocol-revision wire consumes those
source-owned flags and remains non-authorizing.

Current publication retains native resource and custody guards through the
exact registry/ledger comparison and commit. Orphan recovery may complete only
its own exact A-only or A+C suffix. Disk accounting includes missing payload,
metadata and event bytes, without another experiment or validity charge.
Completed historical replay does not require today's live budget or custody.
Unknown/renamed aliases, relevant corrections and source drift refuse.

The private combined matrix passed557/557 in988.027s on unchanged installed and
selected private bytes. Those two source files are now installed exactly, with
five public regression modules; the J test has only AST-identical line expansion
for lint. The pinned predecessor-v1 differential stays private. Installed-only
556 validation passed in988.454s, with the complete242-file Python inventory
unchanged and no failures, errors or skips. These overlapping totals are not
added. The later installed A/J/S combined matrix passes581/581 in1571.530s,
with all243 Python files unchanged and no failures, errors or skips. No
whole-goal or scientific acceptance follows from these matrices.

The installed initializer and its native helper/clock/snapshot-boundary checks pass 66 targeted tests. Independent review of the same initializer passed all 40 component tests after reproducing and repairing protocol/config fraction mismatch, unconsumed selected-history aliases and late-read metadata changes. These counts overlap other checkpoints and are not a full-suite total; exact hashes and retained failures are in the private run ledger.

The explicit v2 [first reservation](SIMULATED_RESERVE_MEMBERSHIP.md) now binds this initialization through its exact fourth parent and sealed source map. The standalone current initialization reader remains intentionally initialization-only; after a reservation, historical initialization replay is used inside the reservation's own complete checks. Native external envelopes must retain the writer's canonical bytes and integer sequence, not merely equal parsed JSON values.

The earlier September 13 Q1/native-lock integration passed182 tests with unchanged Python inventory; the earlier669-test/34-module checkpoint predates Q1. These historical counts are not a final whole-project total. Post-observation amendments and the cumulative two-window lifecycle remain in progress. No scientific freshness, independence, blinding, E4 authority, successful external provider run or public-release approval is claimed.
