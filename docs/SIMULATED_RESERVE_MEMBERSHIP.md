# Simulated reserve membership boundary

This component records allocation bookkeeping for two windows of an existing
public known-answer calibration fixture. It does not implement scientific
confirmation, fresh blinded data, evaluator execution, resource charging, custody
release, independent authority, or human E4 approval.

The profile is `PINNED_CAL_TRUE_NULL_TWO_WINDOWS_V1`. It reuses the checked
`cal-true-null-v1` calibration case, with 16 identified rows and two fixed windows:

| Window | Control members | Treatment members | Allocated units |
| --- | --- | --- | --- |
| 1 | c01–c04 | t01–t04 | 8 |
| 2 | c05–c08 | t05–t08 | 8 |

These are identity and accounting units, not a statistical error budget. The
rows are already public; disjoint identifiers do not establish independence,
blinding, scientific freshness, or multiplicity control. The complete pinned
case, each row, and each fixed evaluator payload are content-checked. Payload
hashes and allocation-manifest hashes have different meanings.

## Existing registry and ledger ownership

`register_simulated_reserve_population` registers the pinned population.
`register_simulated_confirmatory_reserve` publishes one reservation and its
checkpoint. `require_simulated_confirmatory_reserve` replays the allocation.
All use the existing artifact registry; reservations use the existing
`frozen_confirmatory_split` family. Standalone allocation uses `sim-reserve/v1`;
the resource-backed first reservation uses `sim-reserve/v2`; the explicitly
observed second reservation uses `sim-reserve/v3`. There is no separate ledger.

A reservation binds exact protocol, contract, population, metadata identities,
membership, and its prepublication registry map and ledger prefix. Window 1
requires an initial protocol and contract. Standalone v1 window 2 requires the exact first
reservation and actual append-only contract/protocol revision owners. Creating a
new reservation checks the current contract; historical replay checks the
contract's status at the recorded allocation point.

Registered reservation bytes occupy their window even if the publication event
was interrupted. Exact orphan recovery requires the original source population
and ledger prefix. Renaming a request, changing sources, correcting a reservation,
or registering competing records does not refund or reassign its members.
Publication preflights native metadata, capacity, chronology and the complete
prospective event, then compares the captured registry/ledger pair under locks.

## Resource-backed first reservation

Supplying `initialization_artifact_sha256` explicitly selects v2. The first
reservation fully replays the native [resource initialization](SIMULATED_RESOURCE_INITIALIZATION.md),
requires its original protocol/contract/population and exact source population,
and binds that initialization as the fourth direct parent. The sealed registry
map includes its metadata identity; its event must be the original event zero.
Only that fully owned initialization record/event is exempted from the reserve
census. Shared profile names or resource-family labels alone grant no exemption.

New publication, exact orphan recovery and completed-registration retries hold
the native project-resource lock and require the original external initialization
head before and after the operation. Native history accepts only its writer's
exact canonical envelope bytes and integer sequence. Reservations do not write
external resource records or consume validity units. Historical reservation
readback does not require the external head still to be initial and therefore
does not authorize a new allocation or charge.

V2 window two remains refused; the observed second window requires the explicit
v3 branch described below. Omitting the initialization selector does not silently
upgrade v1. Population re-registration
after initialization is unsupported: that API has no ledger context with which
to validate an initialization exemption. Retry the reservation against the
already-owned population; this is not a general end-to-end restart initializer.

## Observed second allocation

The existing facade accepts `prior_observation_artifact_sha256` to select the
closed v3 second-window profile. It requires the exact original initialization,
population and S1, actual completed native J1 observation, and the source-owned
observed amendment A2/C2 and protocol revision P2. It checks each complete sealed
population, not just matching family names or locators. C2 retains `ALL_SEEDS`.
The allocation has seven exact parents: population, P2, C2, original I, S1, J1
and A2. Its eight members are the fixed second-window members shown above.

Fresh publication retains native resource and terminal-custody guards, checks
current C2 and original source/configuration bytes, and compares the whole
registry/ledger population. Payload, metadata and event bytes are included in
publication capacity. Full postwrite replay releases registry/ledger locks
while retaining the native guards, then reacquires those locks for a final
whole-population check. Late source, custody or ordinary registry changes can
therefore cause refusal after the allocation has already been persisted.

A record-only interruption occupies its window within the retained append-only
registry; fresh native readers may complete only its exact missing event.
Completed retries and sealed historical replay add no records or events and
do not need current resource admission. Ambiguous populations refuse use.
Allocation is not a rollback-resistant debit: native I/Q1/T1 remains unchanged
at eight used units. Q2/T2/J2 are still unsupported, and the Q1 charge API refuses
this second reservation. No second release or scientific freshness is granted.

The exact S2 source and 25-test module are installed after private verification:
23 lifecycle/marker tests, two added fresh-reader/final-population controls, and
113 affected legacy tests passed on unchanged inventories. The combined
installed581/581 matrix passed in1571.530s with all243 Python files unchanged
and no failures, errors or skips. Overlapping component counts are not added;
this is not a final project total or scientific/public-release approval.

## Historical replay versus new use

The private lower replay edge receives an enclosing owner's verified source
population and prefix. It does not recursively enumerate later reservations or
acquire today's full amendment population. Public readers retain current
correction and competing-record checks. Historical readability is not permission
to begin another release.

The selected-only protocol/amendment path currently refuses legacy manifest and
scientific-timeline populations: those older dependencies still include live
owners. This is an explicit unsupported combination, not an assertion that an
arbitrary mixed scientific history has been made snapshot-local.

A negative-only guard prevents this simulated profile from authorizing a new
scientific design. Its historical mode inspects only the owned event prefix and
referenced records, preserving earlier unsealed history. Generic legacy split
families and ordinary prose alone do not select the new profile. The allocator
also refuses unsupported prior scientific/operational work, unrecognized custody
state, aliases and ambiguous allocations. These are conservative coexistence
rules, not proof of actual exposure to particular rows.

## Deliberately unfinished integration

The standalone v1 two-window component test creates no custody release. It exercises
native contract/protocol publication and membership replay only. It must not be
reported as a successful two-study experiment.

The first native release/observation, explicitly observed amendment and second
allocation are now connected. The remaining lifecycle must add the cumulative
second resource charge, durable second attempt and second native release. It must preserve source
and configuration verification, unresolved/failed-use refusal, crash recovery,
current correction checks, and the original custody evaluator. That integration
is not supplied by these APIs. Scientific Dataset/Split validity, statistical
controls, independent custody and complete local isolation remain separate
requirements.

The installed initialization and v2 first reservation use one profile/population-derived project-local
namespace, with a prospective fixed 40-unit budget and a 0.4 confirmatory reserve
fraction. Initialization must precede the first reservation. Later charges must
derive eight units from the owned membership and retain cumulative usage and the
original epoch. The existing external resource journal protects against rollback
of the run tree while that journal survives; it does not protect against restoring
or deleting the entire project. Initialization and first allocation are implemented
bookkeeping; the first eight-unit charge is implemented, while the cumulative
second charge and two-release lifecycle remain unfinished.

The existing native persistence and checkpoint-history rules have been extracted
for shared use. Their storage tests do not establish a completed custody release
or a revised study. Real observations must come from the native locked journal,
not caller-supplied result records. The installed versioned amendment keeps
simulated observations distinct from scientific output manifests and preserves
effective exposure facts even though the legacy raw contract flag stays false.

Focused tests cover allocation, immutable source replay, exact orphan recovery,
aliases, corrections, bounds, concurrent source changes and negative scientific
admission. Current combined verification and retained failures are recorded in
the local run ledger; no final scientific or public-release acceptance is implied.
