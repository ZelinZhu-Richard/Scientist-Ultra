# Managed literature acquisition: first operational slice

Status: selected bounded design with a private candidate, **not installed or
acceptance-verified**. The immutable-patch security review was externally stopped;
its related investigation and repair remain stopped. Separate functional evidence
does not clear that review or authorize integration.
This addresses an original dependency of `RESEARCH_OS_VNEXT_META_SPEC.md`;
it is not another governing specification or a FARS adaptation. The installed
[pagination component](LITERATURE_PAGINATION_DESIGN.md) alone does not implement
this workflow. The private candidate passed 450 existing compatibility checks.
The original, nonportable 38-test module passed separately on Python 3.14.6 and
3.11.14 using explicit fixture resource settings. Its revised isolated test
infrastructure has only three positive controls verified on 3.14.6; 35 remain
unrun. A separate six-command offline CLI sequence passed on 3.14.6 with the
ordinary resource configuration unchanged. These are distinct scoped results,
not additive totals, a full-suite pass, live literature evidence or completed
Phase A. Exact private hashes, commands and limitations are in the run ledger.

## Failure and owners

An imported page helper accepts a caller-selected predecessor. It neither knows
which work a run authorized nor accounts for interrupted dispatches across
processes. Recalling its acquisition API after a publication interruption sends
again. Fix those operational gaps through the existing orchestrator, run manifest,
event ledger, artifact registry, scientific-design readers and resource authority.
Do not add another history, experiment authority, state machine or ledger.

The public command owner remains `cli.py` and its captured isolated launcher.
`orchestrator.py` owns guarded command admission, ordinary manifests/checkpoints
and mode routing. One implementation section in `research_os.py` owns acquisition
input validation and checked event interpretation. Source syntax and capture
remain in `scholarly_gateway.py`; registered publication/replay remains in
`scientific_design.py`. Existing modes and fixture receipts retain their contracts.

## Public boundary and scope

- Add `literature-begin --input <project-relative JSON>` and
  `literature-advance <run-id>`. Begin validates all inputs before reserving a run;
  advance accepts no caller cursor, predecessor, totals, overrides or transport.
- Use explicit `literature_acquisition` in the existing run manifest. Keep
  CALIBRATE as the operational holding state, empty dataset/seed declarations,
  no evaluator decisions and no scientific transitions. Search progress is not
  calibration, charter acceptance, GROUND, novelty or manuscript readiness.
- Route status, verify and resume explicitly through the same mode owner.
  Resume may reconcile one outstanding dispatch without I/O or advance one
  admitted page. Refuse legacy experimental advancement, reproduce and package
  for this mode; do not accidentally fall through to demo handlers.
- Before choosing any mode implementation, resolve the uncorrected,
  ledger-anchored frozen run intent and initialization/enrollment through the
  existing registry checks. Compare mutable projections
  and reject disagreement or ambiguity. A manifest relabelled from acquisition
  to `brief` must not reach a legacy handler before this validation; test both
  directions and genuine legacy controls. Cover direct legacy advance, reproduce
  and package as well as the new commands. No second mode authority is added.
- Separate read-only mode identification from permission to recover or advance.
  Identification may inspect a fully valid raw ledger or its explicitly validated,
  nonempty `TRUNCATED_FINAL_EVENT` prefix; no other invalid history qualifies.
  Strict admission still requires a complete valid ledger and external-checkpoint
  agreement before new work. Preserve safe legacy truncated-tail recovery only
  after identifying the genuine legacy owner and checking checkpoint safety;
  revalidate strict identity and admission after repair. Acquisition never enters
  generic legacy repair and this initial profile refuses its truncated ledger.
  Preserve the existing nonpersisted checkpoint-refusal result on legacy resume
  and failed verification, with no repair or quarantine on checkpoint conflict.
  Ordinary recovery is not a read-only diagnostic: any diagnostic-only reuse of
  `RecoveryManager.recover` must set both `repair_truncated_tail=False` and
  `incomplete_paths=()`. These are existing-owner controls, not another history.
- The project command lock spans reload, validation, admission, dispatch and
  outcome commitment. This covers ordinary cooperating public callers, not
  malicious direct low-level writes or rollback of the entire project.
- One immutable enrolled round; at most four unique query plans, each with its
  exact registered goal/SEED target/route parents. Total requested page slots
  across plans is at most four. Process ordered plans and replay-derived pages;
  early terminal/failure observations leave unused obligations visible.
- Preserve the existing OpenAlex/Semantic Scholar and two-round fallback-policy
  defaults. OpenAlex-only work cannot discharge the missing source or second
  round. Do not fabricate `ProblemInvestigationState`, source exhaustion,
  target sufficiency or general-web permission to represent early progress.

## Closed initial transport and input

The first executable profile is literally `OPENALEX_CURSOR_OFFLINE_V1`.
It is an operational offline test profile, **not real external acquisition**.
It instantiates existing exact FixtureTransport/EgressGateway/source-owned
objects. No caller Python, URL, credential, signer, clock, network flag or plugin
is accepted. Freeze the ordinary credentialless cursor policy defaults: three
attempts, 24 MiB total response/request body budget, 30-second exchange timeout
and existing rate/backoff rules. Do not mutate that route to consume a remainder.

Closed input fields are `schema_version`, `transport_profile`, `goal`, `queries`
and `caps`. Version is `literature-acquisition-input/v1`; `goal` is the existing
canonical research-goal wrapper, not another goal format. Each query has exactly
`query_id`, `query`, `synonyms`, `structured_filters`, `page_size`,
`max_page_requests` and `pages`. Reuse existing text/query/filter/page semantics;
query IDs and complete plan contents must be unique. Preserve allowed-source
permissions in the registered plans; do not expose an obligation-relaxation knob.

Each declared page has exactly `page_number` and `responses`, with one to three
responses. Each response has exactly `status_code`, `body_path` and
`body_sha256`. Page ordinals cover the declared plan slots exactly. HTTP status
is an exact integer in the existing range; malformed JSON is allowed as input
to exercise the real parser. Response headers are fixed to JSON. At dispatch,
effective URL comes from the existing source encoder and checked projection,
never an input URL. Instantiate only that page's frozen response bundle; unused
retry entries are not observed attempts or bytes.

Read command JSON (at most 256 KiB) and body paths through existing confined,
no-follow, hardlink-rejecting reads; all paths must be normalized project-relative
paths. Limit each raw body to 5 MiB and all enrolled raw bodies to 60 MiB. Verify
the supplied digest against the exact bytes read. Freeze one labelled base64
input envelope per body, including actual digest/size, below the existing 8 MiB
canonical-JSON limit; the compact enrollment references those envelope hashes.
Do not pre-register raw bytes under a competing logical type: actual dispatch
must create its normal content-addressed `external_response_raw` metadata.

For begin's route-before-plan construction, use a fixed constructor-only offline
sentinel response solely to instantiate the existing route owner. Never call
fetch on that instance; discard it after route registration. No external request,
response, attempt, result or observed spend may originate from this setup. Actual
advance uses only the enrolled responses and exact replay-derived request.
This avoids a second route factory/format or mutable transport replacement.

Original files are not reread on advance. Frozen envelopes are the operational
input evidence, not authenticated historical HTTP captures. Inputs must be public
or synthetic: local path confinement does not prove confidentiality or copyright
clearance. Return hashes and summaries, not raw payloads. None of these artifacts
is automatically eligible for packaging, Git commits or public release.

## Existing ledger projections

Use closed versioned `literature_acquisition` metadata on existing CHECKPOINTs.
All have actual CALIBRATE→CALIBRATE, owning run/code/configuration identities and
existing artifact descriptors. No fixture checkpoint labels or caller metadata
may replace these bindings.

| Kind | Required relationship |
| --- | --- |
| `ROUND_ENROLLED` | Frozen run intent, canonical command/input envelopes, actual goal/target, ordered plan/route hashes, exact caps/profile and unchanged source/round obligations. |
| `DISPATCH_INTENT` | Exact enrollment event, global dispatch ordinal, plan/page slot, exact request ID/projection, predecessor, route, reserved attempt/body ceilings and admitted resource observation. |
| `DISPATCH_OBSERVED` | Exactly one earlier intent, fully replayed current capture, optional result hash, actual outcome/publication status and per-dispatch attempt/request-body/response-body observations. |
| `DISPATCH_UNRESOLVED` | Resource-only observation linked to exact enrollment/intent/global ordinal, once per dispatch and before any final outcome. No captured-result, zero-spend or resolved-dispatch assertion. |
| `ROUND_STOPPED` | Resource-only observation linked to enrollment and latest resolved intent (or null), once per round and only with no outstanding intent; static reason `ROUND_CAP_INSUFFICIENT` or `RUN_WALL_INSUFFICIENT`, rederived from the frozen caps/route and current observed runtime state. |

All metadata uses `schema_version: literature-acquisition-event/v1`; each kind
has an exact closed field set. In addition to `schema_version` and `kind`:

- Enrollment has run_intent_artifact_sha256, command_input_artifact_sha256,
  goal_artifact_sha256, target_artifact_sha256, plan_artifact_sha256s,
  route_artifact_sha256, body_input_artifact_sha256s, transport_profile, caps,
  required_scholarly_sources and minimum_scholarly_rounds. Copied declarations
  must exactly match the intent/input and actual registered artifacts.
- Intent has enrollment_event_id, dispatch_ordinal, plan_index, page_number,
  plan_artifact_sha256, previous_result_artifact_sha256, scholarly_request_id,
  egress_request_id, route_artifact_sha256, request_projection,
  reserved_http_attempts and reserved_body_bytes. Indices are zero-based except
  existing one-based page ordinals; dispatch ordinals are one-based. The projection
  is the exact source-owned public projection, not another request encoder.
- Observed has enrollment_event_id, intent_event_id, dispatch_ordinal,
  raw_artifact_sha256, response_artifact_sha256, result_artifact_sha256,
  publication_status, retrieval_status, observed_http_attempts,
  observed_request_bytes and observed_response_bytes. Publication status is
  PUBLISHED or RESULT_TOO_LARGE; the latter requires exact source normalization
  and the existing serialization bound, never an arbitrary put/readback error.
  A transient publication failure remains unresolved until no-send recovery;
  it cannot mint a final outcome that would later need another final outcome.

For the two resource-only kinds, the member has
exactly schema_version, kind, enrollment_event_id, intent_event_id,
dispatch_ordinal and reason_code. Unresolved uses its outstanding intent and
ordinal with literal `UNRESOLVED_DISPATCH`; round-stop uses the latest resolved
intent/ordinal (both null before dispatch) and one of the two reasons above.
Required resource bindings come from the existing outer artifact descriptors and
resource-authority checkpoint, not an editable duplicate in this member. Do not
persist arbitrary exception strings as reasons. Other pre-intent capacity/path
refusals leave authorities unchanged; they do not fabricate this stop observation.

Combine initial resource binding and ROUND_ENROLLED in the existing INITIALIZED
CHECKPOINT (initialization=true, typed CALIBRATE→CALIBRATE). Bind that resource
head freshly once, not again in a separate enrollment event. Unresolved and
round-stop records are not DISPATCH_OBSERVED and never duplicate enrollment.
Round-stop prevents later automatic dispatch; a resolved capture after an
unresolved observation still uses exactly one final outcome for that intent.

Derive the current head from checked events, never manifest totals or a caller
selection. Reject duplicate/changed enrollment, skipped ordinals, repeated or
conflicting outcomes, corrected owning events and mismatched scope. Bind intent
and outcome by exact event identifiers, not a generic adjacency assumption.
The selected offline profile emits no gateway ledger events: the existing gateway
event producer records audited, signed transport execution authority, which this
profile cannot issue. Refuse non-acquisition events in this profile. Admission and
replay of genuine intervening gateway-authority events remain a required live-profile
integration dependency; do not invent an offline producer or silently accept an
unverified event to claim that integration is complete.
Before a new intent, refuse matching unmanaged request/normalized/result custody.
Shared parentless raw bytes from another exchange alone are not matching request
authority. Registry verification must account explicitly for retained orphans;
it must not silently allow arbitrary extra records or require an invented result.

## Admission and bounded accounting

Input `caps` contains exactly `maximum_dispatches`, `maximum_http_attempts` and
`maximum_body_bytes`: exact positive integers bounded by 4, 12 and 96 MiB
respectively. A cap too small for the next full exchange truthfully prevents
dispatch; it does not mutate the route or prove scholarly exhaustion.

For each prospective exchange reserve the frozen route's three attempts and
24 MiB body ceiling. Remaining budget equals cap minus exact resolved observations
minus unresolved reservations. Keep known lower-bound observations separately
from the unresolved reservation; never charge both. Sum each dispatch once,
not successive cumulative-prefix totals. Identical retry bodies retain attempt
multiplicity. Captured failures and checkpoint-size refusals still spend their
actual observations. Preserve and stop on actual overruns without clamping.

Use the existing ResourceController for one CPU worker, no GPU, no validity stage
and zero validity units. Require the full route timeout to fit remaining wall
budget and a positive conservative artifact estimate covering retry captures,
normalized/result bytes, metadata, ledger and resource/checkpoint overhead.
Do not claim hard OS containment or all-wire/header accounting. Observe actual
wall time through the existing clock owner before exporting state.

Freeze the following history-capacity schedule under the existing 16-record
authority limit: one initial observation; one intent and one final observation
per dispatch; at most one additional unresolved-failure observation per dispatch;
one reserved pre-intent round-stop observation. Thus `1 + 3*D + 1 <= 16`, with
`D <= 4`. Use distinct operational stage names, not scientific validity stages.
Intent/final resource observations share their respective controller CHECKPOINT,
never repeat a resource-authority record as a fresh event. A failure-only resource
checkpoint does not resolve the outstanding dispatch. Repeated failed read-only
recovery/status creates no additional stages. Later actual reconciliation uses
the still-unused final observation slot. Never raise the global cap or silently
reuse a changed single-assignment stage. Check actual remaining capacity before
enrollment and each publication, including input artifact bytes and ledger space.

Round-stop publication also requires existing resource admission with a positive
bounded control-record estimate; it is not an emergency write outside the budget.
It need not reserve another 30-second exchange, but must still satisfy current
wall, disk, artifact and memory checks. If actual wall time is already exhausted
or another admission check refuses, leave authorities unchanged and return a
nonpersisted refusal instead of fabricating a recorded stop. No new emergency
reserve or alternate resource policy is introduced.

## Interruption and acceptance

After an intent, never automatically fetch again for that dispatch. Reconcile a
unique complete capture or result through actual source replay and the no-I/O
publisher. Missing, raw-only, conflicting or ambiguous custody remains unresolved
and blocks new dispatches without a refund. Retain complete negative/oversized
captures; publication failure is not a fake HTTP/parser failure. Resource-authority
or ledger commit failure retains existing fail-closed recovery behavior, not an
unproved transactional rollback promise.

An intact standard parentless raw artifact has no request identity. With an
outstanding intent and its exact matching request, checked status may classify
such bytes as retained UNATTRIBUTED evidence and report UNRESOLVED, but must not
count them as attempts/bytes, attribute them by timestamp, refund the reservation
or report completed acquisition verification. Unknown types/roles/metadata and
conflicting requests still fail integrity checks. Reconciliation must account for
the complete candidate capture and previously checked managed closures; leftover
potentially attributable raw custody keeps the dispatch unresolved even when one
complete receipt exists. Do not delete evidence or add an operator override to
manufacture a unique outcome.

Required acceptance includes real captured `-I -S -B` CLI subprocess begin,
advance, status, verify and restart over one coherent source/configuration tree;
arbitrary valid goal/query inputs; source/config/input substitutions; ordinary
cooperative concurrency; full/one-short budgets; identical-body retries; actual
resource-history/wall/disk exhaustion; intent/capture/result/commit interruptions;
no-send reconciliation; explicit missing obligations; and unchanged legacy modes.
Use fixtures only at the transport edge and fault-injection boundaries, never
replace successful ledger, registry, controller or scientific owners with mocks.

Real externally admitted literature acquisition, required-source/round coverage,
full-text organization, target-specific insufficiency/fallback, scientific GROUND
integration and all original final validation remain unfinished. Passing this
offline profile cannot close those requirements or grant a live/E4/release claim.
Root retains final integration judgment; the independent design advisories and
exact implementation/test decisions are recorded in the private run ledger.
