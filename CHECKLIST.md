# Scientist-One vNext Verification Checklist

Checked implementation items describe the current source. They are not substitutes for the final frozen test and audit evidence, which remains unchecked and **PENDING**.

Current status is **DEVELOPMENT / REVIEW**, not final release or E4 approval.
See the [checkpoint handoff](OVERNIGHT_REPORT.md#development--review-checkpoint-september-23-2026).

## Historical trusted-kernel baseline

- [x] Preserve the historical reported pre-vNext 364/364 result (`73dee18929495015a1693ead7cf6849ae85cb96430b9887cfa7939c78ed28f36`); the missing original suite is not independently recovered/reproduced by the current reconstruction.
- [x] Preserve the historical reported 15/15 architecture and 4/4 validator results (`3d6c80c7f63514c9b711c9d2b98b7512b02550870cda567f18b3a82de112580e`); reconstructed 11 scoped PASS/3 PARTIAL/1 BLOCKED dispositions are separate.
- [x] Fresh legacy demo `run-20260829T170951Z-28d371b6e3` verified at `READY_FOR_HUMAN_REVIEW` / `COMPLETE_DEMO_ONLY`, 21 events, 58 artifacts
- [x] Historical handoff run `run-20260812T204930Z-299b1dad55` reverified without repeating confirmation
- [x] Pre-documentation audit passed after the recorded bounded `.DS_Store` quarantine
- [x] All baseline results labeled historical rather than current vNext evidence

## Provenance and canonical state

- [x] Existing `ArtifactRegistry` remains the sole frozen artifact authority
- [x] Existing `EventLedger` remains the sole append-only event authority
- [x] Canonical research objects materialize through `ResearchStateRepository` into both authorities
- [x] Required provenance parents are checked against registry records
- [x] Producers and authoritative claim verifiers are separated
- [x] Structured research state is authoritative; Markdown remains derived
- [x] Phase checkpoints validate registered artifact readback before downstream consumption
- [x] Exact 11-outcome terminal vocabulary and fail-closed derivation adapters are implemented; materialized outcomes are registry-backed, evidence-parented canonical decisions that do not mutate the legacy macro-state machine
- [ ] Final canonical-object count, type coverage, snapshot SHA-256, registry count/closure, and ledger count/head frozen (**PENDING**)

## Guarded operation and recovery semantics

- [x] `research-os-fixture` is routed through the captured `-I -S -B` launcher and admitted orchestrator root
- [x] Required fixture inputs are checked before run creation
- [x] Run-ID reservation is atomic and same-ID concurrency admits only one invocation
- [x] `fixture-operation.json` is atomically published as `IN_PROGRESS`, `FAILED`, or `COMPLETE`
- [x] Failed operations grant no downstream authority and require a new run ID
- [x] Completed run identities are immutable and cannot be overwritten
- [ ] Final failure-injection and recovery matrix passes on the frozen snapshot (**PENDING**)

## Controlled literature and model boundaries

- [x] All external access is routed through policy-scoped audited egress/adapters
- [x] Exact built-in credentialless live HTTPS execution consumes a one-shot prepared-request capability and can mint only a run-bound, registry-record-bound, ledger-anchored HMAC authority
- [x] Gateway authority replay validates the local `0600` trust root, key ID/tag, exact request/response/policy/implementation profile, registry metadata, ledger prefix, and unique anchoring event
- [x] HMAC authority is labeled narrow local machine authority—not scientific validation, E4, an external signature, or protection from same-process/key/source compromise (`BLOCKED_LOCAL`)
- [x] Synthetic PMC fixture binds source, request, raw response, parsed record, passage locator, and reference verification
- [x] Seed search, bounded citation expansion, relevance filtering, full-text review, and disconfirming search execute as registered investigation rounds
- [x] Citation expansion plan/execution, graph identities, and target-bound scholarly ranking are registered and reproducible
- [x] Novelty clearance re-resolves the investigation state, record/full-text/passage evidence, citation graph, expansion custody, and ranking from the registry
- [x] Synthetic literature is explicitly barred from establishing real-world novelty
- [x] Provider-neutral model contract and strict OpenAI Responses structured-output adapter are implemented
- [x] Fixture-transport model output is advisory, non-scientific, and provenance-bound
- [x] Credential/terminal failure provenance is typed and fail-closed; credential-bearing real-network use stops before gateway request artifacts, budget use, dispatch, response custody, or HMAC issuance; raw/full-header/hex/Base64 reflections are rejected at ordinary custody sinks; and unverified transports receive no resolved credential even when they self-report offline
- [ ] Live scholarly retrieval and independent citation validation completed (`BLOCKED_EXTERNAL`)
- [ ] Live OpenAI credential/model execution completed (`BLOCKED_EXTERNAL`; credential-bearing sensitive-response custody also `BLOCKED_LOCAL`)

## Scientific design and discovery

- [x] Problem Investigator checks answerability, falsifiability, evaluation, baseline, scope, resources, and gap-destroying evidence
- [x] Novelty register, hypotheses, Evaluation Contract, baselines, metrics, splits, resource estimates, and falsification criteria are structured
- [x] Exploration remains separate from confirmation/protected validity resources
- [x] Scientific Dataset acquisition freezes exact HTTPS source, expected body, license, use/derivative/redistribution scope, attribution, and unit identity before access
- [x] Scientific Dataset authority requires signed credentialless live-transport replay, frozen Evaluation Contract, exact raw source projection, and an audited semantic license/use judgment
- [x] Dataset manifest/use/authority, experiment projection, and all four exhaustive disjoint Split roles use zero-write preflight plus append-only/collision-safe publication before Result visibility
- [x] Discovery budget and promotion rules are explicit
- [x] Positive, negative, null, inconclusive, and falsified outcomes remain retainable
- [x] Integrated fixture preserves promoted, negative, and null branches
- [x] Checked discovery recomputes evidence with a pinned reviewed evaluator from frozen registry/ledger inputs; diagnostic-only values cannot authorize promotion
- [ ] Final frozen checked-discovery adversarial/handoff evidence recorded (**PENDING**)
- [ ] External novelty and independent domain-scientist review completed (`BLOCKED_EXTERNAL`)

## Bounded autonomous implementation

- [x] Provider proposals select only a closed reviewed template and bounded numeric parameters
- [x] Provider output cannot supply source, argv, paths, dependencies, shell syntax, or network policy
- [x] Template reviews/catalog, proposal, admission, exact worker bytes, configuration, frozen spec, manifest, execution receipt, and semantic validation are registry-bound
- [x] Autonomous component execution is exploratory and explicitly non-evidentiary

## Experiments and compute

- [x] Provider-independent frozen run specifications bind code, data, configuration, evaluator, environment, seeds, resources, outputs, phase, and evidence class
- [x] `LOCAL_MAC` launches a real `/usr/bin/python3 -I -S -B` child against frozen inputs
- [x] Every declared seed and required ablation is checked and promoted through the registry/ledger
- [x] Raw backend adaptive execution plans are content-addressed and bound to frozen-spec, submission, and collection identities before downstream use
- [x] A second clean Local Mac execution is compared for system reproduction
- [x] Result-v2 materialization preflights the exact canonical ancestor graph and capacity before first write, resumes only an exact inert prefix, and publishes a typed bundle-completion artifact/event before authority becomes visible
- [x] Result-only materialization can extend once to an exact `StatisticalTest`; the latest completion is mandatory and stale Result-only completion cannot authorize downstream use
- [x] Local Mac technical validation/system reproduction are separated from scientific eligibility; primary and clean-rerun comparisons remain `NON_EVIDENTIARY`
- [x] `GPU_CLOUD` lifecycle boundary reports `UNTESTED` and never promotes fake completion to evidence
- [x] Scheduled GPU boundary requires a frozen spec and escalation plan and covers idempotent queueing, retry/preemption, checkpoints, and bounded artifact return while remaining externally `UNTESTED`
- [ ] OS-enforced Local Mac network/filesystem/process sandbox implemented (open internal blocker)
- [ ] Live GPU cloud/CUDA execution validated (`UNTESTED` external blocker)

## Domain validity

- [x] Generic ML adapter contains split/preprocessing/checkpoint leakage, policy-freeze, resource-fairness, pretrained-resource, metric, seed, robustness, and generalization checks
- [x] Medical Imaging adapter contains meaningful subject/patient-level validity logic
- [x] Operations Research adapter contains meaningful feasibility/bound/objective/comparator validity logic
- [x] Systems adapter contains meaningful workload/failure/warmup/resource/repetition validity logic
- [x] Additional Time Series and Recommender Systems adapters are implemented
- [x] Integrated fixture evaluates Generic ML with registered domain evidence
- [ ] Medical Imaging, Operations Research, and Systems exercised end to end on real workloads (external/data prerequisite)
- [ ] Final frozen domain test evidence recorded (**PENDING**)

## Claims, statistics, challenger, and gates

- [x] Deterministic all-seed, ablation, evaluator, result, and statistical analyses are registered
- [x] Claim graph requires every mandatory typed evidence kind
- [x] Canonical scientific ClaimSemantics uses one outcome-independent coarse proposal slot for each exact run/graph/claim/dependency context; alternate favorable semantic branches collide or fail as ambiguous
- [x] Scientific citations follow the acyclic `E -> G -> P -> Jref -> K` order: inert three-parent citation evidence, completed graph, proposal, claim-bound reference judgment, and final ClaimSemantics authority
- [x] Citation evidence requires exact Level-5 reference, citation graph, and signed credentialless transport parents; metadata-only or model-memory references cannot acquire writer authority
- [x] `SCOPE_QUALIFIER` and `LIMITATION` require one exact `Jqual` source authority bound to claim text/producer/confirmatory/evidence-use/assertion plus current Result, Run, latest bundle completion, semantic judgment, and custody closure
- [x] Source-owned v2 Ablation authority binds one required frozen intervention, deterministic component ID, checked raw output, aggregate/promotion, current Result/Run/Method/Experiment state/events, and complete custody closure
- [x] V2 Ablation inherits the Result's eligibility; legacy `ablation_result` artifacts and favorable outcome branches cannot substitute
- [x] Support receipts and registry-resolution receipts are content-bound and independently materialized
- [x] Synthetic claim scope is explicit and cannot convert `NON_EVIDENTIARY` execution into scientific evidence
- [x] Value-only superiority validation returns a non-authoritative `DIAGNOSTIC_ONLY` result
- [x] Checked superiority promotion resolves independent execution eligibility, aggregate, statistics, evaluator, run-spec, and output-manifest authority and recomputes material values before minting a receipt
- [x] The non-evidentiary fixture mints no scientific promotion receipt
- [x] Major unresolved external-validity challenge is retained
- [x] Soundness binds exactly 15 dimension receipts, exactly 14 Challenger category reviews, and every finding
- [x] Soundness assessment yields `MORE_EXPERIMENTS_REQUIRED` under untested generalization/external validity
- [x] Legacy and vNext synthetic reproduction packages resolve categorically `scientific_evidence_eligible=false` and cannot satisfy scientific `ROBUSTNESS`
- [x] Human gates and scientific gates are independently configurable
- [x] E4 cannot be constructed, inferred, or synthesized
- [ ] Independent external challenger/scientific review completed (external prerequisite)

## Paper, venue, and release

- [x] Paper bundle and candidate are registry-derived; verification re-resolves claims, evidence, metrics, method/code bindings, soundness, and limitations
- [x] Fixture superiority diagnostic is excluded from paper authority and scientific baseline/statistics controls remain false
- [x] Numeric, table/prose, method/code, limitation, seed, baseline, statistics, and challenge discrepancies are checked
- [x] Unsupported novelty, scientifically ineligible clean reproduction, and unresolved challenge remain hard blockers
- [x] Integrated fixture paper is `BLOCKED` and venue is `NOT_READY`
- [x] Final release remains `BLOCKED_SCIENTIFICALLY`
- [ ] Human E4 supplied (absent; publication/submission/upload/release prohibited)

## Final frozen verification

- [ ] All vNext modules compile on the frozen source snapshot
- [ ] Targeted provider, literature, state, design, discovery, experiment, domain, gate, paper, CLI, and end-to-end tests pass
- [ ] `/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py test-suite` passes; exact test count and report SHA-256 recorded (**PENDING**)
- [ ] Architecture evaluation and targeted validator pass against the frozen test report; exact identities recorded (**PENDING**)
- [ ] `/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py research-os-fixture` passes system-integrity checks; exact run ID and summary SHA-256 recorded (**PENDING**)
- [ ] Final vNext registry count/closure, ledger count/head, canonical-state count, and operation receipt recorded (**PENDING**)
- [ ] Legacy demo/verify/reproduce/verify/package/post-package verify regression path passes with exact identities; semantic reproduce is accepted only with parsed `ARCHITECTURE_CONTROL_REPLAY_PASS` and expected CLI exit `1` (**PENDING**)
- [ ] Recovery and deceptive failure-injection matrix passes with no hidden blocker
- [ ] Dependency declarations, lockfiles, network primitives, secrets, and path confinement rechecked
- [ ] `/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py audit-project` generated after every other audited mutation; exact snapshot/report SHA-256 read from `reports/final_audit.json` and reported externally (**PENDING**)
- [ ] `reports/final_audit.json` is the last-mutated machine authority; after it is written, only read-only `-B` parsing/hashing occurs and no document is edited to backfill its digest (**PENDING**)
- [ ] Final upstream comparison separates architectural findings from unestablished empirical superiority
- [ ] `.run/STATE.json`, `.run/DECISIONS.md`, `.run/ISSUES.md`, and all top-level docs match the frozen evidence

## Final classification guard

- [x] Provisional capability ceiling is `AUTONOMOUS_EXPLORATION_READY`; current whole-system acceptance remains unfinished.
- [x] No claim of `REAL_EXPERIMENT_PIPELINE_READY`, `RESEARCH_GRADE`, or `SUBMISSION_PIPELINE_READY`
- [x] No claim of upstream ScientistOne empirical superiority
- [x] No live external result, citation, GPU run, approval, or E4 fabricated
