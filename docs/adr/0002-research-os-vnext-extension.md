# ADR 0002: Extend the trusted kernel with a provider-independent research intelligence plane

- Status: accepted
- Date: 2026-08-29
- Amended: 2026-08-30
- Authority: `RESEARCH_OS_VNEXT_META_SPEC.md`
- Supersedes: the greenfield premise in ADR 0001; it does not supersede ADR 0001's verified local security and custody decisions

## Context

Scientist-One vNext is not a greenfield controller. Before this upgrade, THIS_REPOSITORY independently reproduced a 364/364 captured test baseline, 15/15 mandatory architecture controls, a clean project audit, and a fresh bounded end-to-end demo. The verified evidence and the two non-semantic housekeeping repairs are recorded in `docs/baseline_before_vnext.md`.

The trusted kernel already owns filesystem confinement, bounded parsing, immutable content-addressed artifacts, append-only ordered events, transition contracts, protocol versions, holdout custody, monotonic validity resources, claim support receipts, recovery, reproduction, and release-candidate packaging. Replacing those owners would create conflicting authorities and invalidate the strongest evidence in the repository.

The vNext gap is a research intelligence plane: controlled literature acquisition, replaceable model providers, typed research objects, problem and novelty investigation, fair evaluation design, autonomous discovery, real experiment jobs, domain validity, independent challenge, soundness promotion, and evidence-only paper composition.

## Decision

1. Keep `ArtifactRegistry` and `EventLedger` as the sole provenance foundations. New research objects are canonical JSON artifacts with explicit parent hashes and append-only materialization or supersession history. Markdown remains a derived view.
2. Add flat, standard-library modules beneath `src/scientist_one/` so the existing captured-source launcher can admit and attest them without a second importer or nested package.
3. Put all HTTP-capable code in one audited HTTPS gateway. Keep `security.validate_command` unchanged; it continues to reject shells, network executables, package managers, and network Git.
4. Define capability-oriented provider protocols and implement one OpenAI Responses provider through the gateway. Model outputs are proposals or judgments with provenance, never scientific evidence or transition authority.
5. Define replaceable scholarly adapters over the gateway and explicit reference depth `LEVEL_0` through `LEVEL_5`. Metadata resolution cannot be promoted to passage support. Persist executable citation-expansion receipts, immutable occurrence-provenance graphs, target-bound ranking, and complete multi-round investigation state; research-question and novelty gates must reopen those exact registry authorities.
6. Freeze an Evaluation Contract, baseline registry, metric semantics, selection regime, and evaluator-exposure policy before confirmatory work. Amendments are append-only and disclose whether results were already observable.
7. Keep discovery exploratory and structured. Preserve every branch, action, failure, null, invalid result, rejection, selection decision, seed, and budget charge. Checked discovery promotion persists and later revalidates registry receipts. Make the ordered-parent receipt produced by `register_checked_superiority_promotion()` and rederived by `require_checked_superiority_promotion()` the only superiority authority; the value-only validator remains explicitly diagnostic.
8. Keep the existing `DeviceManager` as the local CPU/MPS numerical layer. Add a separate provider-neutral compute-job plane for `LOCAL_MAC` and `GPU_CLOUD`, with frozen run specifications, idempotent submission, checkpoints, preemption, and artifact return. Implement `ScheduledGPUCloudBackend` over an injected structured scheduler to validate the offline planning/state/attempt/checkpoint/cancel/return boundary; fake and scheduled results remain `UNTESTED` and non-scientific until a live remote boundary is validated.
9. Put domain-specific validity behind meaningful domain adapters. The generic kernel owns evidence and transitions; adapters own leakage units, metric interpretation, evaluator validity, and domain-specific checks.
10. Keep human authorization independent from scientific validity. `FULL_AUTONOMOUS` may bypass configured human pauses only after scientific gates pass. It can produce `RESEARCH_COMPLETED_AUTONOMOUSLY` and a release candidate, but never `HUMAN_APPROVED_FOR_RELEASE`, `SUBMITTED`, or E4.
11. Put an independent Challenger and multidimensional research-soundness gate before paper promotion. Require one registry-resolved receipt for each of the exact 15 soundness dimensions and one review for each of the exact 14 Challenger categories; completeness, execution status, finding binding, and blocker resolution are independent requirements. A weighted readiness score cannot waive a hard scientific blocker.
12. Compose papers only from verified structured state, the scientific-only eligible claim view, registry-derived novelty/superiority/reproduction/soundness authorities, authoritative assets, limitations, and review findings. Deterministic consistency checks precede semantic judgment; a caller-selected flag or a non-authoritative diagnostic cannot promote paper readiness.
13. Classify every claim by evidence use. `SCIENTIFIC`, `SYSTEM_FIXTURE`, and `NON_EVIDENTIARY` are receipt-bound values; the default writer view admits only `SCIENTIFIC` claims. A structurally complete system-fixture graph therefore cannot be relabeled into paper evidence by changing mutable metadata.
14. Treat experiment output as an untrusted claim about execution. The verifier recomputes the fixture metric from the frozen dataset/evaluator/configuration and validates ablation identity, intervention, vector, score, and manifest bindings before promotion. Hash-consistent but semantically forged output is rejected.
15. Reserve an integrated-fixture run ID atomically and bind its lifecycle to an immutable terminal operation receipt. `IN_PROGRESS` has no downstream authority, and a failed ID cannot be reused as though it completed. This operational receipt is not scientific, release, or human authority.
16. Treat provider-assisted implementation as a bounded reviewed-template capability, not arbitrary code generation. The provider may select only one of exactly two reviewed template enums plus bounded numeric parameters. Admission fixes the provider attempt, proposal, context/evidence, catalog/reviews, deterministically rendered worker/configuration/descriptor/spec, and exact built-in backend. Completed verification reconstructs the full plan/manifest/output/receipt/semantic graph, independently recomputes the result, checks ledger and canonical-state bindings, and proves claim/paper exclusion.
17. Make adaptive execution plans first-class custody artifacts. Register the backend's exact canonical bytes as a deduplicable frozen `adaptive_execution_plan`; create a per-run `adaptive_execution_plan_binding` parented to that plan and the frozen spec and recording exact run/job/backend/spec/plan plus submission/collection agreement. Promote both through the ledger while preserving an already registered frozen spec.
18. Add a closed terminal scientific vocabulary and authoritative readback. Deterministically map typed existing statuses into exactly 11 truthful Research OS outcomes with no `PASS`/`SUCCESS` pseudo-terminal; persist the raw evidence-parented `research_terminal_outcome`, immediately read it back, and materialize a canonical `Decision` without changing the legacy macro state. Summary generation may reference that authority only after those steps succeed.
19. Distinguish technical execution from scientific eligibility. `LOCAL_MAC` can technically reach `VALIDATED_LOCAL` and reproduce the system fixture, but without a backend-verified OS filesystem/process/network isolation attestation its runtime result is `NON_EVIDENTIARY`, `scientific_evidence=false`, and `UNKNOWN_UNATTESTED`; the derived scientific-readiness classification is `BLOCKED_LOCAL`.
20. Make live external execution source-owned and keyed rather than trusting transport labels or cloneable registry markers. Only the exact built-in gateway, after consuming its prepared-request capability and rechecking the final TLS and standard-library send path, may issue `audited_transport_execution_authority/v1`. A confined, no-follow, no-hardlink, mode-0600 per-registry HMAC root authenticates the exact ledger run and pre-issuance prefix, request and policy, ordered attempts, captured response, artifact metadata, and parents; the authority must occupy the exact next unsuperseded event in the same run. Public replay verifies the signature, graph, response receipt, run/prefix, and ledger position. The key is never an artifact, scientific record, package member, report field, or log. This is a local source-issuance boundary, not independent attestation: same-process introspection, direct key access, or coherent trusted-source/key replacement remains `BLOCKED_LOCAL`, and real live issuance remains `BLOCKED_EXTERNAL` until approved network/provider access exists.
21. Materialize scientific Result state without a content-hash cycle. Register inert exact `scientific_result_state_projection` and `scientific_statistical_state_projection` artifacts before canonical state, then require a source-owned v2 promotion authority that freshly replays the Evaluation Contract, execution Run, Metric, domain, backend, confirmation, statistical, and projection closure. `ResearchStateRepository.materialize_scientific_result_bundle()` materializes canonical `Result` first and may later extend the same exact bundle with `StatisticalTest`; final replay requires the complete pair. The materializer prospectively checks registry/event/byte capacity and semantic collisions before writes, and only exact orphaned stages may resume.
22. Make scientific Dataset and Split eligibility prospective and failure-atomic for predictable publication failures. Before transport, a ledger-anchored acquisition plan binds the approved dataset adapter and policy, exact route, expected content identity, dataset identity/version, usage and license obligations, and unit identifier. A retained independent usage judgment then binds the captured source, manifest, proposed use, and custody closure before `scientific_dataset_authority` can be issued. One deterministic partition projection derives exact unit membership and hashes; four split authorities must jointly prove allocation coverage, pairwise non-overlap, exclusions, and protected confirmation separation before results. Usage, projection, and split publishers precompute every exact registry record and chained ledger event before the first mutation; capacity, collision, correction, or timestamp mismatch fails before another write, while an exact orphan artifact can be resumed. Fixture datasets and splits remain scientifically ineligible.
23. Make ClaimSemantics, not graph shape or caller labels, the scientific writer authority. A closed source-authority matrix must freshly replay every one of the 12 mandatory evidence kinds, transitive scientific dependencies, and their custody closures. Allow at most one canonical semantics proposal for the same run, claim graph, claim, and dependency bindings, excluding caller-selectable semantic outcomes from branch identity. High-impact audited reviews use similarly canonical slots and scan every outcome; zero reviews, multiple accepted reviews, or an accepted/rejected ambiguity fails closed. Paper construction and verification must freshly resolve the canonical proposal, reviewed authority, and final `ClaimSemantics` receipt; direct `ClaimEvidenceGraph.writer_view()` remains diagnostic rather than production paper authority.
24. Keep claim-bound citation authority acyclic. A `SOURCE_CITATION` evidence projection `E` has exactly three inert source parents: Level-5 reference verification, the scholarly citation graph, and signed audited-transport authority. The claim-evidence graph `G` contains `E`; semantics proposal `P` binds `G`; an independent signed reference-support judgment `Jref` reviews the exact `(P, citation)` request; final semantic authority `K` binds `Jref` and its complete retained-input and custody closure. Paper use freshly replays `P`, `Jref`, and `K`. Neither `P` nor `Jref` may be placed back inside `E`, preventing the former `E -> G -> P -> Jref -> E` content-identity cycle.
25. Require assertion-specific authority for scientific scope and limitation prose. A `SCOPE_QUALIFIER` or `LIMITATION` needs a dedicated audited `CLAIM_QUALIFIER` judgment `Jqual` over the exact assertion, claim, eligible Result, evaluated Run, and complete Result-promotion/custody closure. Its canonical branch slot excludes caller-controlled assertion text and evidence IDs, so alternate favorable wording cannot be selected after review; mixed accepted/rejected or otherwise ambiguous outcomes fail closed. Bare Result, Critique, or Challenge artifacts cannot authorize qualifier prose, and the graph-node description must match the reviewed assertion byte for byte.
26. Make scientific robustness depend on source-owned v2 Ablation authority. Derive Method component identities deterministically from the frozen Evaluation Contract ablation declarations. Every required scientific Ablation must bind one exact declared ablation and intervention, its checked output, the Result promotion authority, and the current canonical `Result`, `Run`, `Method`, and `Experiment` revisions. Missing, extra, failed, stale, or spliced ablations fail scientific robustness and claim eligibility.
27. Keep synthetic reproduction categorically non-scientific. The built-in clean rerun and legacy replay remain architecture-control and system-reproducibility evidence even when their deterministic comparison is `PASS`; neither may satisfy scientific `ROBUSTNESS` or create a scientific ReproducibilityPackage. A future positive scientific reproduction path must use a distinct real rerun and an exact source-owned comparison authority over the eligible Result and execution outputs.

## Failures prevented by the added boundaries

| Boundary | Failure it prevents |
|---|---|
| Canonical research objects in the existing registry/ledger | Prose or a mutable side database silently becoming more authoritative than evidence |
| Single audited egress gateway | Scattered HTTP calls bypassing host, licensing, size, secret, provenance, and prompt-injection controls |
| Provider-neutral capability protocol | A model vendor's response format becoming the scientific state schema |
| Reference-depth lattice | DOI or abstract resolution being mislabeled as claim support |
| Research-question, novelty, and hypothesis registers | Intuitive novelty declarations and post-hoc hypotheses being represented as pre-specified |
| Frozen Evaluation Contract and baseline registry | Metric switching, omitted strong baselines, unfair budgets, and proxy-to-system overclaiming |
| Structured discovery history | Best-seed suppression, failed-run erasure, branch contamination, and selection-history loss |
| Registry-checked investigation and novelty authority | A forged brief, unrelated citation graph/ranking, metadata-only source, or changed round history being accepted as research/novelty clearance |
| Checked superiority and paper authority | Caller-selected flags or a diagnostic comparison being promoted into a scientific superiority claim or ready paper |
| Separate compute-job plane | Remote status or a fake backend being confused with locally verified numerical evidence |
| Scheduled GPU adapter | Scheduler identity reuse, state/attempt rollback, checkpoint substitution, unplanned escalation, or malformed artifact return being accepted as a live result |
| Domain adapters | Generic benchmark checks being mistaken for patient-, temporal-, solver-, or system-level validity |
| Exact 15-dimension/14-category Challenger and soundness gate | Missing, SHA-shaped, wrong-role, unexecuted, spliced, or unresolved review inputs being replaced by a polished aggregate score |
| Evidence-only paper pipeline | Table/prose, method/code, citation/claim, and limitation inconsistencies surviving composition |
| Receipt-bound claim evidence-use class | Synthetic system checks being silently promoted into scientific prose |
| Semantic experiment recomputation | Internally hash-consistent fabricated scores or ablations being accepted as execution evidence |
| Reviewed-template admission plus deep completed verifier | A coding provider, substituted context/backend, forged PASS receipt, or false network attestation acquiring executable or scientific authority |
| Raw adaptive plan plus per-run plan/spec binding | Post-submission plan mutation or cross-run/spec/job rebinding surviving output promotion |
| Frozen terminal artifact plus canonical Decision/readback | Summary prose, an operation PASS, or substituted evidence/phase/status rewriting scientific closure |
| Atomic run reservation and terminal receipt | Concurrent reuse, partial-run ambiguity, or failed-run resurrection |
| Exact-next-event HMAC live-transport authority | A caller-controlled transport label or cloned registry/ledger marker being presented as audited live execution |
| Result-first/Stat-second v2 bundle | A cyclic, partial, stale, capacity-overrun, or cross-run Result/StatisticalTest state being accepted as scientific authority |
| Prospective Dataset usage and four-way Split publication | Post-result acquisition, self-declared license/use, overlapping units, split substitution, or predictable partial publication becoming scientific data authority |
| Canonical ClaimSemantics proposal and review slots | Caller-selected semantic labels or a favorable branch among conflicting reviewed outcomes reaching the writer |
| Acyclic `E -> G -> P -> Jref -> K` citation chain | Claim-bound citation review creating a content-identity cycle or being detached from exact passage, graph, proposal, and transport custody |
| Assertion-bound `Jqual` authority | The same Result being relabeled with unreviewed scope or limitation wording |
| Source-owned v2 Ablation authority | Fixture PASS labels, missing interventions, or state-spliced ablations being promoted as robustness evidence |
| Synthetic-reproduction exclusion | A matching architecture-control replay being laundered into scientific robustness or replication |

## Rejected alternatives

- Replace the trusted kernel with a new end-to-end framework. Rejected because it would discard independently reproduced security, custody, recovery, and claim-evidence guarantees.
- Add arbitrary network subprocesses to the command allowlist. Rejected because it would let untrusted content select destinations, commands, credentials, and executable behavior.
- Use one mutable research database as the new source of truth. Rejected because it would create a second provenance authority and weaken content-addressed parent verification.
- Treat model-majority votes as scientific gates. Rejected because UPSTREAM_SCIENTISTONE reports a real evaluator exploit that escaped four of five judges, and model output is not independent evidence.
- Fold remote GPU scheduling into `DeviceManager`. Rejected because numerical device parity and remote job custody/idempotency/cost/artifact-return failures are materially different.
- Reuse E4 for autonomous release. Rejected because E4 is human-only authority and autonomous construction is explicitly prohibited by the trusted kernel.
- Treat an unkeyed live marker or transport-reported `network_used` field as external authority. Rejected because ordinary callers can clone those fields through public registry and ledger APIs; exact source-owned keyed issuance and replay are required.
- Parent scientific authority directly to final Result/StatisticalTest or claim-bound citation state in both directions. Rejected because it creates unreachable content-hash cycles; prospective projections and staged `E -> G -> P -> Jref -> K` authority preserve acyclic identities.
- Accept a bare Result, Critique, Challenge, or synthetic reproduction receipt as qualifier or robustness authority. Rejected because caller wording and non-evidentiary system checks could then be laundered into scientific prose.

## Consequences

- More typed modules and validation records are introduced, but each names a concrete scientific or security failure above.
- Existing synthetic runs remain historical pre-vNext evidence. Source changes correctly prevent those runs from being presented as current-code reproductions.
- Offline fixtures can verify interfaces, checked literature/novelty/discovery/paper promotion, provenance, failure handling, the scheduled-GPU contract, and the local end-to-end composition path. They cannot validate OpenAI access, live scholarly retrieval, real GPU cloud, independent review, external novelty, or E4.
- The current local experiment runner has executable/path/environment/resource controls but no OS-enforced filesystem, process, or network sandbox. Its reviewed synthetic subprocess can succeed technically and validate system composition, but scientific eligibility is `BLOCKED_LOCAL`; it is not validation of arbitrary workloads or scientific evidence.
- The live-gateway HMAC prevents ordinary public-API marker cloning but is deliberately rooted inside the captured trusted process. It does not resist trusted same-process introspection, direct key access, coherent source/key replacement, or provide an external signature, timestamp, or witness; clearing that `BLOCKED_LOCAL` boundary requires an external attester or stronger host trust boundary.
- Result, Dataset, Split, ClaimSemantics, citation, qualifier, and Ablation authorities now have source-owned replay boundaries, but the integrated fixture cannot mint positive scientific instances from its synthetic literature/data or unsandboxed Local Mac execution. Live dataset/provider/literature acquisition, independent scientific review/custody, and real GPU execution remain `BLOCKED_EXTERNAL` or `UNTESTED`.
- A matching synthetic clean rerun remains `NON_EVIDENTIARY` and cannot satisfy scientific robustness or reproduction. The absence of a positive scientific Result, qualifier, Ablation, or reproduction authority is a correct fail-closed outcome, not an incomplete fixture success claim.
- The implemented fixture correctly produces complete 15-dimension and 14-category review authorities while preserving their `UNTESTED`/unresolved statuses, derives terminal `MORE_EXPERIMENTS_REQUIRED`, and blocks soundness promotion, paper generation, venue readiness, confirmation use, and E4. It does not create a scientific release candidate.
- Until OS isolation and the required real external, domain, confirmatory, and independent validation exist, the honest capability is `AUTONOMOUS_EXPLORATION_READY`, with unavailable capabilities explicitly `UNTESTED`, `BLOCKED_LOCAL`, or `BLOCKED_EXTERNAL`—not `REAL_EXPERIMENT_PIPELINE_READY`, `RESEARCH_GRADE`, `SUBMISSION_PIPELINE_READY`, empirical superiority, or publication readiness.
- Final post-vNext captured-suite, architecture-control, audit, end-to-end, and failure-injection measurements and frozen digests remain pending until the tree is frozen and the final evidence run completes. Historical baseline counts are not current-tree results.

## September 23, 2026 V9 measured-evidence and retained-limitations checkpoint

The Context above records the August decision's historical claim of reproduced
364/364 and15/15; those numbers are not current V9 measurements or recovered
original executable evidence. The separately qualified recovered146 suite and
the architecture configuration's greenfield ABSENT comparison are different
populations. Preserve ADR0001 and the dated baseline rather than relabeling them.

V9 is installed and its 300 functional inputs are frozen: the independently
reviewed 16-file union comprises nine replacements and seven additions, with
284 unchanged neighbors. Installation proof SHA-256:
`58c469e5796559217a3877f732cd2d56530d7c027f4994a46093c507f0277976`.

The same 125 distinct selected IDs pass on Python 3.14.6 and 3.11.15, with
enclosing closure
`80ab70ebc68277032e797b40e108f025d12a2493b8eb7e7bb42056e8bf8b0943`.
The separate 192-module selection is terminal with exit 0 and 3,294 successes
on Python 3.14.6 only; its single-runtime enclosing closure is
`1475c93cce4b0c6ee519cfb357ba49740bceeb3f74d8b479d79b9efcf2911955`.
These disjoint selections cover 3,419 distinct current IDs on Python 3.14;
only the 125-ID selection is currently paired. The remaining192 Python 3.11
selection is NOT_STARTED. Both closures leave nested/helper behavior
NOT_ASSESSED; none of these counts is a full-suite, historical, scientific,
security or release PASS.

These observations support only their captured local scopes. They do not newly
reverify every Decision or constitute an all-criteria architecture disposition.
The current architecture packet and four structural validator methods remain
pending. Four validator passes, if later obtained, would check packet bindings,
not independently execute the15 behavioral criteria. The mandatory safety-stopped
criterion remains BLOCKED and prevents an all-mandatory-PASS/final packet; no
proxy evidence or historical PASS may clear it. Other criterion dispositions
must be selected from their exact closed support, not defaulted from this ADR.

The Standard source scan is sealed PARTIAL, with 43 review products and three
LOW findings. Accepted corrections are installed and have scoped test evidence;
this is not full security PASS or clearance of omitted/stopped scopes.

Gates67 retains its original paired and diagnostic 7,200-second timeouts
without complete outcomes; isolation38 retains 37 successes and one inner
900-second timeout error per runtime. Causes remain UNKNOWN. The retained
lint33 result is non-PASS. Original failures and separate private checks remain
preserved, not relabeled or added to installed counts. Operations18, fresh
installed lifecycle/reproduction/package, the current architecture packet and
its four validator methods, and the final audit remain pending. Architecture
packet validation is not proof that all 15 behavioral criteria pass.

The sole registry/ledger authorities, outcome-neutral history, evidence-first
paper boundary, scientific/operational separation and human-only E4 decisions
remain. Synthetic execution/reproduction stays NON_EVIDENTIARY; the scientific
15-dimension/14-category gates are distinct from the15 architecture criteria.
No new positive scientific Result, independent custody, real external validation,
scientific release candidate or capability promotion follows. LOCAL_MAC scientific
isolation and other existing local/external limitations remain unfinished.

The exact safeguard-stopped assess-patch-risk and substitutes, prompt-injection
criterion, scholarly event-key/capture-alias, direct-coordinator legacy-selector/
native-J retained session/thread/fork/FD lifetime, execution/read-restriction
repair, trusted-collector and actual OS-crash collection scopes remain stopped,
not PASS. No alternate reviewer, route, runtime or diagnosis clears them.
Protected data, confidentiality boundaries, custodian requirements, spending
limits, scientific gates and human-only E4 remain mandatory. No credential,
private provider/run payload, protected dataset or unrelated process/descriptor
inspection is authorized here.

D-079 requires owner reporting/triage before any new consequential repair or
expensive campaign, with no delegated repair. Conditional diagnostic permission
and current verification/Git ordering are recorded in the current handoff; this
ADR adds no implementation or execution authorization.

## September 24, 2026 scoped architecture reconciliation

This section supersedes the preceding checkpoint's scheduling statements, not
its historical evidence. D080's 192 modules / 3,294 selected IDs passed on
Python 3.11.15 at the 303-input freeze `8f5b3669`; operations18 and focused24
are separately cross-runtime. The subsequent two-file Colab addition has15
cross-runtime component tests. These scopes are not a current full-suite total
or a paired V9/D080 aggregate. The current305-input inventory is `8204cca1`.

The current guarded vNext fixture/status/verify sequence passed on Python3.14.6
(retained closure `ddf4f878`):342 artifacts,67 events, and scientific outcome
`MORE_EXPERIMENTS_REQUIRED`. Scientific writing/release remained blocked.
The separate legacy demo/verify/resume/verify/reproduce/verify/package/verify
sequence passed its existing exit contract (closure `a236376b`):75 artifacts,
22 events, and a238-file private `DEMO_RESEARCH_PACKAGE` requiring E4.
The synthetic replay returned `ARCHITECTURE_CONTROL_REPLAY_PASS`, expected
exit1, difference0 at tolerance1e-12. Resume reported `SKIP_COMPLETED`, not
recovery from an actual OS crash. Demo already created the same replay/package
receipts; later readbacks are not additional independent experiments.

The existing private architecture report uses the following bounded dispositions.
PASS below is only the frozen local criterion at its stated tested scope—not
scientific, security, independent-custody, platform, live-deployment or release
approval. PARTIAL preserves demonstrated local support and the named missing
evidence; PENDING does not instruct removal of existing source. Report evidence
is hash-bound to retained local records; private raw records/packages are not
distributed with the public engine. Four structural packet checks, when run,
validate bindings and totals rather than independently proving these criteria.

| Frozen criterion ID | Disposition and retained scope / limitation |
| --- | --- |
| `state_transition_safety` | PASS: retained ordinary invalid-order/self-approval/incomplete-calibration refusal and exact-replay tests; current guarded fixture and legacy verification. No coherent trusted-authority rewrite claim. |
| `approval_custody` | PASS: typed E1 refusal, producer/reviewer separation and human-only E4 construction refusal. Genuine independent custody/review and actual E4 remain unavailable; this is logical-role support only. |
| `holdout_integrity` | PARTIAL: ordinary frozen-input/pre-reveal refusal support and synthetic verification; independent custody and stopped mechanisms are not verified. |
| `scientific_validity` | PASS: the frozen known-answer/trap criterion and independently oracle-tested permutation correction. Synthetic calibration is not external scientific validity. |
| `negative_result_handling` | PARTIAL: synthetic six-scenario outcomes and discovery retention are verified; complete current-source negative CLI endpoint evidence is not supplied by the remaining192 selection. |
| `claim_traceability` | PARTIAL: ordinary source/asset/qualifier refusals and scientific-writer exclusion are supported; whole gates67 remains TIMEOUT with unknown outcomes, not replaced by wrapper counts. |
| `crash_recovery` | PARTIAL: retained controlled corruption/quarantine/checkpoint tests and completed-run resume; actual OS-crash collection remains stopped and no new interruption experiment was performed. |
| `deterministic_reproduction` | PASS: fresh synthetic demo's frozen local replay matches its primary result within tolerance; explicit reproduce/readback preserves non-evidentiary status and legacy exit1. No scientific reproduction is claimed. |
| `resource_control` | PARTIAL: retained bounded accounting/admission tests and current technical verification; OS isolation, live GPU capacity and CU accounting/enforcement remain unverified or unimplemented. |
| `prompt_injection_resistance` | BLOCKED: SAFETY_STOPPED; no new assessment, proxy evidence, substitute or inherited historical PASS. |
| `review_packet_usability` | PENDING: current final capability/Git report, qualified baseline history and last audit remain unfinished. Existing handoff and byte bindings are only partial support. |
| `content_addressed_evidence` | PASS: retained immutable-registration/corruption tests and current registry/package verification. Local hashes are not an independent witness against coherent same-authority rewriting. |
| `blind_interpretation` | PARTIAL: retained typed binding refusals and simulated workflow; no new independent confirmation or complete current chronology assessment is inferred. |
| `validity_reserve` | PARTIAL: integer partition/charge refusals are supported, but accounting does not prove40% of actual relevant data remained untouched. Historical second-reserve25 is not replaced. |
| `drift_and_stall_detection` | PARTIAL: retained source/config drift and controlled stall/charge tests; seeded crash counters are not actual crashes and the full current CLI endpoint scope is not newly verified. |

The report therefore remains provisional, not15/15 or FINAL. Earlier failures,
gates67 TIMEOUT, isolation38's unresolved error, lint debt, sealed PARTIAL scan,
safety stops, protected-data/confidentiality/external-access/custodian limits and
human E4 remain open. This reconciliation introduces no source change, repair,
new authority or permission to repeat a stopped investigation.
