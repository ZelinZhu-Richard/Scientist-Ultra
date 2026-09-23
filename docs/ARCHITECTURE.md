# Architecture

## Current status and decision context

The [bounded FARS comparison](FARS_DESIGN_REVIEW.md) confirms the existing
scientific-contract, executable-attempt/resource-plan and trusted-controller
separation; it does not introduce a generic research DAG or parallel authority.
Its A01 adaptation reuses the scientific minimum-output predicate in local and
shared GPU operational manifest acceptance. Presence of all declared output types
is necessary, not semantic correctness, containment, scientific eligibility or E4.
Incomplete old caches refuse fresh acceptance without replacing frozen bytes or
rerunning work; valid complete captures remain compatible.

Scientist-One vNext is an extension of an existing trusted research kernel, not a greenfield replacement. The legacy controller continues to own its verified security, artifact, ledger, state-machine, custody, recovery, reproduction, packaging, and human-release boundaries. The vNext layer composes new literature, provider, scientific-design, discovery, experiment, canonical-state, claim, challenger, and paper-readiness modules through the same `ArtifactRegistry` and `EventLedger` authorities.

The integrated `research-os-fixture` is a supported system path, but it is deliberately synthetic and nonpublishable. Its top-level `PASS` means that the integrated fixture completed and its local authorities validated. It does not mean that a scientific result, live provider, scholarly source, GPU job, external validation, paper, venue, independent review, or E4 release passed.

Final post-vNext captured-suite, architecture-control, and audit counts are still pending. The previously reproduced `364/364` test and `15/15` architecture-control results are the frozen pre-vNext baseline documented in `baseline_before_vnext.md`; they must not be presented as final verification of the current source tree.

## Supported entry path

The supported vNext launcher is:

```sh
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py research-os-fixture --run-id UNIQUE_RUN_ID
```

`--run-id` is optional, but an explicit value must be unique because an existing run directory is never overwritten. The launcher descriptor-captures its own bytes and the `scientist_one` package before import, installs the exclusive in-memory loader, reattests the source tree before dispatch, and supplies the admitted project root to the CLI. Direct `PYTHONPATH` imports, `python -m scientist_one`, direct calls to `run_research_os_fixture`, or the test-only import capability are useful development paths but are not substitutes for captured-launcher evidence.

The fixture also registers a deterministic inventory of the current package sources, the standalone fixture experiment, the synthetic dataset, configuration, evaluator, methods, and execution environment. These registry artifacts bind downstream work; they do not turn an unsandboxed child process into scientific evidence.

## Authority boundaries

1. **Captured startup boundary** — `scripts/scientist_one_cli.py` owns executable source capture and dispatch. The ordinary CLI refuses unisolated startup.
2. **Path and serialization boundary** — `security.py` provides canonical project-root confinement, no-follow and hard-link checks, bounded duplicate-key/non-finite rejecting JSON, and allowlisted argument-vector validation. A directory name alone is never treated as a security boundary.
3. **Single audited egress boundary** — `external.py` is the only vNext module that imports network primitives. Every live or fixture external request must pass through `EgressGateway` under an immutable `EgressPolicy` that limits adapter identity, host, path, method, query keys, headers, content types, request/response sizes, timeouts, request counts, attempts, and retry behavior. Credentials are gateway/transport-owned and are not caller-supplied headers or query data. Fixture responses and credentialless live responses are captured in the registry before parsing. If a credential is configured and the transport reports real network use, the gateway returns `BLOCKED_EXTERNAL` and stops before request registration, request-budget consumption, dispatch, response capture, or audited-authority issuance. Resolved credentials are never passed to an unverified transport, including one that self-reports offline; fixture transport receives `None`. Raw, full-header, hexadecimal, and standard/URL-safe padded/unpadded Base64 matching protects ordinary custody sinks only as defense in depth, because finite matching cannot prove arbitrary hostile transformations secret-free. External bytes remain untrusted evidence and never become control instructions.
4. **Artifact authority** — `ArtifactRegistry` remains the immutable, content-addressed byte and metadata authority. A SHA-shaped string alone is not evidence; registry bytes, metadata, parent closure, type, role, validation, and frozen state must resolve.
5. **Event authority** — `EventLedger` remains the locked, hash-linked operation history. Each vNext phase checkpoint names registered artifact hashes and records `research_os_materialization=REGISTERED_BEFORE_CONSUMPTION`.
6. **Canonical scientific-state boundary** — `ResearchStateRepository` validates, registers, reads, links, and ledger-materializes typed research objects. Markdown is a derived view, never the state authority.
7. **Scientific and human gates** — deterministic scientific checks, Challenger findings, soundness review, configurable human-gate policy, and human-only E4 remain separate. Full-autonomous policy can remove optional human approvals; it cannot turn a failed scientific gate into a pass or synthesize E4.
8. **Terminal-outcome authority** — a truthful Research OS terminal outcome is first a frozen `research_terminal_outcome` registry artifact parented to the exact source evidence and then a canonical `Decision` materialized through `ResearchStateRepository` and the ledger. `load_terminal_outcome()` independently checks canonical bytes, metadata, evidence parents, typed derivation, and the exact 11-value vocabulary; `PASS` and `SUCCESS` are deliberately not terminal scientific outcomes.

## Materialize-before-consume flow

The supported controller never treats an in-memory dataclass or model output as authoritative merely because construction succeeded. Each phase produces frozen registry artifacts and a ledger checkpoint before a later phase consumes those results:

```text
captured launcher
  -> FOUNDATIONS
  -> CONTROLLED_LITERATURE
  -> MODEL_PROVIDER
  -> SCIENTIFIC_DESIGN
  -> AUTONOMOUS_IMPLEMENTATION
  -> real LOCAL_MAC execution and authoritative output promotion
  -> ANALYSIS
  -> DISCOVERY_AND_DOMAIN_VALIDITY
  -> CLAIM_VERIFICATION
  -> CHALLENGER_AND_GATES
  -> canonical research-state materialization
  -> PAPER_AND_VENUE
  -> FINAL_VERIFICATION summary
```

`_phase_checkpoint` first verifies every named artifact in the registry, then records the phase in the ledger. Local experiment outputs have a stronger intermediate boundary: the backend validates the exact output manifest and artifacts, and `_promote_collected_run` checks the collected backend/spec identities, reads and canonically validates the backend's `execution-plan.json`, and requires its semantic SHA-256 to agree with both submission and collection. It registers the exact bytes as a frozen, deduplicable `adaptive_execution_plan` and a distinct per-run `adaptive_execution_plan_binding` parented to that plan and the frozen spec, preserving any already registered frozen spec. The binding records exact run, job, backend, spec, plan, submission, collection, and agreement identities. The spec, raw plan, binding, manifest, outputs, and bounded log descriptors are all ledger-promoted before analysis reads the result. Canonical objects are likewise registered and ledgered one revision at a time by `ResearchStateRepository.materialize` before dependent objects are accepted.

The autonomous implementation phase is narrower than arbitrary code generation. A coding-provider fixture may select one of exactly two reviewed declarative templates and bounded numeric parameters. Admission resolves the provider-attempt/proposal/context/evidence parents, re-renders the worker and configuration deterministically, and requires the catalog, template-review, code, configuration, descriptor, frozen-spec, plan/binding, manifest, output, execution-receipt, and semantic-validation graph to agree. Completed `status`/`verify` then rebuilds that graph, independently recomputes the scalar result from the frozen data/configuration/output, verifies ledger and canonical-state bindings, and proves that the exploratory result did not enter scientific claims or paper authority. Backend subclasses, instance method overrides, arbitrary source/argv/path/shell/network fields, context or model substitution, and unattested network claims fail closed. The admitted run remains `NON_EVIDENTIARY`.

## Controlled external fixtures and blocked live validation

The fixture exercises literature and model-provider contracts without making live calls:

- Five synthetic PMC responses pass through `EgressGateway` with `FixtureTransport`, a host/path/method policy, raw-response custody, strict JSON parsing, normalized response artifacts, explicit synthetic licenses, exact passage locators, and passage-bound `LEVEL_5` verification. The fixture also executes a bounded citation-expansion plan, persists page/terminal receipts, an immutable citation graph with occurrence-level provenance, target-bound ranking, and complete multi-round investigation state. `ProblemInvestigator`, the registry-checked research gate, and the registry-checked novelty gate reopen those exact authorities before design. `network_used=false`; these records prove the checked workflow, not real literature coverage or real-world novelty.
- The OpenAI Responses adapter receives one captured structured-output fixture through the same audited gateway. The unverified fixture transport receives no resolved credential. The output is advisory, schema-checked, immutable, and explicitly not scientific evidence.
- The earlier separate provider availability check reported no credential and sent no request; it is not a current credential inventory. Live OpenAI remains externally unverified. Configuring a credential would not enable dispatch because credential-bearing real-network execution remains disabled until a separately reviewed sensitive-response custody boundary exists (`BLOCKED_LOCAL`).
- Live OpenAlex, Semantic Scholar, Crossref, arXiv, PubMed and PMC behavior, including rate limits, terms, retention and licensing, remains externally unverified. This checkpoint did not retest network availability. PMC production activation remains closed independently of network or credential availability; supplied-response normalization does not establish a working native route for every adapter. Any credentialed route is subject to the sensitive-response custody block. Replaceable normalization and failure boundaries can be fixture-tested without passing a resolved credential to the fixture transport, but a fixture is never reported as a live source.

The installed [PMC wire/custody slice](PMC_WIRE_CUSTODY.md) reuses the existing gateway, artifact registry and scientific ledger for framing, supplied coordination, attempt/outcome joins and versioned replay. Its bounded offline evidence does not certify the unchanged native lifetime implementation or genuine native/TLS/live/signing deployment. It introduces no second provenance authority.

No adapter may import or instantiate its own network primitive. Controlled general web or future providers must use the same audited egress boundary rather than create a second gateway.

Prospective OpenAI invocations additionally apply a provider-specific schema admission profile after preserving exact invocation, input, schema and request intent, before availability or dispatch. The neutral interface and historical request/replay owners do not apply current provider limits retroactively. The profile checks 5,000 total properties, 1,000 enum entries, 120,000 property-name/direct-string-enum characters and the 15,000-character rule for string enums with more than 250 entries, based on the [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs) examined September 19, 2026. Object and array containers conservatively count toward a ten-level local depth bound. Compound enum entries are explicitly excluded because their budget contribution is unspecified in that guide; this is our narrower admission profile, not a claim that the API rejects every compound enum. A present `enum:null` is refused rather than silently rewritten. Refusal retains the exact intent and uses the existing bounded `SCHEMA_NOT_SUPPORTED` policy receipt without transport or scientific authority. Offline checks in `test_external_providers.py` and `test_openai_schema_admission.py` cover boundaries, exact retained inputs and unchanged historical request projection. This does not establish exhaustive model/fine-tune compatibility, endpoint behavior or live confidential deployment.

## Compute plane

`FrozenRunSpec` binds the experiment, hypothesis, phase, admitted argv, working directory, code, data, configuration, evaluator, all seeds, ablations, tolerance, time and log bounds, retry lineage, network/shell policy, evidence class, and metadata.

`LocalMacBackend` runs a real subprocess with `shell=False`, closed file descriptors, no stdin, a small scrubbed environment, an explicit executable allowlist, bounded stdout/stderr capture, timeout handling, and a dedicated per-job directory with an immutable frozen spec and captured logs. A successful exit is not enough. Collection requires an exact `output-manifest.json` whose run/spec/code/data/configuration/evaluator identities match the frozen spec, every planned seed appears exactly once, every required ablation passes, and every declared artifact resolves to the exact confined bytes, SHA-256, and size. Reconciliation repeats those checks so altered output becomes invalid rather than collectable.

The controller runs the local fixture twice under the same scientific binding and frozen zero tolerance, then compares every seed and required ablation. The fixture uses `EvidenceClass.NON_EVIDENTIARY`; therefore a matching clean rerun is recorded as a system-reproduction match and the scientific comparison remains `NON_EVIDENTIARY`, not `PASS` scientific evidence.

The reason is explicit: the current local worker has admitted argv, path checks, a scrubbed environment, and a policy flag saying network is denied, but it has **no OS-enforced filesystem, process, or network sandbox**. Environment variables do not enforce isolation. Technical execution and system reproduction succeed, but scientific-result eligibility is `BLOCKED_LOCAL`; the network-use classification remains `UNKNOWN_UNATTESTED`. Until an enforced or equivalently reviewed boundary exists, the built-in fixture and default local runs are not eligible scientific results.

`FakeGPUCloudBackend` exercises the provider-neutral lifecycle, and `ScheduledGPUCloudBackend` implements the concrete offline boundary over an injected structured scheduler. The scheduled adapter binds equivalent local/cloud specs to an explicit escalation plan, enforces idempotent identity, monotonic states and attempts, checkpoint-bound requeue/preemption, idempotent cancellation, and bounded manifest/artifact return into the registry. Both paths remain `UNTESTED`, use no validated live GPU service, and always report `scientific_evidence=false`. A live scheduler/transport, CUDA execution, credential and cost authority, remote isolation/custody, and independent artifact-return channel remain `BLOCKED_EXTERNAL`.

## Canonical research state

The integrated fixture requires exactly these 21 canonical object types:

1. `ResearchQuestion`
2. `PriorWork`
3. `Hypothesis`
4. `Dataset`
5. `Split`
6. `Metric`
7. `Method`
8. `Implementation`
9. `Baseline`
10. `Experiment`
11. `Run`
12. `Result`
13. `StatisticalTest`
14. `Ablation`
15. `Evidence`
16. `Claim`
17. `Critique`
18. `Challenge`
19. `Decision`
20. `ReproducibilityPackage`
21. `VenueAssessment`

Each object has a stable type and ID, producer role, status, schema, revision and supersession identity, canonical content hash, parent references, relationships, code version, and bounded metadata. Materialization verifies registry and ledger integrity, embedded artifacts, parent identity and freshness, producer authority, and claim/evidence semantics. Validation detects missing materialization events, stale evaluated inputs, gaps in revision lineage, missing provenance edges, missing required relationships, wrong code identity, and registry or ledger corruption.

Terminal scientific state is integrated through object type 19, `Decision`, without changing the legacy macro state. Deterministic adapters map existing typed research-gate, hypothesis, discovery, reproduction, compute, soundness, paper, and legacy statuses into the exact Research OS terminal vocabulary. The integrated fixture derives `MORE_EXPERIMENTS_REQUIRED` from soundness, materializes the raw terminal artifact and canonical decision, immediately reopens the raw artifact through `load_terminal_outcome()`, and exposes only the canonical decision's artifact hash, phase, and outcome in the final summary. The direct end-to-end readback independently repeats that terminal load; summary prose is never the source authority.

## Protocol-scoped operational GPU requirement

`gpu_validation_requirement.py` is a nonissuing source resolver, not another provenance store. It reopens the actual frozen contract/plans, exact retained code/Dataset/configuration/evaluator, design-freeze receipt and existing escalation-plan authority. The closed CUDA-device elapsed-time protocol measures an `INTERMEDIATE` quantity that admitted LOCAL_MAC CPU/MPS profiles cannot supply. This establishes one prospective unperformed obligation, not physical CPU incapacity or the scientific merit of requiring that quantity.

To prevent a renamed or partially observed attempt from appearing never started, selection follows the contract obligation, project identity or the same four retained inputs and scans current registered progress and ledger visibility. Incidental unrelated strings/parents cannot erase progress; only complete existing unrelated-preparation ownership excludes its exact records and event. Unknown work refuses. Both actual admissions must precede the assessment, but neither admission is required to precede the other.

`compute_terminal.py` retains the old wall-budget codec unchanged and adds a separate GPU-requirement codec inside the same artifact/event family. Both use one publisher with project locking, paired registry/ledger compare-and-swap, capacity preflight, event-first exact recovery and full source readback. To prevent publication order from choosing the terminal cause, presence of the prospective GPU-policy key refuses wall-budget fallback after full frozen-source replay and a paired snapshot check; malformed policy also refuses, while absent-key legacy behavior is retained. The downstream canonical terminal adds the assessment to its source parents, so this route caps the source closure at255 within the existing256-parent limit. The terminal is `OPERATIONAL_BLOCKER`, with empty claim IDs, false scientific/spending eligibility and external validation `UNTESTED`. No CUDA dependency, compilation, GPU job or scientific evidence is created by resolving or publishing it. Current repair/review/final evidence status is maintained in `.run/STATE.json`.

## Claim, writing, paper, and venue boundaries

`ClaimEvidenceGraph` is the claim authority. The fixture materializes all 12 required evidence kinds and independent content-bound support receipts, resolves them from the registry, and derives eligibility rather than accepting a caller-supplied status. The canonical `Evidence` and `Claim` objects are checked views of that graph: materialization reopens the graph artifact, requires the exact claim identity/text/producer and an eligible verifier decision, requires distinct claim producer and evidence verifier roles, and binds canonical evidence parents. This does not create a second claim authority.

The narrow writer view re-resolves evidence and receipts and omits any claim whose eligibility has become stale, missing, or contradictory. Paper input is assembled from the canonical state snapshot, claim graph, authoritative evidence, metrics, method/code bindings, limitations, reproduction status, soundness assessment, and external-validation state.

Scientific promotion is checked at every authority edge. The research brief is derived from the persisted investigation state; novelty requires an exact closest-prior-work comparison and registry-resolved evidence. `RegistryDiscoveryEvidenceResolver` recomputes checked branch evidence, and promotion adds a frozen receipt that later consumption revalidates; positive, negative, null, failed, invalid, rejected, and terminated histories remain visible. `register_checked_superiority_promotion()` is the only superiority-authority minting path: it resolves the frozen contract, execution eligibility, aggregate result, statistics, independent evaluator assessment, baseline, metric, units, scope, and compute conditions, recomputes the conclusion, and registers an ordered-parent receipt that `require_checked_superiority_promotion()` rederives. The integrated fixture intentionally does not mint that receipt; its superiority artifact is explicitly a non-authoritative diagnostic. Paper assembly reopens the diagnostic and the canonical claim/state authorities and therefore cannot convert it into a superiority claim.

Soundness requires one registry-resolved receipt for each of the 15 exact dimensions and one category review for each of the 14 exact Challenger categories. Missing, duplicate, substituted, unexecuted-required, or unresolved-blocking inputs fail closed. The fixture records 11 dimensions as `PASS`, four (`NOVELTY`, `GENERALIZATION`, `END_TO_END_EVIDENCE`, and `REPRODUCIBILITY`) as `UNTESTED`, 13 independent attack categories as `UNTESTED`, and only the external-validity attack as executed with an unresolved major finding. It therefore derives `MORE_EXPERIMENTS_REQUIRED`; checklist completeness does not mean scientific success.

The fixture intentionally stops at a machine-verifiable `PaperCandidate`; it does not generate or submit a paper. `verify_paper` hard-blocks unsupported central claims or references, contradictions among prose/tables/methods, omitted baselines, leakage, evaluator exploitation, invalid statistics, unsupported novelty, selection bias, failed clean scientific reproduction, and unresolved blocking challenges. In the current fixture, real novelty is unsupported, the clean rerun is scientifically non-evidentiary, external validation is incomplete, and soundness is `MORE_EXPERIMENTS_REQUIRED`. Paper verification is therefore blocked, final release is blocked scientifically, and venue classification is forced to `NOT_READY` regardless of numeric readiness scores. E4 remains absent.

## Storage layout

- `runs/<run-id>/registry/`: the vNext run-scoped content-addressed object and metadata registry.
- `runs/<run-id>/events.jsonl`: the vNext run-scoped hash-linked phase, experiment-promotion, and canonical-object ledger.
- `.scientist-one-build/experiments/local-mac/<job-id>/`: immutable frozen spec, canonical `execution-plan.json`, and bounded logs plus the child manifest, outputs, and checkpoint inspected before authoritative promotion. Registry custody stores the raw plan separately from its per-run spec binding.
- Legacy `runs/<run-id>/manifest.json`, checkpoint, artifact projection, custody, resource-authority, reproduction, and release-candidate paths remain as documented for the trusted kernel. The vNext fixture does not replace or reinterpret them.

## Legacy-kernel preservation

The existing `preflight`, `calibrate`, `start`, `demo`, `status`, `resume`, `verify`, `reproduce`, and `package` workflows remain present. `status` and `verify` now branch on an unambiguous legacy-manifest versus vNext-operation authority; completed vNext verification checks the operation receipt, full registry/ledger closure, final summary/final-event binding, canonical-state rehydration, the summary's terminal-artifact reference, and the exact autonomous artifact/semantic graph while explicitly reporting resume/reproduce/package and scientific evidence as unsupported. Terminal materialization and direct end-to-end verification separately perform authoritative `load_terminal_outcome()` readback. vNext reuses rather than forks the registry, ledger, path policy, roles, macro-state vocabulary, claim custody principles, E4 boundary, and legacy reproduction/package contracts. It does not weaken command denial, protected-resource custody, confirmatory rerun prohibition, signed-off writing eligibility, or human-release semantics.

Historical demo/replay/package receipts remain historical evidence for the preserved kernel. They are not silently upgraded into evidence for the new literature, provider, LocalMac, GPU, canonical-state, or paper pipeline. Final vNext verification must rerun the captured suite, architecture controls, end-to-end fixture, recovery and failure-injection checks, and final audit after source and documentation freeze.
