# State Machine

## Legacy trusted-kernel controller model

The existing trusted-kernel workflow uses one externally visible deterministic macro-state chain:

```text
CALIBRATE -> CHARTER -> GROUND -> PROTOCOL -> PREFLIGHT -> IDEATE
          -> DISCOVER -> CANDIDATE -> CONFIRM -> CLAIMS -> WRITE
          -> AUDIT -> RELEASE
```

Detailed scientific phases are typed transition requirements, not a second mutable controller. A transition request is accepted only if its source state matches, its required artifacts are frozen and valid, the actor may request it, the necessary evaluator classes have approved it, and the request’s idempotency key has not already committed a different transition.

An accepted transition appends an event containing run/event IDs, timestamp, actor role, before/requested-after state, artifact hashes, code and working-tree fingerprint where available, configuration hash, fixture/dataset IDs, seeds, evaluator outputs, reason, and prior-event hash. A repeated byte-equivalent request returns the already committed result; a conflicting repeat fails.

The implemented `StateController` validates typed `TransitionRequest` objects against the canonical `default_transition_contracts()`. The CLI imports `macro_transition_contracts()` from that same table rather than maintaining an alias table. Required artifacts must be frozen and verified through the run-scoped registry; required evaluator receipts must bind the transition artifacts. Calibration advancement also performs a semantic comparison to the current deterministic calibration report. The orchestrator requests transitions, an allowed logical role approves them, E1 is never counted, and E4 objects are rejected.

This macro-state controller remains authoritative for legacy `start`, `demo`, `resume`, `reproduce`, and `package` workflows. The shared `status` and `verify` commands detect the run authority first: a legacy manifest uses these macro-state rules, while an operation-only vNext run uses the separate receipt/registry/ledger verification described below. The vNext Research OS integration does not rename these states, inject synthetic transitions into this table, or claim that a vNext phase checkpoint has traversed a legacy macro edge.

## Research OS vNext integrated path

The vNext system fixture is an integrated orchestration path over the same authoritative `ArtifactRegistry` and `EventLedger`, not a second mutable macro-state machine. Its materialization order is:

```text
FOUNDATIONS
-> CONTROLLED_LITERATURE
-> MODEL_PROVIDER
-> SCIENTIFIC_DESIGN
-> AUTONOMOUS_IMPLEMENTATION
-> frozen LOCAL_MAC run events and clean system rerun
-> ANALYSIS
-> DISCOVERY_AND_DOMAIN_VALIDITY
-> CLAIM_VERIFICATION
-> CHALLENGER_AND_GATES
-> canonical research-state materialization
-> PAPER_AND_VENUE
-> FINAL_VERIFICATION
```

Each named phase checkpoint first requires its referenced artifacts to be registered, frozen, and read back successfully. Only then does it append a hash-chained ledger event whose metadata marks the materialization `REGISTERED_BEFORE_CONSUMPTION`. The local experiment path contributes its own run-completion events and registered frozen spec, raw `adaptive_execution_plan`, per-run `adaptive_execution_plan_binding`, manifest, logs, and outputs. The raw plan is content-deduplicable; the binding is parented to the plan and frozen spec and records exact run/job/backend/spec/plan plus submission/collection agreement. A persisted-plan, collected-plan, spec, backend, or job substitution fails before promotion. Downstream phases consume registry identities, not unregistered in-memory values.

`AUTONOMOUS_IMPLEMENTATION` is a bounded exploratory substate, not arbitrary model-authored execution. A coding-provider result may choose only one of two reviewed templates and bounded numeric parameters. Admission fixes the proposal, provider attempt, context/evidence, catalog and template reviews, deterministically rendered code/configuration/descriptor, pre-registered frozen spec, and exact built-in local backend. The completed-operation verifier reconstructs the plan/binding, manifest/output/receipt and semantic-validation graph, independently recomputes the frozen scalar result, confirms ledger and canonical `Dataset`/`Method`/`Implementation`/`Experiment`/`Run`/`Result` bindings, and proves claim/paper exclusion. Provider or context substitution, arbitrary control fields, backend subclasses/overrides, forged semantic PASS, or false network attestation fail closed. The resulting run stays `NON_EVIDENTIARY` with network status `UNKNOWN_UNATTESTED`.

Because the existing ledger schema requires before/after state fields, vNext `CHECKPOINT` events use the neutral compatibility projection `GROUND -> GROUND`. That projection is not a `StateController` transition, does not mean the vNext workflow entered or advanced the legacy `GROUND` macro state, and cannot satisfy any legacy transition contract. The typed `metadata.phase` value and registered artifacts describe the vNext checkpoint.

The canonical research-state repository materializes immutable typed JSON objects through the existing registry and ledger. Each object carries identity, revision, producer, status, code version, parents, and type-specific provenance. Superseding revisions are append-only; Markdown rendering is a derived view. State validation resolves embedded artifact hashes, parent relationships, producer/reviewer authority, and claim-graph evidence against the registry. A verified claim remains producer-owned scientific content with a separate claim-verifier review; the verifier cannot become the claim's producer by materializing a checked view.

These objects model scientific relationships and lifecycle status. They do not authorize a legacy macro transition and must not be interpreted as evidence that `CALIBRATE -> ... -> RELEASE` ran. Conversely, the legacy manifest is not a substitute for canonical vNext research state.

### Fixture operation receipt

`research-os-fixture` reserves `runs/<run-id>/` atomically before work begins, so concurrent attempts cannot share one run identity. It atomically publishes `fixture-operation.json` as an operational status receipt:

- `IN_PROGRESS` means no downstream authority and is not resumable scientific state;
- `FAILED` means fail closed and start a new run ID; the failed run is not overwritten or retried in place; and
- `COMPLETE` binds the finished registry, ledger, and integrated summary and is treated as immutable.

The receipt is outside canonical scientific state. It is neither a phase-transition approval nor evidence, custody, soundness, paper, or E4 authority. The fixture's top-level `PASS` means integrated system-fixture integrity only; scientific soundness, evidentiary eligibility, paper readiness, external validation, and human release authority remain separately represented and may remain blocked.

`status RUN_ID` reports `IN_PROGRESS`, `FAILED`, and `COMPLETE` operation states without calling them resumable. For a completed vNext run, `verify RUN_ID` revalidates the exact operation receipt, frozen registry, full ledger-to-registry closure, ledger run identity and head, final summary binding, all 21 canonical object types, and conservative system-fixture classifications. Mixed legacy-manifest and vNext-operation authorities fail closed. These commands do not add vNext resume, reproduction-package, scientific-evidence, or release authority.

### Checked scientific substates

The synthetic literature path persists raw response custody, normalized records, citation-expansion pages and terminal receipt, an immutable occurrence-provenance citation graph, target-bound ranking, and complete multi-round investigation state. `ProblemInvestigator` and the research-question gate reopen those artifacts; novelty clearance separately requires an exact closest-prior-work comparison and registry-resolved evidence. The fixture proves that checked control path but records real-world novelty as unsupported because its sources are synthetic and live literature remains `BLOCKED_EXTERNAL`.

Discovery accepts only checked promotion results bound to the exact frozen run/plan/manifest/ledger, all-seed, ablation, evaluator, and control inventory. It registers both evaluation and promotion receipts and revalidates promoted authority before later consumption; its snapshot retains positive, negative, null, failed, rejected, invalid, and terminated branches. Superiority is not a caller-selected transition: `register_checked_superiority_promotion()` reopens execution eligibility, metric direction/scope/units, complete baselines, all seeds, evaluator validity, statistics, and compute fairness, then mints an ordered-parent receipt that `require_checked_superiority_promotion()` independently rederives. The integrated fixture intentionally has only a non-authoritative diagnostic, so it cannot authorize a superiority claim. Paper input is then rebuilt from canonical state, the scientific-only writer view, exact metrics/method/code/asset bindings, limitations, reproduction, novelty, superiority, soundness, and external-validation artifacts; hard blockers force `BLOCKED`/`NOT_READY`.

Soundness materialization requires the exact set of 15 dimension receipts—`QUESTION_VALIDITY`, `NOVELTY`, `TECHNICAL_CORRECTNESS`, `DATASET_VALIDITY`, `BASELINE_COMPLETENESS`, `EVALUATOR_VALIDITY`, `STATISTICS`, `ROBUSTNESS`, `ABLATIONS`, `GENERALIZATION`, `COMPUTE_FAIRNESS`, `END_TO_END_EVIDENCE`, `ALTERNATIVE_EXPLANATIONS`, `LIMITATIONS`, and `REPRODUCIBILITY`—and the exact 14 Challenger categories—`PRIOR_ART`, `EXPERIMENTAL_DESIGN`, `IMPLEMENTATION`, `LEAKAGE`, `STATISTICS`, `BASELINES`, `COMPUTE_FAIRNESS`, `EVALUATOR_GAMING`, `CONFOUNDING`, `ALTERNATIVE_EXPLANATION`, `SEED_DEPENDENCE`, `EXTERNAL_VALIDITY`, `REPRODUCTION`, and `OVERCLAIMING`. Exact-set completeness, registry readback, execution status, finding closure, and blocking severity are mandatory; a checklist entry marked `UNTESTED` is not a pass. The fixture records 11 dimensions as `PASS`; `NOVELTY`, `GENERALIZATION`, `END_TO_END_EVIDENCE`, and `REPRODUCIBILITY` as `UNTESTED`; 13 independent attacks as `UNTESTED`; and one external-validity attack as executed with an unresolved major finding. It therefore derives `MORE_EXPERIMENTS_REQUIRED`.

### Compute substates

`LOCAL_MAC` may reach technical `SUCCEEDED`, `VALIDATED_LOCAL` output, and matching system reproduction, but no current job receives a backend-private OS-isolation attestation. Because there is no OS-enforced filesystem/process/network sandbox, the documented scientific-readiness classification is `BLOCKED_LOCAL`; runtime evidence remains `NON_EVIDENTIARY` with `scientific_evidence=false` and `UNKNOWN_UNATTESTED` network use. Technical success cannot transition to scientific evidence.

`GPU_CLOUD` is represented by a provider-neutral contract, a fake backend, and `ScheduledGPUCloudBackend` over an injected structured scheduler. The scheduled boundary enforces local/cloud scientific equivalence, an explicit escalation plan, idempotent identity, monotonic job state and attempt, checkpoint-bound requeue/preemption, cancellation, and bounded manifest/artifact return. No live transport, GPU, credential/cost authority, remote isolation, or independent return channel was available, so every result remains `UNTESTED`, non-evidentiary, and externally blocked.

### Research OS terminal-outcome authority

Research OS scientific closure does not reuse the legacy macro terminal enum. Deterministic adapters map typed research-question, hypothesis, discovery, reproduction, compute, soundness, paper, and eligible legacy statuses into exactly these 11 outcomes:

```text
NOT_PUBLISHABLE
INSUFFICIENT_NOVELTY
INCONCLUSIVE
HYPOTHESIS_FALSIFIED
NEGATIVE_RESULT
NO_MEANINGFUL_GAIN
RESULT_NOT_ROBUST
REPRODUCIBILITY_FAILED
INSUFFICIENT_COMPUTE
FULL_VALIDATION_REQUIRES_GPU_CLOUD
MORE_EXPERIMENTS_REQUIRED
```

`PASS`, `SUCCESS`, and intermediate positive statuses are deliberately nonterminal. A derived outcome is serialized as canonical bytes in a frozen `research_terminal_outcome` artifact parented to the exact source evidence. It is then materialized as a canonical `Decision` through `ResearchStateRepository`, which appends a same-state ledger event; the legacy macro state does not change. `load_terminal_outcome()` verifies the raw bytes, SHA-256, role, timestamp, metadata, parents, typed source status, mapping ID, phase, and outcome. The final summary refers to the canonical decision's terminal artifact, phase, and outcome rather than becoming a new authority. The integrated fixture readback yields `MORE_EXPERIMENTS_REQUIRED` from its soundness record.

## State contracts

| State | Evidence required before advancing | Gate and failure behavior |
|---|---|---|
| `CALIBRATE` | Known-answer results for planted signal, true null, leakage, shift/reversal, invalid resampling, multiplicity, baseline mismatch, corrupt provenance, unsupported claim, holdout violation, embedded prompt injection, and domain-invalid permutation | E0 must distinguish all 12 mandatory cases. A security failure stops at `STOP_SECURITY`; invalid scientific discrimination stops at `STOP_SCIENTIFIC_INVALIDITY`. |
| `CHARTER` | `research_charter` with precise question, unit, inputs/outputs, comparison, estimand, falsifiable hypothesis, failure conditions, exclusions | Canonical forward contract requires E0. Producer self-checks are advisory. |
| `GROUND` | `evidence_inventory` with local evidence gaps and citation state | Canonical forward contract requires E0. The legacy demo has no external literature evidence and records `NOVELTY_UNVERIFIED`; the separate vNext synthetic literature path does not change this legacy receipt. |
| `PROTOCOL` | Frozen hypothesis, estimand, metrics, unit/resampling unit, exclusions, split roles, baselines, ablations, controls/nulls, statistics, multiplicity, seeds, budget, stopping/decision ladder, claim scope, interpretation rules, 40% reserve | E0 schema/freeze and E2 methodological approval. Mutation creates a new study version. |
| `PREFLIGHT` | `preflight_report` containing hardware/resource/dependency/path feasibility evidence | Canonical forward contract requires E0. MPS is optional; failed capability/parity selects recorded CPU fallback before confirmatory freeze. |
| `IDEATE` | `hypothesis_set` limited to protocol-permitted development choices | Canonical forward contract requires E0 and uses the development allocation only. |
| `DISCOVER` | `workflow_benchmark` and pilot/control evidence | Canonical forward contract requires E0+E2. The benchmark is synthetic regression evidence, not confirmatory science. |
| `CANDIDATE` | `pilot_report`, `midrun_review`, and `blind_interpretation` | Canonical forward contract requires E0+E2+E3 before confirmation. These are logical same-process contexts in the demo. |
| `CONFIRM` | `custody_record` and `machine_results` bound to frozen protocol/code/configuration/blind identities and one durable simulated-custody access | Canonical forward contract requires E0+E2+E3. Scientific failure is not retryable; custody violation invalidates claim use. |
| `CLAIMS` | `claim_graph` derived by the typed claim verifier | Canonical forward contract requires E0+E2. Every one of the 12 evidence kinds must resolve to a frozen registry object and carry a canonical claim-support receipt; figure/table nodes bind already-generated outputs with exact MIME types. |
| `WRITE` | Eligible claims only, locally verified fixture citation, generated tables/figures, explicit limitations | Writer cannot edit source evidence. It freshly verifies custody/registry/graph/writer-view identity and deterministically re-renders the table, SVG, and paper bytes before publication. |
| `AUDIT` | `audit_report`, `reproduction_report`, `e2_review`, `e3_review`, and `readiness_report` | Canonical forward contract requires E0+E2+E3. The bundled R predicates and reviews are deterministic same-process demo controls with the bounded scope documented below. |
| `RELEASE` | `release_candidate` with truthful labels and content hashes | Canonical forward contract requires E0+E2+E3. It means packaging for human review only; E4 is required for external release. |

## Terminal states

- `READY_FOR_HUMAN_REVIEW`: the canonical forward contract's autonomous ceiling. For the bundled run this means only that bounded demo controls passed; it is not `RELEASED`, accepted, publishable, or submission-ready.
- `NEGATIVE_RESULT`: the valid frozen protocol produced a defensible negative result.
- `INCONCLUSIVE`: evidence is valid but insufficient or unstable under the frozen interpretation.
- `BLOCKED_EXTERNAL`: remaining essential work requires unavailable external evidence/service/authority.
- `STOP_SCIENTIFIC_INVALIDITY`: scientific validity was compromised or mandatory validation failed.
- `STOP_SECURITY`: security confinement, path integrity, approval custody, or another security gate failed.
- `STOP_BUDGET`: bounded compute/storage/time admission ended; the terminal report and checkpoint identify the last valid evidence. The current run is terminal and is not automatically resumed past that decision.

The canonical contract table defines typed stop edges from every macro state using `terminal_report`+E0, and typed `NEGATIVE_RESULT`/`INCONCLUSIVE` edges after confirmatory evidence using `machine_results`+`terminal_report`+E0+E2. The orchestrator dispatches handler-selected outcomes through those contracts. The public `demo` subcommand selects the positive fixture; bounded API/regression scenarios select null (`NEGATIVE_RESULT`) and reversal/unstable (`INCONCLUSIVE`). `start --brief` reaches `BLOCKED_EXTERNAL` because no real providers/evidence are available, and handler-specific resource, security, or scientific failures reach the corresponding typed stops. A stale-ledger/newer-checkpoint rollback is deliberately different: recovery returns an out-of-band `STOP_SECURITY` with `persisted=false`, because writing a terminal record onto the stale fork would manufacture history.

As historical legacy evidence, the selected demonstration `run-20260812T204930Z-299b1dad55` traversed the positive macro path and committed 21 events through `RELEASE -> READY_FOR_HUMAN_REVIEW`; the ledger head is `a9baf2b5e4c5f543c80f59923a33965db8153ef9e04db159d9fabb33cf9e38c2`. Its outcome is `COMPLETE_DEMO_ONLY`, its R0-R7 values are bounded demo `PASS` receipts, and its package still requires E4. This recorded path does not make terminal failure branches hypothetical: the captured regression suite exercises typed refusal and honest-outcome contracts. It is not a vNext Research OS run.

## Evaluator authority

- **E0 deterministic validator:** schemas, hashes, transition/path rules, protocol completeness, result consistency, and required evidence.
- **E1 producer-local check:** advisory self-check only; never sufficient to authorize a gate.
- **E2 scientific-review context:** a logically separate, hash-bound receipt over frozen artifacts. In the demo it is generated in the same process and is not independent human scientific review.
- **E3 adversarial/reproduction context:** a logically separate receipt that includes the deterministic replay comparison and declared adversarial checks. In the demo it is not an independently executed red-team or human review.
- **E4 human release authority:** required for publication/submission/external release and other human-only expansions. The system cannot simulate or self-issue it.

E2/E3 are logical context separation in the local demo, not proof of independent humans or organizations.

## Mechanical retry versus new study

A confirmatory process may repeat only for a predefined mechanical execution failure that revealed no usable scientific outcome, using the same frozen inputs, with both attempts recorded. Changing a seed, exclusion, baseline, metric, code behavior, protocol, stopping rule, or interpretation after observing results is not mechanical retry. It requires a new study ID/version and a newly sealed reserve; the prior result remains in the ledger.

## Verification commands

For a legacy macro-state run:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py status RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
```

Use the same launcher with `--help` for the implemented run-ID syntax. `status` revalidates a terminal package when applicable. `verify` checks the EventLedger schema/hash chain and provenance, ordered external resource authority, live simulated-custody authority, live source/configuration inventories, run intent, run-scoped registry and recursive closure, ledger artifact/metadata projection, manifest state/head/count agreement, transition-edge and typed-receipt edge sequences, evaluator receipt hashes, recovery safety, and final package binding for a completed positive run. It does not re-execute every `StateController` semantic validator or independently redo the full R0–R7 audit/reproduction computation. Resume requires an intact manifest; it is validation and continuation, not full event-sourced reconstruction.

For the integrated vNext system fixture, use the separate command and a fresh run ID if one is supplied:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py research-os-fixture --run-id VNEXT_RUN_ID
```

That command performs registry, ledger, canonical-state, output-manifest, and clean system-rerun validation inside the operation. The legacy `resume`, `reproduce`, and `package` commands are not a recovery or publication path for this fixture. Inspect `runs/VNEXT_RUN_ID/fixture-operation.json`; an interrupted `IN_PROGRESS` or `FAILED` operation carries no downstream authority and requires a new run ID.

Final post-vNext captured-suite, architecture-control, audit, end-to-end, and failure-injection counts and frozen digests remain pending until the source and documentation tree is frozen and the final evidence run completes. Historical legacy counts and run IDs above remain historical evidence, not current-tree measurements.
