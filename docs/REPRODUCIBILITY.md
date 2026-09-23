# Reproducibility

## Status and scope

Scientist-One now has two related but distinct reproduction contracts:

- The preserved legacy `reproduce RUN_ID` path replays a frozen primary result from an intact legacy run manifest into a separate directory, without mutating the original evidence.
- The vNext `research-os-fixture` path executes a real local experiment and a second clean run inside one integrated fixture, promotes both exact output manifests into the registry and ledger, and compares their complete frozen scientific bindings.

Completed vNext fixtures also have a read-only `verify RUN_ID` path. It rehydrates and validates the completed system fixture; it does not resume it, start another reproduction, or create a package. The legacy and vNext operation contracts intentionally remain distinct.

The vNext path is system-reproduction evidence only. It is deliberately synthetic, uses `EvidenceClass.NON_EVIDENTIARY`, and lacks an OS-enforced experiment sandbox. A matching clean rerun therefore cannot establish a scientific result, external validity, novelty, GPU validity, paper readiness, or E4 authority.

Final post-vNext captured test counts, architecture-control counts, end-to-end counts, and final-audit digest are pending. The `364/364` and `15/15` results in `baseline_before_vnext.md` are the verified pre-vNext baseline, not a claim about the current source tree.

## Supported vNext procedure

Use the captured-source launcher with an interpreter admitted by the current bootstrap/handoff evidence:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py \
  research-os-fixture --run-id UNIQUE_RUN_ID
```

The run ID must not already exist. Omitting `--run-id` asks the controller to create one. Do not use direct `PYTHONPATH` imports, `python -m scientist_one`, or a direct call to `run_research_os_fixture` as authoritative launcher evidence.

The command returns canonical JSON. A successful system fixture reports:

- `status=PASS` and `system_fixture_integrity=PASS`;
- a run-scoped registry path and verified artifact count;
- a run-scoped ledger path, event count, and head hash;
- validated canonical research-state status and 21 object types;
- complete claim-evidence-kind coverage and an eligible claim scoped only to the synthetic development fixture;
- controlled literature/provider fixture status with `network_used=false`;
- a provider-advisory, closed reviewed-template implementation with exact admission, local-run, plan-custody, and semantic-recomputation artifacts;
- LocalMac validation and clean system-rerun comparison status;
- fake-GPU status `BOUNDARY_TESTED_ONLY` with external validation `UNTESTED`;
- scientific soundness `MORE_EXPERIMENTS_REQUIRED`;
- paper `BLOCKED`, venue `NOT_READY`, and `human_e4_synthesized=false`; and
- the explicit OS-sandbox, live-provider, live-literature, GPU, external-validation, and scientific-evidence limitations.

The final summary is itself a frozen registry artifact and is ledger-checkpointed only after canonical state, registry, and ledger validation. The JSON printed to stdout is a view of that registered summary plus the final registry/ledger receipts.

## What the integrated clean rerun proves

For each local job, `LocalMacBackend` freezes a `FrozenRunSpec`, launches a real subprocess with `shell=False`, captures bounded logs, and accepts output only through a confined `output-manifest.json`. Before a run is collectable, it verifies:

- exact run, spec, code, data, configuration, and evaluator hashes;
- the frozen complete seed set, with every seed reported exactly once;
- required ablation identities and passing status;
- every referenced output artifact’s path, SHA-256, and byte size;
- absence of duplicate artifacts, seeds, and ablations; and
- immutability on later reconciliation.

The controller then registers the frozen spec, manifest, every output, and log descriptors; checks the promoted registry records against the validated manifest; and records the promotion in the event ledger before analysis consumes it. It also parses the exact immutable `execution-plan.json`, requires canonical serialization and semantic hash agreement with both submission and collection, registers the raw plan bytes as a frozen `adaptive_execution_plan`, and creates a per-run `adaptive_execution_plan_binding` parented to the raw plan and exact frozen spec. The plan and binding are part of the same promotion event and downstream artifact closure. Identical raw plans may deduplicate safely while their spec-to-plan bindings remain run-specific.

The additional autonomous component run is separately reproducible as system plumbing: a provider fixture can select only a closed reviewed template and bounded numeric parameters, never source or command policy. The registry preserves the provider attempt, proposal, catalog/reviews, deterministic data derivation, code, configuration, descriptor, frozen spec, adaptive plan and binding, execution receipt, manifest, outputs, and semantic-validation artifact. The semantic validator recomputes every seed output from the registered fixture data and exact admitted configuration. This remains `NON_EVIDENTIARY` and is excluded from claim and paper authority.

The second run changes only permitted run lineage. `compare_clean_rerun` requires the same complete scientific binding and the same pre-frozen tolerance, compares every declared seed without representative-seed selection, and never widens tolerance after seeing results. The integrated controller separately compares seed statuses/metrics and required ablation outcomes. A mismatch is preserved as evidence and blocks downstream promotion.

Because both built-in runs are explicitly non-evidentiary, a within-tolerance match yields `NON_EVIDENTIARY` from the scientific comparison even when the separate system match is true. The documentation and summary must preserve both facts.

## Missing enforced isolation

The current LocalMac child receives an admitted argv, a scrubbed environment, `SCIENTIST_ONE_NETWORK_POLICY=DENY`, bounded logs, and post-run confined output admission with manifest/hash validation. These are valuable application controls, but they do not prevent the child from opening other filesystem paths, spawning another process, or attempting a network connection.

There is **no OS-enforced filesystem/process/network sandbox** in the current LocalMac path. A policy environment variable is not enforcement. Consequently the technically successful built-in CPU fixture, bounded autonomous component, and clean rerun remain non-evidentiary scientifically even after exact plan custody, manifest validation, deterministic recomputation, and a clean system match. Scientific-result eligibility is `BLOCKED_LOCAL` until a separately implemented and verified isolation boundary or an equivalently reviewed executor exists.

## Controlled fixtures versus live reproduction

The vNext run uses captured synthetic PMC and OpenAI Responses payloads routed through the sole audited `EgressGateway`. The unverified fixture transport performs no network I/O and receives no resolved credential, even though credential presence may be represented at the gateway boundary. Its raw bytes, response receipts, normalized artifacts, parsing, passage locators, structured output, rate/count controls, and provenance are reproducible local boundary evidence.

They are not live validation:

- OpenAI credential/model access is `BLOCKED_EXTERNAL`: an absent required credential blocks availability, while a present credential plus real network use is stopped before gateway request registration, budget use, dispatch, response custody, or signed-authority issuance until separately reviewed sensitive-response custody exists (`BLOCKED_LOCAL`).
- Live OpenAlex, Semantic Scholar, Crossref, arXiv, PubMed, PMC, licensing, terms, and rate-limit behavior are `BLOCKED_EXTERNAL`.
- The integrated fake GPU backend is `UNTESTED`, non-networked, and non-evidentiary. A concrete injected scheduled-backend contract additionally verifies offline submission-plan binding, monotonic scheduler attempts, checkpoint/requeue lineage, cancellation, and bounded hash-verified artifact return. Real scheduler transport, credentials, hardware, preemption service, cost authority, remote isolation, and independent returned-artifact custody remain `BLOCKED_EXTERNAL`.
- Independent scientific review, genuine independent custody, external validation, and human E4 remain unavailable and are never synthesized.

A later credentialless live reproduction must retain provider receipts, approved policy identity, credential status without secret values, ordinary request/response custody, external-validation classification, licensing/access decision, hardware/scheduler identity, cost records where relevant, and exact returned artifacts. Credential-bearing live reproduction must not begin until a separately reviewed sensitive-response store and its provenance/redaction contract replace ordinary response custody. It must never pass a resolved credential to an unverified transport or relabel a fixture as a live call.

## Required vNext comparison record

Preserve at least:

- captured launcher/source inventory and the interpreter/platform identity;
- fixture run ID, registry base path, registry verification result, ledger path, event count, and head hash;
- source snapshot, standalone experiment code, dataset, configuration, evaluator, method, and environment artifact hashes;
- both frozen run-spec hashes and scientific-binding hashes;
- each adaptive plan's semantic hash, exact raw-plan artifact hash, and per-run spec-to-plan binding artifact;
- both output-manifest hashes and every promoted output/log descriptor hash;
- the bounded autonomous implementation's provider attempt, catalog/reviews, proposal, data derivation, deterministic code/configuration/descriptor, execution receipt, outputs, and semantic recomputation receipt;
- planned seeds, per-seed statuses and values, ablation outcomes, and the frozen comparison tolerance;
- comparison status, maximum difference, complete compared-seed set, and separate system-match result;
- `scientific_evidence` and `scientific_evidence_eligible` flags without omission;
- explicit `os_enforced_sandbox=false` and the isolation limitation;
- literature/provider `network_used` and `external_validation` states;
- GPU boundary state;
- canonical object-type set and final state-validation result;
- claim decision, scope, evidence/receipt identities, Challenger finding, and soundness verdict; and
- paper blockers, venue classification, external-validation state, and absence of E4.

Do not compare only the final scalar metric or top-level `PASS`. The registry, ledger, frozen identities, complete seed distribution, ablations, non-evidentiary classification, and conservative downstream gates are part of the reproducibility claim.

## Failure and retry handling

A failed, timed-out, cancelled, preempted-without-valid-checkpoint, malformed, missing, or altered output is not collectable. A child exit code of zero does not override manifest failure. Conflicting idempotency keys or run IDs fail closed. Output mutation detected during reconciliation changes the job to invalid rather than preserving an earlier success.

Exploratory technical retries require explicit new lineage and validation. Confirmatory retries or device fallbacks remain prohibited by the preserved kernel. The fixture’s second run is a planned clean reproduction with a distinct run ID, not a retry chosen after inspecting an unfavorable result. Negative, null, failed, invalid, and inconclusive outcomes must be retained; repeatedly running until a favorable seed or output appears is prohibited.

## Preserved legacy reproduction

For an intact legacy run manifest, the existing captured commands remain:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py reproduce RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py package RUN_ID
```

That path uses the mutable manifest only as an index to registry- and hash-bound protocol/result/input/source/configuration artifacts, freezes a reproduction manifest in a separate project-local directory, revalidates source and configuration identity, applies the pre-frozen comparison tolerance, and never mutates original evidence. Missing or corrupt legacy manifests are not reconstructed solely from checkpoints and the ledger. Packaging remains a human-review candidate and never creates E4.

The historical selected replay and package receipts remain in the pre-vNext baseline and legacy run documents. They demonstrate preservation of the trusted kernel only. After the vNext source and these documents are frozen, final verification must rerun the captured test suite, architecture controls, relevant recovery and failure-injection tests, the captured `research-os-fixture`, and the final project audit before any final counts or digests are reported.

For a completed vNext fixture, `scientist_one_cli.py verify RUN_ID` is a read-only system-integrity verifier. It requires an unambiguous operation-only run, validates the exact completion receipt, frozen registry, ledger identity/head and full artifact closure, final summary event, and rehydrates all canonical research-object types. It always leaves `scientific_evidence_established=false` and `resume_supported`, `reproduce_supported`, and `package_supported` false. A successful verification is therefore stronger operational read-back, not a scientific reproduction or release package.
