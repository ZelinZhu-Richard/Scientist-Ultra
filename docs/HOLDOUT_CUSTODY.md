# Holdout Custody

## Security claim

The local `SimulatedHoldoutCustody` adapter is **simulated custody and is not independent**. Its machine labels are `SIMULATED_NON_INDEPENDENT` and `NON_INDEPENDENT`. It tests interface contracts, access counting, freeze preconditions, and invalidation behavior. Filesystem conventions cannot provide strong blinding when the same user and process can read all project files. No report may shorten this limitation to “independent holdout protection.”

Abstract `HumanControlledHoldoutCustody` and `IndependentServiceHoldoutCustody` interfaces describe future adapters, but neither exists in this offline run. Their interfaces do not count as verified external custody.

## vNext exploration/confirmation boundary

The vNext canonical state represents train, exploratory-development, validation, and confirmatory split roles explicitly. A split object records its dataset parent, unit, frozen definition artifacts, and whether it is protected or used. Those records make selection history inspectable; they do not themselves reveal data or prove independent custody.

The scientific Dataset/Split lane strengthens identity without changing that custody claim. It prospectively freezes the exact source/body/license/use plan, requires a signed run-bound gateway crossing plus audited semantic use review, and atomically publishes one exhaustive disjoint four-role partition before any Run/Result visibility. Each Split resolver replays the complete partition, so an isolated valid-looking confirmatory role cannot hide overlap or omission. This is partition and ordering authority, not secrecy: the same local user can still inspect the source bytes, and the gateway HMAC authenticates only its local captured crossing.

The integrated Research OS fixture executes only the synthetic exploratory-development split. Its confirmatory split remains marked protected and unused, its experiment class is `SMOKE`, and every local run declares `NON_EVIDENTIARY`. The fixture does not call `SimulatedHoldoutCustody`, does not produce a seal or reveal receipt, and does not claim confirmatory evidence. Its local clean rerun verifies system behavior only; repeating the development computation does not turn it into confirmation.

Any future vNext confirmatory run must freeze the Evaluation Contract and identities before reveal, consume genuinely protected validity resources through an admitted custody adapter, preserve exploration and confirmation as distinct experiment phases, and materialize the custody/result chain in the existing registry and ledger. A canonical `Split`, a hash, an operation receipt, a human-gate profile, or a model decision cannot substitute for custody. Post-reveal tuning or a scientifically disappointing result is never a mechanical retry.

The newer checked vNext boundaries do not change this requirement. Registry-resolved discovery can prove that a branch promotion was recomputed from its frozen local artifacts; checked superiority can prove that a promotion receipt satisfied its registered execution-eligibility contract; the registry-derived paper bundle can prove that its claims and policy flags were re-resolved; and the 15 soundness/14 Challenger receipts can prove complete logical gate coverage. All are same-trust-domain roles in the current local process. None proves that confirmatory data stayed hidden from the same user, supplies an independent custodian, creates E4, or converts the non-evidentiary fixture into confirmation.

Likewise, Result-v2 bundle completion, exact `Jqual`, v2 Ablation authority, and a matching synthetic reproduction cannot substitute for custody. They bind current state and reviewed claims; they do not prove that protected data was unseen. Bundled synthetic reproduction is categorically scientifically ineligible and cannot become a confirmatory `ROBUSTNESS` source.

## Seal record

A sealed reserve records at least:

- holdout identity hash, never a novelty or confidentiality claim;
- split-manifest hash;
- sealing time;
- protocol hash;
- authorized access limit/count;
- custody adapter and independence label; and
- invalidation status/reason.

The reserve policy is frozen before pilot iteration. The default is 40% of relevant data or experimental compute. Development work, debugging, method selection, metric selection, feature/seed selection, baseline tuning, and story selection may not consume the reserve.

## Release preconditions and event

Before reveal, the requester supplies its role and reason plus matching frozen identities for protocol, final code, final configuration, and blind interpretation. The blind artifact contains the pre-unblinding mapping from possible outcomes to permitted conclusions.

The simulated adapter writes an fsynced, hash-chained custody journal outside the replaceable run subtree at `.scientist-one-build/custody/<run-id>.jsonl`. Its seal/access/release/violation events are separate from the main run `events.jsonl`. An authorized release journal event records:

- requester and reason;
- release time and access ordinal;
- a seal hash binding protocol/code/configuration, split, holdout, and pre-unblinding interpretation identities; and
- the released holdout identity.

The result artifact is created after release and links back to the custody/seal evidence through its provenance; it is not backdated into the release event. The main run ledger separately records `CONFIRMATORY_STARTED` before reveal and `CONFIRMATORY_COMPLETED` after the frozen result. `CustodyStatus` reports whether later journaled violations leave confirmatory claims valid.

Reveal preconditions also require passed midrun review and an untouched confirmatory reserve. Missing prerequisites are denied and recorded; mismatched identities or an unauthorized/accidental access invalidate that reserve for confirmatory claims. The adapter permits exactly one authorized reveal. `run_confirmatory` is the preferred path because ordinary orchestration receives only the evaluator result, not raw holdout bytes; an evaluator exception after reveal journals a violation and cannot be retried. Admission requires a fresh content- and registry-record-bound custody receipt, a provider-held snapshot, and a ledgered `CONFIRMATORY_STARTED` event before reveal. Boolean-only or claimed-but-absent custody evidence is rejected. Deleting a log or resealing exposed data does not restore validity.

For historical legacy run `run-20260812T204930Z-299b1dad55`, the frozen custody-record SHA-256 is `e6868ca6d2e54ebde59b581a01e278de06a0c94ddd6fc2868bd04e3965a2e655`. Its durable two-event journal has SHA-256 `79a08c6906b5cedd81b5e693e3d1e99bba910ed05476d35c7a93287affd6fb78`, head `4b2c51fe7ade1c47bec500ca30c661a50b95f515b8d5e77006896e39bae5a188`, and identity `0963718138fe4c8f656098604b732041903db8ae591553ff920fc541440f0148`. It records exactly one authorized reveal by `experiment_runner`, `confirmatory_claims_valid=true` within the adapter contract, and `custody_independence=SIMULATED_NON_INDEPENDENT`; `genuine_independence_claimed=false`. This receipt validates local access accounting only and must not be cited as independent blinding or as a vNext fixture reveal.

## Retry rule

A predefined mechanical retry may occur only when execution failed technically without yielding a usable scientific outcome, with unchanged frozen inputs and a complete record of both attempts. Outcome disappointment, high variance, null result, sign reversal, failed robustness, weak baseline performance, or subgroup inconsistency is scientific evidence and cannot authorize a retry.

Changing protocol, code behavior, configuration, seed policy, metric, exclusions, baseline, or interpretation creates a new study and requires genuinely untouched confirmatory material. The original access remains in history.

## Custody lifecycle

```text
split + reserve policy frozen
          |
          v
simulated custodian seals identity hashes
          |
development/pilot uses non-reserve allocation only
          |
midrun review freezes code/config + checks reserve
          |
blind interpretation frozen
          |
authorized request validates every identity
          |
single controlled reveal in custody journal;
main ledger records confirmatory start/completion
          |
result frozen; no post-result tuning
```

## What custody does not prove

- It does not prove that a same-user process never inspected a local file outside the adapter.
- Hashes prove identity comparisons, not secrecy, authorship, or independent timestamping.
- The external-to-run journal detects targeted run-subtree rollback only while that journal survives. The same user/process can coherently rewrite ordinary hash witnesses; even the gateway's narrow HMAC does not help holdout custody because the local process can access its key and the holdout. Strong anti-rollback or secrecy requires a human/service/different-UID/WORM/TPM/transparency authority.
- Role-separated contexts are not separate human custodians.
- A synthetic split does not establish real-world independence or external validity.
- Passing custody tests does not verify novelty or authorize release; `NOVELTY_UNVERIFIED` and E4 human-only still apply.
- Changing a human-gate profile does not repair absent, invalid, or non-independent custody; human authorization and scientific validity remain separate.
- `fixture-operation.json` reports process-level fixture status only. Even `COMPLETE` grants no reserve access, reveal authority, scientific eligibility, discovery/superiority promotion, paper readiness, human approval, E4, publication, submission, or release authority.

## Audit procedure

Use the captured-source CLI without opening raw holdout content. `verify` reopens the external journal through the simulated provider's held-descriptor admission guard, validates its hash chain and identity, and compares its path/head/full seal/access/release/status projection to the frozen custody artifact and run protocol/code/configuration anchors:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py status RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
```

Those commands audit a legacy run that actually has a simulated custody journal. A vNext fixture consumes no holdout and supports only the analogous read-only commands with `VNEXT_RUN_ID`; never call legacy `resume`, `reproduce`, or `package` for it. Its authority-aware `verify` checks absence of confirmatory use and the registered fixture authorities, not an independent reveal.

The final audit and legacy package verifier separately reconcile the custody journal path/head/identity and full seal/access/release records with the frozen custody artifact, then reconcile main-ledger admission/start/completion with the result artifact and ordered resource authority. They must state `SIMULATED_NON_INDEPENDENT`/`NON_INDEPENDENT` explicitly. Neither chain proves secrecy or coherent-rewrite resistance from the same local user. Final vNext custody-adjacent identities remain **PENDING** until the frozen evidence sequence completes. The final audit is the last repository mutation and its machine result is read from `reports/final_audit.json`; this document must not be edited afterward to add its digest.
