# ADR 0001: Greenfield standard-library evidence controller

- Status: Accepted
- Date: 2026-08-12
- Scope: Scientist-One vNext initial architecture
- Evidence scope: historical pre-vNext checkpoint only; not evidence for the current vNext source tree

## Context

The app-selected `<PROJECT_ROOT>` workspace was empty and had no Git metadata at bootstrap. The personal path is redacted in this portable view; this remains a historical bootstrap statement, not the starting state of the later trusted-kernel upgrade. No existing state machine, source, tests, architecture, research target, local literature corpus, dataset, protocol, lockfile, or dependency approval could be preserved or migrated. Python 3.13.9 and standard-library tooling were available locally. Network and dependency acquisition are prohibited.

The objective requires a CALIBRATE-to-RELEASE workflow, typed evidence, authority separation, holdout custody, reproducibility, Apple Silicon adaptation, and honest negative/inconclusive endpoints. It also prohibits treating synthetic success, role-separated model review, or a polished package as proof of novelty or publication readiness.

## Decision

Build one Python 3.11+ standard-library package with:

- a single externally visible macro chain: `CALIBRATE -> CHARTER -> GROUND -> PROTOCOL -> PREFLIGHT -> IDEATE -> DISCOVER -> CANDIDATE -> CONFIRM -> CLAIMS -> WRITE -> AUDIT -> RELEASE`;
- detailed scientific phases represented by typed transition prerequisites rather than a conflicting second controller;
- one canonical transition-contract table consumed by both the foundation controller and CLI forward chain;
- locked append-only canonical JSONL events linked by SHA-256;
- run-scoped content-addressed important artifacts with freeze/provenance metadata;
- a `-I -S -B` captured-source launcher that executes only descriptor-captured project bytes and binds them to the frozen source inventory;
- exact captured `test-suite` and `audit-project` evidence modes that additionally descriptor-capture tests, use exclusive in-memory loaders, repeat live/module/destination attestations, and atomically publish their staged reports only after the final check;
- strict canonical project-root path policy and explicit subprocess argument arrays;
- evaluator/role authority restrictions, with E1 advisory, E2/E3 frozen separate contexts, and E4 human-only;
- a 40% untouched confirmatory validity reserve and blind interpretation before reveal;
- a local custody adapter explicitly labeled simulated and non-independent, with an external-to-run durable journal plus interfaces—not claims—for future human/service custody;
- CPU as the reference device and conditional MPS only after installed-framework capability/parity checks;
- project-local event-bound checkpoints, a ledger-committed external resource authority, conservative bounds, validation/continuation recovery for an intact manifest, and frozen-artifact replay through an immutable reproduction manifest;
- an exactly pre-admitted deterministic review ZIP followed by a detached final envelope that binds the ZIP/release record to the final ledger without a self-hash cycle; and
- a deterministic synthetic demonstration because no real target/evidence corpus exists.

No Git repository is initialized, no dependency is acquired, no server is started, and no external provider is invoked. Source fingerprints record working-tree identity until a human establishes repository policy.

## Alternatives considered

**Install a scientific framework.** Rejected because no dependency authority exists, the run is offline, and the controller/evidence guarantees do not require one. Optional installed adapters may be detected without becoming dependencies.

**Use SQLite as the sole ledger.** The standard library supports it, but canonical JSONL is simpler to inspect, hash, package, and recover for this greenfield bounded core. A future indexed projection may be added without replacing authoritative events.

**Use detailed scientific phases as a second state machine.** Rejected because two mutable state sources invite drift. Typed prerequisites preserve problem investigation through reproduction semantics within the required macro vocabulary.

**Claim local directory separation as independent custody.** Rejected as scientifically false. The adapter is useful for contract testing but cannot hide data from the same local authority.

**Invent a research topic for an end-to-end paper.** Rejected because missing literature/data would make novelty and citations unverifiable. The run instead produces a clearly labeled demo package.

## Retained controls and frozen evaluation hypotheses

The greenfield architecture evaluation froze each ID before integrated scoring. “Retained” means its targeted deterministic checks and bounded synthetic evidence support keeping the control; it does not mean external scientific effectiveness or independent review was established.

| Frozen control ID | Defect or hypothesis and retained control | Tradeoff / residual limit |
|---|---|---|
| `state_transition_safety` | Free-form advancement could bypass authority; retain typed requests, canonical forward/terminal contracts, frozen artifacts, evaluator receipts, idempotency checks, and captured-source startup. | A stale-ledger/newer-checkpoint rollback is returned out of band with `persisted=false`; appending to the stale fork is deliberately forbidden. |
| `approval_custody` | Producer or automation could forge approval; retain typed roles, E1 advisory-only, E2/E3 logical separation, and rejection of autonomous E4. | Same-process E2/E3 are not independent human review. |
| `holdout_integrity` | A local agent could tune on confirmation; retain frozen identities, registry-bound fresh receipt, pre-reveal start event, one authorized reveal, external-to-run held-descriptor journal, and invalidation on violation. | Same-user custody is simulated and non-independent; a coherent rewrite of all local witnesses remains possible. |
| `scientific_validity` | Invalid units, baselines, multiplicity, or nulls could create false signal; retain typed protocol/statistical validators and calibration traps. | Standard-library methods are bounded, and demo R predicates do not exhaust the normative model. |
| `negative_result_handling` | A controller optimized for a paper could hide nulls; retain typed negative/inconclusive terminals and the blind result-pattern mapping. | Public `demo` selects positive; internal API/regression fixtures exercise null/reversal/unstable branches and do not prove arbitrary real-study interpretation. |
| `claim_traceability` | Prose could invent evidence; retain the 12-kind graph, resolver-backed frozen nodes, exact semantic support receipts, post-generation output/MIME parents, and WRITE-time deterministic re-render. | SHA-shaped placeholders are not evidence, and the demo's local fixture citation cannot establish external literature or novelty. |
| `crash_recovery` | Partial writes, sleep, or rollback could corrupt evidence; retain durable confirmatory start, event-bound checkpoints, descriptor-safe quarantine, external resource/custody authorities, and stale-ledger out-of-band refusal. | An absent/corrupt manifest cannot be rebuilt completely; coherent same-user rewrite of every local authority remains possible. |
| `deterministic_reproduction` | A headline value could be irreproducible; retain ledger/registry-bound inputs, immutable reopened replay manifest/result, separate idempotent directory, output hash/tolerance, and live frozen source/config equality. | Adapter covers only built-in synthetic arithmetic and executes live bytes after equality verification rather than arbitrary archived code. |
| `resource_control` | Overnight work could exhaust the host or validity reserve; retain monotonic persisted elapsed/validity state, wall/storage/concurrency/memory/disk/checkpoint limits, and bounded backoff. | Telemetry and thresholds are conservative heuristics; missing probes pause admission but cannot predict every workload. |
| `prompt_injection_resistance` | Artifact text could be mistaken for authority; retain data-only treatment, command allowlists, safe parsing, and the injection calibration case. | Semantic maliciousness beyond tested classes still requires review. |
| `review_packet_usability` | Evidence could be complete but unusable; retain deterministic table/figure/paper rendering, exact package indexes/snapshots, a bounded pre-release ZIP, and detached final ledger envelope. | A polished packet is not publication readiness or E4 approval. |
| `content_addressed_evidence` | Mutable filenames could hide replacement; retain run-scoped SHA-256 objects, immutable metadata `record_hash`, recursive parent descriptors, validation, and orphan checks. | At this historical pre-vNext checkpoint, registry, ledger, and package hashes are unkeyed and not independently witnessed. ADR 0002 later adds a narrow per-registry HMAC for source-owned live-transport execution authority; that extension is not an external witness and does not sign the general history. Bounded byte APIs require future streaming for large evidence. |
| `blind_interpretation` | Post-result storytelling could change conclusions; retain a hash-bound result-pattern mapping before reveal. | The mapping is exercised only on synthetic fixtures here. |
| `validity_reserve` | Pilot choices could consume confirmation; retain a frozen 30%–50% rule with 40% default and new-study lineage after reveal. | Local custody cannot prove the same user never inspected bytes outside the adapter. |
| `drift_and_stall_detection` | Long runs could silently drift or hang; retain midrun review, launcher-inclusive source/config identities, 15-minute stall handling, crash ceiling, bounded retry backoff, and exact-callable device parity binding. | No approved physical MPS adapter was available, and demo duration cannot validate all long workloads. |

Controls remain only when their frozen targeted/regression evidence passes; exact final commands, counts, run IDs, and hashes belong in `STATUS.md` and the final overnight report, not in this architectural decision.

## Consequences

The core is inspectable, offline-capable, testable with `unittest`, and has a small dependency surface. Frozen artifacts can be traced and the built-in result replayed without an external service. Handler outcomes use typed terminal evidence, while public CLI scenario selection intentionally exposes only the positive demonstration.

At this historical pre-vNext checkpoint, the design does not provide signed or independently witnessed history, genuine independent custody/review, rich large-scale numerical computation, external novelty evidence, or autonomous release. ADR 0002 later adds one narrowly scoped local HMAC authority for exact live-gateway execution; it does not retroactively sign this checkpoint, sign the general registry or ledger, or provide independent witnessing. Passing the synthetic suite establishes only the tested local contracts. Output remains `DEMO_RESEARCH_PACKAGE`, `NOVELTY_UNVERIFIED`, with simulated non-independent custody. E4 is human-only.

## Historical pre-vNext evidence checkpoint

The authoritative historical post-fix bounded run is `run-20260812T204930Z-299b1dad55`, terminal `READY_FOR_HUMAN_REVIEW` with `COMPLETE_DEMO_ONLY`. It is pre-vNext evidence only and does not attest the current source tree. It used the captured-source production launcher, exercised one simulated/non-independent reveal, used CPU because no approved MPS adapter was available, and invoked no external integration. Its manifest SHA-256 is `f2f552354326b457f5eaa2e53a8d5ec43eed87ef1255e028ab765aecb2169d4a`; its 21-event ledger SHA-256/head are `43780cb332d9d97e9f0410d1cd80b5eff16cefdc6e321fe292089feb26ef25c7` and `a9baf2b5e4c5f543c80f59923a33965db8153ef9e04db159d9fabb33cf9e38c2`. Recovery selects event 0017 as the latest exact direct prefix, while immutable external checkpoint event 0021 binds the final head and cumulative 58-artifact projection; the external event-0021 checkpoint and current run checkpoint projection have SHA-256 values `06eb75bea3c903139e86b40ca7c69e16a6fe170477f8cd8f6834390577b21bea` and `68111f7465652e1b136c663906e409a38ffae59cfef45ead08faec269dfbf141`. The manifest indexes 58 frozen artifacts and passed verification twice.

Replay `33876fcf55fc9f76d6c6` has manifest/result SHA-256 values `5f6624739072982bbd68b9704d880d0b26e1dbd2d21b5637c0ef6ecc548baaa0` and `bd3ec781660cd928af29e41be8e664bec38f643f95eaaa75612602684c7a2c17`; replay observed exactly `1.0` against expected `1.0`, with absolute difference `0.0` at tolerance `1e-12`. The 155-member pre-release ZIP/final-envelope SHA-256 values are `58512e88ee05266df7517cd0837ac57db777976cfa90eacff7c931b4af7bca2c` and `66a19b93e99447a04fe3f44863f59c821b6c0b1ac8361f99a62d2a098a61ec81`.

The captured full suite passed 364/364 with 26 source and 11 test attestations, including the checkpoint aggregate-admission regression. `reports/test_results.json` has SHA-256 `640f2ab9a210830f38a2e2c15445d301f3d3d234d59a9cb2375e187d5067e8fc` and captured-output SHA-256 `c9e839f42626bcc13eefda62577dfe28fd0e327af148cb3c84103c21f239ecc5`. Independent full-suite and security/recovery review passed with no blocked local item. The prior 363-test run and its packet are superseded by this post-fix evidence. These results retain the 15 frozen local controls; they do not supply E4, novelty, real data, genuine independent custody or human review, physical MPS validation, publication, or release authority.

## Verification

```sh
set -eu
/opt/anaconda3/bin/python3 -I -S -B scripts/scientist_one_cli.py --help
/opt/anaconda3/bin/python3 -I -S -B scripts/scientist_one_cli.py preflight
/opt/anaconda3/bin/python3 -I -S -B scripts/scientist_one_cli.py calibrate
/opt/anaconda3/bin/python3 -I -S -B scripts/scientist_one_cli.py test-suite
/opt/anaconda3/bin/python3 -I -S -B scripts/scientist_one_cli.py audit-project
```

The dependency declaration remains `[]`. Final post-documentation audit, architecture-evaluation, and handoff-report identities belong in final status and the overnight report; this ADR does not predeclare still-pending evidence.
