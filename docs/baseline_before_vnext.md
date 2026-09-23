# Baseline Before Research OS vNext

Status: **VERIFIED PASS after two bounded pre-vNext evidence repairs**

This is the independently reproduced baseline for the trusted research kernel before consequential vNext source changes. It records observed results from 2026-08-29 rather than copying the 2026-08-12 handoff claims. The two repairs below changed no scientific source, test, configuration, selected historical run, or protected evidence.

## Verification context

- Date/time: 2026-08-29, approximately 16:44–17:10 America/New_York.
- Operator/agent: Codex `/goal` run for `RESEARCH_OS_VNEXT_META_SPEC.md`.
- Canonical project root: `<PROJECT_ROOT>` (personal path redacted in this portable view; historical evidence and recorded hashes are unchanged).
- Runtime: `/opt/anaconda3/bin/python3` 3.13.9 under `-I -S -B` for authoritative commands.
- Current platform observed by the captured suite: macOS 26.6.1, arm64. The older bootstrap receipt records macOS 26.5.1; that version drift is explicit.
- Repository identity: no Git metadata. Source identity is the frozen 26-entry source inventory artifact `a4bc87d557696c761b0df05bf0ff3eb8dedd1a5f5d4d7fb0cf8413bff8aee786`, aggregate `72c24a939bd3bb21e76fa7f77688003894ba2ab73c068e23a525e13f1b5378b7`.
- Test identity: 11 captured test-source entries.
- Configuration identity: three-entry aggregate `67d1ee258236cae1f327135dccba73d39e496653f2eb848aac712352657c2544`.
- Dependency declaration: `[]` in `pyproject.toml`; the final pre-documentation audit found zero dependency lockfiles.
- External constraints: no network, credential, provider, external model, cloud compute, dependency acquisition, publication, submission, or upload was used.

## Before-state summary

- Conservative capability classification: `TRUSTED_RESEARCH_KERNEL`.
- Historical handoff run reverified: `run-20260812T204930Z-299b1dad55`.
- Fresh independently executed baseline run: `run-20260829T170951Z-28d371b6e3`.
- Terminal state/outcome: `READY_FOR_HUMAN_REVIEW` / `COMPLETE_DEMO_ONLY`.
- Required labels: `DEMO_RESEARCH_PACKAGE`, `NOVELTY_UNVERIFIED`.
- Custody: `SIMULATED_NON_INDEPENDENT`; one authorized local reveal; no genuine independence claim.
- Human E4: absent and required for external release. No autonomous process issued or implied E4.

## Test baseline

- Command: `/opt/anaconda3/bin/python3 -I -S -B scripts/scientist_one_cli.py test-suite`.
- Result: `PASS`.
- Tests run/passed: `364/364`.
- Failures/errors/skips/expected failures/unexpected successes: `0/0/0/0/0`.
- Unittest elapsed time: 72.269 seconds; captured-report elapsed time: 72.481828 seconds.
- Captured project/test sources: 26/11.
- Report: `reports/test_results.json`, SHA-256 `73dee18929495015a1693ead7cf6849ae85cb96430b9887cfa7939c78ed28f36`.
- Captured output SHA-256: `7d3b8ebadec86f2562bf81389c7937384c1b23d65ad46dd8e34298e4918d1d0f`.
- Historical discrepancy: none in count or pass/fail status. The fresh report hash differs from the historical report because timestamp and elapsed evidence were newly captured.

## Architecture-control baseline

- Frozen control report: `reports/architecture_evaluation.json`.
- Mandatory controls: 15 configured, 15 evaluated, 15 passed and retained; zero pending or failed; `numeric_score=null`.
- Targeted validator: `/opt/anaconda3/bin/python3 -I -S -B tests/test_architecture_evaluation.py`.
- Targeted result: 4/4 passed in 0.009 seconds.
- Final pre-vNext architecture-report SHA-256: `3d6c80c7f63514c9b711c9d2b98b7512b02550870cda567f18b3a82de112580e`.
- Frozen suite SHA-256: `2e9946e31b284df805a9d0a29a3a429b440a00a64bd2da6a46a262e721353921`.
- Validator SHA-256: `ea4bc870936ade19646bde65daa703dda3300ae92d1da8038c3129627cf574c2`.
- Repair required during reproduction: the architecture report referenced the historical test-report digest in 14 evidence records. The captured suite commits its new report only after its in-suite architecture tests run, so a subsequent standalone validator correctly exposed those stale bindings. The 14 bindings were mechanically refreshed to the newly passing report digest, after which the independent 4/4 validator passed. No control status or criterion was changed.

## Audit, security, and dependency baseline

- Audit command: `/opt/anaconda3/bin/python3 -I -S -B scripts/scientist_one_cli.py audit-project`.
- Initial observed result: `FAIL`, one `invalid_text_encoding/invalid_utf8` finding for a 6,148-byte root `.DS_Store` created on 2026-08-29. This result is preserved as an observed pre-repair failure, not hidden.
- Repair: moved the file without deletion to `.scientist-one-build/quarantine/pre-vnext-root.DS_Store`, an existing audit-excluded quarantine boundary. No bytes were discarded.
- Final pre-documentation result after a fresh demo: `PASS`; 899 files, 10,246,578 bytes, zero findings, zero lockfiles.
- Snapshot identity: `codex-security-snapshot/v1:sha256:938f071854af5823eb4759a7025f3c6b0bf66290b18d271b7349b52a4688f125`.
- Report: `reports/final_audit.json`, SHA-256 `d63e984d31541bdce65165193cd3015f282274ca3a91ee099bc09416b60773fa`.
- Audit caveat: this baseline document is necessarily written after the cited self-excluding audit snapshot. Any later documentation/source mutation requires a fresh final audit; the cited digest is not presented as a post-vNext snapshot.
- Dependency command result: `pyproject.toml` dependencies are `[]`; audit lockfile inventory is empty.

## CLI and deterministic demonstration

The supported captured-source CLI exposed these commands: `preflight`, `calibrate`, `start`, `demo`, `status`, `resume`, `verify`, `reproduce`, and `package`. Exact evidence modes `test-suite` and `audit-project` are dispatched by the launcher but intentionally absent from the ordinary parser surface.

Historical run revalidation:

- `status`, `verify`, `reproduce`, `package`, and post-package `verify` all passed for `run-20260812T204930Z-299b1dad55`.
- It retained 21 ledger events, 58 artifacts, ledger head `a9baf2b5e4c5f543c80f59923a33965db8153ef9e04db159d9fabb33cf9e38c2`, exact replay `1.0/1.0`, and the historical ZIP/envelope hashes.
- Global status remained `PASS` but truthfully reported two older, non-selected runs as `ERROR` because their final packet/envelope is unverified.

Fresh baseline demonstration:

- Command: `/opt/anaconda3/bin/python3 -I -S -B scripts/scientist_one_cli.py demo`.
- Run: `run-20260829T170951Z-28d371b6e3`.
- Result: `PASS`; `READY_FOR_HUMAN_REVIEW`; `COMPLETE_DEMO_ONLY`; 21 events; 58 artifacts.
- Manifest: 95,455 bytes, SHA-256 `a304262663f44ce06e25b14bd098d72d62475cfe8cf12ae3c5d28393bdef8f10`.
- Ledger: 76,517 bytes, SHA-256 `f7e691b5cf6fb8fdec7534b8fabadb866aa0e2aa60c837922b2ecf7c715fd6eb`, head `da6bd30ea74de6bd87804f21ee46ba4116c9c188591d75aa621acc4c7dfbb2f6`.
- Bounded R0–R7 demo predicates: all `PASS`, with the narrower meanings documented in `docs/SCIENTIFIC_VALIDITY_MODEL.md`.
- Device/execution: CPU/float32; physical MPS not exercised; no external integration.
- Resource evidence: two exploratory and four confirmatory units from a ten-unit budget; no worker crash; confirmation remained irreversible.

## Recovery, reproduction, packaging, and custody

- Structural verify before and after idempotent replay/package: `PASS`.
- Recovery verdict: `SKIP_COMPLETED`; `CONFIRMATORY_EVALUATION_ALREADY_COMPLETED` and `CONFIRMATORY_RERUN_PROHIBITED` remained enforced.
- Reproduction ID: `d7353223dc44e6747926`.
- Reproduction manifest SHA-256: `ab6846f1169a9e4cd782bb6e1d8817b538ae3d9dd0ca93905251a55a4603962e`.
- Reproduction result SHA-256: `140de17622a4f7f36a8a264520ef0cd0c95947bc5267166a92006eb9239eb512`.
- Source result SHA-256: `b06d183dc9c91fe722a2c82e641655250f4ff23ed47ba01721c4fc0d7d466b6c`.
- Comparison: expected 1.0, observed 1.0, absolute difference 0.0, frozen tolerance `1e-12`, `PASS`.
- Review ZIP: 155 members, 1,532,586 bytes, SHA-256 `e034f77620e210e254dfa511d9224c25cd8415ed36231739f7485159a914d753`.
- Detached envelope: 84,478 bytes, SHA-256 `73796aad3cc44735c0dfbb65a9741481823d6348cfc828e3af2b26ec9cd5d546`.
- Custody journal SHA-256: `8a8070cbc1de7b0e5b6d583afea3854d8b9e7f3c156de4c763807d53ef299c60`; custody remains simulated/non-independent.
- Package is a local human-review candidate only. E4 is absent; `submission_ready=false`; no release occurred.

## Guarantees that vNext must preserve

| ID | Verified guarantee | Baseline evidence | Required regression check |
|---|---|---|---|
| B-01 | Project-root path confinement, no-follow file handling, bounded parsers, secret/lockfile audit, and fail-closed malformed input | Captured 364-test report; passing final project audit | Full suite plus `audit-project`; injected traversal, symlink, hard-link, special-file, malformed/oversize data, and secret cases |
| B-02 | Locked append-only hash-linked event history with exact schemas and superseding corrections | `EventLedger` tests and verified 21-event fresh ledger | Ledger corruption, wrong-prior, duplicate-ID, torn-tail, correction, event/byte-cap tests |
| B-03 | Content-addressed frozen artifacts with immutable metadata, parent closure, and corruption detection | 58-record fresh registry; `ArtifactRegistry` tests | Byte/metadata corruption, orphan, collision, parent-depth/count, namespace-race tests |
| B-04 | Typed state transitions require complete artifacts, allowed roles, authorizing evaluator classes, and idempotent request identity | State-machine tests; verified fresh transition sequence | Invalid skip/backward/self-approval, missing evidence, conflicting replay, terminal-exit tests |
| B-05 | E1 is advisory; same-process E2/E3 are never mislabeled independent; autonomous E4 construction is impossible | Evaluator/state tests; package says E4 required/absent | E4 construction/use rejection and producer/reviewer-separation tests |
| B-06 | Exploration remains separate from protected confirmation and reveal is at most once | Protocol, holdout, validity-budget tests; live custody validation | Fresh-receipt, identity mismatch, second reveal, crash-after-reveal, rollback, rerun-prohibition tests |
| B-07 | Protocol/study versions are immutable; post-reveal changes create explicit lineage and require fresh reserve | Protocol and governance tests | Mutation, skipped lineage, reused reserve, changed interpretation/retry tests |
| B-08 | Deterministic calibration distinguishes signal, null, leakage, reversal, invalid units/nulls, multiplicity, baseline mismatch, provenance, unsupported claims, holdout misuse, and prompt injection | 12/12 frozen calibration cases; statistical-core tests | Full calibration plus domain-unit, multiplicity, finite-number, and exchangeability regressions |
| B-09 | Material prose is writer-eligible only through content-resolved claim/evidence nodes and claim-bound verifier receipts | Claim tests and fresh 12-kind demo graph/write path | Missing/stale/corrupt/contradictory evidence and table/figure/prose mismatch tests |
| B-10 | Resource, elapsed-time, concurrency, disk/memory, worker-crash, GPU-slot, and validity budgets are monotonic and fail conservatively | Runtime/resource tests; fresh resource authority | Restart/rollback/refund/stall/crash/telemetry/limit failure injections |
| B-11 | Recovery validates an intact manifest, ledger, registry, custody, resources, and checkpoints; it never repeats confirmation or extends a known-stale fork | Fresh `SKIP_COMPLETED`; recovery test suite | Torn write, partial quarantine, stale checkpoint/ledger, missing manifest, confirmatory start/completion tests |
| B-12 | Reproduction binds immutable source/config/protocol/input/result identities and compares using a pre-frozen tolerance without mutating originals | Fresh replay exact at `1e-12` | Source/config drift, substituted mutable projection, non-finite/tolerance, partial/symlink output tests |
| B-13 | Packaging is bounded, deterministic, complete, content-bound, and capped at human review without E4 | Fresh ZIP/envelope plus post-package verify | Member/size bounds, custody/resource drift, secret/outside path, final-envelope binding tests |
| B-14 | Negative, contradictory, unstable, security, invalidity, budget, and external-block outcomes are typed and are not converted into positive claims | Captured null/reversal/unstable and terminal-handler tests | Honest-outcome integration regressions; no write/release after non-positive terminal |
| B-15 | Test/audit evidence describes descriptor-captured source/test bytes under isolated startup and is committed only after re-attestation | Fresh report captured 26 source and 11 test files | Isolated-launcher, namespace/module poisoning, bytecode, destination swap, evidence substitution tests |

## Verified pre-vNext gaps

The baseline has no working model provider, controlled scholarly egress gateway, external literature acquisition, passage-level reference verification, evidence-grounded Problem Investigator, external novelty determination, typed vNext canonical research-object graph, autonomous branch discovery, general real-workload orchestration, provider-neutral GPU cloud execution, four domain adapters, independently configurable human-gate profiles, typed Challenger/soundness gate, or evidence-first venue pipeline. Existing writing, replay, and R0–R7 results are bounded synthetic-kernel evidence, not those capabilities.

External validation is also absent for OpenAI credentials/model access, scholarly APIs/full text, physical MPS, CUDA/GPU cloud, proprietary or sensitive datasets, independent scientific review, genuine independent custody, and human E4.

## Baseline verdict

- Overall status: `PASS` after the two explicitly recorded bounded repairs.
- Historical `364/364`: independently reproduced exactly by count and result.
- Historical `15/15`: independently re-established after refreshing stale report-to-test bindings; targeted validator 4/4.
- Unresolved regression: none in the verified trusted-kernel guarantees.
- Safe to begin consequential vNext changes: **yes**, provided every later layer reruns relevant regression checks and the final audit is regenerated after all documentation changes.
