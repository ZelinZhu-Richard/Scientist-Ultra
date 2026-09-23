DEVELOPMENT / REVIEW — NOT FINAL RELEASE OR SCIENTIFIC APPROVAL

# Scientist-One vNext Handoff

## Development / review checkpoint September 23, 2026

This section supersedes older running/pending statements below. The installed
V8 implementation is a coherent development snapshot, not a completed Goal.
No interrupted private patch is included. FARS assessment and its bounded A01
output-completion change are already integrated; they are not being restarted.

- Published branch: `review/vnext-checkpoint`, preserving the owner's README-only
  bootstrap `bba9ec5b652e78b5f4bfda6a101d640f0e07869e`. `main` stays unchanged.
- Implementation commit: `ca2bca940cd22ca785d50ccca5982af4b0512ee7`,
  `chore(checkpoint): import current vnext development state`. Remote refs and
  GitHub's complete tree response verified this SHA, all 343 files, 73 source
  files and 209 test/helper files on September 23. Upstream is
  `origin/review/vnext-checkpoint`; the working tree was clean after that push.
  This handoff is a subsequent documentation-only change; its commit is not a
  different implementation/test freeze. No recovered-baseline tag was created.
- Git state at recovery: one modified tracked README plus untracked implementation,
  tests and documentation; no staged files, no implementation commit or tag.
- Commit rationale: transparent import of the interdependent current source and
  tests, not fabricated historical feature chronology. The qualified recovered
  baseline import/tag remains separate and pending; do not tag this vNext tree
  `v0.1.0-recovered-baseline` or `v0.1.0-trusted-kernel`.

Implemented boundaries include canonical registry/ledger state; append-only
Evaluation Contract and protocol history; bounded OpenAI/offline literature
interfaces; experiment specifications and expected-output validation; resource
accounting; outcome-neutral reporting; domain checks; claim, Challenger, paper
and reproduction authorities. Their existence does not establish live scientific
deployment. Provider confidentiality, real protected data/custody, complete
scientific isolation and non-fixture application driving remain unfinished.

### Evidence applicable to the checkpoint

All 293 installed functional inputs still match the V8 installation inventory
(`8a3f19fe7ad41f39b534111623ddd435775f6b0cc5d190e128d8445a747383a9`).
Documentation changes do not change those source/test/configuration identities.
The following are distinct retained selections, **not an additive suite total**:

| Evidence class | Retained result and limit |
| --- | --- |
| Installed V8 | 468 selected IDs pass on Python 3.14.6 and 3.11.15, with the documented nested-capture limits; a separate 207-ID selection passes both with enclosing evidence. |
| Installed V8 | The 168-module, 2,602-ID selection has 2,601 successes and one terminal-stop fixture error on each runtime. It is not a whole-suite PASS. |
| Failed/incomplete verification | Isolation38 retains 37 successes/one inner timeout error; gates67 reaches its 7,200-second limit without complete outcomes. Causes and cleanup are not established. Original operations timeouts remain preserved. |
| Private candidates, not installed | Operations18 diagnostic passes both runtimes; ZIP admission19 passes both. The later combined125 on Python 3.14.6 has 113 successes/12 setup errors, including 68 successful CLI methods. Those candidate fixes and counts do not transfer to installed V8. |
| Historical reported baseline | Original 364/364 and 15/15 remain historical reports, not recovered original executable verification. |
| Reconstructed baseline | 146 explicitly reconstructed tests on recovered source are separate from vNext; partial/unverifiable historical guarantees remain. |

Repeated IDs on two Python runtimes are cross-runtime validation, not twice as
many distinct tests. Earlier failures and rejected/private attempts remain local.
The interrupted V4 setup-order candidate is unreviewed/uninstalled. A separate
source security scan remains incomplete, with a low-severity bounded ZIP
directory-preallocation finding still present in the installed source; its
private tested correction is not claimed as integrated. This checkpoint is not
a security certification. Full regression, lifecycle, recovery, reproduction,
packaging, architecture and final audit acceptance remain pending.

### Boundaries, excluded evidence and next work

Protected/real data, independent custodians, live OpenAI/scholarly/GPU validation
and confidential deployment remain blocked or externally untested. The exact
safety-stopped platform assessment, prompt-injection criterion, scholarly
event/capture-alias and native lifetime/execution-restriction investigations stay
stopped; another reviewer or Claude cannot substitute for them. E4 is absent.

GitHub excludes orchestration logs, private source-review/test captures, runtime
bootstrap and hardware state, caches, raw provider exchanges, custody/holdout
material, downloaded papers and generated archives. Public synthetic fixtures
are regression inputs, not protected data or scientific evidence. Public source
permits inspection and new appropriately bootstrapped local checks; it does not
supply the private evidence needed to independently reproduce every historical
capture. No private evidence is destroyed or replaced by this summary.

Next: obtain one bounded Claude diagnosis
if an existing permitted interface is available; finish the setup/recovery and
ZIP candidate integration with affected tests; resolve remaining internal
verification failures without repeated unchanged expensive runs; freeze source
once for mandatory final checks; complete qualified baseline/final Git work and
the evidence-backed report. External/safety blockers remain explicit throughout.

## Earlier checkpoints — historical, not current running state

Current September21 V8 checkpoint: the reviewed15-file union is installed with
293 pinned functional inputs. Six whole modules/207 tests have scoped enclosing
acceptance on both runtimes; the separate combined468 selection also passes both
with scoped nested-evidence verification. The separate168-module captures finish
with2,601 successes/1 error each, not2,602PASS; complete retained closure preserves
the terminal-stop test-token provenance error. Its private fixture correction
passes three original methods plus eight separately counted new controls on both
runtimes, with root evidence closure; it is not installed acceptance. CLI68 has
a separate fixture correction in private preparation. Isolation38
retains37PASS/1ERROR per runtime; the operations18 owned-namespace retry also
timed out at7200 seconds on both runtimes without individual outcomes. The
private gates67 diagnostic also timed out, retaining54 progress markers but no
test outcomes. Reviewed private isolation38 and operations18 diagnostics are now
running on Python3.14 under unchanged time limits and whole-module selection.
[Final verification](docs/VNEXT_FINAL_VERIFICATION.md) records the exact limits.
The owner authorized `v0.1.0-recovered-baseline`; no import, tag or push has
occurred. Public-readiness and all original scientific/external/safety gates
remain open. Older running-state descriptions below are historical.

Historical pre-integration checkpoint: 2,022 distinct selected tests pass on each of
Python 3.14.6 and 3.11.15 with source/loaded-test closure reconciliation. This is
not a full-suite result. Captured long tests and independently reviewed test-only
fixture/portability corrections remain unfinished; original failures are kept.
Historical baseline, reconstructed baseline and current vNext totals remain
separate. The provisional architecture packet and portable baseline candidate
are not tag or public-release approval. Original scientific reserve, literature
application, deployment/isolation, durable stall/crash handling and external/safety
limitations remain open. The exact reviewed21-file integration is now installed,
including admission/PILOT durability and prepared fixtures. The private120 methods
pass both runtimes with127 independently verified raw captures each; the earlier
119-case attempt remains116PASS/3FAIL per runtime. Private charge34 plus68 dependent
controls and observer8 retain separate scoped evidence. Installed affected checks
are running;2,022 remains pre-integration evidence rather than acceptance of the
changed source. Two new lint style findings await the next edit boundary. Additional
observation fixtures require a bounded captured-source migration before selection;
ordinary fixture calls are not blanket native/J safety stops. Actual OS-crash
collection and every exact recorded safety/external limitation remain separate.

September 20 current handoff: the current meta-spec is reloaded and semantically
reconciled without a restart or fabricated historical diff. The owner-authorized
[FARS v2 assessment](docs/FARS_DESIGN_REVIEW.md) is complete; A01 fixes a reproduced
operational expected-output omission through existing completion validators.
Corrected14 plus unchanged39 selected tests pass per Python runtime, with exact
source/loaded-closure checks and independent review. Initial errors are preserved;
there was no single green53 invocation or full-suite acceptance. Source/claim
provenance and deterministic manuscript planning already have existing owners;
additional advisory-note indexing is deferred, not original claim-support work.
Continue the original final verification and safe release prerequisites. Data,
custodian, confidential deployment, live and safety/platform limitations remain.
Earlier FARS-unread and sequencing statements below are historical checkpoints.

September 19 continuation: the authorized reconstructed suite passes 146/146 on the unchanged recovered kernel on Python 3.14.6 and 3.11.14, with separate synthetic lifecycle and corrupt-output refusal evidence. Independent scientific/provenance review closes this bounded scope, including null/reversal/unstable lifecycle preservation. These results do not recover the original 364-test suite. The later installed [PMC integration](docs/PMC_WIRE_CUSTODY.md) passes 342 captured PMC/Dataset/package methods plus 81 disjoint offline provider/schema methods on each of Python 3.14.6 and 3.11.15; a separate overlapping 312-check compatibility matrix is not additive. Three earlier neutral-core/wire-parity controls pass separately. Independent correctness reviews close these bounded patches, not the unavailable or safety-stopped platform assessment. PMC production activation and genuine native/TLS/live/signing deployment remain closed. Phase A, confidential live deployment, FARS, full verification and Git/public release remain unfinished; see [reconstruction evidence and limitations](docs/BASELINE_TEST_RECONSTRUCTION.md).

Latest scoped addition (2026-09-13, D073): the publication-only captured-page
recovery helper is installed and independently reviewed. Its combined affected
matrix passes 414/414 in 191.842s on Python 3.14.6, and 16 focused checks pass in
8.991s on Python 3.11.15, with all 255 installed Python files unchanged and no
bad outcomes. This is offline library evidence, not captured-CLI/live/scientific
completion. The next managed workflow has a private implementation candidate,
but it is not installed or acceptance-verified: its revised test infrastructure
passes 3 positive scoped controls and has 35 additional controls `UNRUN`. A
separate six-command offline CLI sequence passes with default resource limits
unchanged. Required immutable-patch security review is externally stopped; no
completed assessment or installation clearance is claimed, and related work is
not retried or rerouted. No test process or subagent writer remained active at that historical checkpoint.
This is not a completion handoff; overlapping
historical component counts are not added. Phase A remains incomplete, FARS is
unread, and Git/public-release gates remain unchanged.

Earlier component checkpoint (2026-09-13, D073): persisted amendments/history and operational BEST_OF_N are scoped-integrated; the installed second-charge matrix passes622/622, followed by unsigned PMC capture/decoder/replay integration235/235 on an unchanged249-file Python inventory. These overlapping results are not a full-suite total. Compile-only checks pass on CPython3.11.15 and3.14.6; runtime compatibility is not established by compilation. Private T2/J2 capacity8 passes, but broader integration remains incomplete and native lifetime work is safety-stopped without retry/reroute. The earlier execution repair is also stopped and uninstalled. The separate non-authorizing literature-context foundation is installed after correcting the independent3.11 failure:30/30 installed-only tests pass on3.11/3.14 with unchanged251-file inventory. Complete-captured OpenAlex HTTP response replay is installed, with the reviewed redirect mismatch fixed:287 affected tests on3.14.6 and22 portable tests on3.11.14 pass with all252 Python files unchanged. The registered SEED/OpenAlex goal/target/plan/result join is installed and scoped-verified: 360 affected tests pass on Python 3.14.6 and 22 focused tests on Python 3.11.14, with all 253 installed Python files unchanged. The bounded v2 pagination component passes 398/398 affected tests in 183.395s on Python 3.14.6 and 36/36 focused tests in 27.843s on Python 3.11.15, with all 254 installed Python files unchanged. No failures/errors/skips occurred. Non-fixture run/controller admission, prospective complete scope, resumable accounting and general-web insufficiency/acquisition remain incomplete. The user chose MIT; LICENSE is added locally without Git mutation or third-party/public clearance. Confidential provider custody, concrete isolated deployment, full scientific local isolation, live full text and original scientific/final-release work remain open. FARS remains unread pending the complete pre-existing stable boundary. The user published README-only bootstrap `bba9ec5` on canonical `main`; no agent commit/push or public-readiness acceptance occurred. Earlier broad descriptions below refer to bounded components and the synthetic fixture; use `STATUS.md` and `.run/STATE.json` for current scope.

Research OS vNext is integrated through a legitimate synthetic research representation. The build now spans executable multi-round literature/citation/ranking, registry-checked novelty, bounded reviewed-template autonomy, registry-resolved discovery, adaptive-plan custody, real local execution, deterministic analysis and superiority diagnostics, domain checks, claim verification, complete Challenger/soundness authority, truthful terminal outcomes, canonical state, and a registry-derived paper/venue gate. It deliberately stops short of scientific or release authority.

The source-owned scientific lane is also implemented without pretending that its unavailable prerequisites have run. It adds signed credentialless live-gateway execution authority, prospective `Dataset`/`Split` custody, Result-v2 plus an optional exact `StatisticalTest`, canonical ClaimSemantics, acyclic claim-bound citation review, exact qualifier authority, and source-owned v2 Ablation. Those boundaries fail closed when audited live acquisition, semantic review, backend isolation, confirmation, external review, or human authority is absent.

This handoff does not assign a final vNext run ID or freeze provisional counts. Exact final artifacts, events, canonical objects, hashes, test totals, audit identity, and reproduction identities remain **PENDING** until the final source/document snapshot is verified.

## Current integrated outcome

- **System path:** `research-os-fixture` is routed through the captured launcher and admitted orchestrator root. It validates inputs, atomically reserves a run identity, and publishes an atomic operational receipt with fail-closed `IN_PROGRESS`, `FAILED`, or immutable `COMPLETE` semantics.
- **Provenance:** every downstream scientific value is materialized in the existing `ArtifactRegistry` and `EventLedger`; canonical research objects are registered and ledgered through `ResearchStateRepository`. There is no parallel provenance authority.
- **Literature and novelty:** controlled synthetic PMC-shaped acquisition crosses the audited gateway and executes seed search, bounded citation expansion, relevance filtering, full-text review, and disconfirming search. The citation graph, expansion plan/execution, target-bound ranking, investigation state, normalized records/full text/passages, and novelty evidence are registered and re-resolved before fixture-local clearance. Live literature is `BLOCKED_EXTERNAL`; the fixture cannot establish real novelty.
- **Provider:** a strict structured-output OpenAI Responses path is exercised through an unverified fixture transport that receives no resolved credential, as advisory, non-scientific output. A missing required credential blocks live availability; a present credential with real network use is also `BLOCKED_EXTERNAL` until separately reviewed sensitive-response custody exists (`BLOCKED_LOCAL`).
- **Signed live gateway authority:** for credentialless requests, the exact built-in HTTPS transport can consume a one-shot prepared request, HMAC-authenticate the full request/response/metadata claim with a local `0600` trust root, and ledger-anchor one run-bound execution authority. Credential-bearing real-network execution stops before gateway request registration, request-budget consumption, dispatch, response capture, or authority issuance, and no resolved credential is passed to an unverified transport even if it self-reports offline. No live crossing occurred. This is not scientific validation or an external witness; same-process/key/source compromise remains `BLOCKED_LOCAL`.
- **Dataset and splits:** the public scientific path freezes source URL/body/license/use before access, requires signed credentialless transport plus a retained audited semantic license/use review, then preflights and append-only publishes the raw manifest, dataset authority, experiment projection, and an exhaustive disjoint four-role partition before any Run/Result visibility. Live data acquisition remains `BLOCKED_EXTERNAL`.
- **Autonomous implementation:** a provider may choose only an independently reviewed closed worker template and bounded numeric parameters. It cannot supply source, argv, paths, dependencies, shell, or network policy; exact proposal/admission/execution/semantic receipts are registry-bound, and the component remains non-evidentiary.
- **Discovery:** branch promotion is recomputed by a pinned reviewed evaluator from exact registry and ledger evidence; diagnostic-only values cannot authorize it. Positive, negative, and null branches are retained. Final frozen discovery-hardening evidence remains **PENDING** until handoff.
- **Local Mac:** the system runs `/usr/bin/python3 -I -S -B scripts/vnext_fixture_experiment.py` against frozen inputs, captures and binds the backend adaptive plan, checks every seed and required ablation, promotes declared outputs, and performs a second clean system rerun. Technical validation can pass, but scientific evidence remains `NON_EVIDENTIARY` because no OS-enforced network/filesystem/process sandbox exists and network status is unattested.
- **GPU cloud:** deterministic lifecycle and scheduled-provider boundaries cover plan-bound submission, queues, retry/preemption, checkpoints, and bounded artifact return. External validation is `UNTESTED`; no credential, network, live GPU job, or scientific evidence is claimed.
- **Domains:** Generic ML, Medical Imaging, Operations Research, and Systems have meaningful typed validity logic; Time Series and Recommender Systems are also implemented. Only Generic ML is exercised in the integrated fixture.
- **Claims:** the scope-limited synthetic claim resolves mandatory typed evidence through registry artifacts plus independent content-bound support and verification receipts. This authorizes a faithful research representation, not a real-world or confirmatory conclusion.
- **Result and statistics:** Result-v2 materialization validates the complete exact canonical ancestor graph before its first write, resumes only an identical inert prefix, and withholds authority until the typed bundle-completion artifact/event. A later `StatisticalTest` extension creates the only current completion; Result-only stale completion cannot remain authoritative. Current Local Mac output still cannot become scientific because backend isolation authority is absent.
- **Claim semantics and citations:** one outcome-independent proposal slot binds the canonical graph/claim/dependencies. Scientific citation support follows `E -> G -> P -> Jref -> K`: inert three-parent citation evidence, completed graph, proposal, claim-bound reference judgment, and final ClaimSemantics receipt. Scope and limitations additionally require exact `Jqual` over claim qualifiers, the current Result/Run, and latest Result-bundle completion. Parallel favorable branches and rewrites are rejected as collision or ambiguity.
- **Ablations and reproduction:** v2 Ablation authority is source-owned by the frozen contract, deterministic component, checked raw output, aggregate/promotion, and current Result/Run/Method/Experiment closure. It inherits—never creates—Result eligibility. Legacy ablation artifacts are barred. Every bundled synthetic reproduction remains categorically `scientific_evidence_eligible=false` and cannot satisfy scientific robustness.
- **Superiority:** caller-supplied value checks return only `DIAGNOSTIC_ONLY`. Checked scientific promotion requires registry-resolved execution eligibility and deterministic recomputation; the fixture cannot satisfy that boundary, mints no promotion receipt, and exposes only an explicitly non-authoritative diagnostic.
- **Gates:** the soundness assessment binds all 15 dimension receipts, all 14 Challenger category reviews, and every finding. A major unresolved external-validity challenge forces `MORE_EXPERIMENTS_REQUIRED`. Final release is `BLOCKED_SCIENTIFICALLY`; E4 is absent and never synthesized.
- **Terminal outcome:** the exact 11-outcome registry boundary derives and materializes `MORE_EXPERIMENTS_REQUIRED` as a frozen artifact and canonical decision without changing the legacy macro-state machine.
- **Paper:** the authoritative bundle is registry-derived and re-resolved. The fixture diagnostic is excluded and scientific baseline/statistics controls remain false; deterministic checks retain hard blockers for unsupported novelty, scientifically ineligible clean reproduction, and the unresolved challenge. Paper status is `BLOCKED`; venue classification is `NOT_READY`.
- **Capability:** `AUTONOMOUS_EXPLORATION_READY`, not `REAL_EXPERIMENT_PIPELINE_READY`, `RESEARCH_GRADE`, or `SUBMISSION_PIPELINE_READY`.

## Historical baseline preserved

The preserved August29 record reports the following pre-vNext measurements;
the missing complete original test/report evidence is not independently
reproduced by the later recovered-source reconstruction:

- captured suite: 364/364 passed; report SHA-256 `73dee18929495015a1693ead7cf6849ae85cb96430b9887cfa7939c78ed28f36`;
- architecture: 15/15 controls retained and targeted validator 4/4; report SHA-256 `3d6c80c7f63514c9b711c9d2b98b7512b02550870cda567f18b3a82de112580e`;
- fresh legacy demo: `run-20260829T170951Z-28d371b6e3`, `READY_FOR_HUMAN_REVIEW` / `COMPLETE_DEMO_ONLY`, 21 ledger events, 58 artifacts;
- legacy reproduction: exact 1.0 versus 1.0 at tolerance `1e-12`;
- pre-documentation audit: `PASS`, report SHA-256 `d63e984d31541bdce65165193cd3015f282274ca3a91ee099bc09416b60773fa`;
- no network, credentials, provider, external model, cloud compute, dependency acquisition, publication, submission, upload, independent review, or E4 was used.

The same historical record reports structural reverification of the earlier
handoff run `run-20260812T204930Z-299b1dad55`. Both run IDs and all hashes above
remain historical only. The original `docs/baseline_before_vnext.md` is unchanged.
The separate [reconstruction record](docs/BASELINE_TEST_RECONSTRUCTION.md) gives
146 semantic reconstruction results and11 scopedPASS/3PARTIAL/1BLOCKED
architecture dispositions; missing historical coverage remains explicit.

## Final verification still required

1. Freeze source/tests/configuration and record the functional-source inventory; retain mandatory review gates, exact safety stops and permissible targeted checks. A stopped platform investigation must not be retried or rerouted.
2. Full captured regression remains required. While unrestricted `test-suite` would select exact stopped probes, run permissible whole modules through the existing captured interface and report mixed stopped modules, fixture prerequisites, failures and timeouts separately. Do not suppress tests or present the selected total as a full-suite pass.
3. Refresh and independently validate architecture-control bindings against the captured report.
4. Run `/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py research-os-fixture` once on the frozen tree and reverify its registry, ledger, canonical state, operation receipt, literature/novelty chain, bounded autonomy, plan custody, discovery boundaries, terminal outcome, Local Mac rerun, negative/null history, 15/14 gates, and blocked paper outcome.
5. Rerun legacy demo/verify/reproduce/verify/package/verify and recovery checks. Treat the semantic reproduction's expected CLI exit `1` as valid only when its parsed status is exactly `ARCHITECTURE_CONTROL_REPLAY_PASS`.
6. Run the failure-injection/security matrix and dependency/network-boundary checks; finalize this documentation, the architecture report, and `.run`; verify the frozen source inventory again; then quarantine caches and run the architecture validator.
7. Generate `reports/final_audit.json` with `/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py audit-project` as the last repository mutation.
8. Parse/hash the final reports read-only and report their identities externally. Do not mutate this file after the audit to insert its digest.

## Pending final evidence

| Evidence | Value |
|---|---|
| Final vNext run ID | **PENDING** |
| Artifact count and registry closure | **PENDING** |
| Event count, ledger head, and digest | **PENDING** |
| Canonical-state count and snapshot digest | **PENDING** |
| Integrated summary SHA-256 | **PENDING** |
| Full-suite count/report SHA-256 | **PENDING** |
| Architecture-control/validator identities | **PENDING** |
| Final audit snapshot/report SHA-256 | **PENDING**; after the last mutation, read from `reports/final_audit.json` and report externally |
| Final legacy regression/reproduction/package identities | **PENDING** |

## Human and external decisions

- E4 remains human-only and absent; scientific publication, submission and research-data release remain blocked. Software-source synchronization with the canonical GitHub repository is separately owner-authorized, conditional on all public-readiness and Git-release gates.
- Live literature, provider, GPU, external novelty, and independent scientific validation remain untested or blocked. Credential-bearing response custody is an additional `BLOCKED_LOCAL` prerequisite for live OpenAI; credentialless scholarly routes remain structurally reachable.
- The Local Mac subprocess is real, but its lack of OS-enforced isolation prevents scientific evidence eligibility.
- No empirical comparison establishing superiority over upstream ScientistOne exists.
