# Scientist-One vNext

Scientist-One vNext extends an existing research-control kernel into a provenance-first Research OS. This is an unfinished **DEVELOPMENT / REVIEW** checkpoint, not a final release. `AUTONOMOUS_EXPLORATION_READY` is a provisional ceiling supported by earlier bounded synthetic fixtures, not current whole-system acceptance. Known regression errors, timeouts and unverified paths remain. It is not research-grade, submission-ready, independently validated science, or evidence of superiority over upstream ScientistOne.

The [current checkpoint handoff](OVERNIGHT_REPORT.md#current-handoff--owner-d085-september-24-2026) distinguishes installed tests from private candidates and historical/reconstructed evidence. Private run state, credentials, reports and captured runtime/bootstrap evidence are intentionally excluded from GitHub; a fresh clone does not reproduce those private captures merely by containing the same source. Do not enable live credentials, protected data or external workloads from this checkpoint.

The integrated `research-os-fixture` is deliberately nonpublishable. A top-level `status: PASS` means only that the bounded system fixture completed with internally consistent registry, ledger, state, and gate evidence. Scientific soundness, external validation, paper readiness, and human release authority remain separate outcomes and fail closed.

Historical baseline results, the newly [reconstructed executable baseline](docs/BASELINE_TEST_RECONSTRUCTION.md), and vNext regressions are distinct evidence sets. Reconstruction does not recover the missing original test suite or establish public-release readiness. The OpenAI reference adapter has an [offline-tested prospective schema profile](docs/ARCHITECTURE.md#controlled-external-fixtures-and-blocked-live-validation); live service and confidential deployment remain unverified.

The milestone is unfinished. Material gaps include protected-data reserve and
independent-custodian integration, confidential deployment, non-fixture literature
application control, complete scientific execution isolation, and durable handling
of stalled or failed owned work. Passing component tests and the synthetic fixture
do not close these gaps. See [current verification scope](docs/VNEXT_FINAL_VERIFICATION.md)
for passing selections, original failures and unresolved safety/external gates.

## Current bounded follow-up

The owner-directed focus is one ML core: Generic ML/CV, ML+OR, ML+Management
Science & Engineering and offline-only quantitative-finance research. NeurIPS,
ICML, ICLR and CVPR are fit targets, not readiness or acceptance claims. The
first CVPR topic is still owner-supplied. Existing domain code/tests remain.
Autonomous execution is the intended default only within approved scientific,
data/tool and budget scope; optional human gates and human-only E4 remain.

Colab is the first concrete cloud-worker target, not yet a working integration.
The new offline preparation component binds existing frozen input hashes and
inspects returned manifest/artifact bytes;15 synthetic checks pass on both
Python runtimes after non-author review. It does not authenticate a commit/job,
invoke a worker, reserve CU or collect scientific evidence. The CLI was not found
on PATH and no live job ran. See the [bounded engineering path](docs/OVERNIGHT_RUNBOOK.md#colab-engineering-preparation--offline-only)
and handoff for account, spending, confidentiality and compatibility prerequisites.

The permutation-test numerical correction is integrated after independent
non-author review: exact represented-value comparisons replace the fixed
`1e-15` tolerance. The reported scaled example now returns `1/35`. Eighteen
focused numerical tests pass on Python 3.14.6 and 3.11.15. See
[comparison semantics and limits](docs/SCIENTIFIC_VALIDITY_MODEL.md#permutation-comparison-semantics-v2).
These results do not revalidate the whole system after the source change.

The unsupported installed `scientist-one` console declaration has been removed;
use the guarded source-checkout command below. Fresh-workspace research execution
is blocked at app-bound bootstrap admission; no private receipt is supplied by
this repository. The requested configurable workflow remains unfinished.
The single authorized gates67 diagnostic ended in a 7,200-second timeout with
no complete test-result payload; its cause remains unknown. No retry is queued.

The subsequent D080 source passed the original3,294-ID selection on Python3.11.15
and the separate18 operations IDs on both runtimes, with retained-source closure.
Those full-source records precede the two-file Colab extension and are not a
paired current full-suite result. Historical V9 measurements below stay separate.

## Verified V9 checkpoint — historical source

The following measurements apply to V9, not the numerical follow-up above.

September 23, 2026 checkpoint, incorporating the Python 3.14 terminal observation at 16:19:20 UTC: V9 is installed and frozen with 300 functional inputs.
The same 125 selected IDs pass on Python 3.14.6 and 3.11.15 at enclosing scope;
a disjoint 3,294-ID selection passes on Python 3.14.6 only. This is 3,419 distinct
selected current IDs on Python 3.14, with only 125 currently paired; remaining192
on Python 3.11 is NOT_STARTED. Nested/helper behavior remains NOT_ASSESSED by
the enclosing closures. These are not whole-suite, security, scientific or
release acceptance.

The Standard source scan is sealed PARTIAL, with 43 review products and three
LOW findings. Accepted corrections are installed and have scoped test evidence;
this is not full security PASS or clearance of omitted/stopped scopes.

The prior verified V8 checkpoint is `f6b3d92` on
`review/vnext-checkpoint`. Publication identities and observed Git status for
the accepted V9 delta are recorded in the checkpoint handoff. Qualified
recovered-baseline import/tag and final feature-history integration remain
pending; `main` stays at the owner's README-only bootstrap. V9 is a development
checkpoint, not a final release.

Exact portable evidence digests and remaining gates are in the
[checkpoint handoff](OVERNIGHT_REPORT.md#development--review-checkpoint-september-23-2026).
Private captures are not included in a fresh public clone. Known timeouts and
lint failures remain unresolved; scoped success does not complete unfinished
local features or synthesize E4.

## Authority and security boundary

- `ArtifactRegistry` and `EventLedger` remain the sole artifact and event authorities. vNext does not create a parallel provenance system.
- Canonical typed research objects are materialized through `ResearchStateRepository` into the registry and ledger. Structured state is authoritative; Markdown is a view.
- External content is untrusted data. Literature and model traffic must pass through the audited egress gateway and typed adapters; retrieved content never becomes control instructions.
- A successful **credentialless** built-in live HTTPS crossing can mint one run-bound `audited_transport_execution_authority`: the gateway consumes a one-shot prepared-request capability, signs the exact request/response/registry claim with a repository-local HMAC key, and anchors the authority in the co-rooted ledger. If a credential is configured and the transport reports real network use, the gateway instead reports `BLOCKED_EXTERNAL` and stops before gateway request registration, request-budget consumption, dispatch, response capture, or authority issuance. Resolved credentials are never passed to an unverified transport, including one that self-reports offline; fixture transport receives `None`. Raw, full-header, hexadecimal, and standard/URL-safe padded/unpadded Base64 matching protects ordinary custody sinks only as defense in depth. This is narrow machine authority for a captured credentialless crossing, not scientific validation, human approval, an external signature, or resistance to same-process/key/source compromise.
- Producers cannot authoritatively verify their own claims. Claim verification uses registry-resolved evidence and independently materialized, content-bound support receipts.
- Discovery promotion, scientific superiority promotion, and paper composition each have separate registry-resolved authority. Diagnostic values, serialized passes, and SHA-shaped strings cannot substitute for re-resolution and deterministic recomputation.
- Research termination uses an exact 11-outcome diagnostic vocabulary. Persisting an outcome as a frozen registry artifact and canonical `Decision` additionally requires its complete source owner; a diagnostic label alone grants no authority. The integrated, scoped-reviewed GPU-requirement owner is limited to one unperformed mandatory CUDA-device protocol. Termination does not drive or rewrite the legacy macro-state machine.
- Human and scientific gates are independent. E4 is human-only and the program cannot synthesize it.
- The default Local Mac fixture launches a real isolated-interpreter child process and can pass technical manifest/output validation, but that mode has no OS-enforced network, filesystem, or process sandbox. A separate limited opt-in Seatbelt path has bounded host-test evidence, not complete scientific read isolation/resource containment or attestation. Technical success therefore remains distinct from scientific eligibility, and fixture results and clean reruns are `NON_EVIDENTIARY` scientifically.
- Live literature, OpenAI service access, GPU execution, external novelty, independent scientific review, genuine independent custody, and E4 remain unavailable or untested. Credentialless scholarly routes remain structurally reachable, but credential-bearing live egress additionally requires a separately reviewed sensitive-response custody design.

See [Threat model](docs/THREAT_MODEL.md), [Scientific validity](docs/SCIENTIFIC_VALIDITY_MODEL.md), [Architecture](docs/ARCHITECTURE.md), and [Known limitations](docs/KNOWN_LIMITATIONS.md).

## What vNext implements

The integrated fixture follows this evidence-bearing path:

```text
controlled multi-round literature, citation expansion, and evidence ranking
-> evidence-grounded research question and registry-checked novelty
-> frozen hypothesis, baseline, evaluator, and Evaluation Contract
-> bounded reviewed-template autonomous implementation
-> registry-resolved discovery with positive, negative, and null retention
-> adaptive execution-plan custody, real Local Mac child execution, and clean system rerun
-> deterministic analysis and domain validity
-> registry-resolved claim graph and verifier receipts
-> non-authoritative superiority diagnostic for the fixture
-> 14-category Challenger and 15-dimension scientific-soundness authority
-> canonical research state
-> truthful terminal-outcome materialization
-> registry-derived paper discrepancy checks and venue gate
```

Implemented behavior includes:

- a provider-neutral model interface and an OpenAI Responses adapter with strict structured-output parsing, exercised through an unverified fixture transport that receives no resolved credential; fixture output is advisory and non-scientific. Live OpenAI execution is `BLOCKED_EXTERNAL` both when its required credential is unavailable and when a configured credential would otherwise cross a real-network transport, because sensitive-response custody is not implemented (`BLOCKED_LOCAL`);
- a policy-scoped literature gateway and scholarly adapters, exercised through synthetic seed-search, citation-expansion, relevance-filtering, full-text-review, and disconfirming-search rounds with bounded citation graph expansion and target-bound ranking. Native OpenAlex components and offline PMC wire/custody handling are present, but non-fixture application driving is unfinished and PMC production activation is closed. Supplied-payload normalization is not live acquisition; live validation remains unverified;
- a prospective scientific `Dataset`/`Split` lane that freezes the exact source snapshot, body digest, license and permitted use before access; requires the signed run-bound credentialless live-transport authority and an audited semantic license/use judgment; atomically publishes the raw-data manifest, use record, dataset authority, experiment projection, and one exhaustive disjoint four-role split set before result visibility; and rejects partial, colliding, late, or substituted publication;
- a Problem Investigator that can reject a question when gap-destroying evidence is present, plus registry-checked novelty that re-resolves the investigation state, normalized records/full text/passages, citation graph, expansion plan/execution, and evidence ranking before clearance; synthetic records still cannot establish real novelty;
- bounded implementation autonomy in which a provider may select only an independently reviewed closed worker template and bounded numeric parameters—not source, paths, commands, dependencies, shell, or network policy—and every proposal, admission, execution, and semantic result remains registered and non-evidentiary;
- an exploration engine whose promotable evidence is recomputed from exact frozen registry artifacts by a pinned reviewed evaluator, while diagnostic-only branch values cannot authorize promotion; promoted, negative, null, inconclusive, and falsified outcomes remain retained rather than rewritten around a positive branch;
- provider-independent `LOCAL_MAC` and `GPU_CLOUD` experiment contracts, frozen run specifications, declared outputs, resource estimates, clean-rerun comparison, and evidence-class separation. Backend adaptive plans are content-addressed and bound to submission, collection, and frozen-spec identities before downstream use;
- a scheduled GPU-cloud boundary covering plan-bound idempotent submission, queue state, retries/preemption, checkpoints, and bounded artifact return through an explicitly `UNTESTED` transport; the integrated fake GPU lifecycle and the scheduled boundary use no live credential, network, or hardware and create no scientific evidence;
- typed validity logic for the four required domain status families—Generic ML, Medical Imaging, Operations Research, and Systems. Time Series and Recommender Systems adapters are also present. The integrated fixture currently exercises Generic ML only;
- deterministic statistics, baseline/resource comparison, all-seed reporting, ablation checks, evaluator-integrity checks, and a claim graph covering every mandatory evidence kind. Value-only superiority checking is `DIAGNOSTIC_ONLY`; scientific promotion requires exact registered execution-eligibility, aggregate, statistical, and evaluator authority plus deterministic recomputation;
- a public Result-v2 materialization boundary that preflights one exact source-owned canonical graph, commits it append-only, can safely continue an exact inert prefix, and exposes `Result` or its later `StatisticalTest` extension only through the current typed bundle-completion artifact and ledger checkpoint;
- canonical scientific `ClaimSemantics` proposals with one outcome-independent coarse branch per run/graph/claim/dependency context. Writer-visible semantics require fresh source replay and audited semantic authority; a favorable duplicate, alternate qualifier wording, or substituted dependency collides or becomes ambiguous instead of becoming selectable authority;
- an acyclic citation authority order: inert `SOURCE_CITATION` evidence (`E`) owns exactly the Level-5 reference, citation graph, and signed credentialless transport; the completed graph (`G`) permits a canonical proposal (`P`); the claim-bound reference judgment (`Jref`) reviews that frozen projection; and the final ClaimSemantics receipt (`K`) freshly replays the whole chain. Model memory or metadata-only resolution cannot enter scientific prose;
- source-owned qualifier authority (`Jqual`) for `SCOPE_QUALIFIER` and `LIMITATION`, bound to the exact claim text, producer, confirmatory flag, evidence-use class, assertion, current `Result`/`Run`, latest Result-bundle completion, audited judgment, full custody closure, and ledger identities;
- source-owned v2 `Ablation` authority over a required frozen-contract intervention, deterministic component identity, checked raw `experiment_output.ablation_output`, aggregate/promotion closure, and current `Result`/`Run`/`Method`/`Experiment` revisions. Its eligibility can only inherit the exact Result; legacy `ablation_result` artifacts cannot enter this authority;
- a categorical reproduction boundary: the bundled and legacy synthetic clean reruns remain architecture/system controls and resolve `scientific_evidence_eligible=false`; they cannot satisfy scientific `ROBUSTNESS`, even when their deterministic comparison matches;
- complete soundness authority over 15 dimensions and Challenger review over 14 categories. A major unresolved external-validity challenge forces `MORE_EXPERIMENTS_REQUIRED`, a blocked paper, `NOT_READY` venue status, and `BLOCKED_SCIENTIFICALLY` final release;
- a registry-derived paper bundle that re-resolves claims, evidence, metrics, method-code bindings, soundness, and limitations. The fixture's non-authoritative superiority diagnostic is excluded from paper authority;
- an exact terminal vocabulary: `NOT_PUBLISHABLE`, `INSUFFICIENT_NOVELTY`, `INCONCLUSIVE`, `HYPOTHESIS_FALSIFIED`, `NEGATIVE_RESULT`, `NO_MEANINGFUL_GAIN`, `RESULT_NOT_ROBUST`, `REPRODUCIBILITY_FAILED`, `INSUFFICIENT_COMPUTE`, `FULL_VALIDATION_REQUIRES_GPU_CLOUD`, and `MORE_EXPERIMENTS_REQUIRED`. Diagnostic mappings and source-authorized persistence are distinct; the integrated GPU-requirement path grants only a protocol-scoped operational blocker, never scientific or spending authority;
- atomic run-ID reservation and an atomic `fixture-operation.json` receipt that moves from `IN_PROGRESS` to `COMPLETE` or `FAILED`. A completed run ID is immutable; failure requires a new run ID and grants no downstream authority.

## Supported source-checkout entry point

Use an already trusted CPython installation, version 3.11 or later. Focused
startup checks were run on 3.11.15 and 3.14.6. From a checkout named
`ScientistOne`, the portable entry sequence is:

```sh
python3 --version
python3 -I -S -B scripts/scientist_one_cli.py --help
python3 -I -S -B scripts/scientist_one_cli.py status
```

`--help` works without private development state. In a fresh checkout, `status`
currently exits **2** with an app-session bootstrap error before creating run
state. The controller requires a truthful app-bound workspace receipt, and this
checkpoint does not yet provide its fresh issuer. Do not copy historical
receipts, fabricate markers, remove guards or call the guarded module directly.
There is no supported installed `scientist-one` console command at this boundary.
See the [onboarding limitation and exit contract](docs/OVERNIGHT_RUNBOOK.md#fresh-checkout-onboarding-and-exit-contract).

## Guarded fixture command — admitted workspaces only

Only after legitimate workspace admission, run from that canonical project root
through the captured-source launcher. This is a fixed synthetic fixture, not
the requested configurable real-input workflow:

```sh
python3 -I -S -B scripts/scientist_one_cli.py research-os-fixture
```

An explicit identifier is optional:

```sh
python3 -I -S -B scripts/scientist_one_cli.py research-os-fixture --run-id vnext-local-fixture-1
```

The launcher rejects unisolated startup, captures and reattests project source around dispatch, and passes the command through the admitted orchestrator root. The fixture validates required inputs before reserving a run directory. Reusing an existing run ID fails closed. `--run-id` is a named argument, not a positional argument.

The child experiment itself is pinned to:

```text
/usr/bin/python3 -I -S -B scripts/vnext_fixture_experiment.py
```

It reads frozen hash-bound specifications, executes every declared seed and required ablation, and writes only declared outputs. A second clean run is compared for system reproducibility. Because the child lacks an OS-enforced sandbox, both the primary run and the matching rerun remain `NON_EVIDENTIARY` for scientific claims.

The legacy trusted-kernel commands remain available through the same launcher (`preflight`, `calibrate`, `start`, `demo`, `status`, `resume`, `verify`, `reproduce`, and `package`). `--help` is authoritative for that ordinary command surface. `test-suite` and `audit-project` are separate exact single-argument captured-evidence modes documented in `docs/OVERNIGHT_RUNBOOK.md`.

## Interpreting the fixture

The integrated fixture is synthetic and intentionally reaches different outcomes on different axes:

| Axis | Conservative outcome |
|---|---|
| System-fixture integrity | Designed to return `PASS` after registry, ledger, canonical-state, and semantic checks pass |
| Claim representation | Scope-limited synthetic claim may be verifier-eligible only for the frozen fixture |
| Discovery | Registry-evaluator-verified fixture promotion with contrary branches retained; final frozen hardening evidence `PENDING` |
| Superiority | `DIAGNOSTIC_ONLY`; no scientific promotion receipt exists for the fixture |
| Local Mac experiment | Technical manifest/output validation and clean rerun can pass; scientific evidence remains `NON_EVIDENTIARY` |
| Scientific Result/Stat lane | Exact source-owned canonical bundle and freshness boundary implemented; no current Local Mac result clears scientific backend authority |
| Scientific Dataset/Split lane | Atomic, prospective, source/license/use/split authority implemented; live acquisition remains `BLOCKED_EXTERNAL` |
| Scientific claim semantics | Canonical `E -> G -> P -> Jref -> K`, exact `Jqual`, and source-owned v2 Ablation boundaries implemented; no supported fixture claim becomes scientific prose |
| GPU cloud | Fake lifecycle plus scheduled-provider boundary only; externally `UNTESTED`, no scientific evidence |
| Literature and novelty | Executable synthetic multi-round/citation/ranking path with registry-checked fixture novelty; live path `BLOCKED_EXTERNAL` |
| Autonomous implementation | Reviewed closed-template component runs successfully but remains non-evidentiary |
| Challenger/soundness | Complete 14-category/15-dimension authority; unresolved external validity remains |
| Terminal outcome | Registry-backed `MORE_EXPERIMENTS_REQUIRED` for the integrated fixture |
| Model provider | Fixture-transport path only, with no resolved credential passed to the unverified transport; live OpenAI is `BLOCKED_EXTERNAL`, and credential-bearing response custody remains `BLOCKED_LOCAL` |
| Scientific soundness | `MORE_EXPERIMENTS_REQUIRED` |
| Paper and venue | `BLOCKED` / `NOT_READY` |
| Human release | E4 absent and never synthesized |
| Provisional capability ceiling, not current acceptance | `AUTONOMOUS_EXPLORATION_READY` |

## Historical pre-vNext baseline

The preserved August 29 record reports a pre-vNext freeze before consequential vNext changes. These are historical reported results, not independently reproduced current counts; some original test/report sources remain unrecovered:

- captured suite: 364/364 passed; report SHA-256 `73dee18929495015a1693ead7cf6849ae85cb96430b9887cfa7939c78ed28f36`;
- architecture controls: 15/15 retained, targeted validator 4/4; report SHA-256 `3d6c80c7f63514c9b711c9d2b98b7512b02550870cda567f18b3a82de112580e`;
- fresh bounded demo: `run-20260829T170951Z-28d371b6e3`, `READY_FOR_HUMAN_REVIEW` / `COMPLETE_DEMO_ONLY`, 21 events and 58 artifacts;
- historical handoff demo `run-20260812T204930Z-299b1dad55` was also reverified;
- final pre-documentation audit passed after quarantining a root `.DS_Store`; audit SHA-256 `d63e984d31541bdce65165193cd3015f282274ca3a91ee099bc09416b60773fa`.

The full baseline, including reproduction, custody, packaging, repair, and audit details, is recorded in [Baseline before vNext](docs/baseline_before_vnext.md). Later source and documentation changes invalidate those hashes as evidence of the final vNext snapshot.

## Final verification freeze

Current305-input technical fixtures are closed: vNext run
`vnext-final-current-20260924T042350Z-ac8bcf3968d00c17` has342 artifacts/67 events/
40 canonical objects; legacy run `run-20260924T044518Z-166217a8bd` has75 artifacts/
22 events and238 private package files. Exact hashes and independently scoped
selected tests are in the [current measured table](docs/VNEXT_FINAL_VERIFICATION.md#current-d083-checkpoint--september24-2026).
Four architecture-packet validators pass both runtimes, but architecture remains
5 scopedPASS/8PARTIAL/1BLOCKED/1PENDING. Whole-suite, scientific and final-audit
acceptance remain unresolved. No source-dependent lifecycle rerun is pending.

The qualified recovered31-input baseline and146 reconstructed methods are
published separately on `codex/recovered-baseline`, tagged
`v0.1.0-recovered-baseline` at4762578. This is not the missing historical364-test
suite or a current vNext release. Main stays at the owner's README bootstrap.

The final audit is intentionally self-producing and must be the last repository mutation. Its authoritative machine result will be `reports/final_audit.json`; this documentation does not attempt to backfill that report's digest after the audit.

Consult [STATUS.md](STATUS.md), [PLAN.md](PLAN.md), [CHECKLIST.md](CHECKLIST.md), and [OVERNIGHT_REPORT.md](OVERNIGHT_REPORT.md) for the current checkpoint and remaining work.
# Scientist-Ultra
