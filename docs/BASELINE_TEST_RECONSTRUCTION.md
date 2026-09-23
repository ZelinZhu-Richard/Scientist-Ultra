# Baseline test reconstruction

Status (2026-09-19): 146 reconstructed controls pass on Python 3.14.6 and 3.11.14, alongside a separate seven-command synthetic lifecycle and two corrupt-output refusal scenarios. Independent scientific/provenance review is closed for this bounded scope. This is not complete historical coverage, architecture/security acceptance, a baseline tag, public-readiness clearance, or historical test-source recovery beyond the one file identified below.

## Three distinct evidence sets

1. **HISTORICAL REPORTED BASELINE**: the August 29 record reports 364/364 tests, 26 captured project-source files, 11 captured test-source files, 15/15 architecture controls and a separate 4/4 architecture validator. These are historical results, not current execution. [The original record](baseline_before_vnext.md) is preserved unchanged (SHA-256 `93cfa6a2a8e977c144125927599b89b74183589ba9c5fc2e6f479ea2799010d7`). Its original contemporaneous wording remains historical evidence.
2. **CURRENT RECONSTRUCTED/RECOVERED EXECUTABLE BASELINE**: newly evaluated tests against the exact recovered 26-source/three-configuration kernel. Newly written tests are `SEMANTIC_RECONSTRUCTION`, never the original missing files. Execution results will be recorded separately below.
3. **VNEXT REGRESSION SUITE**: tests of the later implementation, including provider/literature/domain capabilities absent from the baseline. Its counts and source identities must not be combined with either baseline set.

## Recovery exhausted before reconstruction

The bounded search examined project-local frozen snapshots, release-package member lists, recorded reproduction/run manifests, registry and report inventories, prior goal evidence, project-specific temporary snapshots and the known outside preservation archive. No unrelated external source was used. Sensitive run/custody/holdout/provider payloads were not extracted to recover tests.

| Evidence | Observed identity and conclusion |
| --- | --- |
| Original deterministic release package | `e034f77620e210e254dfa511d9224c25cd8415ed36231739f7485159a914d753`; contains the original source/configuration snapshot but no historical `tests/` source members. |
| Original source inventory | `a4bc87d557696c761b0df05bf0ff3eb8dedd1a5f5d4d7fb0cf8413bff8aee786`; all 26 recovered files independently verified by path, size and SHA-256. |
| Original configuration inventory | `95fba6687d56bd503a4689bb0c4d0ef030499af5fffe3d509e8f7d14a219a52e`; all three recovered files independently verified. Source/configuration total: 1,142,799 bytes. |
| Historical 364-test report | Reported hash `73dee18929495015a1693ead7cf6849ae85cb96430b9887cfa7939c78ed28f36`; matching report bytes and complete 11-entry test inventory were not located. |
| Historical runtime test | Recorded identity `730b7961fc3d77eb7cd268f4af22cc84e93f05172b003572823a8380a3529ea1`; matching source bytes were not located. |
| Architecture validator | `test_architecture_evaluation.py`, `ea4bc870936ade19646bde65daa703dda3300ae92d1da8038c3129627cf574c2`; exact bytes verified in three preserved project-local copies. One unique recovered file, not three tests/suites. |
| Older ten-file test tree | Readable source exists, but its adjacent report records 278 tests with 16 errors. It is a distinct older variant, not the original 364-test suite. Its tests may inform semantic reconstruction only with explicit attribution. |
| Named outside preservation archive | Fresh hash `3b7e20ee8022c268a233bbcfdd01040f91af9a76bdd39c35cf61fae9605a45d2`; 196,946 members, including 129 later vNext test-source members, not the missing 11-file tree. |
| Second preservation snapshot | Recorded archive `1cd2e59f3c7cd2705967a37ce92e185e8f739a8297af891b28517eae9e3c991c`; its recorded temporary directory is now absent. Historical verification is not current backup availability. |

The original architecture validator is `RECOVERED_ORIGINAL` with `HASH_VERIFIED_RECOVERY`. Recovering it alone does not recover its original evidence packet or establish a fresh4/4 pass. September20 source inspection corrects an earlier overstatement: the validator accepts a separately dated, hash-bound reconstructed packet with honest partial/blocked statuses; original packet bytes are required only to recover the historical evaluation itself. Its frozen configuration and comparator must remain unchanged. A provisional packet can pass structural validation while explicitly reporting `NOT_ALL_MANDATORY_CHECKS_PASS`; that is not15/15 architecture acceptance or baseline-tag clearance. Keep original validator bytes and historical evidence separate from contemporary reconstruction.

The remaining historical test bytes, exact 11-file inventory, and reproducibility of the reported 364-test run are `HISTORICALLY_UNVERIFIABLE` from the available evidence. This is a source-recovery limitation, not proof that those historical results were false.

On September20 the unchanged original validator passed **4/4** on Python3.14.6
against a newly authored, private provisional reconstruction packet. This is
packet consistency only:14 criteria are `PARTIAL`, one is `BLOCKED`, none is
`PASS`, and every retention decision remains `PENDING`. The packet directly
maps the already executed146-test reports, synthetic lifecycle and output-refusal
evidence; none was rerun merely to assemble it. Its report hash is
`dffb5b34a5b6a7c00cf664998e4404219cbb00a5d9b57ff4f1e6c1b0a8baa1b3`;
validator execution result is
`fa521f1cf1df9ab5ee83f92984252581511de3f5d15b4c21e97141b9d941d216`.
The legacy provisional schema wording does not mean that the retained synthetic
demo is missing. This4/4 is separate from the historical4/4 and reconstructed146;
it does not establish15/15 controls, comprehensive security or tag eligibility.

Private recovery inventories retain exact local locations and per-file identities. Root corrected a preliminary advisory's nonexistent registry-object location before accepting the recovery conclusion, then independently rehashed all three actual architecture-validator copies. Corrected recovery inventory: `ab74fcc277713fbf69f9cea137acc4bf4af2cf4c655321280a7be21eb3f7a493`. Verified source-recovery report: `bad6ea56ad7918003cbb6a119fc0f608da3ea3f21403022e3fbf2d87dc16a2e9`.

## Reconstruction method and family coverage

Reconstruction uses documented B-01–B-15 guarantees and the recovered kernel APIs. The older variant is a semantic reference, never hash-verified original-suite evidence. Tests use synthetic inputs and temporary state. Source/configuration bytes remain unchanged. The original captured-source launcher, under actual isolated startup, is the intended executable boundary; no synthetic launcher markers or mutable import overlays may impersonate it.

| Family | Sources used | Classification | Current acceptance evidence |
| --- | --- | --- | --- |
| State legality, role separation, E4 prohibition, idempotency | B-04/B-05; recovered `models.py`, `roles.py`, `evaluators.py`, `state_machine.py`; older governance/state tests | `SEMANTIC_RECONSTRUCTION` | 12 state controls within the 28-method state/ledger module pass. |
| Ledger chaining and immutable recursive provenance | B-02/B-03; recovered `ledger.py`, `artifacts.py`; older state/scientific tests | `SEMANTIC_RECONSTRUCTION` | Nine ledger and seven artifact controls pass. |
| Frozen protocol, study lineage and confirmatory reserve | B-06/B-07; recovered `protocol.py`, `holdout.py`; older scientific-core tests | `SEMANTIC_RECONSTRUCTION` | Ten protocol and ten simulated-custody controls pass; not independent custody. |
| Independent units, pseudoreplication, domain nulls and multiplicity | B-08; recovered `statistics.py`; older scientific-core tests | `SEMANTIC_RECONSTRUCTION` | 15 statistics controls pass; no empirical scientific claim. |
| Claim support and evidence-bound writing | B-09/B-14; recovered `claims.py`, `writing.py` and documented negative-result rules | `SEMANTIC_RECONSTRUCTION` | 18 controls pass with real temporary registries and synthetic judgments. |
| Resources, recovery, reproduction and packaging | B-10–B-13; corresponding recovered kernel owners and historical documented demonstrations | `SEMANTIC_RECONSTRUCTION` | 22 resource and 20 recovery controls pass; separate seven-command synthetic lifecycle and two corrupt-output refusal scenarios pass. This is bounded family coverage, not every historical control. |
| Calibration failure cases and bounded input/security controls | B-01/B-08; recovered calibration/security owners | `SEMANTIC_RECONSTRUCTION` | Eight calibration and 12 inert input-boundary controls pass; not comprehensive security validation. |
| Isolated capture and final evidence publication | B-15; recovered captured-source launcher | Intended execution boundary | Startup checks from prior recovery are historical; complete adversarial coverage is not yet reconstructed. |
| Architecture packet validation | Original hash-verified validator and frozen configuration | `RECOVERED_ORIGINAL` / `HASH_VERIFIED_RECOVERY` | Source recovered; original evidence dependencies unresolved. |

New checks extending beyond a documented historical guarantee must be labeled `NEW_REGRESSION_TEST`. No target count is imposed to imitate 364. Acceptance requires meaningful failure controls, exact tested file identities, genuine failure reporting and root integration—not a chosen numerical total.

## Execution results and remaining limitations

The first tranche passed **89/89** on Python 3.14.6 using the unchanged recovered `scripts/scientist_one_cli.py test-suite` with actual `-I -S -B` startup in the private snapshot root. Zero failures, errors, skips, expected failures and unexpected successes; 2.988 seconds unittest / 3.105726 seconds complete report. The launcher captured and reattested 26 source files and four newly authored test files. All 29 original source/configuration files were independently reverified afterward with identical results. This count is not additive to historical364 or vNext totals.

| New test file | Methods | SHA-256 |
| --- | ---: | --- |
| `test_reconstructed_state_ledger.py` | 28 | `ff5c4ca95c8ebdabc3a1e7fddfe682d886068c8f028ac10007dcd3358eeb6cb7` |
| `test_reconstructed_protocol_statistics.py` | 35 | `a3b4f0b997cff6b19f918641f556c0e1d84ae7ab603d40af83c5e50f4e8a6cc8` |
| `test_reconstructed_claim_writing.py` | 18 | `6feb7a6fe9a00fc5a7720d0ee900107590ff5a58f83b1c2d41272557da45bd40` |
| `test_reconstructed_calibration.py` | 8 | `8df9e835d08b80d8bd7a1332cf24aa1970785130fa40e39a710ae00b89c53884` |

Machine report: `fe36ff9b7f89f5877a5193cc94ad9ddad7aee77a2de98813aafe0a7f63f1016f`; complete output log: `6da2fc302cb323bf32cab452b83c0b8817508cf63f59415de18f25e95dba8e07`. Two inert original fixture files were recovered by matching constants embedded in the frozen calibration owner: `calibration_cases.json` (`c5697cc4207bfc3c2c93287274fe0c87cfed43f74ed5f4dffe60d8c7730ef543`) and `synthetic_workflow_tasks.json` (`3bef85d9e02ca5a532ecedb0bbabd7b537aeb60509f318d485d170e4e927153d`). New test code checks the original frozen 12-case calibration digest and six-scenario workflow digest; those synthetic cases are nested checks, not an additional suite count.

The expanded run passes **123/123** on Python 3.14.6 (2.856 seconds unittest / 2.982486 seconds report), all bad outcomes zero, with 26 source/six test attestations. Original source/configuration hashes remain exact. It contains the prior 89, not 89 additional passes. Added files are `test_reconstructed_input_boundaries.py` (12 methods, `14c7148411db5f59a3424f58360ef16c1ae058f2fed1dcb69b5c9b895fd0873d`) and `test_reconstructed_resources.py` (22 methods, `b1e1916c4006d27e9c51925ba8e4edc42c91c982d9532f0ad1a19d539d9efcb5`). Report: `feadfb29ff5a905da02e7754795fe116c870fe9b1d33a815569a53710fc5ed20`; output: `4d2f02e2562c67daf6cbcc0e87c11c9b705595e5744f5fc38e60ef2cbde092c5`. Its first attempt had 122 passes/one fixture error: a macOS `/var` alias failed the frozen canonical-root contract. The fixture was canonicalized; the production validator was not changed. That failed report is retained as `5bacdf6ce5e57eab1033ccbe2d227bb1c1a412de78ee3492ea97dce2ee983023`.

The author missed copying the pre-correction resource test before its one-line change. Root subsequently reversed exactly that recorded fixture line into a separate file and verified the captured original SHA-256 `750248ca7abb8567b6a44c7ca5ec4aeac5c61f2726d81e9a2c1b58bc4f211900`. This is hash-verified recovery of a newly authored September 19 test preimage, not contemporaneous preservation or recovery of the historical suite.

The next expanded run passes **143/143** on Python 3.14.6 (2.964 seconds unittest / 3.097356 seconds report), all bad outcomes zero, with 26 source/seven test attestations and exact source/configuration recheck. The added `test_reconstructed_recovery.py` has 20 methods and SHA-256 `dcc49a8c2402509b9da292afb22a1c490eb1ae5a40676b04ff343294cd144e74`. It exercises actual temporary ledger/registry recovery, malformed chains, partial-tail quarantine, checkpoint selection/rollback, and started/completed confirmation refusal without injected validators. Its events are synthetic valid ledger records, not whole state-machine gate passage; replay counts describe plans, not experiment execution. Report: `fd8d1f7dc2743d0040699ee499172361d973889f73eb35b8d2354d5bcf1edaae`; log: `5a3ac14d87dba06fdc1a4b93a5e08147397a19ac4c24153e735d1262d6b4e8ca`. This 143 includes the prior 123 and 89.

The same 143 methods also pass on Python 3.11.14 (2.814 seconds unittest / 2.929952 seconds report), all bad outcomes zero, with equal source/test attestations and exact recovered source/configuration recheck. Retained report: `94a8279d97cf607f6b0d291cfadf604ac6bf2bc508d389fe5b17c85ec3e96046`; log: `01e2b30540a6e04ed7c63505c14e575c494570f9d6b54f424337be07ba429d14`. This is runtime portability evidence, not 286 distinct controls.

The separately reconstructed CLI lifecycle uses 31 exact recovered source/configuration/fixture inputs in a new private project root and an explicitly `NEW_TEST_FIXTURE` bootstrap, never an original app receipt or human authority. Actual isolated `demo`, `verify`, `resume`, `reproduce`, `package`, `verify`, and `status` commands exit zero. Root independently checks outputs, retained file hashes and unchanged inputs: verification `e6cfed8e7f129d0369b8421fae57a621cf30916876515eed1b35b238245618a4`. The run remains `COMPLETE_DEMO_ONLY` / `READY_FOR_HUMAN_REVIEW`, with 21 events and 58 artifacts; recovery skips completed confirmation with zero replay, reproduction difference is zero, and repeated packaging returns the same 155-member archive. Custody is simulated, external network is unused, and E4 remains required. The first setup attempt correctly failed calibration because the new bootstrap fixture supplied a dictionary instead of the required nonempty PASS-check list; its failed report `47071022879671ecb2051e6453848989a1b8fb88b9fb1cd4f0a369d519201f94` remains preserved. Only the fixture changed.

Two further isolated synthetic roots independently run successful `demo` and `verify` before damaging only their newly created reproduction result or ZIP. Repeating `reproduce` exits 2 with `ReproductionError: frozen reproduction packet digest mismatch`; repeating `package` exits 2 with `PackagingError: final package or envelope digest mismatch`. The damaged bytes are not silently replaced; ledgers, manifests and frozen output populations remain unchanged after the injected damage, as do all 31 source/configuration/fixture inputs. Reproduction scenario report: `d84f530e891ae2f3e2e49f3a470db2c25c439ed122fe352ec7635318f2a2b453`; packaging scenario: `6ab0fb713839d172b3df540d26fd361a1a5493897c57df243da35d92935a7e63`; runner: `fafb084fc9f7c4e9bbddb84da0583841f6ddc570d9f3f9756445426b93ba75d1`. These are two separate lifecycle scenarios, not two extra unittest methods or comprehensive B-12/B-13 coverage. Only generated private test fixtures are damaged, never original project evidence.

Claim graph controls use real temporary registries and the production resolver but synthetic same-process logical judgments. One typed negative-state unit uses an explicit test verifier; it does not establish a whole negative-outcome workflow. Resource probes are injected deterministic test observations, not physical GPU/host validation. Complete recovery/reproduction/packaging failure coverage, complete input/security/capture adversarial coverage and the original architecture packet remain unresolved. Future results must retain exact runtime/input identities and unsuccessful attempts, not merely replace this checkpoint with a total.

Independent nonauthor Astra/MAX review `4a7ac053eb39193c04cbb40a900aa582946ccf4390e7c0cbf540ddeb99bdc4bf` read all seven initial test sources and bound reports. It accepted the two output-refusal scenarios at their narrow boundary and identified B-14's missing full null/reversal/unstable lifecycle coverage. The original review is retained. Closure `2de7f5cc8068d7bfbe8b95e7a0c297a0acad6c4d456e1cd8ef6a59b2f94e863d` examines the complete added test source, driver and both runtime reports and closes that finding for the three synthetic cases. This is scientific/provenance correctness review only, not a security scan or substitute for any stopped platform assessment.

The final expanded suite passes **146/146 on each runtime** through the unchanged isolated captured-source launcher. The new `test_reconstructed_nonpositive_lifecycle.py` has three `SEMANTIC_RECONSTRUCTION` methods, SHA-256 `17000fe52b49a9fde22bd7fe53ffcf4fcf945658c5d013777165dad32d6aa9bb`. Each fresh canonical test root contains the same 31 recovered inputs and eight new test files, all unchanged after execution; the original snapshot is unchanged. Driver: `439e2d57a4937c1ed25a96d2ba36dfd12261413b3b6ad08df25cae7f2684374b`.

| Runtime | Unittest / report seconds | Captured test report SHA-256 | Full run result SHA-256 |
| --- | --- | --- | --- |
| Python 3.14.6 | 10.157 / 10.333509 | `75d4ccfb019f51c5d18073749112ad2c9931784d70d78fa2c81d838c6f021487` | `c051816bf0afe538242d3b06c25aae1e5dee989d2b9ef3a330397eb300aedffc` |
| Python 3.11.14 | 9.622 / 9.757005 | `9826a368184a0bca3ba37e325734d2cacb173ac0e338b0c00df023edcae7b8cc` | `42f1a3596dad13c4c8fc35827896a90261979a12260a4a2718882178ea0f6798` |

All bad outcomes are zero, with identical 26-source/eight-test attestations across runtimes. Null results remain `NEGATIVE_RESULT`; reversal and unstable results remain `INCONCLUSIVE`, including the unstable case's positive point estimate. Each real temporary controller/ledger/registry run has 17 events and exactly one confirmation access/start/completion. Verification passes; resume skips completed confirmation without replay; packaging is refused without modifying authority bytes, sizes or timestamps. There is no claim/writing/audit/release transition, manuscript, reproduction packet, E4 or independent custody. These are API scenarios executed inside the genuine test launcher, not new CLI scenario flags. The 146 includes all earlier 143/123/89 controls; two runtimes do not create 292 distinct tests. Remaining limitations below still apply.

No live provider, physical accelerator, independent custody, proprietary dataset, human E4 or upstream-comparison result can be inferred from synthetic baseline tests. Previously stopped investigations are not retried through this reconstruction. Incomplete family coverage, missing architecture evidence and any such excluded checks remain explicit limitations.

The recovered-component draft is not a new complete outside-repository preservation snapshot. Fresh whole-project preservation and all [Git/public-release requirements](GIT_HISTORY_RECONSTRUCTION.md) still apply before history reconstruction, commit or push.

## September 20 additional checkpoint controls

Two separate `NEW_REGRESSION_TEST` cases now pass on Python 3.14.6 and 3.11.15 against the unchanged recovered kernel. They are additional current evidence, not recovered historical tests or a rerun/relabeling of the 146-method suite above. Each uses a fresh physical `NEW_TEST_FIXTURE`, all 31 previously verified source/configuration/calibration inputs, one captured test file, and the unchanged launcher.

- **Checkpoint continuation:** a preparation process stops at the completed CONFIRM checkpoint before any confirmatory start; after that process exits, a separate normal CLI process resumes to the synthetic `NEGATIVE_RESULT`. Existing ledger bytes, registry records, artifacts, checkpoints and completed transitions are preserved; pilot work is not repeated, and confirmation starts/completes exactly once. Separate `verify` passes. This is interruption at a completed checkpoint, not arbitrary mid-write crash recovery.
- **Configuration drift:** a pre-staged inert JSON marker changes after freeze. Normal advancement persists a typed `STOP_SECURITY` event/report/checkpoint before pilot or confirmatory work, retaining prior evidence. The exact marker is the only changed input; source, execution limits and authority records are not repaired or replaced. Overall live-inventory verification is not claimed to pass after intentional drift.

| New case | Python 3.14.6 run-result SHA-256 | Python 3.11.15 run-result SHA-256 |
| --- | --- | --- |
| Checkpoint continuation | `0cd0fe3e578f68801afaad858a63c74ff1bca187599a52a42ac70f0a89bc83c0` | `d602f33e8f1f630e6e3ae3c7140836082e0a8709faf4cef9d0e2940624cd113b` |
| Configuration drift | `d4403ca73bd351611d37ccdba4baa39abb98afce9d55ce4fb3a44dff10962cdd` | `f8c563bfaba3ea1e5860f8c7ecec6b319430cede676d0fd3675c599c198160b5` |

Root's retained-evidence verification is `8525d1df4431db03e8e25a0b672e94845d851b0b38e18cfbd0cc2978254ce994`, checking all four captured reports, eight command logs, exact copied inputs and preserved evidence. Test hashes are `d0c2a97605e3bf96d2924b2f584a6aac9cb6807662b50ae3b47f4af78571a248` and `3ff705b2dfb3e279710d231428f5bb464e6975b3f29d1a03616049844d4314db`; driver is `15f90386bf27667c0bc10c7e60a2617ef98bae1f4bb40436fcbbeff81acd4054`. Independent read-only review corrected incomplete fixture pinning, misleading final-status handling, and a nonexistent drift-report field before execution; original unrun tests are retained. Requested author/reviewer routing was LUNA HIGH / ASTRA HIGH; actual runtime configurations remain UNVERIFIED.

Durable integrated no-progress/worker-failure stopping and actual untouched-data accounting remain unproved; the drift subcase does not close the entire drift/stall criterion. These results do not clear the stopped security/platform review, real custody, scientific confirmation, E4, public release or baseline-tag requirements. The original historical baseline document remains unchanged.

Later source review identifies implementation limitations, not just absent test
coverage: the recovered admission path discards a typed stall/crash decision into
a message-only exception without its own durable refusal record, while successful
completion alone records progress after charged work. Integer validity budgets
and labeled roles do not establish actual untouched-data membership/access
accounting. Current vNext repairs must be separately reviewed and tested; they
cannot retroactively strengthen the immutable recovered baseline or its historical
claims. Post-charge failure collection remains distinct from admission refusal.

## September 20 portable candidate verification

A newly authored staging runner now assembles the same31 recovered inputs and
eight reconstructed test modules in fresh physical projects. It passed the same
146-method suite on Python3.14.6 and3.11.15 in12.971s and13.387s respectively.
This verifies new packaging support; it is not146 additional methods or recovery
of the missing original tests. The September19 results above remain unchanged.

Result hashes are `059203dd284e403aaf5c7a74fd124dce588f980e9ae94f52730732ca4d0b1aa1`
and `74d02c495ab732142aeac20dd3c8e1b5ac2eb4a9a69e828fa26ba9a997239389`.
The runner verifies exact146 unique IDs, actual runtime, source/test attestations,
input preservation and zero bad outcomes; root rehashed all39 candidate/staged
input pairs and output logs. Six separate runner-support controls pass on both
runtimes, including timeout retention and malformed-report rejection. These
support checks do not contribute to the146 kernel-suite count.

Independent complete-support review and root integration corrected path,
directory-portability, timeout, attestation and output-parser defects before
actual candidate execution. No recovered implementation or test bytes changed.
The separate provisional architecture packet passes its four original structural
checks with11 scopedPASS/3PARTIAL/1BLOCKED dispositions. Neither result establishes
historical15/15, standalone evidence portability, public readiness or tag approval.
