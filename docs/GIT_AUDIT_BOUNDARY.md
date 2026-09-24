# Git-aware project audit

The project audit includes raw Git metadata in the same file inventory and
snapshot digest as the working tree. It does not exclude `.git` to accommodate
compressed objects. Git-specific coverage is an additional section of the
existing report, not scientific provenance or permission to publish.

## Supported parser profile

`COMPLETE_SHA1_GIT_INDEX_V2_AUDIT001_V1` supports a populated, complete SHA-1 repository,
index version 2 with only the TREE extension, loose objects, paired pack/index
files, ordinary branches, tags and tracking references. The native parser is a
checked supported system Git executable. Its identity, version and content
digest are recorded together with raw, decoded-object and index-inventory
digests.

The parser receives only bytes already reread through the audit's confined,
identity-bound descriptors. It builds a disposable private parser image. The
original Git configuration is checked against a closed grammar but never
installed in that image. Fixed local commands run with restricted configuration,
protocols, replacement-object behavior and prompts; hooks are not executed.

Raw secret-pattern checks remain active. Native object decoding also checks
unreachable objects, so removing a secret-bearing file from the current branch
does not hide its retained object. Only complete successful Git coverage permits
removal of the raw invalid-UTF-8 finding for the exact validated object, pack and
index and supported sidecar paths. It never removes raw secret findings or grants
a general binary-file exception. The exact reviewed rejection fixture can be
nonblocking only under the sealed classification policy below. No Git-specific
inventory exclusion is allowed.

Unsupported or incomplete input fails closed, including empty/unborn
repositories, non-UTF-8 decoded blobs (including archives), active locks or hooks,
alternates, worktree/gitfile indirection, replacement objects, shallow/promisor
layouts, unsupported index extensions and unknown metadata. The additional
closed SHA-1 formats are MIDX version1 with only PNAM/OIDF/OIDL/OOFF chunks,
RIDX version1 and MTME version1, plus the two exact app-managed loose-ref shapes
specified below. Captured-byte envelope checks supplement mandatory native
integrity verification; a header alone never qualifies. MTME consistency does
not establish timestamp truth or retention authority. No metadata deletion or
live repository rewrite is authorized.

## Bounds and freshness

The profile bounds raw files and decoded objects to 64 MiB each, aggregate raw
and decoded content to 2 GiB each, and inventory/object/index populations to
100,000. Native commands have 30-second deadlines within a 120-second session.
These are accepted-data and process-duration bounds, not an operating-system
RSS limit: native Git's header discovery may allocate or decompress internally.

After native validation, the audit repeats the full live inventory and checks
file and directory identities after the content reads. Publication binds the
exact report bytes and repeats freshness checks. The captured launcher may omit
only its newly created, verified exact copy of the report while staging it;
every other inventoried file remains checked. Final staged-file checks require
mode `0600`, matching held/named identity, unchanged metadata and exact bytes.
Failed cleanup does not authorize deletion of a pre-existing or substituted
file. A stale audit must not replace the previous report.

These checks detect bounded concurrent changes; they are not an atomic
transaction over the entire filesystem or protection against arbitrary changes
after an individual final check. Git operations, implementation, synchronization
and bookkeeping must finish before the final audit. Any subsequent relevant
mutation requires a fresh audit. A repository without Git retains the previous
report JSON format; adding Git requires a new Git-bearing audit before
publication.

## Public-release limits

Format integrity and lexical secret scanning are not the complete public-readiness
audit. Confidential prompts, outputs and derivatives, private literature/data,
local paths, generated and large artifacts, dependency licenses, redistribution
rights, effective ignores and README capability claims require the separate
[public-release review](PUBLIC_RELEASE_POLICY.md). Neither a clean parser fixture
nor an audit `passed` flag authorizes a push by itself.

Tests use real disposable repositories with explicitly synthetic authorship and
ordinary current timestamps. They are not reconstructed project history, a
trusted-kernel baseline, a remote synchronization or scientific execution.

## AUDIT-001 decision packet — proposed, not implemented

**Historical D084 proposal, reproduced below:** owner D085 subsequently
approved this specific design for implementation and exact cache preservation.
The approved whole-document SHA-256 is
`a9239befd71f89ec761a004f0298b43059f11c0d2ed9ddef680cbdeb5a189f02`; an exact
private copy is retained. The public reviewer label is normalized to omit its
orchestration-path prefix. Its design-only tense is historical, not the current
authorization. Current implementation follows G/S/P below, including strict
no-Git behavior and successful-Git/live-seal prerequisites. Focused verification,
actual-patch review, preservation and final audit have separate evidence and
must not be inferred from this approval.

September 24, 2026; owner D084. This section is the single consolidated design.
The preceding sections describe installed behavior. Approval of this design or
its review is **not audit clearance**. Production changes, cache transfer, Git
mutation and another audit have not been authorized or performed.

### Evidence and original-to-proposed dispositions

The immutable non-PASS `reports/final_audit.json` has SHA-256
`ebac97243f61b36115fa4ee1d0db93f9d9a6f2dd90dda29e628445c0e10cca58`:
5,196 files, 545 findings. Its source was published checkpoint `e299087` with
305-input functional freeze `8204cca1`. These new documentation edits make that
report historical; even a matching functional freeze does not establish an
unchanged Git/workspace snapshot. No cache or metadata has been adjudicated by
running a replacement audit.

| Original group | Count | Proposed disposition; remaining limitation |
| --- | ---: | --- |
| Git index / three packs / three pack indexes: encoding | 7 | Existing exact-path binary waivers only after complete successful Git coverage; currently unresolved |
| MIDX / three reverse indexes / one cruft-mtimes file: encoding | 5 | Narrow validated-format extension below; currently unvalidated, not harmless by filename/header |
| Python bytecode / Ruff cache: encoding | 424 / 89 | Preserve and relocate only the exact inventoried 513 files if approved; no binary exception or innocence finding |
| Tracked synthetic rejection-test rule match | 1 | Exact content/rule/location/blob-bound reviewed classification; retain raw finding |
| Private-cache pattern records on 11 files | 17 | Remain unresolved historical observations in preserved evidence, even after relocation; some fixture resemblance is not provenance authentication |
| Outside-root interpreter reference | 1 | Typed recorded-provenance classification only; retain original manifest and raw observation, no target access or execution authority |
| Unsupported Git metadata | 1 | First refusal is MIDX; extension requires all checks, not dismissal of this historical failure |

The counts are rule/file records, not independent defects. The first Git refusal
explains the seven eligible binaries lacking waivers, not the 513 cache files.
Two app-managed loose refs were inventoried historically and are now absent:
`refs/codex/turn-diffs/captures/<timestamp>/<uuid>/base` and
`refs/codex/turn-diffs/checkpoints/<hex32>/<hex32>/<timestamp>/<uuid>`.
Their exact original paths/hashes remain in the report. Cause/time of absence
are UNKNOWN. Do not recreate them or infer corruption, deletion, or clearance.
Only the source test is in the retained outgoing public-file inventories; local
Git objects may expose additional findings once decoding succeeds. Outgoing
branch review is not all-local/unreachable-object clearance.

### G — smallest Git compatibility extension

**Before:** `git_audit.py::_classify` refuses these five binary metadata files
before `_pin_tool` or decoding. **After, if approved:** add a new explicit profile
`COMPLETE_SHA1_GIT_INDEX_V2_AUDIT001_V1`; support only the observed SHA-1 formats
and two loose-ref shapes below. Existing object/index checks are not replaced.

Runtime evidence: the existing `_pin_tool` selects root-owned system
Git **2.50.1 (Apple Git-155)** here. PATH Git **2.55.0** is not that adapter.
No tool-trust expansion or upgrade is proposed. Official versioned sources
establish available mechanisms; actual Apple-build enforcement must be shown
by the focused synthetic acceptance tests, not assumed from upstream source.

| Mechanism evaluated first | Proposed use and exact limit |
| --- | --- |
| Existing `fsck --full --strict --no-dangling --no-progress` | Reuse inside the captured private parser image. Upstream 2.50.1 calls MIDX verification and on-disk reverse-index validation; it is not a public-readiness/secret adjudicator. Pin `core.multiPackIndex=true` and `pack.readReverseIndex=true` only in the fixed parser command configuration. No original config is installed. |
| Documented `multi-pack-index verify` | Native integrity owner for MIDX via the existing fsck path; no redundant extra verifier if tested fsck coverage suffices. Checksum, referenced packs, OID ordering and offsets are checked. A successful exit alone cannot admit unknown chunks or prove complete secret scanning. |
| Documented `verify-pack` | Verifies a pack/index pair, not complete sidecar or secret coverage. Existing full fsck already verifies the pairs; no additional per-pack command/campaign proposed. |
| Existing `cat-file --batch-all-objects` header/content passes | Retain both, including unreachable objects and the exact header/content/hash joins. Use fixed `core.multiPackIndex=false` for these passes so the added accelerator is not their enumeration authority. No reachability-only substitution. |

Sources: [2.50 MIDX manual](https://git-scm.com/docs/git-multi-pack-index/2.50.0),
[verify-pack manual](https://git-scm.com/docs/git-verify-pack/2.50.0),
[2.50.1 fsck, check_pack_rev_indexes and cmd_fsck](https://github.com/git/git/blob/v2.50.1/builtin/fsck.c#L815-L1070),
[MIDX verifier](https://github.com/git/git/blob/v2.50.1/midx.c#L835-L963),
[reverse-index verifier](https://github.com/git/git/blob/v2.50.1/pack-revindex.c#L301-L328).
These are technical source facts, not execution evidence for this repository.

Only small captured-byte **profile/coverage checks** supplement native parsing:

- **MIDX:** version1/hash1/base-count0, exactly PNAM/OIDF/OIDL/OOFF chunks (observed
  header `01 01 04 00`). Require bounded unique chunk IDs, ordered non-overlapping
  offsets, exact table lengths/terminator/EOF/checksum, valid zero padding,
  sorted unique pack-index basenames belonging to captured pairs, bounded pack
  and object counts, valid pack IDs and offsets. No LOFF, RIDX chunk, bitmap,
  chain, incremental, SHA-256 or future version accepted. Native verification
  remains mandatory. This is a closed envelope, not a replacement MIDX engine.
- **Reverse indexes:** RIDX version1/hash1 only, a captured matching pack/index
  pair, length `12 + 4*N + 40`, matching pack trailer and own checksum. Native
  fsck must verify every on-disk table against pack-offset order; do not accept
  in-memory fallback as validation. No custom reverse-index implementation.
- **Cruft mtimes:** MTME version1/hash1 only; same exact length/count/trailer
  rules, complete uint32 timestamp table in index order. Native mtimes loading
  only checks shape in the examined source, so a bounded byte/checksum validator
  is needed. It proves format/pair consistency, **not the truth of timestamps,
  file age, authorship or retention eligibility**. No expiry action follows.
- **App refs:** only the two full loose-ref shapes above: timestamp exactly13
  decimal digits, lowercase canonical UUID, lowercase hex32 components. Content
  must be exactly40 lowercase hex digits plus LF and identify an actually
  decoded commit. No symbolic fallback, additional suffix/namespace, app reflog
  or packed-app-ref extension. No app-attestation/approval authority inferred.

[Format reference](https://github.com/git/git/blob/v2.50.1/Documentation/gitformat-pack.adoc#L278-L414)
and [mtimes loader](https://github.com/git/git/blob/v2.50.1/pack-mtimes.c#L22-L91)
define the limited sidecar treatment. The five current header/hash observations
identify the proposed profile only; they do not validate the current files.

All raw bytes still receive existing scans. Existing per-file/object/count,
aggregate, command and session bounds stay unchanged (including the disclosed
absence of an OS RSS bound). Reject oversized counts before native work.
Every sidecar must join a captured pair and be accounted for; no silent skips.
Any unsupported/malformed/unverified input, drift, native failure or incomplete
decoding means failed Git coverage and **empty binary waivers**. No metadata is
removed from the live repository. No configuration, subprocess/cancellation,
cleanup, object-repair, index-rewrite or trust-boundary redesign is authorized.

### C — exact, evidence-preserving cache management

The exact proposed set is the original report's `files` rows joined by path to
its `invalid_text_encoding` findings for `.pyc` files under `__pycache__` and
`.ruff_cache/` entries: **513 unique files, 41,973,903 bytes**. Sort rows by path;
serialize the unchanged `{path,size,sha256}` rows as JSON with sorted keys,
ASCII escaping and compact separators, no trailing newline. SHA-256 must be
`0b982e1eaf5ebbe17f1316f76ac51faf512a7cf8f49c965ca49a5d6dbf33ef30`.
This defines an exact inventory, not permission to expand a directory glob.
All per-file hashes already exist in the immutable report; do not infer current
identity from that historical inventory. Changed/new/unlisted files are excluded
from the proposed transfer and remain subject to the future audit.

Recommended destination: an exclusively created owner-only sibling directory
`Scientist-Ultra-private-evidence/audit001-ebac9724` outside this repository
(exact local path in D084 ledger). It is outside current writable roots:
**owner path approval and platform filesystem permission are required before
transfer**. This is retained private evidence, never a public artifact. The
already-authorized temporary root can hold a copy-only staging directory named
`Scientist-Ultra-audit001-quarantine-ebac9724`, but temporary storage may be purged
and is not the proposed basis for removing originals. No automatic destination
fallback. Neither destination was created. Existing backups stay untouched.

After approval: establish a writer-free boundary; reject links, hardlinks,
changed identities/hashes, unknown files and destination conflicts. Confined
no-follow reads copy the exact513 files to exclusive0600 destinations beneath
0700 directories, alongside the original report and exact inventory. Before
removing **any** source file, successfully synchronize every destination payload,
report, inventory and preservation checkpoint, plus directory entries through
all newly created ancestry; reopen and verify every byte/hash. Reuse existing
confined/atomic-write helpers, adding only the missing one-shot ancestor-sync
barrier, not changing shared write semantics. Unsupported/failed synchronization
stops removal; reopen/hash alone is not durability. Then recheck each
source against its held/named identity and original hash immediately before
unlinking that exact regular file; no recursive deletion, directory deletion,
import, deserialization or cache execution. If a conflict/drift/read/write error
appears, stop, retain all copies and originals still present, and record per-file
COPY_VERIFIED / SOURCE_REMOVED / UNCHANGED / FAILED status in existing private
evidence. No automatic overwrite, refresh-to-new-content or repair. This is not
an atomic filesystem-wide transaction; unexpected concurrent activity stops it.
Restoration must likewise refuse to overwrite a regenerated or changed file.

The next workspace inventory intentionally lacks only successfully transferred
files; it is **not** a rerun on the historical snapshot. Preserve the17 pattern
records, raw hashes and qualified assessment (7 exact known-fixture matches;
13 fixture-prefix-plus-extra-byte occurrences across20 occurrences). No cache
content is declared synthetic, safe or authentic merely by location or absence.
Do not add an audit exclusion or broaden `.gitignore` to obtain clearance.

### S — one exact synthetic-fixture classification

**Before:** one `secret_assignment` finding in
`tests/test_external_providers.py`; decoded Git content will encounter the same
bytes after G succeeds. **Proposed after:** a reviewed synthetic classification
for only the following indivisible identity:

- file SHA-256 `d0e59a5f285498633b98c7c152e62b0ae1e0ed856b9d3f910af997e6ffdfceab`,
  139,137 bytes, source line584, byte span `[21865,21889)`;
- matched-byte SHA-256 `2c66730fbffaa076361f7c3d291251c8243143bbd4c2e462e0386a026cc295df`,
  rule `secret_assignment`, exactly one occurrence and no other secret rule;
- sole reviewed historical blob `bce2eed606bb7eed19f902167a60a9e9248fe5a1`,
  independently bound to that complete payload and path by the retained outgoing
  history review. No unseen historical blob inherits it.

Purpose: `test_idempotency_keys_cannot_expose_credentials_or_secret_patterns`
requires rejection before transport sends. This disposition does not change the
test, global regex, provider behavior or historical evidence. Working-tree
classification requires that exact path; decoded-object classification requires
blob type, exact OID, size and SHA-256. Same blob bytes can occur in multiple
trees without becoming a new credential; copied raw files at other paths do
not qualify. Any changed byte, extra match, rule, location or historical blob
remains blocking pending separate review. Private caches never inherit this rule.

### P — typed provenance, not an operational path exception

**Before:** `_outside_root_paths_in_payload` examines every JSON string as a
possible operational absolute path. **Proposed after:** only the root field
`/interpreter_path` in schema `scientist-one-functional-source-inventory/v1`
at `reports/final_functional_source_inventory.json` can be classified as
`RECORDED_INTERPRETER_PROVENANCE`, with explicit `target_access=NOT_PERMITTED`.
For this first bounded patch also pin the reviewed manifest SHA-256
`912835d3dc91f4e9cab26b46d7aeb7e55b5f2a049284632e68fdc5351b205abe`.
Future generated manifests do not inherit classification without review.

Require the exact closed top-level field set/types already recorded: schema,
generation time, interpreter path/version, selection rule, file/byte totals,
aggregate hash and entries. Entries are bounded `{path,size,sha256}` records
with unique relative confined path syntax, nonnegative integer size (not bool),
SHA-256 syntax and matching counts/totals. Reject duplicates/unknown keys and
malformed types. A schema label alone is insufficient. The provenance string
must be a bounded absolute path without control characters; classify it
lexically, **without resolve/stat/open/execute of its target**. This establishes
recorded metadata only, not interpreter authenticity or a current inventory.
All other strings/fields, other schemas, nested lookalikes and operational
external inputs/outputs retain existing confinement/refusal rules. Neither this
classification nor the original report proves that external contents were read.

### Minimal patch, compatibility and acceptance boundary

Proposed implementation files: `src/scientist_one/git_audit.py` (G and exact S
decoded-blob classification), `src/scientist_one/audit.py` (S/P and report
semantics), and `scripts/scientist_one_cli.py` (report counts only, if needed).
No `security.py` regex change. Reuse captured reads, private parser image,
source/input freshness, report binding and atomic publication. Cache transfer is
a one-shot reviewed operation using existing confinement/preservation helpers,
not a product cleaner, service or new ledger.

Deliberate audit-semantic change requiring approval: retain raw S/P findings in
`findings`, with exact, non-user-configurable `reviewed_dispositions` in the same
report; distinguish unresolved count from total. Use explicit report policy
`AUDIT001_REVIEWED_DISPOSITIONS_V1` whenever applied and a versioned Git profile.
Only those two exact identities may be nonblocking. Git coverage still requires
complete parsing; an adjudicated decoded fixture is retained in its coverage
section, never dropped from raw evidence. All disposition bytes participate in
the existing report seal and publication freshness checks; no arbitrary
caller-supplied whitelist, setter or report editing may confer a classification.
Effective S/P classification is restricted to **Git-bearing reports with complete
successful Git coverage and the existing live `_AuditBinding`**. During decoding
the exact fixture observation is pending; later failure/drift leaves it blocking.
No-Git reports retain their strict behavior and exact existing wire format:
their current early publication return is not a seal and cannot authorize these
classifications. No no-Git binding migration is included.
Old reports/receipts remain unchanged; reports without classifications retain
their existing meaning. `passed=true` would mean zero **unresolved** findings
under the named policy, not zero raw observations or permission to publish.
CLI exit0/1 remains tied to that declared audit result, never scientific/E4
authority. This is an explicit narrow semantic change, not a claim that existing
strict no-finding semantics are identical.

Focused acceptance (not run; future approved captured path only):

| Scope / tests | Observable acceptance |
| --- | --- |
| G: `test_git_audit.py`, `test_project_git_audit.py` | Synthetic MIDX/RIDX/MTME positives plus checksum, table, pairing, count, truncated/trailing/unknown-format corruption fail closed; checksum-valid wrong-table/wrong-offset fixtures must reach and fail native Apple-Git validation, not mocked rejection. Exact app-ref shapes/commit targets pass; malformed/unknown/symbolic refs refuse. Orphan sidecars, unreadable native coverage, timeout/drift give empty waivers. Keep unreachable loose/packed secret, decoded non-UTF8, index integrity, bounds and freshness regressions. Existing reverse-index/empty-MIDX refusal tests become explicit supported-valid versus malformed/unsupported cases, not blanket assertion deletion. |
| S: audit/Git project tests plus the unchanged provider rejection test | Exact raw file and historical blob retain finding+classification; modified/additional literal, another path/blob, other rule and cache remain blocking. Forged/mismatched disposition or mutated report cannot publish; no-Git remains strict and later Git failure/drift makes pending classifications blocking. |
| P: `test_audit.py` and captured audit-publication tests | Exact typed/pinned field is classified before any resolver; target-access spy must refuse any attempted access. Wrong schema/path/hash, unknown/duplicate keys, nested/lookalike/operational paths and malformed types cannot qualify. Original manifest bytes and strict no-Git behavior unchanged. |
| C: disposable non-code transfer fixtures | Verified, fully synchronized preservation precedes any removal; injected file or ancestor-sync failure before the barrier removes no source. Conflict, changed hash, links, interruption and partial transfer preserve evidence and refuse unsafe continuation. Only the513 pinned rows are eligible; temporary-only storage cannot authorize removal; no private cache execution. |

Minimum sequence **after separate approval**: bounded patch and transfer-script
review → affected captured checks on both existing runtimes, serially → coherent
source freeze → safe existing-branch disclosure/diff checks and permitted commit
→ preserve failed audit/report and caches, perform approved exact transfer →
finish all ledger/Git/publication mutations → **one** original guarded final
audit at the canonical root. Capture new source/Git/workspace identity and
retained terminal output. No unchanged broad regression campaign, automatic
retry or deadline increase. A new material failure returns to owner triage.
Select only already-permitted case IDs plus approved new focused cases: a
stopped test is not reopened by naming its module above. If a necessary case
cannot run within existing safeguards, record that acceptance dependency rather
than substituting another runtime/tool or declaring coverage complete.
Fresh audit output may reveal additional decoded content or other findings;
no prediction of PASS is made. The old report must be preserved byte-for-byte
before the normal report location is replaced by that separately approved run.

### Independent review and requested decision

Non-author `audit001_design_review` returned **ACCEPTABLE FOR OWNER
DECISION**, with no remaining material design disagreement after one correction
readback. Requested configuration: ASTRA HIGH; actual model/effort UNVERIFIED.
Initial reviewed section SHA-256:
`dc3d31601f1f8397c6ef05d7a06c3e23e1f5a2649cbbb6b12d23cfa9494a26d3`.
Original approved private packet's reviewed design body SHA-256 (original
packet heading through the line before its review heading; not the modified
public span containing the later D085 annotation):
`22fe7d9067a6fa59c90aae9204feb6b03123f5489633833db49f734494495f25`.

Two high-confidence P2 design findings were resolved: existing no-Git reports
lack the Git publication seal, so their behavior stays strict; copy/readback
alone lacks a durable-before-unlink barrier, so explicit data/directory sync
and a retained private destination are required. The reviewer examined the
complete packet, narrowly relevant source/tests and native Git source, then
verified the corrections read-only. No implementation, experiment or test was
performed. This is neither unavailable `assess-patch-risk` nor a stopped-review
substitute. Apple-Git enforcement, future patch correctness, transfer execution
and final audit acceptance remain UNVERIFIED.

**Specific next approval:** implement G/S/P in the named files with the listed
focused tests and retained raw findings; implement/review the one-shot C operation
and transfer only the pinned513 files to the proposed durable private destination
after owner/platform path permission and the preservation barrier; then follow
the finite regression/disclosure/checkpoint and one-final-audit sequence above.
This includes preserving the old report exactly before a newly authorized run
replaces its normal output location. No automatic retry, broader ignore, metadata
mutation, source refactor or widening of classification identities is included.
Until approved, all those actions remain unperformed. D082, Colab setup/spending,
gates67 and all existing safety stops remain unchanged.
