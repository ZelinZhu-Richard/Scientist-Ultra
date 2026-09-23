# Git-aware project audit

The project audit includes raw Git metadata in the same file inventory and
snapshot digest as the working tree. It does not exclude `.git` to accommodate
compressed objects. Git-specific coverage is an additional section of the
existing report, not scientific provenance or permission to publish.

## Supported parser profile

`COMPLETE_SHA1_GIT_INDEX_V2` supports a populated, complete SHA-1 repository,
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
index paths. It never removes secret findings or grants a general binary-file
exception. No Git-specific inventory exclusion is allowed.

Unsupported or incomplete input fails closed, including empty/unborn
repositories, non-UTF-8 decoded blobs (including archives), active locks or hooks,
alternates, worktree/gitfile indirection, replacement objects, shallow/promisor
layouts, unsupported index extensions and unknown metadata. The supported packed
profile requires `pack.writeReverseIndex=false`; reverse-index files are not
silently exempted. This restriction is not authorization to delete existing
metadata or rewrite an existing repository.

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
