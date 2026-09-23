# Descriptive PMC context foundation

`src/scientist_one/pmc_coordination.py` is an installed, read-only prerequisite,
not a PMC coordinator or an acquisition permission. It adds no ledger, state
machine, provenance authority, provider, signing key or scientific source of truth.

## Implemented scope

The no-argument native context acquisition requires an existing fixed account
namespace on LOCAL_MAC. It captures private principal, directory identity,
local-filesystem/ownership flags, boot, clock and bounded system-TZif observations.
It does not create directories or change permissions. Unavailable native facts
produce a typed, static refusal. The context is non-serializable and has a
redacted representation; it is not a credential or a transferable authorization.

The separate pure schedule projection accepts bounded TZif2 bytes and an exact
signed-64-bit nanosecond instant. It explicitly reports
`UNVERIFIED_SUPPLIED_TZIF_BYTES`. Its calendar, offset, DST-fold and schedule-window
fields do not authenticate those bytes as the native New York rules or permit a
request to run. Other TZif versions remain unsupported.

## Focused lifetime repair: fixed in the tested scope

Before integration, actual temporary-fixture controls exposed two defects:
renaming the acquired namespace caused a filename-bearing exception with seven
descriptors retained; a successor thread could reuse the owner's numeric ID.
The first Thread-object correction still accepted a low-level native successor
on CPython3.11 because both threads received the same cached dummy Thread object.
The independent review retained that failure despite all26 earlier tests passing.

Owner checks now retain PID, effective UID, actual Thread object and a strong
per-thread-lifetime marker stored in native `_thread._local` attributes. The
Python fallback is not used. Acquisition refuses before opening paths when
native local storage is unavailable, while pure schedule projection remains
usable. Thread-local storage follows native thread-state lifetime in the examined
[CPython v3.11.15 implementation, lines594–627](https://raw.githubusercontent.com/python/cpython/v3.11.15/Modules/_threadmodule.c).

Foreign-owner refusal leaves the owner's descriptors intact. Owner-admitted
namespace validation failures close and expire the context, with static ordinary
errors and original cancellation propagation. A fork child may only close its
inherited descriptor copies; the parent context remains usable. No automatic
reclamation of abandoned live references is promised.

## Verification

Root installed-only runs of `tests/test_pmc_native_context.py` passed all30 tests
on CPython3.11.15 (0.162s) and3.14.6 (0.193s), with no failures, errors or skips.
The genuine low-level successor test observed recycled numeric IDs and different
native IDs; on3.11 it additionally observed the identical cached Thread object.
Entry and close were refused, retaining all seven owner descriptors. Legitimate
raw-thread reentry/idempotent close, ordinary threads, stat/fstat failure,
cancellation, body exceptions, fork behavior and pure projection also passed.
Syntax and Ruff checks passed. These are30 tests across two runtimes, not60
distinct tests or a full regression result.

All251 installed Python files remained unchanged during both runs. The original
249 files were byte-identical to the earlier235-test PMC integration snapshot.
The new module exactly matches the reviewed source; its installed test differs
only in the package import. Complete private evidence and the single independent
review/refinement chronology are retained in the run ledger.

## Remaining limitations

- Native trust facts are emulated in temporary fixtures; descriptor operations,
  threads and fork are real. Successful production namespace acquisition is not
  established by these tests.
- Effective ACL privacy, deployment/provisioning, source-global request
  coordination, persistent scheduling/recovery, live dispatch and signed capture
  are not implemented or validated by this foundation.
- CPython3.12/3.13, other interpreters and free-threaded builds were not executed.
  Imported runtime primitives are trusted; arbitrary interpreter/import tampering
  and interruption at every cleanup instruction are outside this proof.
- This work neither changes nor retries the separately safety-stopped native
  confirmation/J lifetime or local execution workstreams.
- Scientific capability, public-readiness and final Goal completion remain
  unchanged. The original pre-FARS work is still incomplete.
