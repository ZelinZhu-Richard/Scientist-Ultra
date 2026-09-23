# Versioned PMC wire custody

Status: **installed and verified at a bounded offline scope**. Production
activation remains refused.
This does not establish live PMC access, native/TLS validation, confidential
deployment, scientific evidence or public-release readiness.

## One existing authority chain

The implementation extends `external.py`, the schedule consumer in
`pmc_coordination.py`, and `scholarly_gateway.py`. It reuses the existing request
capability rows, artifact registry, local signing owner and scientific event
ledger. It adds no second ledger, signing root, experiment state machine or
scientific authority.

| View | New profile |
| --- | --- |
| Adapter | `scholarly-pmc-oai-jats-v3` |
| Policy | `scholarly-pmc-oai-keyless-v3` |
| Request wire | `PMC_OAI_GETRECORD_GZIP_DEFLATE_V1` |
| Attempt | `controlled-egress-attempt/v3` |
| Response receipt | `controlled-egress-response/v4` |
| Transport authority | `audited-transport-authority/v3` |
| Native scholarly response | `scholarly-native-response/v5` |

The selected sender generates `Accept-Encoding: gzip, deflate`; callers cannot
select that header. Identity, gzip and zlib-deflate representations use the
existing bounded decoder. Old signed JSON, unsigned PMC and OpenAlex profiles
retain their meanings rather than being relabeled as the new profile.

Every attempt must retain its own prepared request, settled representation-byte
count, complete outcome, response controls, raw artifact metadata and schedule
observation. Issuance checks all and only the invocation's retained rows before
consuming them. A valid final response cannot substitute for missing or changed
earlier attempts. The final prepared request is a checked projection of that
same history.

## Replay and its limits

Replay checks the recorded pending → schedule observation → cleanup → terminal
ordering, original deadline, attempt offsets, same boot/coordinator identities,
increasing sequence, prior-cleanup spacing and actual registry record identities.
Sequence gaps are permitted; other invocations and the first global predecessor
are not reconstructed from this receipt. New-profile timing checks account for
the represented floating-point arithmetic without restarting the deadline or
changing old replay tolerances.

The actual bounded TZif bytes used by the schedule consumer are retained in the
existing registry. Replay recomputes the calendar decision from those bytes,
not today's host timezone. This verifies a supplied rules-based calculation,
not native rule origin, wall-clock truth, exact remote work or OS cleanup.
The existing native context acquisition/lifetime implementation is unchanged;
this work does not re-certify it or retry separately stopped investigations.

Native v5 distinguishes:

- `SIGNED_HTTP_CAPTURE`: verified transport authority and required custody.
  This can describe a policy-admitted non-2xx response, malformed XML, or a
  license-restricted result. It does not imply usable full text or scientific
  evidence. Non-2xx capture has no decoded-content claim.
- `UNVERIFIED_TERMINAL_DIAGNOSTIC`: no accepted authority, payload or AVAILABLE
  claim. Known partial facts may be retained, but a diagnostic cannot be promoted
  into a signed capture. AVAILABLE replay separately requires an available,
  successfully replayed signed result.

HTML errors remain subject to the XML media-type policy. Incomplete framing and
failed decoding do not become signed captures merely because bytes were read.

## Deadline and publication

The deadline endpoint is the successful observation after transport, applicable
bounded decoding, and rules-registration/readback admission, under the original
invocation deadline. Later receipt/signature/native-record publication is **not**
certified to finish inside that timeout. Bounded registry operations are not a
hard wall-time guarantee.

Publication failure cannot justify another request, refunded bytes, or fabricated
accepted content. Immutable raw/rules/receipt artifacts can remain unaccepted in
the registry. A returned failure diagnostic does not necessarily enumerate every
such write and must not be described as a complete reconstruction of the failure.

## Private evidence and redistribution

The entire generated evidence bundle stays private pending separate export and
rights review. There is no invented per-artifact privacy flag. A required rules
ancestor cannot be omitted while claiming a complete reproduction package.
Tests construct synthetic TZif bytes; no operating-system timezone file or
redistribution permission is bundled with this feature.

## Current verification

Root executed 350 scoped controls on each of Python 3.14.6 and 3.11.15:
24 composition controls, 14 direct supplied-data replay controls, and 312 legacy
operational controls. All passed without failures, errors, skips or load errors;
input inventories and executed legacy copies were unchanged. These are 350
controls across two runtimes, not 700 distinct tests or a full repository suite.

The legacy selection preserves 204 original test-method ASTs with one synthetic
interval fixture port. Eight explicit obsolete whole-snapshot assertions are
excluded, with separate new unchanged-owner projection evidence; no excluded
assertion is counted as passing. Earlier setup failures, the old gateway dispatch
refusal and the reproduced timing defect remain recorded alongside their repairs.
Root read the complete independent nonauthor corrected review and accepted the
bounded correctness closure; all four initial findings were closed at the exact
final source. Separate complete mechanical-port reviews verified the permanent
tests. This is not the unavailable platform review or native/live acceptance.

After preserving the prior functional sources, root installed the exact reviewed
26-file patch: three implementation owners, the finite captured-support allowlist,
one existing package test, and 21 new test/support files. All 256 nonselected
functional inputs were unchanged. The installed tree passed 342 selected captured
tests on each runtime: 307 PMC behavior controls and 35 Dataset/package regressions.
The separately selected 81 offline provider tests also passed against the changed
shared gateway. These two captured selections contain 423 distinct methods;
neither is a full repository suite or live provider validation.

An overlapping 312-method compatibility matrix passed against physical copies
of the installed sources on each runtime. It includes 196 predecessor behaviors,
74 root-edge controls and 42 existing public controls. Do not add 312 to 423:
many controls are shared. The private-to-portable migration retained test bodies
except three documented temporary-directory path adaptations; shared synthetic
fixtures now use real elapsed sleep and supplied observation intervals. Initial
port omissions of constants/decorators were caught before execution, preserved,
and corrected without changing production code or weakening assertions.

Positive integration fixtures use reconstructed test-only factories, disposable
files, local socketpairs, synthetic observations and fixture signing keys. They
exercise the real ordinary implementation bodies but do not demonstrate the
genuine native/TLS/provider path. All production activation gates remain closed.
Private evidence is indexed in `.run`; generated reports and keys are not release
contents. Full pre-FARS integration and the original Goal remain incomplete.
