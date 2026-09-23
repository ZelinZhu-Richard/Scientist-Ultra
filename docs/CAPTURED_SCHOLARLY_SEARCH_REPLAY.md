# Captured scholarly search response replay

This installed component replays one complete captured OpenAlex search HTTP
response. It preserves negative and malformed outcomes without declaring a
search complete or scientifically sufficient. Installed-only verification passed
287 affected tests on Python 3.14.6 and 22 focused tests on Python 3.11.14. All 252
installed Python files were unchanged during both runs. The private reviewed
source previously passed 288 tests, including one private-only AST check; these
overlapping results are not added together.

## Existing owners, distinct responsibilities

| Owner | Responsibility | Does not establish |
| --- | --- | --- |
| `SourceOwnedScholarlyGateway.fetch` | Execute the source-owned request through the existing gateway and register captured provenance | Scientific sufficiency or authenticity from a replaceable transport |
| `require_captured_scholarly_search_response` | Recompute one complete native-v2 OpenAlex search outcome from exact registered request, route, raw bytes, receipt, attempts and budget | Search exhaustion, fallback permission, or scientific authority |
| `require_available_scholarly_native_capture` | Keep the existing strict available-result replay contract, including its existing PMC paths | Permission to accept negative outcomes as available evidence |

Both replay entry points live in `src/scientist_one/scholarly_gateway.py` and
share the existing validator. There is no caller-selectable skip-validation
flag, second registry, ledger or scientific authority. The new entry point
requires an exact `ScholarlySearchRequest` for OpenAlex and native-v2 custody.
It returns `ReplayedScholarlyNativeCapture`; descriptive outcome consumers use
its `.envelope`, not the replay object as a gateway-response DTO.

The later [registered-query reader](REGISTERED_SCHOLARLY_SEARCH_REPLAY.md)
additionally joins a SEED query outcome to its immutable goal, target, plan and
result. It preserves these response boundaries and still grants no coverage,
fallback or scientific authority.

HTTP failures are rederived through the producer's existing status mapping.
Successful HTTP bodies are decoded with the same bounded strict JSON and native
OpenAlex projection rules. Stored status, failure code/reason, payload, license
and full-text status must agree with the recomputed outcome. Rehashed labels,
changed requests, raw splices, malformed metadata, parent changes and inconsistent
attempt or budget state are refused. Replay does not send another request or
publish new registry records.

## Redirect correction

The reviewed private precursor accepted a coherently rehashed completed 404
receipt labelled as a 3xx HTTP failure. The actual gateway rejects all 300–399
as redirect denials before completed-response publication, so that precursor
could accept an impossible completed outcome. This did not grant live,
signature or scientific authority.

The installed correction excludes terminal 300–399 only in the new profile.
Outcome for this bounded finding: **fixed**, after source/diff and Ruff checks,
actual before/after regression controls, legitimate-outcome compatibility,
one fresh candidate review and installed-only affected verification.
Earlier redirect attempts already fail the unchanged closed retry policy.
Actual redirect denials remain outside this complete-response reader. The old
available-only reader and all source producers, parsers and wire formats remain
unchanged. Unusual nonredirect statuses from replaceable test transports retain
their existing outcomes; those fixtures do not verify native HTTP framing.

## Evidence and limits

`tests/test_captured_search_replay.py` contains 22 portable tests for success,
zero-hit bounded pages, HTTP failures, malformed JSON/native projections,
request/metadata/custody/attempt/budget binding, redirects and status types.
An additional private preimage/AST check establishes preservation of the
preexisting non-replay definitions; no source preimage is needed in the public
test suite. Exact retained evidence is indexed in the private run ledger.

One independent candidate review tested all 100 redirect status values with
actual offline denials and coherent before/after relabelling, all 400 other
status values, earlier retries, invalid representations and transport-failure
then-complete-response cases. It found no surviving defect in that bounded
correction. It was not a full repository security scan.

Missing custody, pre-egress refusals, terminal transport failures, timeouts and
denial receipts are unsupported by this first complete-response reader. A
transport failure followed by a complete admitted response remains replayable
when the whole existing attempt chain verifies. Negative outcome preservation
is not a claim that all failed workflow lifecycles are implemented.

An available first page, even with zero hits or `next_cursor=None` in the current
projection, is not proof of source exhaustion. HTTP 404 means requested-object
failure, not zero search hits. No prospective multi-query inventory, complete
pagination assessment, source insufficiency, general-web acquisition or fallback
authorization is added here. Unavailable Semantic Scholar is not counted as
exhausted and the default source policy is not weakened. No live source,
credentialed provider, independent scientific authority or public release was
validated by these fixture checks.
