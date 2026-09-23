# Bounded scholarly query pagination

Decision and scoped integration date: 2026-09-13. This original literature
component is installed and locally verified; it is not a FARS adaptation or a
complete non-fixture application workflow. The existing meta-spec remains
authoritative. The registered first-page reader remains integrated and unchanged.

## Failure being addressed

Historical search v1 captures one bounded first page and synthesizes a null
continuation field. It cannot establish actual pagination termination. Adding
progress fields to its dataclasses would change historical `asdict` identities;
subclassing would enter existing `isinstance` dispatch. Preserve those contracts.

Add independent frozen/slots `ScholarlySearchPlanV2`,
`ScholarlySearchPageRequest`, and `ScholarlySearchResultV2` in the existing
literature owner and search-artifact family. No second ledger, investigation
history, scientific state machine or Evaluation Contract authority is introduced.

## Selected boundaries

- Plan v2 freezes the existing goal/target/purpose/query/synonyms/filters,
  complete allowed-source permissions and exact parents, with `page_size` and
  `max_page_requests`. It contains no cursor or progress. Initially permit page
  size 1–100, at most 16 requests, and their product at most 512. These constrain
  an exact recorded chain, not all activity under the plan across possible forks.
- An exact page request binds both semantic and registered plan identities,
  source, ordinal, immutable query projection, exact cursor and immediate prior
  result identity. First cursor is `*`; later cursors come only from a replayed
  predecessor. Cursor strings are opaque: preserve exact UTF-8 or reject, never
  normalize/strip/decode them. Bound tokens to 1,024 UTF-8 bytes, reject ASCII
  control characters and empty tokens, and enforce the existing encoded URL cap.
- Store one immutable result-v2 checkpoint per captured page, not a second
  growing prefix artifact. Preserve actual status, failure, page-local hits,
  explicit returned cursor, reported count/page size and capture provenance.
  Missing successful metadata is not zero or terminal. Replay derives the
  ordered chain, counts, anomalies, pending continuation and inspected hashes.
- Use a distinct explicit OpenAlex cursor descriptor/policy and native-v4
  capture profile. Keep the default descriptor and native-v2/PMC-v3 behavior
  unchanged. Close dispatch by exact type/source/descriptor/schema; reject both
  cross-profile directions. The new source profile fixes explicit
  `sort=relevance_score:desc` and `corpus=core`; its registered descriptor is a
  plan parent. Provider-specific syntax stays outside the core plan authority.
- New request custody parents are exactly route, registered plan and immediate
  predecessor when present, validated before I/O. Result parents are plan,
  raw/normalized capture and predecessor. The old route-only request contract
  remains literal. Reuse existing registered goal and SEED target/question
  validators; leave DISCONFIRMING and scientific selection with their old owners.
- Register and replay each checkpoint before the next send, even in a one-shot
  loop. Publication failure stops further sends and preserves captured custody.
  Apply existing registry limits and bounded iterative prefix/provenance work;
  do not raise registry limits to accommodate this feature.
- Before checkpoint publication, measure the exact registry UTF-8 canonical JSON
  including its trailing newline. Refuse values over the inherited 4 MiB reader
  cap; equal-size values remain permitted. Retain raw/normalized capture and prior
  checkpoints on refusal. This is a derived-checkpoint bound, not a raw-response
  size rule, parser failure, or global resource charge.

## Derived outcomes

Only a successful empty page with explicit null cursor on an otherwise valid
prefix establishes a provider-terminal observation. Nonterminal at the request
ceiling is truncation. Empty/non-null can continue. Preserve and stop on repeated
cursors, cross-page canonical source/identifier overlap, reported-count drift,
or nonempty/null termination anomalies. Do not silently deduplicate observations
or use title/rank-dependent `hit_id` as the cross-page identity.

Within-page malformed data remains captured parser failure. HTTP failures retain
their statuses; missing custody, pre-egress refusal and terminal transport
failures remain outside complete-response replay and never authorize advance.
Count each final empty page and captured failure against the selected chain's
page ceiling. Sum actual transport attempt/byte observations separately, retaining
multiplicity when identical bodies share a content-addressed artifact.

## Evidence required and unfinished authority

Acceptance requires actual offline producer/registry/replay chains, checkpoint
partition equivalence, failure-before-next-send controls, opaque Unicode tokens,
all termination/anomaly cases, coherent rehashed substitutions, complete inspected
artifact closure, both profile-mismatch directions, unchanged v1 serialized
identities and old scientific/citation/native regressions, plus supported-runtime
tests. Private source must be independently reviewed before installation.

The native `require_captured_scholarly_search_page_response` API returns page-local
custody and registered-intent identities, not the full recursive predecessor
closure. `require_captured_scholarly_search_result_v2` reopens the entire selected
prefix and returns its complete inspected union. Pre-egress continuation validates
that prefix; the narrower native view alone does not authorize continuation.

This slice cannot certify a unique latest head, absence of abandoned/forked
captures, global spending, exactly-once network execution, freshness or a stable
corpus snapshot. Those require original controller/run-history/resource work;
they are not waived or deferred out of the Goal. Existing per-exchange byte/time
limits and per-gateway attempt counters are not durable whole-query budgets.

Neither provider-terminal observation nor the bounded chain proves source-wide
exhaustion, complete query/round/source coverage, literature sufficiency, fallback
permission or scientific authority. Preserve all allowed-source declarations;
the existing required-source/round policy remains unchanged. Prospective complete
scope, authoritative continuation ownership and target-specific sufficiency remain
original mandatory dependencies. No live API behavior has been validated here.

## Primary references and review

The current [paging guide](https://help.openalex.org/api/paging/) documents cursor
continuation, the supported page-size limit, and empty-plus-null termination
(updated August 11, 2026). The [search guide](https://help.openalex.org/api/searching/)
and [sort guide](https://help.openalex.org/api/sorting/) describe relevance ordering.
The [corpus guide](https://help.openalex.org/data/works/corpus/) documents the
current corpus selector and deprecated older controls (updated August 12, 2026).
The [API reference](https://help.openalex.org/api/) distinguishes reported total
matches from the results captured on a page. These are provider statements, not
live validation or snapshot guarantees.

Root reconciled actual owners with two read-only design advisories, including
independent high-capability review. Exact private advisory hashes and selected
implementation ownership are recorded in the persistent run ledger.

## Pagination-only integration evidence

At the pagination-only integration checkpoint, the installed owners were
`literature.py` (versioned types and pure progression),
`scholarly_gateway.py` (explicit native-v4 capture/replay), and
`scientific_design.py` (registered prefix replay and one-page acquisition).
`tests/test_search_pagination.py` contains 36 actual offline controls. No new
application controller or scientific selection consumer is claimed here.

- Installed affected matrix: 398/398 PASS in 183.395s on Python 3.14.6.
- Installed focused matrix: 36/36 PASS in 27.843s on Python 3.11.15.
- No failures, errors, skips, expected failures, unexpected successes or loader
  errors. Both runs preserved all 254 installed Python files; the runner-inclusive
  255-file inventory is `5d8db62c2921b0585cb4305b723e1baf8545e753226feb6ce8c1bcacbcc40560`.
- Exact candidate-to-installed equality and the 250 unchanged neighboring files
  were independently checked by the root. Installed inventory:
  `0190bb6d7ca41278c18d39ab8bf474b1dee9f491d39436dd44dde17bf8c56d32`.
- The corrected candidate also preserves 24 frozen v1 format/default-wire
  comparisons. Independent reviews found the old oversized checkpoint defect,
  then verified its exact pre-publication correction and seven new boundary
  controls. The old defect and prior failed/setup evidence remain retained.

The 398 comprises 362 affected existing checks plus 36 new checks. Overlapping
focused, historical and private counts are not added. This is scoped installed
verification, not captured-CLI end-to-end, full regression, live OpenAlex,
scientific sufficiency or release acceptance. Exact source, test, log, result,
review and preservation hashes are recorded in the private persistent run ledger.
The remaining controller, enrolled scope, resumable accounting and sufficiency
dependencies above remain open under the original goal.

## Publication recovery without another request

The subsequent installed `publish_captured_scholarly_search_page` API accepts
registered goal/plan, raw/normalized capture and optional predecessor hashes.
It rederives the exact next request, replays complete source custody, uses the
same bounded serialization/metadata path as acquisition, and requires complete
selected-prefix readback. It accepts no gateway or transport. Acquisition's
existing preflight order and shared publication behavior are preserved.

This closes a specific interruption gap: complete captured response bytes can be
published after an earlier publication/readback failure without another HTTP
request. Missing or conflicting custody is not repaired by inventing evidence.
Valid negative responses remain negative; oversize checkpoints still refuse
without erasing captures or prior checkpoints. Republication is not proof that
the original dispatch was managed, fresh, globally unique or scientifically valid.

Exact installed source and `tests/test_captured_search_page_publication.py` were
independently reviewed; 253 neighboring Python files were verified unchanged.
The current combined affected matrix passes **414/414 in 191.842s on Python
3.14.6**. The new 16 focused controls pass **16/16 in 8.991s on Python 3.11.15**.
There are no failures, errors, skips, expected failures, unexpected successes or
loader errors. Both runs preserve the complete 255-file installed inventory
`aae0a8fba804cd9accc9d8feed20870ba0bde23a71ad135eea0c93b8db0c49d6`
(257 including the two root validation runners). The earlier private 414,
author-focused and pagination-only matrices overlap and are not added.

The [managed workflow design](LITERATURE_WORKFLOW_DESIGN.md) remains a selected
design, not implemented command-line acquisition. These library tests are not
captured-CLI, live-source, scientific or whole-Goal acceptance. The original
controller, resource/history, source-obligation and sufficiency work remains open.
