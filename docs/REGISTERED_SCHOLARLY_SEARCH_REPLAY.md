# Registered scholarly search result replay

The installed `require_captured_scholarly_search_result` reader binds one
captured SEED/OpenAlex query outcome to its registered goal, target, plan and
result. Negative HTTP/parser outcomes need no fabricated selection. This is a
read-only provenance check, not scientific approval or a search-coverage decision.

Installed-only verification passed 360 affected tests on Python 3.14.6 and
22 focused tests on Python 3.11.14, with no failures, errors or skips. All 253
installed Python files were unchanged during both runs. Private evidence includes
361 affected tests on Python 3.14.6, 23 focused tests on Python 3.11.14, seven
independent review controls, and four paired legacy-equivalence controls.
These overlapping counts must not be added together.

## Existing owners

| Owner | Checked responsibility |
| --- | --- |
| `scientific_design.require_captured_scholarly_search_result` | Reopen immutable goal/plan/result artifacts; derive the exact SEED target and source request; verify stored typed representations and lineage |
| `scholarly_gateway.require_captured_scholarly_search_response` | Recompute the complete captured OpenAlex HTTP/parser outcome and its request, route, raw bytes, receipt, attempts and budgets |
| Existing scientific selection resolver | Continue requiring AVAILABLE capture, exact selection and its contextual scientific checks |

The derived frozen `ReplayedScholarlySearchResult` contains the typed plan,
typed result, replayed capture, and complete inspected artifact identities. It
does not persist a second registry, history, ledger, claim or scientific authority.

Both existing canonical and fixture goal wrappers are supported; neither wrapper
format itself proves a live run. The goal must have no parents. The SEED target
must have exactly that goal parent, null contribution/reviewed-set fields, and a
statement identical to the parsed goal question. Requests are rederived from the
plan, including its complete allowed-source declaration. Allowed sources are
permissions, not required or completed coverage.

Stored plan/result bytes are compared using the registry's UTF-8 canonical JSON
serializer on both sides. Literature semantic hashes use a different serializer;
semantic hashes and registered artifact hashes are not interchangeable. Existing
scientific consumers retain their older typed comparisons, validation ordering,
set-based parent semantics and returned artifact sets.

## Verification and limits

`tests/test_registered_search_replay.py` contains 22 portable behavior tests.
They cover Unicode, success and empty pages, HTTP/parser failures, retries,
metadata and parent changes, exact goal/target bindings, normalized-byte
substitutions, request/raw/capture splices, source declarations, strict scientific
refusal and read-only behavior. The private extraction/AST test stays private;
the portable suite needs no source snapshot.

Independent controls also used coherently reconstructed typed objects, an actual
second valid gateway route, alternate wrappers for the same goal, and a matching
selection over a negative capture. Each substitution failed at the substantive
join, not merely at parsing. Traced registry reads matched the returned artifact
set. The two small integration changes correct the source-permission wording and
export the public names; no runtime validation rule was relaxed.

Only complete native-v2 OpenAlex SEARCH responses are supported by this new
entry point. DISCONFIRMING requires its existing contextual owner. Legacy
captures, other sources, missing custody, terminal transport failures and
pre-egress/redirect denials remain unsupported here. Their limitations are not
silently converted into empty searches.

One selected registered query is not a prospectively complete query/round/source
inventory. An empty first page is not source exhaustion. The separate
[bounded v2 pagination component](LITERATURE_PAGINATION_DESIGN.md) is now installed;
aggregate coverage and target-specific sufficiency remain original requirements;
general-web fallback is not authorized. Semantic Scholar obligations are neither
removed nor treated as completed. Fixture checks establish no live authenticity,
independent scientific authority, complete-goal acceptance or public readiness.

See [captured-response replay](CAPTURED_SCHOLARLY_SEARCH_REPLAY.md) for the
underlying response boundary and its redirect correction. Exact private evidence
and the remaining original roadmap are indexed in the persistent run ledger.
