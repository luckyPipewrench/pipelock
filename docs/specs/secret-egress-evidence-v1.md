# Secret-egress evidence contract v1: additive foundation

Status: candidate interface and fixtures only. No production transport emits this
contract yet. This document does not claim a complete classification-site census,
a durable writer, transport parity, a queryable map, or release readiness.

`internal/egressevidence` is the dependency-light contract layer. It neither scans
nor forwards traffic and does not change the existing signed-v1 or signed-v2
receipt admission rules. The candidate payload's `version: 1` is independent of
any future receipt-envelope version.

## Three independent dimensions

- Finding handling describes the selected policy: `block`, `redact`, `observe`,
  `authorize`, or `exempt`, with a rule and pattern-class reference. Authorization
  and exemption carry the exact named reference; being destination-specific alone
  does not determine which one occurred. Named references explicitly distinguish
  built-in from operator-authored policy.
- Planned request-byte form is `none`, `original`, or `transformed`. An `intent`
  contains no observed outcome. An `outcome` records `none`, `partial`, `complete`,
  or `unknown` release and its observed byte form. A truthful contradiction between
  policy intent and observed behavior is accepted as evidence, not discarded.
- The persistence policy is `required_before_action` or `best_effort`. It is a
  signed-intent candidate, not a claim that the record's own future fsync succeeded.
  Actual confirmation and reader verification are separate runtime/read-side facts.

When safe rewriting was unavailable, `rewrite_fallback` preserves its typed reason
and the exact named fallback policy and origin. This distinguishes an unrewritable
original-byte forward from an ordinary warning or generic exemption. The effective
handling and observed release remain separate: a residual finding may still block
the request, and fallback metadata never grants permission to send original bytes.

`ValidateOutcomeOf` binds an outcome to the same action, decision, site, policy
handling and intended bytes. Each eventual envelope has its own record identity;
retrying identical content must preserve that identity. Conflicting duplicate
identities must be rejected by the writer/reader, not resolved last-write-wins.

The strict parser rejects unknown fields, duplicates, case aliases, nulls,
unsupported versions, invalid relationships and trailing input. Its bounded
symbolic identifiers and canonical host checks are structural checks. Producers
still must apply existing secret-sanitization policy: a syntactically valid host
or rule reference is not proof that its content is non-secret.

Structural validity is not policy compliance. A core finding can legitimately
appear in retained pre-transform observation evidence or safe redaction followed
by a clean rescan, or a compiled-in audience authorization. Readers need the
classification view, selected handling, effective authority, residual findings
and observed release context to assess the immutable floor;
they must not classify every non-block core record as a violation. Actual
contradictions, such as a blocked intent followed by observed original-byte
release, remain representable and must be surfaced. Validation never relaxes
the existing floor. Before signing, a production adapter must resolve named
policy references and origins against the effective policy snapshot; this
structural model does not authenticate that resolution.

## Classification sites

A `SiteID` names a particular plane, transport, carrier location, scan view and
protected boundary. Original, normalized, post-transform, authorization and
reassembled views are explicit. The immutable `Registry` rejects malformed
declarations and transport/boundary category errors and binds a decision to an
exact declaration. Exact protocol-specific location/view/mode combinations still
require the maintained production registry; accepting an enum combination is not
proof that such a site exists.

Registry membership is an obligation, not a production-capability claim. The
foundation intentionally supplies no default complete registry. Maintainers must
bind every actual classification boundary and independently check production
site declarations against their producer obligations before enabling this model.
A test deriving both expected and actual sites from one table cannot establish
exhaustiveness.

The initial decision model is the outbound proxy plane. Hook decisions may have
site declarations for explicit coverage exclusion, but cannot become a proxy
request-byte record. Encrypted passthrough contents, responses, offline scans and
unmediated traffic likewise cannot silently become covered outbound requests.

## Independent coverage

`Registry.Assess` evaluates a half-open interval across explicit required sites
using independently established capability/health segments. It takes no event
count. Missing intervals and declarations become `unavailable`. An expected proxy
classification site can be only complete or unavailable; it cannot be excused as
an unrelated scope. The reducer permits `out_of_scope` only for explicitly
registered hook-plane sites. Mixed results retain proxy gaps and hook exclusions.
Broader exclusions for opaque, unmediated, response or offline traffic belong to
the future query-scope model, not this per-site reducer. Recovery cannot erase an
earlier failed interval. A complete zero-event window says collection covered its
declared scope, not that no secret could have escaped detection.

Callers must first authenticate and bind segments to the exact run, configuration
generation, session, agent and destination being queried. The pure reducer does
not manufacture that evidence or infer producer liveness from registry presence.

## Required runtime integration

The single existing `flight_recorder.require_receipts` posture controls whether
new authoritative classification evidence must be confirmed before the protected
action. Failed confirmation blocks that action only in the required posture;
best-effort failures preserve the underlying DLP decision and mark evidence
unavailable. A map/report or secondary projection must never authorize forwarding
or substitute for the primary confirmation. Existing signed-receipt obligations
are not reclassified as projections by this contract.

The writer integration must define bounded admission, append and confirmation,
uncertain-write quarantine, stable retry identities, restart/reload recovery and
non-secret failure signals. A timeout never counts as confirmation. Post-action
failure cannot establish that no bytes left. This foundation does not adapt a
synchronous filesystem call into a supposedly bounded writer.

## Signed format and release acceptance

No new field is added to signed-v1 records or their unsigned `ext`. The eventual
typed receipt payload requires an explicit new payload kind, strict validation in
all supported verifier implementations, exact-byte fixtures and frozen-v1
compatibility tests before production emission. This candidate interface is not
registered as a new signed payload in this slice.

Release acceptance includes every applicable fetch, forward, CONNECT admission,
intercept, reverse, WebSocket and MCP boundary, with explicit opaque/summarized
exceptions. Required-append failures must be observed before their protected
continuations. Held acknowledgments, missing writers, advisory failures, partial
sends, reload/restart, independent coverage, deduplication and reader visibility
need behavioral tests using benign fixtures. Removing an emission or reader
obligation must make its test fail. Separate foundation, producer and consumer
PRs are allowed; the complete feature is not claimed until all obligations pass.
