# Secret-egress evidence contract v1: additive foundation

Status: candidate interface and signed receipt fixtures. No production transport emits this
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
Decision-only pairing does not bind the enclosing registry hash, effective policy
hash, signer or run/session context. A signed reader must verify those separately
before treating two receipts as observations of the same protected operation.

The strict parser rejects unknown fields, duplicates, case aliases, nulls,
unsupported versions, invalid relationships and trailing input. Its bounded
symbolic identifiers and canonical host checks are structural checks. Producers
must apply the declared evidence privacy policy before retaining a reference.
Syntax alone cannot establish whether a host or rule reference contains
classified material. A forwarding result of `Clean` is not a privacy permit:
warn-only or otherwise retained findings may still need metadata redaction.

Strict structure does not require a unique JSON byte encoding. JSON escapes for
the same decoded field name or value and ordinary formatting changes can describe
the same typed facts. Signature verification belongs to the separately specified
signed-envelope canonicalization boundary; successful model parsing does not
prove canonical emitted bytes or authenticate a record.

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

## Destination identity and privacy

A decision carries exactly one of `destination_ref` or `destination_redaction: { "reason": "classified_sensitive" }`. A retained reference keeps the canonical-host or configured local-process reference rules. A redacted record omits the reference, without substituting a fictional hostname. `destination_kind` still describes the network or local-process carrier. Both forms together, neither form, null values and unknown redaction reasons are invalid.

Redaction is a stored fact about withheld identity. It doesn't imply that redacted records name the same destination, that collection failed, or that the request was blocked. Action and decision IDs retain their independent meaning, and intent/outcome pairing preserves the destination facts by value. A destination-filtered report must account for unresolved attribution rather than turn a redacted record into a clean empty result.

Live producers are still pending. They must preserve useful grouping for ordinary unexpected destinations and remove classified-sensitive destination material under the declared evidence privacy policy. Existing receipt sanitization can supply structural coarsening, but its forwarding-oriented `Clean` predicate alone isn't that policy. Original classification/view context, including informational and pre-policy findings, must survive until the privacy decision. This is a detection-scoped guarantee, not proof that arbitrary text can never contain an unknown secret.

The new map's evidence privacy policy must withhold classified-sensitive destination material even when `flight_recorder.redact=false`. That legacy option retains its existing receipt behavior. This candidate represents the stored redaction fact and adds no runtime flag or key. Live finding-aware producer enforcement remains a separate integration gate.

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

MCP carrier labels follow the current runtime: `mcp_stdio` names a local
subprocess and requires `local_process`; `mcp_http_upstream` names the stdio-to-
HTTP bridge, `mcp_ws` the stdio-to-WebSocket bridge, and `mcp_http_listener` the HTTP
listener. Those remote carriers require `network`. A stdio client interface does
not turn the remote upstream into a local-process destination.

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

## Proposed runtime integration

This integration remains pending production wiring and the public contract
correction. The candidate model does not enable or change required-receipt
behavior.

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

## Signed fixture format

No new field is added to signed-v1 records or their unsigned `ext`. The explicit
EvidenceReceipt v2 payload kind `secret_egress_decision_v1` is registered as
`fixture_only`. It requires the same-named critical feature in addition to
`canonicalization`, a canonical envelope `policy_hash`, and the `receipt-signing`
purpose. The existing v2 signature and canonicalization recipe is unchanged.

This new kind has a closed wire profile before typed decoding. Required envelope keys must be present with their exact spelling; unknown keys, duplicates and null values reject. The nested canonicalization and signature objects also use exact keys and string types. The signature value is exactly `ed25519:` followed by 128 lowercase ASCII hexadecimal digits, without whitespace normalization. Optional strings must be nonempty when present. An optional delegation chain must contain at least one nonempty string.

`receipt_version` is the integer token `2`. `chain_seq` uses an unsigned decimal integer from zero through `9007199254740991`; optional `contract_generation` uses the same range starting at one. Negative zero, decimal and exponent spellings reject. The timestamp is a valid, nonzero UTC RFC3339Nano value ending in `Z`, with no trailing fractional zeros. Its JSON value uses unescaped ASCII. This is the candidate encoding requirement, not a general RFC3339 restriction. The builder converts input timestamps to UTC. These restrictions apply only to the new payload kind; existing receipt formats retain their current interpretation.

Go file, stream and recorder verification use `receipt.ParseEvidenceReceipt` before signature checks. Recorder extraction requires the original `RawDetail` bytes for this new kind; reconstructing JSON from an already-decoded object can't establish its original field presence or number spelling. Generic `json.Unmarshal` only parses an object. The object-taking `VerifyWithKey` API validates typed facts and signatures, without claiming to validate source bytes it never received.

The payload is `{ "registry_hash": "sha256:<lowercase hex>", "decision": ... }`.
`decision` is the strict version-1 model above. `registry_hash` commits to a
versioned canonical manifest of every complete site declaration, sorted by site
ID. The manifest contains `manifest_kind: "secret_egress_registry"`,
`manifest_version: 1`, and `sites`. Each site has the lowercase keys `id`, `plane`,
`transport`, `location`, `view` and `boundary`. The digest is SHA-256 over the
repository's JCS-canonical JSON bytes, prefixed with `sha256:`.

The builder validates the decision against the supplied immutable registry and
computes the registry commitment. It does not accept a caller's arbitrary digest
as proof of membership. Each record has its own envelope event ID, distinct from
the action and decision IDs. The envelope supplies record time and effective
policy context; the decision's intent/outcome linkage remains separate.

Offline structural/signature validation checks the receipt and the registry-hash
shape. It does not resolve the committed registry or establish producer liveness,
complete coverage, authenticated policy-reference resolution or durable append.
Those require the corresponding trusted manifest and runtime/coverage evidence.
A signature over `required_before_action` is still a statement of the requirement,
not confirmation that this record's persistence succeeded.

Go, TypeScript, Rust and Python consume the shared signed corpus under
`sdk/conformance/testdata/secret-egress-v1/`. Its deterministic key is test-only.
Unknown fields, changed metadata, unsupported versions/features, missing policy
or registry commitments and invalid purposes must be rejected consistently.
Frozen-v1 compatibility and all existing payload behavior remain required.

The new-kind Go lane uses `pipelock-verifier receipt`, whose existing standalone
receipt command accepts typed v2 files. The ordinary main-CLI single-v1-receipt
lane remains unchanged. The new-kind Python lane is the in-repository reference
implementation. The ordinary legacy corpus continues to run against its separately pinned published
Python verifier. New-kind conformance here does not claim that the published
Python package has been updated; that consumer and its coordinated release/pin
remain a prerequisite before live feature support is claimed.

## Runtime and release acceptance

Release acceptance includes every applicable fetch, forward, CONNECT admission,
intercept, reverse, WebSocket and MCP boundary, with explicit opaque/summarized
exceptions. Required-append failures must be observed before their protected
continuations. Held acknowledgments, missing writers, advisory failures, partial
sends, reload/restart, independent coverage, deduplication and reader visibility
need behavioral tests using benign fixtures. Removing an emission or reader
obligation must make its test fail. Separate foundation, producer and consumer
PRs are allowed; the complete feature is not claimed until all obligations pass.
