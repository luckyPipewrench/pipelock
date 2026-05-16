# Browser Shield production readiness

Browser Shield is a defensive response-rewrite layer. It reduces browser-side
probes and hidden agent traps in HTML, JavaScript, and SVG returned through
Pipelock. It is not an anti-bot bypass system, and it does not promise access
to websites that deliberately deny automation or proxy traffic.

Browser Shield is opt-in. `browser_shield.enabled` defaults to `false`; the
strictness, size, and rewrite toggles have safe defaults for operators that
explicitly enable it.

## Current enforcement boundary

Browser Shield runs after Pipelock has fetched a response and before the agent
or browser receives the body. It only rewrites content that the local pipeline
can classify as shieldable:

- HTML and XHTML
- JavaScript
- SVG active content

Binary media, PDFs, JSON, and unknown specific content types bypass the shield.
This avoids treating large legitimate media responses as shield failures.

## Production invariants

- Shield rewrites are response-local. They never grant outbound network access.
- Shield rewrites are additive to scanning. Response injection scanning still
  runs after shield rewriting on applicable transports.
- Oversized shieldable responses fail according to `oversize_action`.
  `block` fails closed. `warn` returns the body unchanged. `scan_head` rewrites
  only the configured prefix and records the intervention as partial.
- Signed action receipts include a `shield` summary whenever Browser Shield
  rewrites a response and receipt emission is enabled.
- Adaptive enforcement records a low-weight `SignalShieldRewrite` signal for
  repeated shield interventions. The signal is capped at one signal per
  response body, worth 0.25 points, so one noisy page cannot immediately
  escalate a session.

## Receipt fields

The optional `shield` block in ActionReceipt v1 records:

- pipeline: `html`, `javascript`, or `svg`
- total rewrite count
- extension probe rewrites
- tracking beacon rewrites
- hidden agent-trap rewrites
- fingerprint shim injection
- SVG active-content rewrite counts
- body size, scanned size, and whether the rewrite was partial
- adaptive signal count recorded for that response

Existing verifiers that ignore unknown optional fields remain compatible.

## Receipt volume

Each response that Browser Shield rewrites emits one shield receipt when
receipt emission is configured. Operators should size receipt storage for
browser-heavy workflows and treat future aggregation or rate limits as an
evidence-retention policy decision, not as a transport safety requirement.

Shield receipt targets strip URL userinfo, query strings, and fragments before
signing. They also redact common path-borne token shapes, including JWT-like
path segments, long opaque token segments, and sensitive path parameters such
as `;jsessionid=`. This is a defensive scrubber, not a full PII classifier;
operators should still avoid routing credential-bearing paths through
shareable receipt stores.

## HUMAN and PerimeterX class systems

Commercial browser-integrity systems such as HUMAN and PerimeterX combine
server-side reputation, client-side telemetry, challenges, behavioral scoring,
and encrypted JavaScript signals. Browser Shield does not try to defeat those
systems. Treating that as a product goal would blur Pipelock's security
boundary and create brittle site-specific behavior.

The defensive scope is narrower:

- remove page-side probes that try to enumerate local browser extensions or
  automation state
- remove tracking beacons and prefetch-style telemetry that are not required
  for rendering agent-visible content
- remove hidden prompt traps and concealed instructions
- record when Pipelock changed content so operators can audit the intervention

## Explicit non-goals

- solving CAPTCHAs or challenges
- bypassing commercial bot-management access decisions
- forging browser-integrity telemetry
- impersonating a specific human browser profile
- patching every obfuscated anti-automation script

If a page depends on a commercial browser-integrity system for access, the
operator should either configure an allowed human/browser workflow outside the
agent path or treat the target as unsupported for automated access.

## Review checklist

Before changing Browser Shield behavior:

1. Prove transport parity across fetch, forward, intercept, and reverse paths
   when the path buffers a response body.
2. Keep non-shieldable binary/media responses outside the oversize block path.
3. Clear body validators (`ETag`, `Digest`, `Content-MD5`) when a rewrite
   changes response bytes.
4. Keep shield receipts shareable: strip URL query strings and fragments from
   receipt targets, and link shield intervention receipts to the request action
   with `parent_action_id` when a request action exists.
5. Cap adaptive Browser Shield rewrite scoring at one low-weight signal per
   response body so ordinary ad-supported pages do not escalate from tracker
   volume alone.
6. Add adversarial tests for padding, encoded active content, and mixed
   extension/tracking/trap payloads.
7. Keep public copy defensive. Do not describe the feature as anti-bot evasion.

## Production soak profile

Use a staged rollout rather than turning Browser Shield on fleet-wide at the
standard fail-closed posture.

1. Build and verify the release candidate locally.
2. Run the synthetic transport canary across fetch, forward, intercept, and
   reverse paths with receipt signing enabled.
3. Enable Browser Shield on a small opt-in agent group with
   `strictness: minimal` and `oversize_action: warn`.
4. Monitor shield receipts, validator-clearing behavior, adaptive score
   movement, response scanner deltas, and page breakage.
5. Move to `strictness: standard` and `oversize_action: block` only after the
   soak shows stable browsing behavior and no unexpected escalation.
