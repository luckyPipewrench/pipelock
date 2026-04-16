<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Mediation envelope

The mediation envelope is sideband metadata that pipelock attaches to every
proxied request. It tells downstream services what pipelock decided (verdict,
action), who the agent is (actor identity and trust level), and how to
correlate the decision with the flight recorder (receipt ID).

## When to use

Enable the mediation envelope when:

- A backend service needs to know whether pipelock allowed, blocked, or warned
  on the request without parsing pipelock's log stream.
- You are building a trust chain where each hop carries evidence of the
  previous hop's security decision.
- You want to correlate backend audit logs with pipelock's flight recorder
  entries using the receipt ID.
- Your authorization layer needs the actor identity and its trust level
  (bound, matched, or self-declared) to make access decisions.

## Configuration

Minimal (unsigned envelope):

```yaml
mediation_envelope:
  enabled: true
```

Signed envelope (Ed25519, RFC 9421 HTTP Message Signatures):

```yaml
mediation_envelope:
  enabled: true
  sign: true
  signing_key_path: /etc/pipelock/envelope-sign.key   # versioned pipelock ed25519 private key
  key_id: pipelock-envelope-2026-04                   # passed as keyid in the signature input
  signed_components:                                   # per-request component list
    - "@method"
    - "@target-uri"
    - "pipelock-mediation"
    - "content-digest"
  created_skew_seconds: 30      # tolerance for clock drift between signer and verifier
  max_body_bytes: 1048576       # upper bound on body bytes drained for Content-Digest
```

When `sign: true`, pipelock attaches an RFC 9421 HTTP Message Signature alongside the `Pipelock-Mediation` header. The signature uses the `pipelock1` dictionary label and the `pipelock-mediation` tag so it coexists with upstream `sig1` / Web Bot Auth signatures on the same request.

Fail-closed semantics: if `sign: true` is set without a readable Ed25519 key, pipelock refuses to start. Hot-reload with an unreadable key aborts the entire config swap rather than silently downgrading to unsigned traffic.

The signing key must use the versioned pipelock Ed25519 format (see `pipelock keygen`). The envelope signing key SHOULD be distinct from the receipt signing key so an envelope-key rotation does not invalidate historical receipts.

## HTTP header format

HTTP requests get a `Pipelock-Mediation` header encoded as an
RFC 8941 Structured Fields Dictionary:

```
Pipelock-Mediation: v=1, act="read", vd="allow", se="external_read", actor="agent-1",
  aa="bound", ph=:dGVzdA==:, rid="019...", ts=1712764800
```

Optional fields (`taint`, `task`, `auth`, `authr`, `reauth`) are omitted
when they carry no value.

The mediation envelope rides only on requests pipelock forwards downstream. Blocked requests do not reach the backend, so use signed receipts rather than headers to audit blocked decisions.

## MCP meta format

MCP JSON-RPC messages get the envelope injected into the `_meta` map under
the `com.pipelock/mediation` key:

```json
{
  "_meta": {
    "com.pipelock/mediation": {
      "v": 1,
      "act": "read",
      "vd": "allow",
      "se": "external_read",
      "actor": "agent-1",
      "aa": "bound",
      "ph": "sha256-128:dGVzdA==",
      "rid": "019...",
      "ts": 1712764800
    }
  }
}
```

## Envelope fields

| Wire key | Name | Description |
|----------|------|-------------|
| `v` | Version | Schema version (currently `1`) |
| `act` | Action | Classified action type: `read`, `derive`, `write`, `delegate`, `authorize`, `spend`, `commit`, `actuate`, `unclassified` |
| `vd` | Verdict | Enforcement verdict: `allow`, `block`, or `warn` |
| `se` | SideEffect | Side effect description (empty when none) |
| `actor` | Actor | Agent identity string |
| `aa` | ActorAuth | Trust level: `bound` (infra-set), `matched` (profile match), `config-default` (operator-set default), `self-declared` (unverified) |
| `ph` | PolicyHash | Truncated SHA-256 of the active config (16 bytes, base64 in MCP) |
| `rid` | ReceiptID | UUIDv7 receipt ID for flight recorder correlation |
| `ts` | Timestamp | Unix epoch seconds |
| `taint` | SessionTaint | Session taint state (omitted when clean) |
| `task` | TaskID | Task boundary identifier (omitted when no active task) |
| `auth` | AuthorityKind | Authority type backing this action (omitted when absent) |
| `authr` | AuthorityRef | Authority reference (omitted when absent) |
| `reauth` | RequiresReauth | True when the action requires re-authorization |

## Inbound stripping

Pipelock strips any inbound `Pipelock-Mediation` header and any
`pipelock`-prefixed members from `Signature` and `Signature-Input` headers
before processing. This prevents agents or upstream proxies from forging
mediation metadata.

For MCP, any existing `com.pipelock/mediation` key in `_meta` is deleted
before the envelope is injected.

## Interaction with receipts

The envelope's `rid` field carries the same UUIDv7 action ID written to the
flight recorder. A downstream service that receives the header can:

1. Extract `rid` from the envelope.
2. Query the flight recorder JSONL for the matching `action_id`.
3. Verify the receipt's Ed25519 signature to confirm the decision was made by
   a trusted pipelock instance.

The `ph` (policy hash) field lets the verifier confirm which policy version
was active when the decision was made.

## Actor trust levels

| Level | Meaning | How it is set |
|-------|---------|---------------|
| `bound` | Identity set by infrastructure. Spoof-proof. | Two modes: (1) dedicated listen address per agent, or (2) `bind_default_agent_identity: true` with a set `default_agent_identity` in the companion-proxy topology generated by `pipelock init sidecar`; caller-supplied `X-Pipelock-Agent` / `?agent=` values are ignored |
| `matched` | Agent name matches a configured profile but was self-declared via header or query param. | `X-Pipelock-Agent` header or `?agent=` query param |
| `config-default` | Identity resolved from `default_agent_identity` without trusting caller input. | Proxy uses the configured default identity |
| `self-declared` | Unknown agent or fallback path. Attacker-controllable. | No matching profile or no identity header |

Use `bound` in production by either assigning each agent its own listen port, or by running a generated companion-proxy deployment (`pipelock init sidecar`) which sets `bind_default_agent_identity: true` automatically. The `matched` and `self-declared` levels are informational and should not be trusted for authorization decisions without additional verification.

## Signing

RFC 9421 HTTP Message Signatures for the mediation envelope ship in v2.2.0. The signer uses a dedicated Ed25519 envelope key (separate from the receipt signing key), the `pipelock1` signature label, and the `pipelock-mediation` tag. Cloudflare Web Bot Auth (`sig1`, tag `web-bot-auth`) and other RFC 9421 signatures coexist on the same request via distinct signature labels — pipelock's inbound-strip only removes members tagged `pipelock-mediation` and never disturbs upstream signatures.

**Canonical policy hash (`ph`).** The envelope's `ph` field is the first 16 bytes of SHA-256 over a canonicalised, slice-order-preserving JSON projection of the effective config. Reformatting, comments, and reordering noise fields no longer shift `ph`, while behavioural rule reorders (DLP patterns, MCP tool policy rules, chain rules) still do. Per-agent resolved configs compute their own canonical hash and stamp it via `BuildOpts.PolicyHash` at the transport inject site. This makes `ph` admission-grade for downstream verifiers.

**Redirect refresh.** On every allowed redirect through the fetch or forward proxy, pipelock rebuilds the `Pipelock-Mediation` header on the redirected request so `@target-uri`, `hop`, `ph`, and `action` reflect the redirected leg. Stale `Content-Digest` is dropped and the signature is re-attached. The `hop` dictionary key counts refresh hops; original requests omit it.

**Reverse-proxy signing.** For reverse-proxy transports, envelope signing runs in an `http.RoundTripper` wrapper installed on `httputil.ReverseProxy.Transport`, so `@target-uri` reflects the post-Director upstream URL rather than the inbound relative path. This prevents signature / URL mismatches when the reverse proxy rewrites the path.

**Body plumbing.** Transport inject sites hand the already-scanned request body bytes to the signer so `Content-Digest` is computed without a second drain. When request body scanning is disabled but signing is enabled, the envelope emitter drains `req.Body` itself (bounded by `max_body_bytes`) and installs a fresh `GetBody` closure so the stdlib can replay the body on 307/308 redirects.

Deferred to a later release: SPIFFE actor format and well-known envelope-key discovery (`/.well-known/pipelock-envelope-keys`). Until those ship, key distribution is an out-of-band deployment concern — publish the envelope public key (hex or versioned format) alongside your receipt public key and rotate via `key_id` changes.

## Example: reading the envelope in Go

```go
env, err := envelope.Parse(req.Header.Get("Pipelock-Mediation"))
if err != nil {
    // malformed or missing envelope
}
fmt.Println(env.Action, env.Verdict, env.ReceiptID)
```

## See also

- [Configuration reference](../configuration.md#mediation-envelope-v21) for all config fields
- [Flight recorder guide](flight-recorder.md) for receipt correlation
- [Receipt verification guide](receipt-verification.md) for verifying receipt signatures
