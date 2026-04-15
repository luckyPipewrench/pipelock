# Mediation Envelope

The mediation envelope is the compact per-request metadata record that
pipelock attaches to every outbound mediated request. It carries the
action type, verdict, actor identity, policy fingerprint, and receipt
correlation ID that a downstream verifier needs to decide whether to
trust the request and to correlate it with pipelock's receipt chain.

This document describes the envelope wire format, the configuration
surface, the signing contract added in v2.1.3, and the transport
coverage matrix.

## Wire format

- **HTTP surfaces:** pipelock writes the envelope to the
  `Pipelock-Mediation` HTTP header as an RFC 8941 Structured Fields
  Dictionary.
- **MCP stdio surface:** pipelock writes the same fields to the
  `_meta["com.pipelock/mediation"]` key on the MCP JSON-RPC message.

The dictionary members are:

| Key | Type | Meaning | Always present |
|-----|------|---------|----------------|
| `v` | integer | Envelope version (currently `1`) | yes |
| `act` | string | Action class (`read`, `write`, `delegate`, …) | yes |
| `vd` | string | Verdict (`allow`, `warn`, `block`, …) | yes |
| `se` | string | Side-effect class (`external_read`, `external_write`, …) | yes |
| `actor` | string | Actor identity string | yes |
| `aa` | string | Actor auth level (`bound`, `matched`, `self-declared`) | yes |
| `ph` | byte-sequence | First 16 bytes of SHA-256 of the canonical policy projection (see below) | yes |
| `rid` | string | UUIDv7 receipt ID for correlation with the receipt chain | yes |
| `ts` | integer | Unix timestamp of envelope creation | yes |
| `taint` | string | Session taint level (when session profiling is active) | optional |
| `task` | string | Current task ID (when taint task boundaries are configured) | optional |
| `auth` | string | Authority kind | optional |
| `authr` | string | Authority reference | optional |
| `reauth` | boolean | True when the action requires re-authentication | optional |
| `hop` | integer | Redirect refresh counter (added in v2.1.3) | omitted when zero |

Example Pipelock-Mediation header value on a forward-proxy POST that
has been refreshed once across a redirect:

```
v=1, act="write", vd="allow", se="external_write", actor="agent:claude-code", aa="bound",
ph=:Yn5mZAAAAAAAAAAAAAAAAA==:, rid="01961f3a-7b2c-7000-8000-000000000001",
ts=1712345678, hop=1
```

## Canonical policy hash (`ph`)

Before v2.1.3, `ph` was `first16(sha256(raw_yaml_bytes))`. Cosmetic
changes to the on-disk YAML (whitespace, comments, top-level section
reorder) produced different `ph` values for semantically identical
policies. Downstream verifiers could not use `ph` as a stable
statement about the rules that governed a request.

From v2.1.3 onwards, `ph` derives from a canonical projection of the
config:

1. Shallow-copy the live `*config.Config`.
2. Zero fields whose values do not affect a scanning decision —
   listen addresses, logging, Sentry, emit destinations, flight
   recorder paths, licence metadata, the envelope signing key path,
   and the agents map (per-agent resolved configs hash their own
   views separately).
3. Sort set-like string slices (`api_allowlist`, `internal`,
   `trusted_domains`) into canonical order. Behavioural rule slices
   (DLP patterns, MCP tool policy rules, chain detection rules,
   suppress entries) are **not** sorted — their order is first-match
   semantics and must shift `ph`.
4. Marshal the projection via `encoding/json` — map keys are sorted
   alphabetically, slice order is preserved by construction.
5. Hash with SHA-256 and truncate to 16 bytes.

Per-agent config resolution computes and caches its own canonical
hash, so an agent whose profile overrides the global policy gets its
own `ph` stamped on the requests it originates. The global hash is
the fallback for requests without a resolved agent binding.

## RFC 9421 envelope signing (v2.1.3)

When `mediation_envelope.sign: true` is configured, pipelock attaches
an RFC 9421 HTTP Message Signature to outbound mediated requests on
the HTTP surfaces. The signature is labelled `pipelock1` and tagged
`pipelock-mediation` so it coexists with any upstream signature
(Cloudflare Web Bot Auth `sig1` / `web-bot-auth`, or any other) on
the same request.

### Config surface

```yaml
mediation_envelope:
  enabled: true                               # required for signing
  sign: true                                  # opt-in; default false
  signing_key_path: /etc/pipelock/envelope.key  # required when sign is true
  key_id: pipelock-mediation-v1               # defaults to v1
  signed_components:                           # maximal declared set
    - "@method"
    - "@target-uri"
    - "content-digest"
    - "pipelock-mediation"
  created_skew_seconds: 60                    # inbound verify tolerance
  max_body_bytes: 1048576                     # body buffer cap (1 MiB)
```

### Algorithm

Pipelock's signer uses **Ed25519** exclusively. The `alg="ed25519"`
parameter is emitted on `Signature-Input` so verifier libraries that
dispatch by algorithm (common-fate/httpsig, among others) can select
the matching key. The Ed25519 private key must live in a filesystem
location pipelock can read and the agent cannot — capability
separation is enforced by deployment, not by the binary.

### Dynamic component list

The maximal list in `signed_components` declares what pipelock *will*
sign when applicable. The signer builds a per-request subset:

- `@method`, `@target-uri`, `pipelock-mediation` always apply.
- `content-digest` is included only when the request has a body.
  Body-less GETs and WebSocket handshakes drop `content-digest` from
  the declared list; their `Signature-Input` carries only the other
  three components.
- Any HTTP header field component is included only when the request
  actually carries the header.

The per-request declared list appears on the outbound
`Signature-Input` so verifiers reconstruct the same base string.

### Coexistence

Pipelock's `pipelock1` dictionary member is added to any existing
`Signature` / `Signature-Input` headers via `httpsfv` dictionary
merge. Upstream `sig1` or `web-bot-auth` signatures are preserved
verbatim. On redirect refresh, any stale `pipelock*` member is
replaced in place before the new one is added.

### Reload semantics

- **First load or reload with `sign: true`:** the Ed25519 key file is
  loaded fresh on every reload. Key rotation works by replacing the
  file contents; pipelock picks them up on the next SIGHUP or config
  change.
- **Key file unreadable on reload:** the reload is **aborted
  entirely**. The previous envelope emitter (and its in-memory key)
  stays installed. No silent downgrade to unsigned. Operators see a
  `LogError` entry and the proxy continues running on the last good
  config until the key file is fixed.
- **`sign: true` → `sign: false` transition:** `ValidateReload` emits
  a warning because downstream verifiers relying on the signature
  will start accepting unsigned envelopes. This is not blocked — an
  operator can still roll back — but the downgrade is visible in the
  audit log.
- **`key_id` rotation without publish:** `ValidateReload` warns so
  operators do not silently start emitting signatures no verifier
  can check.

## Transport coverage

| Transport | Envelope header | Signing | Where signing runs | Redirect refresh |
|-----------|-----------------|---------|--------------------|------------------|
| Fetch proxy (`/fetch?url=…`) | yes | yes | pre-dispatch | yes (shared fetch+forward redirect client) |
| Forward proxy (`HTTPS_PROXY`) | yes | yes | pre-dispatch | yes (shared fetch+forward redirect client) |
| Intercepted CONNECT / TLS tunnel | yes | yes | pre-dispatch | no (upstream RoundTrip is one-shot) |
| Reverse proxy | yes | yes | `http.RoundTripper` wrapper (post-Director) | n/a (redirects disabled on reverse proxy upstream) |
| WebSocket handshake | yes | yes | pre-dial (synthesised `*http.Request` with the dial URL) | n/a (no redirects on WS handshake) |
| MCP stdio | yes | **no** | pre-dispatch (header-only `InjectHTTPEnvelope`) | n/a |
| MCP HTTP / SSE | yes | **no** | pre-dispatch | **n/a — redirects disabled** |

**MCP stdio is not signed in v2.1.3.** RFC 9421 is defined on HTTP
messages; the MCP stdio transport rides the envelope in JSON-RPC
`_meta`, not on HTTP headers. Signing MCP stdio would require a
different signature format and is explicitly out of scope for this
release.

**MCP HTTP / SSE does not follow redirects** (SSRF hardening). The
envelope refresh helper in `internal/proxy/proxy.go` is consequently
moot for that transport — there is no second hop to refresh over. If
a future change enables redirect following on the MCP HTTP path, the
refresh helper must be wired into the new `CheckRedirect` closure.

## Redirect refresh

On every allowed redirect through the fetch or forward proxy client,
`refreshEnvelopeForRedirect` rebuilds the Pipelock-Mediation header on
the redirected request:

1. Parse the previous envelope from `req.Header`.
2. Increment `hop` by 1.
3. Recompute `action` and `side_effect` from the (possibly new)
   request method — a 303 that downgrades POST to GET shifts the
   action class.
4. Drop any stale `Content-Digest` header that was copied from the
   original response.
5. Call the emitter to build a new envelope with the refreshed
   fields, the per-agent canonical policy hash, and the incremented
   hop.
6. If signing is enabled, re-sign the request with the new
   `@target-uri`, dynamic component list, and (if the redirect
   preserves method + body via `GetBody`) a fresh Content-Digest.

Errors from any step log an anomaly but do not fail the redirect:
taking down an otherwise allowed hop on a signing accessory failure
is the wrong trade-off.

## Capability separation

The envelope signing key must live in pipelock's own privilege
domain. The agent must not have read access to the key file, or the
"proxy holds no agent secrets" invariant breaks and an attacker who
compromises the agent can forge mediation signatures.

Pipelock enforces this by deployment conventions, not by the binary:

- Kubernetes: mount the key from a Secret volume with
  `fsGroup`-only read permissions.
- Host deployments: chown the key to the pipelock service account
  with mode `0600` and ensure agents run under a different UID.
- SOPS: encrypt the key file in git and decrypt at deploy time under
  the pipelock service account.

`signing.LoadPrivateKeyFile` — the helper pipelock uses to load all
Ed25519 keys (receipt signing, flight recorder checkpoints, envelope
signing) — rejects group-write, group-execute, and any other-access
bits. Group-read is allowed for Kubernetes `fsGroup` compatibility.

## Known limitations (v2.1.3)

- **MCP stdio signing:** out of scope. Follow-up work will define an
  MCP-native signing envelope format.
- **Inbound verification:** pipelock strips inbound `pipelock*`
  signatures today on the assumption that they are forged or stale.
  Inbound RFC 9421 verification against a trust list and a replay
  cache lands in a follow-up (tracked in ops as `v2.2.x: envelope
  inbound verify`).
- **Algorithm agility:** Ed25519 only. A future pass will thread the
  algorithm selection through `SignerConfig` and support P-256 for
  ecosystems that do not accept Ed25519.
- **Content-Digest digest family:** pipelock uses SHA-256 per
  RFC 9530 defaults. Some verifier libraries (common-fate/httpsig)
  hard-code SHA-512 for the Ed25519 algorithm. The external interop
  test exercises body-less GETs to avoid the mismatch; a follow-up
  will make the digest family configurable.
