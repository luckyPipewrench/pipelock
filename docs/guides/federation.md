# Federation: Inbound Envelope Verification, SPIFFE Actors, Well-Known Directory

When two organisations both run Pipelock, the mediation envelope makes their proxies interoperate. The federation surface includes:

- **Inbound envelope verification** so a Pipelock that receives a request signed by another Pipelock can verify the signature, check the trust list, and protect against replay.
- **SPIFFE actor format** so mediators identify themselves with cryptographically-defined trust-domain identities instead of free-form strings.
- **`/.well-known/http-message-signatures-directory`** per RFC 9421 so verifiers fetch public key material via the standard HTTP discovery endpoint instead of out-of-band SHA pinning.

This guide is for operators wiring two Pipelock deployments together (or wiring an external verifier against a Pipelock deployment). For the receipt format itself see [receipt-transports.md](receipt-transports.md).

## What Pipelock signs and what it verifies

Outbound (existing, since v2.2.0): every proxied request carries a `pipelock-mediation` envelope with the proxy's verdict, action, actor identity, and receipt correlation. The envelope is signed via RFC 9421 HTTP Message Signatures with a canonical policy hash.

Inbound (new in v2.4): when a request arrives carrying a `pipelock-mediation` signature from another mediator, Pipelock can verify the signature, confirm the actor is in the configured trust list, and reject replays. Without inbound verification, Pipelock strips inbound signatures unconditionally and treats the request as if it came from a non-mediated client.

## Configuration

Inbound verification is opt-in. Add `mediation_envelope.verify_inbound` to `pipelock.yaml`:

```yaml
mediation_envelope:
  verify_inbound:
    enabled: true
    trust_list:
      - key_id: "partner-pipelock-2026-q2"
        public_key: "64-char-hex-encoded-ed25519-public-key"
        # Optional: a discovery / metadata URL pointing at the partner's
        # RFC 9421 directory. Validated as HTTPS at config-load. NOT used
        # by inbound verification to fetch the key — `public_key` above is
        # required and is the source of truth. The directory URL is for
        # humans tracing key provenance and for tooling outside Pipelock.
        well_known_url: "https://partner-org.example/.well-known/http-message-signatures-directory"
        trust_domains:
          - "partner-org.example"   # restrict this key to envelopes whose
                                    # actor SPIFFE ID is under this trust
                                    # domain. Empty = any (v2.4 migration
                                    # default; production should pin).
    replay_cache:
      window: 5m                    # signed envelopes older than this are rejected
      max_entries: 100000           # nonce-keyed in-process cache
```

### Permissive vs strict actors

`mediation_envelope.actor_format: spiffe` is the default. It emits SPIFFE actor IDs on outbound envelopes and requires verified inbound envelopes to carry syntactically valid SPIFFE actors. The same knob controls both surfaces; set `mediation_envelope.actor_format: legacy` only for migration windows where a trusted peer still signs free-form actor strings.

A `trust_list` entry with empty `trust_domains` accepts a signature for any claimed SPIFFE trust domain under that key. Production deployments should pin every key from day one so a compromised partner key cannot impersonate an actor in another federation peer's trust domain.

### Trust list

Each `trust_list` entry names a trusted signing key and what it is allowed to sign for.

- `key_id` — opaque identifier echoed in receipts so an auditor can trace which trusted key validated which envelope.
- `public_key` — REQUIRED. Ed25519 public key, either raw 64-character hex or the versioned `pipelock-ed25519-public-v1` format emitted by Pipelock signing tooling. Validated at config-load.
- `well_known_url` — optional metadata pointer. Validated as HTTPS at config-load. Inbound verification does NOT fetch from this URL; it is for human and tooling provenance. To rotate keys, update `public_key`.
- `trust_domains` — optional. When non-empty, restricts the actor SPIFFE trust domain a signed envelope can claim under this key. When empty, the key signs for any SPIFFE trust domain accepted by the current `actor_format`.

Key rotation is a config change. Edit `public_key`, hot-reload (`SIGHUP` or fsnotify watch), and the new key is in effect. There is no automatic well-known fetch.

## TLS termination and target URIs

Inbound signatures bind RFC 9421 `@target-uri`. For ordinary origin-form HTTP requests, Pipelock reconstructs the absolute target URI from the actual listener state: `https` when the request arrived over TLS, `http` otherwise, plus the request `Host` and path/query.

Pipelock intentionally does not trust `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded`, or similar headers for this reconstruction. Those headers are caller-controlled unless a trusted frontend strips and rewrites them, and trusting them in the verifier would create a downgrade or host-spoofing path.

For signed inbound mediator endpoints, terminate TLS at Pipelock itself, use mTLS to the Pipelock listener, or have a trusted local mediator re-sign after TLS termination. If an ingress, ALB, CDN, or reverse proxy terminates public HTTPS and forwards plaintext HTTP to Pipelock, peers that signed `https://...` will fail closed because Pipelock correctly reconstructs `http://...`.

## Outbound signing — over-cap body limitation

When Pipelock signs an outbound mediated request, the signer buffers the request body up to `mediation_envelope.max_body_bytes` (default 1 MiB) to compute the RFC 9421 `Content-Digest` header. If the body exceeds the cap, **the request is still signed**, but `Content-Digest` is dropped from the declared component list and the signature covers headers + envelope only — NOT the body.

A standards-compliant RFC 9421 verifier reads the declared component list (`@signature-params`) and knows the body was not covered. **Partners running non-compliant or bespoke verifiers may miss this** and believe the body was authenticated.

**Mitigation today:** ensure your federation peers verify the declared component list and fail-closed on missing `content-digest` for body-bearing requests. Pipelock's own inbound verifier (`verify_inbound`) does this correctly.

**Operator config:** raise `mediation_envelope.max_body_bytes` to cover your peak request size if your federation partners cannot enforce the declared component list. The cap is buffer-cost driven, not security-driven; lifting it preserves digest coverage at the cost of memory per signed request.

**v2.5 plan:** add `mediation_envelope.fail_closed_oversize_body: true` to refuse to emit a signature when the body exceeds the cap. Default-off in v2.5 for migration; default-on in v2.6+.

## Replay cache

The replay cache keys on the envelope nonce, not on URL or body. Legitimate retries with different bodies still verify (they have different nonces); a captured signed envelope cannot be replayed within the cache window.

The cache is in-process. Multi-replica deployments (HA pairs, load-balanced sidecars) need to size the window slightly larger than their failover RTT so a request that arrives at replica B after replica A has already verified it does not falsely fail the second replica. Cross-replica nonce sharing is out of scope.

## SPIFFE actor format

Outbound envelopes write SPIFFE format by default:
`spiffe://<trust-domain>/agent/<name>` for individual agents,
`spiffe://<trust-domain>/mediators/<deployment-id>` for the mediator itself.

Inbound requires SPIFFE by default. Operators can temporarily set
`mediation_envelope.actor_format: legacy` to accept free-form actor strings
from older trusted peers during migration.

SPIFFE parsing follows the SPIFFE-ID §2 spec:

- Trust domain must be a bare DNS name. No userinfo, no port, no query, no fragment.
- Trust domain MUST NOT be an IPv4 or IPv6 literal. Pipelock rejects IP-address trust domains both in SPIFFE actor parsing and in config validation, so a federation peer cannot impersonate a domain by claiming a numeric host.
- Workload path must be non-empty and canonical (no empty, `.`, or `..` segments) so allowlist checks comparing the workload as a string cannot be bypassed via path traversal.
- Scheme must be exactly `spiffe`.

Pipelock rejects malformed SPIFFE IDs at envelope verification time. Legacy
free-form actors are accepted only when `mediation_envelope.actor_format` is
set to `legacy`.

## Trust CLI

Use `pipelock envelope trust` to manage the local operator trust list used for
manual envelope verification and peer onboarding:

```sh
pipelock envelope trust add partner.example --key <64-char-ed25519-public-key-hex>
pipelock envelope trust add spiffe://partner.example/agent/proxy \
  --source https://partner.example/.well-known/http-message-signatures-directory
pipelock envelope trust list
pipelock envelope trust list --json
pipelock envelope trust verify --stdin < signed-request.http
pipelock envelope trust remove partner.example
```

The default trust store is
`$XDG_STATE_HOME/pipelock/envelope/trust.json` (or
`~/.local/state/pipelock/envelope/trust.json` when `XDG_STATE_HOME` is unset)
and is written with `0o600` permissions. Its containing directory
(`$XDG_STATE_HOME/pipelock/envelope` or
`~/.local/state/pipelock/envelope`) is created with `0o750` permissions.
`--store` intentionally selects an operator-controlled alternate path.
`--source` fetches a public verification key from a well-known HTTP Message
Signatures directory. Only use `--source` for a directory you already intend to
trust; the fetched key becomes local trust material for operator verification
workflows.

Adding a peer to this store does not change runtime admission. Inbound proxy
verification still uses the pinned keys in
`mediation_envelope.verify_inbound.trust_list` in `pipelock.yaml`; update that
config and reload the proxy to change what runtime traffic can present.

## Well-known directory

Pipelock serves a directory of its current signing keys at the standard well-known path:

```http
GET https://<pipelock-host>/.well-known/http-message-signatures-directory
```

Response (per RFC 9421):

```json
{
  "keys": [
    {
      "keyid": "<key-id>",
      "alg": "ed25519",
      "public_key": "<64-char-hex-ed25519-public-key>",
      "use": "pipelock-mediation"
    }
  ]
}
```

External verifiers fetch this endpoint on a configurable interval and use it as the source of truth for the deployment's current outbound mediation-envelope signing keys.

The directory is served on the same listener as the proxy. There is no auth on the endpoint; the keys are public verification keys, not secrets. If you do not want this endpoint exposed publicly, gate it at your ingress layer.

### Prepared `pipelock-verify-python` 0.2.0 example

The prepared Python verifier update includes a directory-fetch helper:

```python
from pipelock_verify import fetch_directory, verify

directory = fetch_directory("https://pipelock.example.com")
result = verify(receipt, public_key_hex=directory.public_key_hex())
if not result.valid:
    raise SystemExit(f"verification failed: {result.error}")
```

The 0.1.x example pinned a SHA hex out of band; the prepared 0.2.0 update uses well-known fetch to resolve the public key for individual receipt verification once published. See [`receipt-transports.md`](receipt-transports.md) and the Python verifier's README.

## Authenticated agent identity

`X-Pipelock-Agent` and the `?agent=` query parameter are convenience attribution hints, not authenticated identity sources. They are caller-asserted: a reverse-proxy upstream (or any caller that controls the request) can set them to any value.

For inbound verification policy that depends on agent identity, bind the agent through one of:

- **Listener binding.** A dedicated listener per agent, so the listener address is the identity.
- **Source identity.** mTLS client certificate, SPIFFE workload identity, or an authenticated reverse-proxy that strips and re-asserts `X-Pipelock-Agent` only after authenticating the upstream.
- **Source CIDR.** When the deployment topology guarantees a one-to-one mapping between source CIDR and agent.
- **Mediation envelope.** When the caller is itself a Pipelock instance, the envelope's `actor` field carries an authenticated agent identity bound under signature.

Reverse-proxy operators in particular **must not** trust caller-supplied `X-Pipelock-Agent` headers when promoting agent identity into security-relevant decisions (per-agent policy, per-agent allowlist, audit attribution). The convenience attribution hint is for operator dashboards and capture-record provenance, not for authorization.

## Observability

Inbound mediation envelope verification increments `pipelock_envelope_verify_total{result}` on every inbound request when `verify_inbound.enabled: true`. The closed result set is:

| Result | Meaning |
|---|---|
| `disabled` | `verify_inbound.enabled: false`. The counter still increments so an operator can see the configured-off state from metrics alone. |
| `verified` | Signature verified, actor in trust list, nonce not in replay cache. The request proceeded. |
| `missing` | Inbound `Pipelock-Mediation` header was missing while verification was enabled. The request was rejected 403 / `inbound_verify_failed`. |
| `failed` | Signature invalid, actor not trusted, replay detected, or any other verification failure. The request was rejected 403 / `inbound_verify_failed`. |

Watch this counter alongside the capture observability counters in [`learn-and-lock.md`](learn-and-lock.md#operator-metrics) during soak.

## Deployment scenarios

### Two organisations, peer trust

Org A's Pipelock and Org B's Pipelock both run with `mediation_envelope.verify_inbound.enabled: true`. Each pins the other's current `public_key` in `trust_list` and may set `well_known_url` as provenance for humans or external tooling. Inbound verification does not fetch from that URL; rotation is a config update plus hot-reload.

### One organisation, multiple Pipelock instances

Different deployments (region A, region B) sign their own envelopes. A central audit pipeline that wants to verify both maintains a single trust list with both well-known URLs, or pulls the keys into a curated registry that both regions publish to.

### External auditor

The auditor doesn't run Pipelock at all. They can use the standalone Go `pipelock-verifier` today, or `pipelock-verify-python` after the prepared 0.2.0 update is published, against the Pipelock deployment's well-known directory. The auditor verifies individual receipts the deployment emits without ever needing the deployment's blessing — the public verification keys are public, the directory endpoint is open.

## Receipt verification

A request that traverses two mediated Pipelocks accumulates two layers of signed evidence:

1. The originating Pipelock signs an outbound envelope.
2. The receiving Pipelock verifies the inbound envelope and emits its own outbound envelope on the next hop (or on the response). The `EvidenceReceipt v2` schema reserves `proxy_decision.policy_sources` for runtime contract-aware decision evidence as that emit path is wired progressively.

External auditors verify both envelopes independently using the standalone Go `pipelock-verifier` today, or `pipelock-verify-python` after the prepared 0.2.0 update is published, against the corresponding deployments' well-known directories.

## Failure modes

All failures reject the request with HTTP 403 and increment `pipelock_envelope_verify_total{result="failed"}`. The receipt and audit-event `result` field carries a more specific `inbound_verify_*` pattern so operators can diagnose without re-running verification:

| Failure | Receipt / audit pattern |
|---|---|
| Inbound signature invalid | `inbound_verify_signature` |
| Inbound digest mismatch | `inbound_verify_digest` |
| Inbound parse error (envelope structure malformed) | `inbound_verify_parse` |
| Inbound actor not in trust list | `inbound_verify_not_trusted` |
| Replay (nonce already seen within cache window) | `inbound_verify_replay` |
| Inbound envelope expired (timestamp outside the replay window) | `inbound_verify_expired` |
| Inbound signature missing while `verify_inbound.enabled: true` | `inbound_verify_missing` |
| Other / uncategorised verification failure | `inbound_verify_failed` |

Pipelock requires the `Pipelock-Mediation` header on every inbound request when verification is enabled. The missing-header check runs before any body buffering, so unsigned callers fail cheaply. To accept unsigned mediator-less traffic, leave `verify_inbound.enabled` false.

Do not enable `verify_inbound` on a listener that ordinary agents, browsers,
CI jobs, or package managers call directly unless those clients are wrapped by
a component that signs Pipelock mediation envelopes. `verify_inbound` verifies
the caller-to-Pipelock hop; it is meant for Pipelock-to-Pipelock federation or
other explicitly signed clients. On a normal forward-proxy or fetch-proxy
deployment, enabling it before clients sign envelopes will fail closed with
`inbound_verify_missing`.

## Anti-patterns

- **Turning on `verify_inbound` for unsigned proxy clients.** This is not a
  stricter version of the normal agent egress proxy. It requires the immediate
  caller to present a signed mediation envelope, so unsigned clients fail.
- **Listing a `trust_list` entry without a `public_key`.** The `key_id` field alone is not authentication; `public_key` is required and is the source of truth for verification.
- **Treating `well_known_url` as a key fetcher.** It is metadata. Inbound verification does not fetch from it. Edit `public_key` to rotate.
- **Setting `replay_cache.window` smaller than your network RTT.** Legitimate retries fail.
- **Setting `replay_cache.window` to hours.** Memory grows unbounded; a deployment with high request volume needs a tighter window.
- **Assuming `well_known_url` changes inbound trust automatically.** The directory helps discovery and external verification, but inbound verification uses the pinned `public_key`. Rotate by editing `public_key` and hot-reloading.

## See also

- [`receipt-transports.md`](receipt-transports.md) — receipt verification recipe.
- [`mediation-envelope.md`](mediation-envelope.md) — outbound envelope format and signing.
- [`learn-and-lock.md`](learn-and-lock.md) — `EvidenceReceipt v2` envelope (independent of mediation-envelope verification).
- [`pipelock-verify-python`](https://github.com/luckyPipewrench/pipelock-verify-python) — external Python verifier; prepared v0.2.0 update uses well-known fetch for individual receipt verification once published.
