# Request Policy (GraphQL) Example

Runnable walkthrough for Pipelock **request_policy** on GraphQL-over-HTTP:
benign queries forward, protected mutations are denied, and parse errors on the
matched route fail closed.

This is **operation intent control** (which GraphQL fields may run), not SSRF,
DLP, or static MCP tool denylists.

Fully offline: local Python GraphQL stub + forward proxy (`HTTP_PROXY` /
absolute-URI). `/fetch` is GET-only and does **not** evaluate GraphQL POST bodies.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Allow query | `query { record { id } }` reaches upstream (HTTP 200) |
| Block mutation | `mutation { deleteRecord … }` → 403 `request_policy_deny` |
| Alias still blocked | `rm: deleteRecord` still matches the root field |
| Parse fail-closed | Malformed GraphQL on `/graphql` → 403 |

## Prerequisites

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
```

## Quick Verify

From the repository root:

```bash
./examples/request-policy-graphql/verify.sh
```

## Manual Try

Start the stub API and pipelock (see `verify.sh`), then:

```bash
# --noproxy '' clears env no_proxy so 127.0.0.1 traffic still goes via pipelock
curl -sS --noproxy '' -x "http://127.0.0.1:PROXY" -X POST "http://127.0.0.1:API/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"query":"query { record { id } }"}'

curl -sS --noproxy '' -D - -x "http://127.0.0.1:PROXY" -X POST "http://127.0.0.1:API/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"query":"mutation { deleteRecord { id } }"}'
# expect X-Pipelock-Block-Reason: request_policy_deny
```

## Config Notes

- `forward_proxy.enabled: true` is required for absolute-URI inspection.
- Route `hosts` must match the URL host exactly (`127.0.0.1` ≠ `localhost`).
- See `../../docs/guides/request-policy.md`.

## Contributing

Improvements welcome: JSON discriminator rule, or batch GraphQL case. Open a PR
against `main`.
