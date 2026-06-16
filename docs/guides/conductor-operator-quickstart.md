# Conductor Operator Quickstart: Read-Only Fleet Audit

This quickstart takes an operator from zero to a single read-only audit query
against an already-running Conductor. It is the short path for an auditor who
needs to inspect a fleet without changing anything: list enrolled followers,
read the publication-stream state, and query accepted audit-batch metadata.

For standing up a fleet from scratch (CA, follower enrollment, signing a batch,
offline verification), see the
[Conductor Operator Runbook](conductor-operator-runbook.md). For the feature
overview and trust model, see the [Conductor guide](conductor.md).

Conductor is an Enterprise-tier control plane. Its commands only exist in an
enterprise build of Pipelock, and every command fails closed on license
verification before it opens a network connection.

## What you need before you start

1. **An enterprise build of Pipelock.** The public release binary does not carry
   the `conductor` command; it is compiled only with the `enterprise` build tag.

   ```bash
   go build -tags enterprise -o ./pipelock-ent ./cmd/pipelock
   ./pipelock-ent conductor --help
   ```

2. **A fleet license.** The operator command gates on a license that grants the
   `fleet` feature. Provide the token in `PIPELOCK_LICENSE_KEY`. On a build that
   embeds the official license public key, that is all you need. On a build
   compiled without an embedded key, also provide the verifier public key in
   `PIPELOCK_LICENSE_PUBLIC_KEY` as **raw hex** (the embedded key, when present,
   always takes precedence and the environment variable is ignored).

   ```bash
   export PIPELOCK_LICENSE_KEY="$(cat fleet-license.token)"
   # only needed on a build with no embedded license public key:
   export PIPELOCK_LICENSE_PUBLIC_KEY="<64-hex-char public key>"
   ```

   Without a valid fleet license the command stops with an entitlement error and
   never connects.

3. **The Conductor's network address.** The Conductor serves an HTTPS API
   (default `127.0.0.1:8895`). For a remote Conductor use its reachable address,
   for example `conductor.example:8895`.

4. **Connection material for mutual TLS plus a bearer token** — covered next.

## The two-part operator credential

A read-only call authenticates in two independent layers, and you need both:

- **An operator client certificate (mutual TLS).** The Conductor requires and
  verifies a client certificate at the TLS layer (TLS 1.3, `RequireAndVerify`).
  The certificate must be signed by the fleet CA that the Conductor trusts and
  must carry the `clientAuth` extended-key-usage. Operator read endpoints do not
  require a SPIFFE URI SAN — that identity form is only required for a follower
  posting audit batches, not for an operator reading them.
- **A scoped bearer token.** The Conductor authorizes the *application*-layer
  call by role. There are three roles: `publisher` (publish policy), `auditor`
  (read-only), and `admin`. For a read-only audit you use an **auditor** token.
  The token may be scoped to an org and optionally a fleet; a query outside that
  scope is refused with `403`.

The client certificate proves *which machine or operator* is connecting; the
bearer token proves *what that caller is allowed to do*. Both are checked on
every request.

### Mint an operator client certificate from the fleet CA

The certificate must chain to the same CA bundle the Conductor was started with
(its `--client-ca`). Two common paths:

**cert-manager (Kubernetes).** If the fleet CA is represented by a
cert-manager `Issuer`/`ClusterIssuer`, request a short-lived client certificate
with a `Certificate` resource. Set `usages` to include `client auth` and give it
a common name that identifies the operator. cert-manager writes the cert, key,
and CA bundle into a `Secret`; mount or extract those three files. (Exact
`Issuer` and `Secret` names depend on your deployment; this quickstart does not
assume any.)

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: conductor-operator
spec:
  secretName: conductor-operator-tls   # holds tls.crt, tls.key, ca.crt
  duration: 24h
  commonName: operator-auditor
  usages:
    - client auth
  issuerRef:
    name: fleet-ca           # your fleet CA issuer
    kind: Issuer
```

**openssl (generic).** Given the fleet CA certificate (`ca.crt`) and its private
key (`ca.key`), mint a client certificate locally. The key step is the
`clientAuth` extended key usage:

```bash
# 1. operator key + CSR
openssl req -new -newkey ed25519 -nodes \
  -keyout operator.key \
  -out operator.csr \
  -subj "/CN=operator-auditor"

# 2. sign it with the fleet CA, stamping clientAuth EKU and a 24h validity
openssl x509 -req \
  -in operator.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 1 \
  -extfile <(printf 'extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature') \
  -out operator.crt
```

You now have `operator.crt`, `operator.key`, and the fleet `ca.crt`.

### Get an auditor bearer token

The auditor token is configured on the Conductor at startup (its
`--auditor-token-file`). Obtain that token value from whoever operates the
Conductor and place it in a local file readable only by you:

```bash
install -m 0600 /dev/stdin auditor.token <<<"<auditor-bearer-token>"
```

## Connect and run a read-only command

Every operator read command takes the same connection flags:

| Flag | Meaning |
| --- | --- |
| `--server` | Conductor HTTPS base URL (default `https://127.0.0.1:8895`) |
| `--server-name` | TLS server-name override (defaults to the `--server` host) |
| `--ca-file` | PEM bundle for the CA that signed the Conductor's server certificate |
| `--client-cert` | operator client certificate (mutual TLS) |
| `--client-key` | operator client private key |
| `--token-file` | file containing the bearer token |
| `--org-id` | org to query (required) |
| `--fleet-id` | fleet to scope the query (optional) |
| `--json` | emit the raw JSON response instead of a table |

A convenient pattern is to export the connection flags once:

```bash
CONN=(
  --server https://conductor.example:8895
  --ca-file ca.crt
  --client-cert operator.crt
  --client-key operator.key
  --token-file auditor.token
)
```

### List enrolled followers

```bash
./pipelock-ent conductor fleet status "${CONN[@]}" --org-id my-org
```

This prints the enrolled-follower roster for the org: identity (org, fleet,
instance, environment), audit key id, active state, and enrollment time. Add
`--fleet-id` or `--instance-id` to narrow the scope, `--limit N` to cap the
list, or `--json` for the raw response. `conductor followers` is an alias for
the same command.

> The roster is enrollment metadata only. The Conductor does not track each
> follower's applied policy version or last-contact time, so those are not
> reported.

### Read the publication-stream state

```bash
./pipelock-ent conductor stream status "${CONN[@]}" --org-id my-org
```

This summarizes each publication stream: the current head version and hash, the
highest-ever published version (the monotonicity gate), whether an active
rollback caps the head, and the active remote-kill and rollback authorizations
in scope. If the emergency-control store could not be read, the output says so
explicitly rather than letting an empty list read as "nothing active."

For the full stream detail including every bundle chain, use:

```bash
./pipelock-ent conductor stream inspect "${CONN[@]}" --org-id my-org
```

`inspect` always emits the raw JSON response.

### Query accepted audit-batch metadata

```bash
./pipelock-ent conductor audit query "${CONN[@]}" --org-id my-org
```

This lists the most recent accepted audit batches for the scope. The response is
**metadata only** — sequence ranges, hashes, counts, and timestamps. Raw audit
evidence stays behind the Conductor's storage backend and is never returned over
this endpoint. To fetch a single batch, pass `--batch-id` together with
`--fleet-id` and `--instance-id`; add `--limit N` to cap the list.

## What authorization is enforced

The Conductor enforces scope, fail-closed:

- A bearer token that is not `auditor` or `admin` is refused on a read query.
- An `auditor`/`admin` token scoped to one org/fleet cannot read another. A
  query with the wrong `--org-id` returns `403` even though the certificate and
  token are otherwise valid.
- The mutual-TLS layer rejects any client certificate that does not chain to the
  Conductor's configured client CA.

These checks are enforced by the Conductor binary. Whether an agent's traffic is
actually mediated by Pipelock in the first place — that is, that nothing reaches
the network around the proxy — remains a deployment property (capability
separation, container or network policy, per-user egress control), not something
the audit query itself can prove.

## Quickstart done-state

You have completed this quickstart when, against a running Conductor:

1. `conductor fleet status --org-id <org>` returns the enrolled-follower roster.
2. `conductor stream status --org-id <org>` returns the stream summary.
3. `conductor audit query --org-id <org>` returns audit-batch metadata.
4. The same query with a wrong `--org-id` returns `403` (scope is enforced).

All four use only read-only commands and an auditor token; none mutates fleet
state.
