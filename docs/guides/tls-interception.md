# TLS Interception Setup Guide

Pipelock can intercept CONNECT tunnel traffic by performing a TLS MITM: it terminates TLS with the client using a forged certificate, scans the decrypted request and response, then forwards to the upstream server over a separate TLS connection. This closes the body-blindness gap that exists with opaque CONNECT tunnels.

Without TLS interception, CONNECT tunnels only get hostname-level scanning (blocklist, SSRF, rate limiting). With it, you get full DLP on request bodies/headers and response injection detection.

## Quick Start

```bash
# 1. Generate a CA
pipelock tls init

# 2. Trust it (prints platform-specific instructions)
pipelock tls install-ca

# 3. Enable in config
cat >> pipelock.yaml << 'EOF'
tls_interception:
  enabled: true
EOF

# 4. Run
pipelock run --config pipelock.yaml
```

## Step 1: Generate the CA

```bash
pipelock tls init
```

This creates two files in `~/.pipelock/`:
- `ca.pem`: the CA certificate (share this, it's public)
- `ca-key.pem`: the CA private key (protect this, `0600` permissions)

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | `~/.pipelock` | Output directory |
| `--org` | `Pipelock` | Organization name in certificate subject |
| `--validity` | `87600h` (10 years) | How long the CA is valid |
| `--force` | `false` | Overwrite existing files |

Custom output directory:

```bash
pipelock tls init --out /etc/pipelock/tls --org "My Company"
```

If using a custom directory, set `ca_cert` and `ca_key` in your config:

```yaml
tls_interception:
  enabled: true
  ca_cert: /etc/pipelock/tls/ca.pem
  ca_key: /etc/pipelock/tls/ca-key.pem
```

> **Use `pipelock tls init` — don't hand-mint the CA with openssl RSA.** Pipelock's CA loader (`certgen.LoadCA`) calls `x509.ParseECPrivateKey` on the key file, so it requires an ECDSA private key (any curve the `crypto/ecdsa` package accepts — P-224, P-256, P-384, P-521). RSA and Ed25519 CA keys are rejected at startup with `load TLS CA: parse ec private key` and pipelock exits rather than run without interception. `pipelock tls init` generates a P-256 ECDSA CA, which is what end-entity certs pipelock mints at runtime also use; if you need an org-rooted CA chain, an ECDSA intermediate (e.g. `openssl ecparam -name prime256v1`) signed from your root will load. End-entity certs for your upstream servers signed by this CA can be RSA without issue — the ECDSA constraint is only on the CA key itself.

## Step 2: Trust the CA

The agent (or whatever makes HTTPS connections through pipelock) must trust the CA certificate. Otherwise TLS handshakes fail with certificate verification errors.

### System Trust Store

```bash
pipelock tls install-ca
```

This prints platform-specific instructions. You still need to run the commands it shows.

**Linux (Debian/Ubuntu):**
```bash
sudo cp ~/.pipelock/ca.pem /usr/local/share/ca-certificates/pipelock-ca.crt
sudo update-ca-certificates
```

**Linux (RHEL/Fedora):**
```bash
sudo cp ~/.pipelock/ca.pem /etc/pki/ca-trust/source/anchors/pipelock-ca.crt
sudo update-ca-trust extract
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.pipelock/ca.pem
```

**Windows (elevated Command Prompt):**
```cmd
certutil -addstore -f "ROOT" %USERPROFILE%\.pipelock\ca.pem
```

### Per-Application Trust

Some tools ignore the system trust store. Set the CA path explicitly:

**Node.js / npm:**
```bash
export NODE_EXTRA_CA_CERTS=~/.pipelock/ca.pem
```

**Python (requests/httpx):**
```bash
export REQUESTS_CA_BUNDLE=~/.pipelock/ca.pem
export SSL_CERT_FILE=~/.pipelock/ca.pem
```

**Go:**
```bash
export SSL_CERT_FILE=~/.pipelock/ca.pem
```

**curl:**
```bash
curl --cacert ~/.pipelock/ca.pem https://example.com
# Or set globally:
export CURL_CA_BUNDLE=~/.pipelock/ca.pem
```

## Step 3: Configure

Minimal config:

```yaml
tls_interception:
  enabled: true
```

Full options:

```yaml
tls_interception:
  enabled: true
  ca_cert: ""                    # default: ~/.pipelock/ca.pem
  ca_key: ""                     # default: ~/.pipelock/ca-key.pem
  max_response_bytes: 5242880    # 5MB, block responses larger than this
  passthrough_domains:           # bypass interception for these domains
    - "*.pinned-service.com"
    - "api.payment-provider.com"
```

### Passthrough Domains

Some services use certificate pinning or mutual TLS that breaks under interception. Add them to `passthrough_domains`:

```yaml
tls_interception:
  enabled: true
  passthrough_domains:
    - "*.apple.com"              # Apple services pin certificates
    - "mtls.internal.corp.com"   # mTLS endpoint
```

Passthrough connections are spliced (bidirectional byte copy) without decryption. Hostname-level scanning (blocklist, SSRF, SNI verification) still applies.

Supports exact match (`api.example.com`) and wildcard prefix (`*.example.com` matches `sub.example.com` and the apex `example.com` itself).

### Fail-Closed Behavior

TLS interception is fail-closed:
- Compressed responses (Content-Encoding other than identity): blocked (scanning would be bypassed)
- Responses larger than `max_response_bytes`: blocked
- TLS handshake failures: connection closed
- Certificate generation errors: connection closed

## Verifying It Works

```bash
# Start pipelock with TLS interception
pipelock run --config pipelock.yaml &

# Test through the proxy (should succeed)
HTTPS_PROXY=http://127.0.0.1:8888 curl -s https://example.com

# Test DLP through CONNECT tunnel (should be blocked)
HTTPS_PROXY=http://127.0.0.1:8888 \
  curl -s "https://httpbin.org/post" \
  -d "token=AKIAIOSFODNN7EXAMPLE"
```

Check the pipelock logs (stderr) for scan results.

## Troubleshooting

### "certificate signed by unknown authority"

The agent doesn't trust the pipelock CA. Either:
1. Install the CA in the system trust store (Step 2)
2. Set the per-application CA env var (see above)
3. Add the domain to `passthrough_domains` if you can't modify the client

### "x509: certificate is valid for X, not Y"

The hostname in the request doesn't match what pipelock generated. This usually means a DNS or proxy misconfiguration. Check that `HTTPS_PROXY` is set correctly and the target hostname resolves properly.

### Compressed response blocked

Pipelock blocks compressed responses during interception because it can't scan content it can't read. The upstream server sent `Content-Encoding: gzip` (or similar). Pipelock's transport sets `Accept-Encoding: identity` to request uncompressed responses, but some servers ignore this.

If you trust the domain, add it to `passthrough_domains`.

### Performance

TLS interception adds latency for the MITM handshake. Pipelock mitigates this with:
- Connection pooling (shared `http.Transport` reuses TCP+TLS connections)
- Bounded certificate cache (avoids regenerating leaf certs for repeated hosts)
- ECDSA P-256 keys (faster than RSA for signing)

For high-throughput environments, consider using passthrough for trusted high-volume domains.
