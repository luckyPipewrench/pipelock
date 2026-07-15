# Flight Recorder Guide

The flight recorder writes every enforcement decision pipelock makes to a hash-chained, tamper-evident evidence log. Each entry is cryptographically linked to the one before it, so any deletion or modification breaks the chain. Signed checkpoints let auditors verify the chain was intact at specific points in time without replaying every entry. The recorder is designed for post-incident investigation, compliance evidence, and forensic replay.

**On by default.** `enabled` defaults to `true` so receipts are available out of the box ("verify the boundary"). It only *records* once a `dir` and a signing key are configured, though: without them the recorder is inert and writes nothing, so the default flip never breaks an existing config. `pipelock init` generates a recorder directory and an Ed25519 signing key and writes them into the config, which is what makes receipts live. Receipt emission is best-effort by default; set `require_receipts: true` when allow-path receipt failures must fail closed before traffic is forwarded.

## What Gets Recorded

The recorder captures two categories of evidence:

- **Enforcement decisions**: every allow, block, warn, redirect, and ask verdict with the scanner layer, pattern name, match text, transport, and tool name that triggered it.
- **Checkpoint entries**: periodic summaries covering N entries, with an Ed25519 signature over the chain state.

Each entry has a type field. Common types: `decision`, `checkpoint`. Session IDs tie entries to a specific proxy session.

## Configuration

Add a `flight_recorder` block to your `pipelock.yaml`:

```yaml
flight_recorder:
  enabled: true
  dir: /var/lib/pipelock/evidence
  checkpoint_interval: 1000      # entries between signed checkpoints
  retention_days: 90             # auto-expire files older than 90 days (0 = forever)
  redact: true                   # DLP redaction before commit (recommended)
  require_receipts: false        # fail closed before forwarding when allow receipts cannot be emitted
  sign_checkpoints: true         # Ed25519 signed checkpoints
  signing_key_path: /etc/pipelock/keys/flight-recorder-signing.key   # `pipelock init` writes this next to your config
  max_entries_per_file: 10000    # rotate to a new file after this many entries
  raw_escrow: false              # encrypted raw sidecar (see below)
  escrow_public_key: ""          # X25519 hex public key for raw escrow
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | true | Master switch. **On by default.** Recording requires `dir` and a signing key too — `enabled: true` with no `dir` is inert (nothing is written), not an error. Set `enabled: false` to opt out. |
| `dir` | (empty) | Directory for evidence files. The recorder stays inert until this is set; created if absent. `pipelock init` generates one. |
| `checkpoint_interval` | 1000 | How many entries between signed checkpoints. |
| `retention_days` | 0 | Auto-expire files after N days. 0 = never expire. |
| `redact` | true | DLP scan each entry before writing. Replaces matched content with a redaction marker. |
| `require_receipts` | false | Require receipt emission before allow-path traffic is forwarded. When true, missing or failed receipt emission blocks the action with `receipt_emission_failed`; block-path receipts remain best-effort because the action is already denied. |
| `sign_checkpoints` | true | Sign each checkpoint with the agent's Ed25519 private key. |
| `max_entries_per_file` | 10000 | Rotate to a new JSONL file after this many entries. |
| `raw_escrow` | false | Write an encrypted sidecar with the unredacted detail for each entry. |
| `escrow_public_key` | "" | X25519 hex public key for escrow encryption. Required when `raw_escrow: true`. |

The receipt-signing private key is loaded from
`flight_recorder.signing_key_path`.

`pipelock init` and `pipelock contain install` also write a public-key sidecar
next to that private key at `<signing_key_path>.pub`. The sidecar contains the
64-hex Ed25519 public key that verifiers pin with `--key`; it is safe to share.
Never share the private key file itself.

For an existing install, or to refresh the sidecar without rotating the key:

```bash
pipelock signing pubkey --config /etc/pipelock/pipelock.yaml --out /etc/pipelock/keys/flight-recorder-signing.key.pub
```

You can also derive from the private key directly:

```bash
pipelock signing pubkey --key-file /etc/pipelock/keys/flight-recorder-signing.key
```

### Fail-closed receipts (`require_receipts`)

By default receipt emission is best-effort: if signing or the recorder fails,
the decision is logged and traffic still flows (evidence, not enforcement). Set
`require_receipts: true` to make an *allow-path* receipt a precondition for
forwarding. When it is on, pipelock emits the allow receipt **before** the
request leaves the proxy; if that emission fails it blocks with
`receipt_emission_failed` instead of egressing. This is enforced on every
egress transport — `/fetch`, forward proxy, CONNECT tunnel admission,
TLS-intercepted CONNECT inner HTTP requests, WebSocket, reverse proxy, MCP
stdio, and MCP HTTP. Block-path receipts stay best-effort because the action is
already denied.

Two operational notes:

- **It needs a live signed recorder.** `require_receipts` has nothing to emit
  unless `enabled`, `dir`, and `signing_key_path` are all set. With no live
  emitter every request would fail closed, so `pipelock run` and
  `pipelock mcp proxy` **refuse to start** in that state rather than serve an
  all-blocked proxy. `require_receipts` is hot-reloadable, but because the
  recorder is built once at startup, enabling it via reload without a recorder
  only logs a warning — restart with a recorder configured to actually use it.
- **An allowed request that is later blocked carries two receipts.** The
  pre-egress allow receipt attests the egress *decision*; if response scanning
  then blocks the reply, a block receipt is emitted under the **same
  `action_id`**. Under `require_receipts` you will therefore see an allow
  followed by a block for one action — the request did egress, and the response
  was blocked separately.

### Default-on footguns (handled)

Because the recorder is on by default, two footguns are bounded by the defaults — keep them in mind if you change them:

- **Disk growth.** Evidence files rotate at `max_entries_per_file` (default 10000) and can auto-expire with `retention_days`. Leave rotation on so a busy proxy cannot silently fill the disk; set `retention_days` for a hard cap.
- **Privacy.** Receipts record the *targets* of mediated traffic. `redact` (default `true`) DLP-scrubs each entry before it touches disk so secrets are not persisted in the clear. Do not disable it unless you have a separate control around the evidence directory.
- **Sign-without-a-key.** `sign_checkpoints` defaults to `true`, so once you set a `dir` the recorder expects a signing key. Starting a persisting recorder with `sign_checkpoints: true` and no `signing_key_path` is a hard startup error (it would otherwise write checkpoints with an empty signature that `verify-receipt` later rejects as "missing signature"). Provide `signing_key_path`, or set `sign_checkpoints: false` for an explicitly unsigned hash-chained recorder. `pipelock init` sets both, so this only bites hand-written configs.

### Completeness anchor (transcript root)

On a **clean shutdown** the recorder seals the chain with a `transcript_root` entry: a single record naming the final sequence number and the chain's root hash. This is the completeness anchor — `verify-receipt --chain` can confirm the chain reached the sealed root rather than reporting a chain that was silently truncated at the tail as VALID.

Scope and limits:

- **Clean exit only.** The root is written during graceful shutdown, after in-flight receipt emits have drained (drain-then-seal). A `SIGKILL` (or power loss) terminates the process before the seal runs, so the tail is truncated with no root. Detecting that case requires an external/periodic anchor and is not closed here.
- **Restart resumes cleanly.** A transcript root is a per-run checkpoint, not a permanent seal. The next start resumes emission into the same hash-linked chain (a continuous chain still verifies), so receipts are never silently bricked by a prior clean shutdown.

### Key-free evidence capture (`--capture-output`)

Signed action receipts require a signing key. To capture evidence **without** a
key, use the `--capture-output` flag, available on both the HTTP proxy and the
MCP proxy:

```bash
pipelock run --capture-output /var/lib/pipelock/evidence
pipelock mcp proxy --capture-output /var/lib/pipelock/evidence -- node server.js
```

This writes `evidence-*.jsonl` for every scan verdict (DLP, injection,
tool-policy, CEE) across all transports — including all MCP transports (stdio,
streamable-HTTP, HTTP-reverse, WS-listener) — using the same on-disk format as
the signed recorder, minus the signatures. Pass `--capture-escrow-public-key`
(64 hex chars / 32 bytes) to encrypt payload sidecars. Captured payloads are
DLP-redacted before they reach disk unless `flight_recorder.redact` is set to
`false`. Signed receipts (`signing_key_path`) and key-free capture
(`--capture-output`) are independent evidence streams and can run together.

### Windows file-permission enforcement

The signing-key, license, secrets, CA-key, salt, and `--header-file` loaders
enforce strict file permissions on Unix as a fail-closed gate (a key readable or
writable by group/other is rejected before it is read). On Windows this check is
**skipped**: Go derives the file mode from the read-only attribute and never
reflects the NTFS ACL, so the reported bits (`0666`/`0444`) are not
security-meaningful — enforcing the Unix mask would reject every key. Enforce
access control on Windows with NTFS ACLs at deployment time; Pipelock does not
inspect them.

### Rotating the signing key

Pipelock **rejects `flight_recorder.signing_key_path` changes at hot-reload time.** If you edit the config and SIGHUP (or rely on fsnotify), pipelock keeps the previously loaded key in memory, logs `WARNING: config reload: flight_recorder.signing_key_path changed — receipt chain cannot rotate at runtime, ignoring (restart required)`, and continues signing with the old key. This is intentional: rotating the key mid-run would break chain verification (consumers would see entries signed with two different public keys under one `chain_id`). To rotate safely:

1. Stop pipelock so the old chain closes cleanly at its last checkpoint.
2. Swap the key file referenced by `signing_key_path`.
3. Start pipelock. On resume it detects the key change and opens a new chain
   **segment** that is cryptographically linked to the old one (see below).

If you keep the same `signing_key_path` and replace the key file at
that path, a reload re-reads the file contents. Treat that as an
advanced operation: the documented operator-safe path is still a
restart so the old chain closes cleanly before the new key starts
signing.

The new segment is a linked verifiable unit, not an orphan: its first receipt
carries a `KeyTransition` marker and links to the prior segment's tail hash, so
`pipelock verify-receipt --chain DIR --key old.pub --key new.pub` verifies
continuously across the rotation and lists each segment's signer for you to
confirm. Earlier builds opened a fully *separate* chain here — and, worse, could
brick emission entirely when the resume saw the rotation; both are fixed, and a
rotated chain now stays offline-verifiable. See the
[receipt verification guide](receipt-verification.md#chains-that-rotated-the-signing-key)
for the verification flow.

## Evidence File Format

Each file is named `evidence-<session_id>-<seq_start>.jsonl`. One JSON object per line. Example entry:

```json
{
  "v": 1,
  "seq": 42,
  "ts": "2026-03-01T10:00:00.123456789Z",
  "session_id": "abc123",
  "type": "decision",
  "transport": "forward",
  "summary": "block: dlp (AWS access key pattern)",
  "detail": {
    "version": 1,
    "type": "decision_record",
    "session_id": "abc123",
    "timestamp": "2026-03-01T10:00:00.123456789Z",
    "verdict": "block",
    "scanner_result": {
      "layer": "dlp",
      "pattern": "AWS access key pattern",
      "match_text": "[REDACTED:AWS access key pattern]",
      "confidence": "high"
    },
    "policy_rule": {
      "source": "dlp",
      "section": "dlp.patterns"
    },
    "request_context": {
      "transport": "forward"
    }
  },
  "prev_hash": "a1b2c3d4...",
  "hash": "e5f6a7b8..."
}
```

Fields:

| Field | Description |
|-------|-------------|
| `v` | Schema version. Readers must reject unknown versions. |
| `seq` | Monotonically increasing sequence number within the session. |
| `ts` | RFC 3339 timestamp with nanosecond precision. |
| `session_id` | Proxy session identifier. |
| `type` | Entry type: `decision`, `checkpoint`. |
| `transport` | Proxy transport: `fetch`, `forward`, `connect`, `websocket`, `mcp-stdio`, `mcp-http`. |
| `summary` | One-line human-readable description. |
| `detail` | Typed payload. For `decision` entries, a `DecisionRecord`. For `checkpoint`, a `CheckpointDetail`. |
| `raw_ref` | Filename of the encrypted escrow sidecar, if present. |
| `prev_hash` | SHA-256 hex hash of the previous entry. First entry has `"genesis"`. |
| `hash` | SHA-256 hex hash of this entry over all fields except `hash`. |

## Hash Chain

The hash covers all entry fields joined with null-byte separators:

```
SHA256(v \0 seq \0 ts \0 session_id \0 trace_id \0 type \0 transport \0 summary \0 detail_json \0 raw_ref \0 prev_hash)
```

The first entry in a chain has `prev_hash: "genesis"`. Each subsequent entry's `prev_hash` must equal the `hash` of the previous entry. Any gap, deletion, or modification breaks the chain.

To verify a chain:

```go
entries, _ := recorder.ReadEntries("evidence-abc123-0.jsonl")
err := recorder.VerifyChain(entries)
```

Pass a public key to also verify checkpoint signatures:

```go
err := recorder.VerifyChain(entries, pubKey)
```

## Checkpoints

A checkpoint entry is written every `checkpoint_interval` entries and at `Close()`. The checkpoint detail contains:

```json
{
  "entry_count": 1000,
  "first_seq": 0,
  "last_seq": 999,
  "signature": "ed25519-hex-signature"
}
```

The signature covers the `prev_hash` of the checkpoint entry, which represents the cumulative chain state up to that point. Verifying the checkpoint signature confirms the chain was intact at that exact point, without re-hashing every entry.

To verify checkpoints independently:

```go
entries, _ := recorder.ReadEntries(path)
err := recorder.VerifyCheckpoints(entries, pubKey)
```

Checkpoints without signatures are rejected if a public key is provided.

## DLP Redaction

When `redact: true`, each entry's `detail` field is scanned by the DLP engine before being written. If a DLP pattern matches, the entire `detail` is replaced with a redaction marker:

```json
{
  "redacted": true,
  "detected_patterns": ["[REDACTED:AWS access key pattern]"],
  "original_size": 412
}
```

Redaction is surgical at the entry level but wholesale at the detail level: if any pattern matches, the entire detail is replaced. The original_size field lets you confirm the content existed and measure how much was withheld.

When `raw_escrow: true`, the unredacted detail is preserved in an encrypted sidecar before redaction runs. This gives you forensic replay capability without storing plaintext secrets in the main evidence file.

## Raw Escrow

Raw escrow writes an encrypted sidecar file alongside each evidence entry:

```
evidence-abc123-42.raw.enc
```

The sidecar is encrypted with X25519 NaCl box using an ephemeral key pair. The format is:

```
[32 bytes: ephemeral public key] [24 bytes: nonce, prepended to ciphertext] [ciphertext]
```

To decrypt, you need the private key corresponding to `escrow_public_key`. Decryption is your responsibility; pipelock only writes the sidecar.

To enable raw escrow:

```yaml
flight_recorder:
  enabled: true
  dir: /var/lib/pipelock/evidence
  signing_key_path: /etc/pipelock/keys/flight-recorder-signing.key   # `pipelock init` writes this next to your config
  redact: true
  raw_escrow: true
  escrow_public_key: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"  # 32-byte X25519 key, 64 hex chars
```

Generate an X25519 key pair with standard Go tooling or a library of your choice. Store the private key offline (not on the pipelock host). The escrow public key is safe to include in config.

Raw escrow is off by default. Enable it only if you need forensic replay capability and have a key management process for the escrow private key.

## Session Querying

Query evidence for a specific session:

```go
result, err := recorder.QuerySession(
    "/var/lib/pipelock/evidence",
    "abc123",
    &recorder.QueryFilter{
        Type:      "decision",
        Transport: "forward",
    },
)
```

Filter fields:

| Field | Description |
|-------|-------------|
| `SessionID` | Exact match. Empty = all sessions. |
| `Type` | Entry type filter. |
| `Transport` | Transport filter. |
| `After` | Include entries after this time. |
| `Before` | Include entries before this time. |
| `MinSeq` | Include entries at or above this sequence number. |
| `MaxSeq` | Include entries at or below this sequence number. |

List sessions with recorded evidence:

```go
sessions, err := recorder.ListSessions("/var/lib/pipelock/evidence")
```

## File Rotation and Retention

Files rotate when a file reaches `max_entries_per_file` entries. The new file picks up where the old one left off, with the new file's first entry linking to the last entry in the previous file via `prev_hash`.

Auto-expire removes evidence files older than `retention_days` days based on file modification time. Call `recorder.ExpireOldFiles()` periodically to trigger cleanup. Expiry is not automatic. You need to call it on a schedule (a cron job, or at startup).

Expired files are gone. If you need longer retention, either increase `retention_days` or copy evidence files to external storage before they expire.

## Integration with Session Manifest and AgBOM

The flight recorder is one component of a larger evidence pipeline. When pipelock assess runs, the evidence directory can be included as an annex in the assessment bundle. The recorded decisions provide a per-session audit trail that complements the assessment's aggregate scoring.

For compliance purposes, the combination of:
- Hash-chained JSONL evidence (tamper detection)
- Ed25519 signed checkpoints (tamper-evidence with point-in-time proof)
- Optional X25519 encrypted raw escrow (forensic replay)

provides a defensible evidence record for incident investigation and regulatory audits.

## Verifying Evidence Files Externally

Compute the SHA-256 of an evidence file for external verification:

```go
hash, err := recorder.ComputeFileHash("/var/lib/pipelock/evidence/evidence-abc123-0.jsonl")
```

This hash can be committed to an external ledger or included in an assessment artifact manifest to prove the evidence file has not been modified.

### Verify a live receipt chain end-to-end

Signed action receipts are produced once `flight_recorder` is enabled with a
`dir` and a `signing_key_path` (all three are needed — without a key the
recorder can only hash-chain, not sign). Setting `require_receipts: true`
additionally makes a successful signed emission a precondition for allow-path
traffic, so a receipt failure fails closed instead of forwarding silently.

The full loop uses only shipped commands and verifies offline against the public
key — no server, no account:

```bash
# 1. Provision the recorder: pipelock init writes flight_recorder.enabled/dir/
#    signing_key_path into the config, generates the Ed25519 signing key, and
#    writes the shareable public-key sidecar at <signing_key_path>.pub.
pipelock init

# 2. Run the proxy. Every mediated allow/block decision is signed into the
#    hash-linked chain under flight_recorder.dir.
pipelock run --config /etc/pipelock/pipelock.yaml

# 3. Stop it cleanly (Ctrl-C / SIGTERM). Graceful shutdown seals the chain with
#    a transcript_root completeness anchor; a SIGKILL skips the seal and leaves
#    the tail unsealed (verification then reports no root rather than VALID).

# 4. Verify the entire chain offline with the public-key sidecar. Use the dir
#    and .pub path that step 1 wrote into your config.
pipelock verify-receipt --chain /var/lib/pipelock/evidence \
  --key /etc/pipelock/keys/flight-recorder-signing.key.pub
```

`--chain` walks every evidence file in the directory (across rotations and
restarts), checks `prev_hash` linkage and sequence continuity, verifies each
signature against the pinned key, and confirms the sealed `transcript_root`. If
the chain rotated its signing key, pass each public key with a repeated `--key`.
