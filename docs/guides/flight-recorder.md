# Flight Recorder Guide

The flight recorder writes every enforcement decision pipelock makes to a hash-chained, tamper-evident evidence log. Each entry is cryptographically linked to the one before it, so any deletion or modification breaks the chain. Signed checkpoints let auditors verify the chain was intact at specific points in time without replaying every entry. The recorder is designed for post-incident investigation, compliance evidence, and forensic replay.

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
  sign_checkpoints: true         # Ed25519 signed checkpoints
  max_entries_per_file: 10000    # rotate to a new file after this many entries
  raw_escrow: false              # encrypted raw sidecar (see below)
  escrow_public_key: ""          # X25519 hex public key for raw escrow
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | false | Master switch. Off by default. |
| `dir` | (required) | Directory for evidence files. Created if absent. |
| `checkpoint_interval` | 1000 | How many entries between signed checkpoints. |
| `retention_days` | 0 | Auto-expire files after N days. 0 = never expire. |
| `redact` | true | DLP scan each entry before writing. Replaces matched content with a redaction marker. |
| `sign_checkpoints` | true | Sign each checkpoint with the agent's Ed25519 private key. |
| `max_entries_per_file` | 10000 | Rotate to a new JSONL file after this many entries. |
| `raw_escrow` | false | Write an encrypted sidecar with the unredacted detail for each entry. |
| `escrow_public_key` | "" | X25519 hex public key for escrow encryption. Required when `raw_escrow: true`. |

The agent private key used for signing is the same key used for `pipelock assess` signing. It is loaded from the keystore at `~/.pipelock/` (or the path configured with `--keystore`).

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
  redact: true
  raw_escrow: true
  escrow_public_key: "a1b2c3d4e5f6..."  # 32-byte X25519 key, hex-encoded
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
