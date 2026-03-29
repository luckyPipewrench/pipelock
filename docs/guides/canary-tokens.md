# Canary Token Guide

Canary tokens are synthetic secrets you inject into your agent's environment. They look like real credentials but are never used for authentication. Their only job is to trip an alarm if an agent tries to exfiltrate them. Because pipelock knows the exact value, it can detect canary exposure in URLs, request bodies, base64-encoded payloads, URL-encoded strings, and split-across-separator patterns that would evade regex-based DLP.

## How Detection Works

Canary scanning runs as part of the DLP layer. It has two distinct call sites:

- **URL scanning**: when pipelock evaluates the request URL, it checks the decoded URL string for canary values before DNS resolution.
- **Text DLP**: `ScanTextForDLP` also calls canary scanning when checking any text content (request bodies, MCP tool arguments, WebSocket frames).

Detection applies these normalization passes in order:

1. Direct match on the normalized string
2. URL-decoded match (iterative, catches `%41%57%53...`)
3. Subdomain match (strips dots, catches `AK.IA.IO.SF...` in hostnames)
4. Separator-collapsed match (strips `./-\_@%+#:;,` and more, catches tokens split across URL components)
5. Base64 / hex decoded match (via the shared encoding decoder)
6. Segment-level encoding decode (checks each URL path/query segment independently)

A match at any pass triggers a `blocked` event with severity `critical` and pattern name `Canary Token (<name>)`.

Unlike DLP regex patterns, canary matching is exact string containment after normalization. There are no false positives from substring collisions.

## Configuration

Add a `canary_tokens` block to your `pipelock.yaml`:

```yaml
canary_tokens:
  enabled: true
  tokens:
    - name: aws_canary
      value: "canary-aws-trap-value-0x42a7"  # minimum 8 characters
      env_var: AWS_CANARY_KEY
    - name: db_password_canary
      value: "db-canary-credential-value"
      env_var: DB_CANARY_PASSWORD
```

Field reference:

| Field | Required | Description |
|-------|----------|-------------|
| `enabled` | yes | Master switch. Must be `true` with at least one token. |
| `tokens[].name` | yes | Unique name (case-insensitive). Used in event pattern names. |
| `tokens[].value` | yes | The canary value to watch for. Minimum 8 characters. |
| `tokens[].env_var` | no | Environment variable to inject the value into. Optional. |

Token names must be unique. Token values must be unique. Both are validated at startup.

## Generating a Config Snippet

`pipelock canary` prints a ready-to-paste YAML snippet:

```bash
pipelock canary
```

Output:

```yaml
canary_tokens:
  enabled: true
  tokens:
    - name: "aws_canary"
      value: "${AWS_CANARY_KEY}"
      env_var: "AWS_CANARY_KEY"
```

By default, the value field contains an env var placeholder (`${AWS_CANARY_KEY}`). This keeps the actual token value out of your config file. At startup, pipelock reads the env var and uses the real value for matching.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | `aws_canary` | Token name |
| `--value` | built-in fake AWS key | Token value (used with `--literal`) |
| `--env-var` | `AWS_CANARY_KEY` | Environment variable name |
| `--literal` | false | Emit the actual value instead of `${ENV_VAR}` |
| `--format` | `yaml` | Output format: `yaml` or `json` |

To print the actual value (for testing):

```bash
pipelock canary --literal
# warning: --literal prints the canary token value to stdout; avoid capturing in shared logs
```

To generate a snippet for a database canary:

```bash
pipelock canary --name db_canary --env-var DB_CANARY_VALUE
```

## Choosing Canary Values

Good canary values look like real credentials of the type you're protecting:

- AWS access key format: `AKIA` + 16 alphanumeric characters (20 chars total)
- Database password: long, high-entropy string (the kind you'd generate with a password manager)
- API token: prefix that matches your real token format, then random suffix

The value must be at least 8 characters. Make it long enough that accidental matches against unrelated content are not plausible. 20+ characters is a reasonable floor.

Do not reuse values across tokens. Each token value must be unique.

## Injecting Canary Values

The most reliable deployment pattern is to inject the canary as an environment variable into the agent, then reference it from your config:

```bash
# Inject into the agent at startup
export AWS_CANARY_KEY="canary-aws-trap-value-0x42a7"

# pipelock.yaml references it
canary_tokens:
  enabled: true
  tokens:
    - name: aws_canary
      value: "${AWS_CANARY_KEY}"
      env_var: AWS_CANARY_KEY
```

For agents in containers or Kubernetes:

```yaml
# pipelock configmap
canary_tokens:
  enabled: true
  tokens:
    - name: aws_canary
      value: "${AWS_CANARY_KEY}"
      env_var: AWS_CANARY_KEY

# Agent deployment env
env:
  - name: AWS_CANARY_KEY
    valueFrom:
      secretKeyRef:
        name: canary-secrets
        key: aws_canary_key
```

The goal is for the agent to see the value in its environment (making it realistic bait) while pipelock knows to block any request that exfiltrates it.

For canary tokens that represent secrets the agent doesn't legitimately need in its environment (e.g., a database password injected to simulate a compromised secret store), you can skip `env_var` and just set `value` directly in the config. The token still works; pipelock will match it in any outbound content.

## What Happens on Detection

A canary match produces a `blocked` event with:

```json
{
  "severity": "critical",
  "type": "blocked",
  "fields": {
    "scanner": "dlp",
    "reason": "Canary Token (aws_canary)",
    "url": "https://attacker.com/...",
    "client_ip": "...",
    "request_id": "..."
  }
}
```

The request is blocked. The event is emitted to all configured sinks (webhook, syslog, OTLP) because severity is `critical`. If you have automated kill switch response wired up, this is the event that should trigger it.

Canary matches are severity `critical` regardless of `mode` or `enforce` settings. The token was never supposed to leave the system; any appearance in outbound traffic is unambiguous evidence of exfiltration.

## Example: Triggering a Detection

With canary tokens configured, trigger a detection for testing:

```bash
# Start pipelock
pipelock run --config pipelock.yaml &

# Set the canary value
export AWS_CANARY_KEY="canary-aws-trap-value-0x42a7"

# Make a request that includes the canary token in the URL
curl -x http://localhost:8888 "https://example.com/?key=${AWS_CANARY_KEY}"
```

Pipelock will block the request and emit a critical event. Check stderr or your configured SIEM sink to confirm.

To test URL-encoded evasion:

```bash
# URL-encoded canary value
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${AWS_CANARY_KEY}'))")
curl -x http://localhost:8888 "https://example.com/?key=${ENCODED}"
```

This should also be blocked. The iterative URL decoder catches it.

## Limitations

Canary detection runs on content that passes through pipelock. It does not detect:

- In-memory reads of the value that never reach the network (e.g., the agent reads the env var but doesn't make a request)
- Exfiltration through channels not routed through pipelock (side channels, DNS over non-standard ports, etc.)
- Values split across three or more separate requests (two-part splits across URL components are caught by the separator-collapse pass; three-way splits are not)
