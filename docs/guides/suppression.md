# Finding Suppression Guide

Pipelock has three layers for suppressing false positives, from most precise to broadest:

1. **Inline comments** — suppress one rule on one line
2. **Config suppress entries** — suppress a rule across matching paths
3. **`--exclude` flag** — remove entire paths from results

All three work in `pipelock audit`, `pipelock git scan-diff`, and the GitHub Action.

## Layer 1: Inline Comments

Add `// pipelock:ignore` to a source line to suppress findings on that line.

```go
// Suppress a specific rule:
url := buildTestURL("token", testToken) // pipelock:ignore Credential in URL

// Suppress all rules on this line (use sparingly):
testValue := loadFixture("fake-key.txt") // pipelock:ignore
```

**Supported comment styles:**

| Language | Syntax |
|----------|--------|
| Go, JS, TS, Java, C | `// pipelock:ignore [RuleName]` |
| Python, YAML, Bash | `# pipelock:ignore [RuleName]` |

Rule names are case-insensitive. `pipelock:ignore credential in url` works.

**When to use:** Test files with fake credentials, documentation examples with placeholder tokens, assignments that look like credentials but aren't.

## Layer 2: Config Suppress Entries

Add `suppress` entries to your pipelock config file to silence findings across file paths:

```yaml
suppress:
  - rule: "Credential in URL"
    path: "docs/"
    reason: "Documentation examples use placeholder tokens"

  - rule: "Social Security Number"
    path: "test/fixtures/*.csv"
    reason: "Test data with synthetic SSNs"

  - rule: "JWT Token"
    path: "*.test.ts"
    reason: "Test JWTs with no real claims"

  - rule: "Jailbreak Attempt"
    path: "*/robots.txt"
    reason: "robots.txt content triggers developer mode regex"
```

**Path matching supports five styles:**

| Style | Example | Matches |
|-------|---------|---------|
| Exact path | `app/config.go` | Only that file |
| Directory prefix | `vendor/` | All files under `vendor/` |
| Full path glob | `config/initializers/*.rb` | `config/initializers/auth.rb` |
| Basename glob | `*.generated.go` | `pkg/api/types.generated.go` |
| URL suffix | `robots.txt` | `https://example.com/robots.txt` |

The `reason` field is optional but recommended — it appears in audit logs and helps future maintainers understand why the suppression exists.

**When to use:** Directories with known false positives, third-party code, generated files, documentation directories.

## Layer 3: `--exclude` Flag

Remove entire paths from scan results. Available on `pipelock git scan-diff` and `pipelock audit`:

```bash
pipelock git scan-diff --exclude vendor/ --exclude "*.generated.go"
pipelock audit --exclude node_modules/ --exclude dist/
```

Path patterns use the same matching rules as config suppress entries (exact, directory prefix, glob, basename glob).

**When to use:** Third-party code, build artifacts, generated files — anything you don't control.

## GitHub Action

### Exclude paths

Use the `exclude-paths` input (one pattern per line):

```yaml
- uses: luckyPipewrench/pipelock@v0.3.0
  with:
    exclude-paths: |
      vendor/
      *.generated.go
      node_modules/
```

### Config-level suppression

Use the `config` input to provide inline YAML config with suppress entries:

```yaml
- uses: luckyPipewrench/pipelock@v0.3.0
  with:
    config: |
      suppress:
        - rule: "Credential in URL"
          path: "docs/"
          reason: "Documentation examples"
        - rule: "JWT Token"
          path: "test/"
          reason: "Test tokens"
```

### Inline comments

Inline `// pipelock:ignore` comments work automatically — no action config needed.

## Available Rule Names

### DLP (Secret Detection)

| Rule Name | What It Detects | Severity |
|-----------|----------------|----------|
| Anthropic API Key | `sk-ant-*` | critical |
| OpenAI API Key | `sk-proj-*` | critical |
| OpenAI Service Key | `sk-svcacct-*` | critical |
| Fireworks API Key | `fw_*` | critical |
| Google API Key | `AIza*` | high |
| Google OAuth Client Secret | `GOCSPX-*` | critical |
| Google OAuth Token | `ya29.*` | critical |
| Google OAuth Client ID | `*.apps.googleusercontent.com` | medium |
| Stripe Key | `sk_live_*` / `rk_live_*` | critical |
| GitHub Token | `ghp_` / `ghs_` / `gho_` / `ghu_` / `ghr_` | critical |
| GitHub Fine-Grained PAT | `github_pat_*` | critical |
| AWS Access ID | `AKIA*` / `ASIA*` / `AROA*` + 6 more prefixes | critical |
| Slack Token | `xox[bpras]-*` | critical |
| Slack App Token | `xapp-*` | critical |
| Discord Bot Token | Base64 three-segment token | critical |
| Twilio API Key | `SK` + 32 hex | high |
| SendGrid API Key | `SG.*.*` | critical |
| Mailgun API Key | `key-` + 32 chars | high |
| Private Key Header | `-----BEGIN * PRIVATE KEY-----` | critical |
| JWT Token | `eyJ*.eyJ*.*` (three base64url segments) | high |
| Social Security Number | `###-##-####` | low |
| Credential in URL | `password=`, `token=`, `apikey=`, etc. | high |

### Injection Detection

| Rule Name | What It Detects |
|-----------|----------------|
| Prompt Injection | "ignore previous instructions" patterns |
| System Override | `system:` at line start |
| Role Override | "you are now DAN/evil/unrestricted" |
| New Instructions | "new instructions/directives/rules" |
| Jailbreak Attempt | "DAN", "developer mode", "sudo mode" |
| Hidden Instruction | "do not reveal this to the user" |
| Behavior Override | "from now on you will/must" |
| Encoded Payload | "decode from base64 and execute" |
| Tool Invocation | "you must call/execute the function" |
| Authority Escalation | "you now have admin access" |
| Instruction Downgrade | "treat previous instructions as outdated" |
| Instruction Dismissal | "set the previous instructions aside" |
| Priority Override | "prioritize the current request" |

## Precedence

When multiple layers apply to the same finding:

1. **Inline comments win first** — checked before anything else
2. **Config suppress entries** — checked if no inline match
3. **`--exclude` flag** — applied last, removes from output entirely

## What NOT to Do

- **Don't remove patterns from config** to suppress findings — that disables detection everywhere, including for real secrets.
- **Don't lower severity** to avoid emission — use `min_severity` on emit sinks instead.
- **Don't use blanket `// pipelock:ignore`** without a rule name — too broad, suppresses all detection on that line.
- **Don't suppress findings you haven't investigated** — every suppression is a risk acceptance decision.
