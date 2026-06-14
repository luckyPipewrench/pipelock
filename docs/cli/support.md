# `pipelock support bundle`

`pipelock support bundle` collects a secret-redacted diagnostics archive (`.tar.gz`) that can be attached when filing a bug report or support issue. The command omits raw config and referenced file contents, redacts known secret fields, and DLP-scans included audit-log lines before writing the archive. Review bundles before sharing them outside your support boundary, especially when logs are included.

```sh
pipelock support bundle
pipelock support bundle --config pipelock.yaml
pipelock support bundle --output /tmp/pl-diag.tar.gz
pipelock support bundle --config pipelock.yaml --output /tmp/pl-diag.tar.gz --json
pipelock support bundle --config pipelock.yaml --no-logs
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | (none — built-in defaults) | Config file to summarise in the bundle. |
| `--output` | `-o` | `./pipelock-support-<timestamp>.tar.gz` | Output path for the archive. |
| `--json` | | (off) | Also write a standalone `<basename>-manifest.json` alongside the archive. |
| `--no-logs` | | (off) | Omit `audit-log-tail.txt` even when `logging.file` is configured. |

## Archive Contents

| File | What |
|------|------|
| `manifest.json` | Top-level index: Pipelock version, build metadata, OS/arch, Go version, config path, redacted config snapshot, env var names, and the list of included files. |
| `version.txt` | Human-readable version and build info. |
| `config-summary.json` | Redacted copy of the loaded config (or built-in defaults). All secret values replaced with `<redacted>`. Private key paths noted as `_configured: true/false` only — the path itself is omitted. |
| `scanners.json` | Scanner and feature enable flags derived from the loaded config. |
| `env-var-names.txt` | Names of relevant environment variables present in the process environment. **Values are never included.** |
| `config-path.txt` | The effective config file path (or `"defaults"` if no config was specified). |
| `audit-log-tail.txt` | Last 200 lines of the audit log, if `logging.file` is configured and readable and `--no-logs` is not set. Each line is literal-redacted, then DLP-scanned; a line with remaining secret-shaped content is replaced with `<redacted>`. |

## What Is and Is Not Included

**Included (sanitised):**
- Pipelock version, build date, git commit, Go version, OS, and architecture
- The effective config path
- A structured config summary with secrets replaced
- Scanner feature flags
- Environment variable **names** matching `PIPELOCK_*`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, and `SENTRY_*`
- A redacted audit log tail (if the log file is configured and readable, unless `--no-logs` is set)

**Never included:**
- License tokens, bearer tokens, API keys, webhook auth tokens → replaced with `<redacted>`
- Private key file contents — CA key, signing keys, escrow keys. Their configured status (present/absent) is noted as a boolean; the path itself is not included.
- Environment variable **values** — names only, always
- The contents of any referenced file (license file path is included; the file itself is never read)
- Webhook URL userinfo (Basic auth credentials embedded in the URL)
- Known secret query parameters in URLs (`token`, `api_key`, `client_secret`, etc.)
- Authorization-class header values (`Authorization`, `X-Api-Key`, `X-Token`, etc.) → replaced with `<redacted>`; non-secret headers are preserved

## Redaction Details

Redaction is fail-closed by design:

1. **Config redaction** uses a hand-curated map — only explicitly listed fields are included in the output. A newly-added field in the config schema is silently omitted rather than accidentally included. This is the opposite of a marshal-then-strip approach, which would require keeping a blocklist in sync with new secret fields.

2. **URL sanitisation** strips userinfo (`user:pass@host`) and redacts known secret query parameters. URLs that cannot be parsed are replaced with `<redacted>` entirely.

3. **Header redaction** redacts values for headers whose names match auth-like prefixes (`authorization`, `x-api-key`, `x-auth`, `x-token`, `bearer`, `secret`, `token`, `password`). Non-secret headers (e.g., `X-Request-ID`) are preserved.

4. **Audit log redaction** first applies a literal-match pass using `scanner.RedactionSecretValues()`, which includes encoded forms (base64, hex, base32 variants). It then DLP-scans each line; if a line still contains secret-shaped content, the whole line is replaced with `<redacted>`. Use `--no-logs` to omit audit logs entirely.

## Exit Codes

| Exit code | Meaning |
|-----------|---------|
| 0 | Bundle written successfully. |
| 1 | Config load error, I/O error, or archive write failure. |

## Notes

- The command does not require Pipelock to be running. It reads the config file directly.
- If no `--config` flag is specified, built-in defaults are used. The `config-path.txt` entry will contain `"defaults"`.
- The `--json` flag writes a companion file alongside the archive. For `--output /tmp/pl-diag.tar.gz`, the manifest is written to `/tmp/pl-diag-manifest.json`.
- The archive does not include the raw config file itself — only a redacted summary of the parsed config is included.
