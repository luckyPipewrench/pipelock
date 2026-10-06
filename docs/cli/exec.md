# pipelock exec

`pipelock exec` checks a running Pipelock proxy, then launches a command with proxy and CA environment settings. It's free and doesn't need a license or root.

This steers cooperative clients. It isn't containment: a program can ignore environment variables, choose its own proxy or trust store, or make direct connections. Use [contain](../contain-cli.md) or `pipelock sandbox` for operating-system enforcement, subject to their platform requirements. Readiness is checked before launch; `exec` doesn't supervise proxy health or configuration changes during the command.

```sh
pipelock run --config pipelock.yaml
# In another terminal:
pipelock exec --config pipelock.yaml -- claude
pipelock exec --ca ~/.pipelock/ca.pem -- codex
```

## Flags

```text
pipelock exec [--config FILE] [--proxy-url URL] [--ca FILE]
              [--no-proxy LIST] [--dry-run] [--print-env sh|pwsh|cmd|json]
              [--require-intercept] -- CMD [ARGS...]
```

| Flag | Behavior |
|---|---|
| `--config FILE` | Reads listener and CA defaults from the running service's config, without needing its private CA key or license file. Relative CA paths resolve beside that config. Interception with no explicit CA path uses the same `--home`, `PIPELOCK_HOME`, or `~/.pipelock` default as the proxy. Live health determines whether the service is ready. |
| `--proxy-url URL` | Overrides the listener default. Without a config, defaults to `http://127.0.0.1:8888`. Accepts an HTTP or HTTPS origin without credentials, path, query, or fragment. HTTPS proxy certificates must already be trusted by the system. |
| `--ca FILE` | Overrides `tls_interception.ca_cert`. Requires a PEM signing CA certificate that's valid now, and live TLS interception. |
| `--no-proxy LIST` | Sets both bypass-list variables. Defaults to empty, so cooperative clients proxy local traffic too. Each entry deliberately permits direct connections. |
| `--require-intercept` | Requires live TLS interception and a valid CA file. Also implied by a supplied CA or interception enabled in the config. |
| `--dry-run` | Performs readiness checks and prints JSON without launching. A command is optional. |
| `--print-env FORMAT` | Performs readiness checks and prints environment assignments and inherited overrides to remove. A command is optional. |

The command must follow `--`; its flags pass through unchanged. Unix replaces the launcher process, preserving the command's exit code and normal signal handling. Windows starts the child suspended, assigns it to a kill-on-close Job Object, resumes it, waits, and returns its exit code. Closing the launcher terminates the job's descendants. A job setup failure terminates the suspended child. These lifecycle controls don't enforce network routing.

## Readiness and trust

Before launch, the existing `/health` endpoint must return HTTP 200, `status: healthy`, an enabled forward proxy, and an inactive kill switch. If interception is required, the response must explicitly report it enabled. Missing, null, invalid, or unhealthy state refuses launch. Redirects are refused. The probe connects to the selected proxy itself, independently of inherited proxy settings. The child is pointed at that same URL. `exec` doesn't pin the process, compare the CA file with the certificate the proxy is using, or keep watching the proxy after launch. A proxy that is already intercepting still allows launch when no CA was requested. Clients then need that proxy's CA in their own trust store.

For interception, `exec` reads the system CA bundle and appends the Pipelock CA, matching containment's combined-bundle approach. Clients that replace their trust store retain the system roots. Linux and other Unix systems need a readable operating-system PEM root bundle; Windows exports its native ROOT store. Failure to obtain system roots refuses launch instead of creating a Pipelock-only trust store.

Each distinct CA bundle is written once, as a private file in the user cache under `pipelock/exec-ca`, named by its content. The same bytes are reused. A different bundle gets a new file so a child that's still reading the previous one keeps it. Bundles persist after exit so Unix process replacement, long-running children, and printed environment settings keep working. After every command using an old bundle has exited, the operator can remove that file. Dry-run with a CA also creates the bundle. A symlink in the cache path is refused. On Unix, Pipelock removes group and other write access from cache entries you own, and refuses an entry owned by another account or a cache directory other accounts can write without the sticky bit, because another account could replace the bundle after Pipelock checks it.

## Environment contract

Inherited `*_PROXY` variables are removed case-insensitively, including custom names and a `NO_PROXY=*` bypass. Managed CA overrides, `npm_config_noproxy`, `npm_config_cafile`, and `NODE_USE_ENV_PROXY` are replaced. Other environment settings are retained, including credentials and `NODE_OPTIONS`. A program flag or an application config file can still override routing. CA variables below are set only when a CA is supplied. Proxy variables, `npm_config_noproxy`, and `NODE_USE_ENV_PROXY=1` are always set.

<!-- BEGIN launchcontract:exec -->
| Variable | Value |
|---|---|
| `HTTP_PROXY` | proxy URL |
| `http_proxy` | proxy URL |
| `HTTPS_PROXY` | proxy URL |
| `https_proxy` | proxy URL |
| `ALL_PROXY` | proxy URL |
| `all_proxy` | proxy URL |
| `NO_PROXY` | explicit bypass list |
| `no_proxy` | explicit bypass list |
| `npm_config_noproxy` | explicit bypass list |
| `SSL_CERT_FILE` | combined CA bundle |
| `REQUESTS_CA_BUNDLE` | combined CA bundle |
| `CURL_CA_BUNDLE` | combined CA bundle |
| `GIT_SSL_CAINFO` | combined CA bundle |
| `CARGO_HTTP_CAINFO` | combined CA bundle |
| `PIP_CERT` | combined CA bundle |
| `NODE_EXTRA_CA_CERTS` | combined CA bundle |
| `npm_config_cafile` | combined CA bundle |
| `CODEX_CA_CERTIFICATE` | Pipelock CA file |
| `DENO_CERT` | combined CA bundle |
| `NODE_USE_ENV_PROXY` | 1 |
<!-- END launchcontract:exec -->

The table is checked against `internal/launchcontract` by `TestDocumentationParity`. Containment retains its existing CA variables and Node shim. Sandbox retains its existing HTTP/HTTPS variables and empty bypass list, without CA overrides or `ALL_PROXY`.

Node's built-in HTTP/HTTPS proxy support requires **Node 22.21+ or 24.5+**. `NODE_USE_ENV_PROXY` arrived in 24.0, but HTTP/HTTPS support arrived in 24.5; these minimums cover both HTTP/HTTPS and built-in fetch. `exec` uses the native flag and doesn't install an undici shim. Older runtimes or custom clients need their own proxy support or containment. See the [Node CLI documentation](https://nodejs.org/api/cli.html#node_use_env_proxy1) and [HTTP proxy documentation](https://nodejs.org/api/http.html#built-in-proxy-support).

`CODEX_CA_CERTIFICATE` takes precedence over `SSL_CERT_FILE`. Codex adds every certificate in that file to its existing roots, and it refuses to build its HTTP client if one certificate fails to load, so the variable points at the Pipelock CA file rather than the combined system bundle. See [Codex's CA loader](https://github.com/openai/codex/blob/main/codex-rs/http-client/src/custom_ca.rs). `DENO_CERT` loads PEM authorities (the environment form of `--cert`); see [Deno's environment reference](https://docs.deno.com/runtime/reference/env_variables/). The combined bundle is what Deno gets, so ordinary public roots are still in the file if Deno treats it as the authority list.

Go on Windows and macOS uses the operating-system trust store and ignores `SSL_CERT_FILE` ([`crypto/x509`](https://pkg.go.dev/crypto/x509#SystemCertPool)). On other Unix systems, Go honors `SSL_CERT_FILE`. `exec` doesn't set Java trust or proxy properties, or PHP's CA file. A repository git `http.proxy` or `http.sslCAInfo` value overrides the environment, and a curl config file can do the same. SSH doesn't use these HTTP settings. Inherited settings that turn certificate checks off, including `GIT_SSL_NO_VERIFY` and `NODE_TLS_REJECT_UNAUTHORIZED`, are left as they are.

## Printing settings

```sh
pipelock exec --config pipelock.yaml --print-env sh
pipelock exec --config pipelock.yaml --print-env pwsh
pipelock exec --config pipelock.yaml --print-env cmd
pipelock exec --config pipelock.yaml --print-env json
```

Shell output unsets inherited overrides before setting the contract. `sh` and `pwsh` use literal quoting. `cmd` emits quoted `set` statements and refuses values with quotes, percent signs, exclamation marks, or line breaks, which can't be safely represented in both interactive and batch contexts. Use PowerShell or JSON for those values. JSON contains a `set` object and an `unset` array; apply both to reproduce the launch environment. Output never includes unrelated inherited values or credentials.

Printed settings are a snapshot. They don't repeat readiness checks when later used. Prefer `pipelock exec -- CMD` for each launch.

## Refusals and remedies

| Refusal | Remedy |
|---|---|
| Proxy unavailable or unhealthy | Start `pipelock run --config pipelock.yaml`, repair service health, or fix `--proxy-url`. |
| Forward proxy disabled | Enable `forward_proxy.enabled` in the running service's config. |
| Interception required but disabled | Enable `tls_interception.enabled` and configure its CA certificate and key in the running service. |
| Kill switch active | Inspect and clear its activation sources; changing an unrelated config field won't clear runtime activation. |
| CA missing, invalid, expired, or not a signing CA | Fix `--ca` or `tls_interception.ca_cert`, or create/renew the CA with `pipelock tls init`. |
| System roots unavailable | Install or repair the operating system's CA certificate bundle or Windows ROOT store. |

`tls init` refuses to overwrite an existing CA by default. For an expired CA, generate a replacement in a new directory with its `--out` option, update the running service's certificate and key paths, restart the service, and distribute the replacement CA to clients. See the [TLS setup guide](../guides/tls-interception.md).

Interception passthrough domains remain encrypted and aren't body-scanned. A readiness check can't prove that a particular client honors the environment or that every request will be intercepted.
