# Hot Reload Example

Runnable walkthrough for Pipelock **config hot reload** (fsnotify + SIGHUP):
the same `/fetch` target flips from allowed to blocked **without restarting**
the process, while `/health` stays up.

Fully offline: local echo server + loopback SSRF allowlist tighten.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Permissive baseline | `/fetch` reaches a local echo server |
| Policy rewrite | Temp config drops `ssrf.ip_allowlist` |
| Hot reload | File write (fsnotify) and optional SIGHUP apply the new scanner |
| Same request blocked | Identical echo URL returns HTTP 403 after reload |
| Health continuity | `/health` stays 200; same PID; uptime keeps increasing |

## Prerequisites

- `pipelock` on `PATH`, or set `PIPELOCK_BIN`
- Bash 3.2+, `curl`, Python 3

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
```

## Quick Verify

From the repository root:

```bash
./examples/hot-reload/verify.sh
```

Or from this directory: `./verify.sh` (with `PIPELOCK_BIN` set if needed).

## Manual Try

Terminal 1:

```bash
"$PIPELOCK_BIN" run --config examples/hot-reload/pipelock.yaml
```

Terminal 2 (with a local echo on loopback and `ssrf.ip_allowlist` as in this yaml):

```bash
curl -sS -G --data-urlencode "url=http://127.0.0.1:ECHO_PORT/" \
  "http://127.0.0.1:8888/fetch"
# expect allowed

# Edit the running config: remove the ssrf.ip_allowlist entries (or the ssrf block),
# save the file, or send SIGHUP to the pipelock PID.

curl -sS -G --data-urlencode "url=http://127.0.0.1:ECHO_PORT/" \
  "http://127.0.0.1:8888/fetch"
# expect HTTP 403 blocked

curl -sS "http://127.0.0.1:8888/health"
# expect status healthy (process still up)
```

If `pipelock` is already on your `PATH`, you can use `pipelock` instead of `"$PIPELOCK_BIN"`.

## Config Notes

- Hot reload watches the config **directory** (fsnotify) and listens for **SIGHUP** on Unix.
- `fetch_proxy.listen` is not changed by reload — keep the bound port stable.
- Narrowing or removing `ssrf.ip_allowlist` is a supported reload; core SSRF then blocks loopback literals.
- Distinct from `examples/kill-switch/` (503 deny-all) and `examples/fetch-proxy-ssrf/` (always-blocked metadata).

See `../../docs/guides/health.md` and `../../docs/configuration.md` (SSRF).

## Contributing

Improvements welcome: blocklist-based flip, or Windows fsnotify-only notes. Open a PR against `main`.
