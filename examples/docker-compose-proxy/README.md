# Docker Compose Proxy Example

Runnable docker-compose walkthrough for running Pipelock as an HTTP forward proxy
and sending traffic through it using curl's explicit proxy flag.

This example is fully local: it starts a local upstream HTTP service inside the
compose network and configures Pipelock to allow that service via `trusted_domains`.

## What This Demonstrates

| Check | What it proves |
|------|----------------|
| Proxy routing | `curl` routes via Pipelock using `-x` |
| Local upstream reachability | Proxy can reach `http://upstream:8080/` on the compose network |
| DLP on URL/header | Secret-shaped payload is blocked |

## Prerequisites

- Docker Desktop / Docker Engine
- Docker Compose v2 (`docker compose`)
- Bash 3.2+, `curl`, and Python 3 (for the verify harness)

## Quick Verify

From this directory:

```bash
./verify.sh
```

Exit code `0` means all checks passed. The script:

1. Builds a local `pipelock` Docker image from the repo’s `Dockerfile`
2. Starts `docker compose` (Pipelock + upstream service)
3. Waits for `http://127.0.0.1:${PIPELOCK_PROXY_PORT:-18088}/health`
4. Uses `curl -x` to fetch `http://upstream:8080/` through the proxy
5. Sends a runtime-generated secret-shaped value and confirms it is blocked

The host port defaults to `18088` so the example does not conflict with a local
Pipelock service on `8888`. Override it with `PIPELOCK_PROXY_PORT=18888 ./verify.sh`.

## Manual Try

Start the stack:

```bash
cd /path/to/pipelock/examples/docker-compose-proxy
docker compose up --build
```

In another terminal, route a request through the proxy:

```bash
curl -x "http://127.0.0.1:18088" -sS http://upstream:8080/
```

## Config Notes

`pipelock.yaml` enables `forward_proxy` and binds the listener on `0.0.0.0:8888`
inside the container; `docker-compose.yml` maps that to host port `18088` by
default, or the value of `PIPELOCK_PROXY_PORT` when set. The upstream container is
on a private Docker subnet; this would normally be blocked by SSRF protections,
so the config uses `trusted_domains: ["upstream"]` to explicitly trust the
internal service hostname for this example. The config bind mount includes `:Z`
so it works on SELinux-enabled Docker hosts.

## Related Docs

See `../../docs/guides/transport-modes.md` for the full transport matrix.
