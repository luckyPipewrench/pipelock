# Docker Compose Proxy Example

Runnable docker-compose walkthrough for running Pipelock as an HTTP forward proxy
and sending traffic through it using standard `HTTP_PROXY` / `HTTPS_PROXY` env vars.

This example is fully local: it starts a local upstream HTTP service inside the
compose network and configures Pipelock to allow that service via `trusted_domains`.

## What This Demonstrates

| Check | What it proves |
|------|----------------|
| Proxy env vars | `curl` routes via Pipelock using `HTTP_PROXY` |
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
3. Waits for `http://127.0.0.1:8888/health`
4. Uses `HTTP_PROXY` to fetch `http://upstream:8080/` through the proxy
5. Sends a runtime-generated secret-shaped value and confirms it is blocked

## Manual Try

Start the stack:

```bash
cd /path/to/pipelock/examples/docker-compose-proxy
docker compose up --build
```

In another terminal, route a request through the proxy:

```bash
HTTP_PROXY="http://127.0.0.1:8888" curl -sS http://upstream:8080/
```

## Config Notes

`pipelock.yaml` enables `forward_proxy` and binds the listener on `0.0.0.0:8888`
so the host can reach it via the compose port mapping. The upstream container is
on a private Docker subnet; this would normally be blocked by SSRF protections,
so the config uses `trusted_domains: ["upstream"]` to explicitly trust the
internal service hostname for this example.

## Related Docs

See `../../docs/guides/transport-modes.md` for the full transport matrix.

