# Pipelock Quickstart

Run any AI agent behind pipelock with enforced network isolation. The agent gets secrets but no internet. Pipelock gets internet but no secrets. Docker's `internal: true` network flag enforces this at the iptables level, not the `HTTPS_PROXY` honor system.

## Start

```bash
docker compose up
```

This starts two containers:

- **pipelock:** fetch proxy on both networks, scanning all traffic
- **agent:** Alpine placeholder on the internal network only (replace with your agent)

Set your agent's `HTTP_PROXY` and `HTTPS_PROXY` to `http://pipelock:8888`. The agent container already has these configured.

Pin a specific version with `PIPELOCK_VERSION=0.3.1 docker compose up`.

## Verify

Run 5 tests that prove isolation and scanning work. No external network needed.

```bash
docker compose --profile verify up --abort-on-container-exit --exit-code-from verify
```

| # | Test | What it proves |
|---|------|---------------|
| 1 | Network isolation | Verify container cannot reach the attacker container directly |
| 2 | Proxy works | Fetch through pipelock succeeds |
| 3 | DLP blocks secrets | AWS key in URL is blocked |
| 4 | Injection detected | Response scanning flags hidden instructions |
| 5 | MCP tool poisoning | Tool description scanning catches poisoned tool |

Exit code 0 means all passed. Use this in CI to gate deployments.

## Customize

**Replace the agent.** Change `image` and `command` in `docker-compose.yml`. Keep the agent on `pipelock-internal` only.

**Edit the allowlist.** `pipelock.yaml` controls which domains agents can reach, DLP patterns, response scanning rules, and MCP tool policies. See the [configuration reference](../../docs/configuration.md).

**Restore SSRF protection.** The quickstart disables SSRF checks (`internal: []`) because Docker containers use private IPs. For production, copy the CIDR list from [configs/balanced.yaml](../../configs/balanced.yaml) and add your Docker network subnets.

**Docker version.** Docker >= 25.0.5 recommended. Older versions have a DNS leak on internal networks ([CVE-2024-29018](https://github.com/moby/moby/security/advisories/GHSA-mq39-4gv4-mvpx)).

## Next steps

- [Deployment recipes](../../docs/guides/deployment-recipes.md) for Kubernetes, systemd, and advanced Docker setups
- [Configuration reference](../../docs/configuration.md) for all config options
- [Framework guides](../../docs/guides/) for Claude Code, Cursor, and other agents
