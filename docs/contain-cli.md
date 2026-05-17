# `pipelock contain` — host containment lifecycle

`pipelock contain` is the operator CLI for installing, verifying, and rolling back a kernel-enforced containment model on a single Linux host. It splits one workstation into three roles — the operator account, `pipelock-proxy`, and `pipelock-agent` — and uses nftables owner-match rules to force every agent process through the Pipelock proxy. The install is idempotent and rolls back applied steps to a known state on any failed step.

The subcommands are:

| Subcommand | What it does | Mutates state |
|---|---|---|
| `install` | Create users, systemd unit, nftables rules, wrappers, sudoers entry, CA bundle | yes (root only) |
| `verify` | Read-only probes that report pass / fail / skip for the 12 invariants below | no |
| `rollback` | Idempotently undo `install`. Restores the prior state and removes wrappers, users, unit, rules | yes (root only) |
| `add-tool` | Register an additional tool wrapper under `/usr/local/bin/plk-<name>` after install | yes (root only) |
| `ca-refresh` | Rebuild the combined CA bundle at `/etc/pipelock/combined-ca.pem` after a CA rotation | yes (root only) |

Each mutating subcommand accepts `--dry-run` to print the planned actions without touching state.

## Why a separate user model

Single-user containment can't enforce egress at the kernel: the same user who runs the agent can also stop the proxy, edit the config, replace the binary, or rewrite the sudoers entry. Three users solve that:

- **`operator`** — the human. Owns the install. Reaches the internet directly.
- **`pipelock-proxy`** — runs `pipelock` itself. Owns the config, the CA bundle, the binary-integrity pin. The agent user cannot read its state directory.
- **`pipelock-agent`** — runs the AI agent process. Cannot reach the internet directly: nftables owner-match denies its outbound TCP except to loopback. All egress goes through `pipelock-proxy` on 127.0.0.1.

The agent runs with reduced capabilities (no privileged ports, no raw sockets, no NET_ADMIN). It cannot bypass the proxy because the kernel refuses to forward its packets anywhere else.

## `pipelock contain install`

Run as root (typically via `sudo`):

```bash
sudo pipelock contain install \
  --config /etc/pipelock/pipelock.yaml \
  --pipelock-binary /usr/local/bin/pipelock
```

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | false | Print the planned steps without mutating state. |
| `--operator-user` | `$SUDO_USER` | Operator account that the `plk-*` wrappers run from. |
| `--proxy-port` | `8888` | Pipelock listen port baked into wrappers and the systemd unit. |
| `--pipelock-binary` | current process | Pipelock binary to install. Hashed and pinned at install time. |
| `--config` | (required if not already in place) | Source `pipelock.yaml` copied to `/etc/pipelock/pipelock.yaml`. |

Install steps run in order; each one is idempotent. If any step fails, every previously-applied step is rolled back before exit so the system never settles in a partial state.

1. Create `pipelock-proxy` and `pipelock-agent` system users.
2. Lay down `/etc/pipelock/` and `/var/lib/pipelock/` with strict ownership and permissions. Agent-readable config artifacts stay traversable under `/etc/pipelock`; proxy-owned runtime state stays private under `/var/lib/pipelock`.
3. Copy the pipelock binary into a system path the agent user cannot replace.
4. Compute the binary SHA-256 and pin it at `/etc/pipelock/integrity/binary-pin.sha256`. Subsequent `verify` runs re-hash the binary and compare against the pin.
5. Migrate the user-mode systemd unit (if present) to a system unit running as `pipelock-proxy`.
6. Install the nftables containment ruleset: deny outbound from the agent user except to loopback, allow operator and `pipelock-proxy` to reach the internet directly.
7. Drop the `plk-launch` wrapper plus one wrapper per registered tool into `/usr/local/bin/`.
8. Install the sudoers entry that lets the operator user invoke `plk-launch` as `pipelock-agent` without a password prompt.
9. Bootstrap the combined CA bundle at `/etc/pipelock/combined-ca.pem` from the system trust store plus the Pipelock CA.

Exit codes:

- **0** — all steps applied (or already in place).
- **1** — a step failed; earlier applied steps were rolled back.
- **2** — precondition error: not root, missing executable, bad `--config`.

## `pipelock contain verify`

Verify is read-only. It walks 12 probes in order and prints pass / fail / skip per probe. It does not require root.

```bash
pipelock contain verify
```

| # | Probe name | Reports |
|---|---|---|
| 1 | `system_users_exist` | `pipelock-proxy` and `pipelock-agent` UIDs exist. |
| 2 | `pipelock_systemd_unit` | `pipelock.service` is running as `pipelock-proxy`. |
| 3 | `nftables_containment_ruleset` | The containment ruleset is loaded and matches the expected shape. |
| 4 | `wrapper_scripts_installed` | `plk-launch` plus the registered tool wrappers exist with correct mode. |
| 5 | `ca_bundle_present` | `/etc/pipelock/combined-ca.pem` is readable by the agent user. |
| 6 | `pipelock_listening_loopback` | Pipelock is accepting connections on `127.0.0.1:<proxy-port>`. |
| 7 | `no_proxy_env_correct` | `plk-launch` sets `NO_PROXY` to the loopback set documented in policy. |
| 8 | `cc_agent_egress_denied` | A direct outbound canary from `pipelock-agent` is blocked by nftables. |
| 9 | `operator_egress_reachable` | The same canary from the operator user is allowed (proves the rule scopes correctly). |
| 10 | `binary_integrity_pin` | The installed pipelock binary hash matches `/etc/pipelock/integrity/binary-pin.sha256`. |
| 11 | `cc_launch_allow_list_enforced` | `plk-launch` rejects tools that are not in the registered allow-list. |
| 12 | `listed_tool_targets_resolvable` | Every entry in `tools.list` resolves to an executable absolute path in the agent user's PATH. |

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--json` | false | Emit newline-delimited JSON records instead of text output. |
| `--port` | `8888` | Loopback port to probe for the listener check (matches `--proxy-port` from install). |

Exit code is 0 if every probe passed, 1 if any probe failed, and 2 if verification was incomplete because one or more probes skipped. Each failing probe prints a structured one-line detail so operators can dashboard the output.

## `pipelock contain rollback`

Idempotently undoes `install`. Safe to re-run on a partial install — every step checks state before mutating.

```bash
sudo pipelock contain rollback
```

Removes wrappers, sudoers entry, nftables rules, systemd unit migration, and the `pipelock-proxy` / `pipelock-agent` users by default. It preserves `/etc/pipelock` and `/var/lib/pipelock` unless you pass `--keep-data=false`.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | false | Print planned rollback actions without mutating state. |
| `--keep-data` | true | Preserve `/etc/pipelock` and `/var/lib/pipelock`. |
| `--keep-users` | false | Preserve the `pipelock-proxy` and `pipelock-agent` users. |
| `--purge-users` | false | Delete users even when `--keep-users` is set. |

## `pipelock contain add-tool`

Registers an additional tool wrapper without rerunning `install`. Useful when adding a new agent-callable tool after the initial install.

```bash
sudo pipelock contain add-tool claude
```

Drops `/usr/local/bin/plk-claude`, records the wrapper in `/etc/pipelock/contain/wrappers.json`, and adds the tool to `/etc/pipelock/contain/tools.list`.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | false | Print planned actions without mutating state. |
| `--target` | resolved from `pipelock-agent` PATH | Pin an explicit absolute executable path for the tool. |

## `pipelock contain ca-refresh`

Rebuilds `/etc/pipelock/combined-ca.pem` after the Pipelock CA has rotated, or after the system trust store has changed.

```bash
sudo pipelock contain ca-refresh
```

The agent user reads the combined bundle via `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` in `plk-launch`, so refreshing it picks up new trust without changing the wrapper.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | false | Print planned actions without mutating state. |
| `--ca-output` | `/etc/pipelock/ca.pem` | Destination for the Pipelock-only CA export. |
| `--bundle-output` | `/etc/pipelock/combined-ca.pem` | Destination for the combined bundle. |
| `--system-bundle` | system default | Source system CA bundle to combine with the Pipelock CA. |

## Operational notes

- **Binary integrity is TOFU.** The first `install` pins the binary hash. Verify compares the installed binary against that pin on every run. To install a new pipelock binary, run `install` again with `--pipelock-binary <new path>`; install rewrites the pin atomically.
- **The agent never gets `NET_ADMIN`.** Even if the agent runs as root inside a namespace, the host nftables ruleset blocks its egress. The proxy is the only egress path.
- **Dry-run is honest.** `--dry-run` prints exactly the commands install would run, with the same arguments. CI can dry-run an install change and review the diff before applying it.
- **Rollback uses guarded backups.** Managed file writes preserve prior content as `path.bak` when prior content existed. Rollback restores those backups where applicable, then removes managed artifacts.

For the deployment-tier threat model see [`security/per-deployment-ca-threat-model.md`](security/per-deployment-ca-threat-model.md). For the current unsupported-paths surface (raw sockets, browsers without explicit proxy config, processes that ignore CA bundle env vars) see [`security/current-unsupported-paths.md`](security/current-unsupported-paths.md).
