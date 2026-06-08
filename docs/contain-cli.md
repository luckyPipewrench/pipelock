# `pipelock contain` — host containment lifecycle

`pipelock contain` is the operator CLI for installing, verifying, and rolling back a kernel-enforced containment model on a single Linux host. It splits one workstation into three roles — the operator account, `pipelock-proxy`, and `pipelock-agent` — and uses nftables owner-match rules to force processes running as the contained agent user through the Pipelock proxy. The install is idempotent and rolls back applied steps to a known state on any failed step.

The subcommands are:

| Subcommand | What it does | Mutates state |
|---|---|---|
| `install` | Create users, systemd unit, nftables rules, wrappers, sudoers entry, CA bundle, runtime contract | yes (root only) |
| `verify` | Read-only probes that report pass / fail / skip for the 12 invariants below | no |
| `doctor` | Live self-test that proves common tooling reaches the internet *through* the proxy, with per-check remediation | no |
| `rollback` | Idempotently undo `install`. Restores the prior state and removes wrappers, users, unit, rules | yes (root only) |
| `add-tool` | Register an additional tool wrapper under `/usr/local/bin/plk-<name>` after install | yes (root only) |
| `explain` | Explain a contain egress block event and print remediation | no |
| `grant-workspace` | Grant the contained agent user ACL access to one project workspace | yes (root only) |
| `revoke-workspace` | Revoke a previously granted workspace ACL and clean unused parent traversal ACLs | yes (root only) |
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
2. Lay down `/etc/pipelock/` and `/var/lib/pipelock/` with strict ownership and permissions, copy `pipelock.yaml`, and set proxy ownership on the config/data roots. Agent-readable config artifacts stay traversable under `/etc/pipelock`; proxy-owned runtime state stays private under `/var/lib/pipelock`.
3. Copy the pipelock binary into a system path the agent user cannot replace, then compute and pin its SHA-256 at `/etc/pipelock/integrity/binary-pin.sha256`. Subsequent `verify` runs re-hash the binary and compare against the pin.
4. Migrate the user-mode systemd unit (if present), write and enable the system unit running as `pipelock-proxy`, then export the Pipelock CA.
5. Bootstrap the combined CA bundle at `/etc/pipelock/combined-ca.pem` from the system trust store plus the Pipelock CA.
6. Install the nftables containment ruleset: deny outbound from the agent user except to loopback, allow operator and `pipelock-proxy` to reach the internet directly. Raw-egress drops are classed in nft logs (`direct_dns_blocked` or `not_routing_through_pipelock`) and counted before the terminal drop.
7. Write `/etc/pipelock/contain/tools.list`, the runtime allow-list consumed by `plk-launch`.
8. Write the node undici proxy shim at `/etc/pipelock/contain/undici-shim.cjs` (see [Runtime contract](#runtime-contract)).
9. Drop the `plk-launch` wrapper plus one wrapper per registered tool into `/usr/local/bin/`.
10. Drop the known-good `pipelock-curl` / `pipelock-python` / `pipelock-node` wrappers into `/usr/local/bin/`.
11. Write the login-shell runtime contract to `/etc/profile.d/pipelock-contain.sh`.
12. Write per-tool proxy + CA config (`git` / `npm` / `pip` / `cargo`) into the agent home.
13. Write the wrapper inventory, then install the sudoers entry that lets the operator user invoke `plk-launch` as `pipelock-agent` without a password prompt.

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

## Runtime contract

The containment boundary is security-correct, but a tool that ignores the proxy environment looks *broken* — it dies with a generic network error and no hint that the firewall is the cause. To close that gap, `install` provisions a complete, proxy-correct runtime contract for the contained agent so common tooling works out of the box and stays routed through Pipelock.

The contract has four parts:

1. **Full environment matrix.** `plk-launch` (and the login-shell script below) export the complete proxy + CA set, because different ecosystems read different variables:

   - Proxy (upper- and lower-case): `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` and their lowercase forms, all pointing at `http://127.0.0.1:<proxy-port>`.
   - `NO_PROXY` / `no_proxy` = `127.0.0.1,localhost,::1` (IPv6 loopback included so IPv6-first clients don't proxy a local dial).
   - CA trust for the Pipelock MITM CA: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`, `PIP_CERT` → the combined bundle; `NODE_EXTRA_CA_CERTS` → the Pipelock CA (node *appends* this to its built-in store).
   - `NODE_OPTIONS=--require <undici-shim>` (see below).

2. **node undici shim** (`/etc/pipelock/contain/undici-shim.cjs`). Node's built-in `fetch()` and undici-based clients ignore `HTTPS_PROXY` unless a global dispatcher is installed. The shim installs an undici `ProxyAgent` at startup. It is best-effort: if undici cannot be required, `http`/`https`-module traffic still honors the proxy env, so the shim degrades silently rather than breaking node.

3. **Known-good wrappers** on the agent PATH: `pipelock-curl`, `pipelock-python`, `pipelock-node`. Each forces the full contract before exec'ing the real tool, so it is proxy- and CA-correct even when the caller's environment is incomplete (for example, a bare `sudo -u pipelock-agent <cmd>` that inherits no proxy env).

4. **Per-tool config files** written into the agent home (`~/.gitconfig`, `~/.npmrc`, `~/.config/pip/pip.conf`, `~/.cargo/config.toml`). These tools read their own config regardless of environment, so config-driven invocations are proxy-correct on every exec path.

A login-shell script at `/etc/profile.d/pipelock-contain.sh` exports the same matrix so an interactive `sudo -iu pipelock-agent` session inherits it too. Because `/etc/profile.d` is sourced by all login shells, the script returns immediately for every user except `pipelock-agent`.

This makes compatible tooling work; it does **not** widen egress. Direct (proxy-bypassing) connections from the agent user remain blocked by the nftables owner-match rule.

## `pipelock contain doctor`

Where `verify` proves the boundary is *installed*, `doctor` proves it is *usable*: it runs live checks that the contained agent can actually reach an allowed host through the proxy, and that direct egress is blocked. Run it as root (it sudoes to the agent for the live probes).

```bash
sudo pipelock contain doctor
```

Crucially, doctor makes the four failure classes distinguishable, so a *compatibility* problem doesn't read as a *broken agent*:

| Class | Meaning |
|---|---|
| `policy` | Blocked because the request is dangerous (DLP / policy decision). |
| `proxy-compat` | The tool isn't proxy-compatible (ignores `HTTPS_PROXY`). Use a `pipelock-*` wrapper. |
| `local-context` | Pipelock misclassified harmless local context. |
| `infra` | Infra protection tripped (DNS failure, gateway down, CA mismatch). |

Checks:

| # | Check | Proves |
|---|---|---|
| 1 | `gateway_health` | Pipelock is accepting connections on the loopback proxy port. |
| 2 | `curl_through_proxy` | `curl` reaches an allowed host through the proxy (explicit `--proxy`/`--cacert`). |
| 3 | `python_through_proxy` | `python` reaches an allowed host via the `pipelock-python` wrapper. |
| 4 | `node_through_proxy` | node's `fetch()` reaches an allowed host via the `pipelock-node` wrapper + undici shim. |
| 5 | `dns_failure_clean` | An unresolvable host fails fast with a clean proxy error — no hang, no bypass. |
| 6 | `raw_egress_blocked` | Direct, proxy-bypassing egress from the agent is blocked. This is also the root cause a proxy-unaware tool surfaces, so the remediation names the fix. |

Each non-passing check prints a one-line remediation tagged with its class. For example, a proxy-unaware tool produces:

```text
  [PASS] check 6: direct (proxy-bypassing) egress is blocked for the agent — direct egress blocked at dial (curl exit 7); proxy-unaware tools fail here
          ↳ [proxy-compat] a tool that 'can't reach the internet' is ignoring the proxy, NOT broken — run it via pipelock-curl / pipelock-python / pipelock-node, or export HTTPS_PROXY=http://127.0.0.1:8888
```

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--json` | false | Emit newline-delimited JSON records (`check`, `name`, `status`, `detail`, `remediation`, `class`) instead of text. |
| `--port` | `8888` | Loopback proxy port to test (matches `--proxy-port` from install). |
| `--url` | `https://example.com/` | Allowed canary URL the agent should be able to reach. |

Exit code is 0 if every check passed, 1 if any check failed, and 2 if the diagnosis was incomplete because a check skipped (for example, not run as root, or a tool isn't installed). Checks that can't proceed skip with remediation rather than failing.

## `pipelock contain explain`

Explains a contained-egress block event from the contain JSONL event log:

```bash
pipelock contain explain evt-01HZ...
pipelock contain explain evt-01HZ... --format json
```

By default the command reads `/var/lib/pipelock/contain/egress-events.jsonl`; pass `--events <path>` to inspect a copied event log. Each event can carry process, pid, uid, destination, port, protocol, response host, response size, and scan limit fields. The command maps the block class to an operator remediation:

| Class | Remediation |
|---|---|
| `tool_ignores_proxy` | Use the `plk-*` wrapper or configure `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` for the tool. |
| `missing_ca` | Refresh/install the contain CA bundle and point the tool at `/etc/pipelock/combined-ca.pem`. |
| `direct_dns_blocked` | Stop direct DNS; route the tool through Pipelock or the wrapped runtime. |
| `not_routing_through_pipelock` | Use `plk-launch` / `plk-*` wrappers or proxy-aware tool configuration. |
| `dangerous` | Keep blocked unless policy review explicitly allows it. |
| `misclassified_local_context` | Add a narrow suppression or rule fix without disabling egress scanning. |
| `infra_protection` | Inspect session/airlock state and reset only after confirming non-adversarial traffic. |

## `pipelock contain rollback`

Idempotently undoes `install`. Safe to re-run on a partial install — every step checks state before mutating.

```bash
sudo pipelock contain rollback
```

Removes the `plk-*` and `pipelock-*` wrappers, the node undici shim, the `/etc/profile.d` runtime-contract script, the per-tool agent config, the sudoers entry, nftables rules, systemd unit migration, and the `pipelock-proxy` / `pipelock-agent` users by default. It preserves `/etc/pipelock` and `/var/lib/pipelock` unless you pass `--keep-data=false`.

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

## `pipelock contain grant-workspace`

Grants `pipelock-agent` access to one project directory after containment is installed. This is the normal fix for a contained tool that launches correctly through `plk-*` but cannot read or edit the operator's repo.

```bash
sudo pipelock contain grant-workspace /home/alice/src/my-project
```

By default the command grants execute-only traversal on parent directories and read-only access inside the workspace. Use `--mode read-write` only when the contained agent should edit files in place.

```bash
sudo pipelock contain grant-workspace /home/alice/src/my-project --mode read-write
```

The command resolves symlinks, requires the target to be an existing directory, rejects protected system prefixes such as `/`, `/etc`, `/usr`, `/var`, `/proc`, `/sys`, and `/root` by default, and records the grant in `/etc/pipelock/contain/workspaces.json` so later revocation knows which parent traversal ACLs are still needed.

Default ACLs are applied only below the granted directory, not on the directory root. That keeps config roots such as `~/.codex` or `~/.claude` traversable without making future root-level credential files inherit agent-read. During every grant, credential-shaped files named `auth.json`, `.claude.json`, `.credentials.json`, or `*.token` are stripped of the contained agent ACL and chmodded to `0600`.

`pipelock contain install` also installs a root-managed credential guard (`pipelock-cred-guard.path` / `.service`) that watches the operator's home directory, `.claude`, `.claude-cc2`, and `.codex` roots and re-applies the same credential lock if a later tool recreates or widens those files. The home-directory pass is depth-limited to top-level credential files such as `~/.claude.json`.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | false | Print planned ACL commands without mutating state. |
| `--mode` | `read-only` | Workspace ACL mode: `read-only` or `read-write`. |
| `--agent-user` | `pipelock-agent` | Contained agent user to grant access to. |
| `--allow-system-path` | false | Allow grants under protected system path prefixes. Use only for deliberate admin workflows. |

## `pipelock contain revoke-workspace`

Revokes ACL access previously granted with `grant-workspace`.

```bash
sudo pipelock contain revoke-workspace /home/alice/src/my-project
```

The command removes the workspace ACL and removes execute-only parent traversal ACLs that are no longer needed by any other tracked workspace. It can revoke a recorded workspace even if the workspace directory was deleted after the grant.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | false | Print planned ACL commands without mutating state. |
| `--agent-user` | `pipelock-agent` | Contained agent user to revoke access from. |

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
- **Workspace ACLs are explicit.** `install` does not automatically grant the agent user access to every repo the operator can read. Grant only the workspace needed for the current agent task, prefer read-only when possible, and revoke the grant when the work ends.
- **Dry-run is honest.** `--dry-run` prints exactly the commands install would run, with the same arguments. CI can dry-run an install change and review the diff before applying it.
- **Rollback uses guarded backups.** Managed file writes preserve prior content as `path.bak` when prior content existed. Rollback restores those backups where applicable, then removes managed artifacts.

For the deployment-tier threat model see [`security/per-deployment-ca-threat-model.md`](security/per-deployment-ca-threat-model.md). For the current unsupported-paths surface (raw sockets, browsers without explicit proxy config, processes that ignore CA bundle env vars) see [`security/current-unsupported-paths.md`](security/current-unsupported-paths.md).
