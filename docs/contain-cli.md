# `pipelock contain`, host containment lifecycle

`pipelock contain` is the operator CLI for installing, verifying, and rolling back containment on a single Linux host. It splits one workstation into the operator account, `pipelock-proxy`, and `pipelock-agent`. The agent runs in a private network namespace with no route off-host. A socket forwarder exposes only the Pipelock proxy inside that namespace, while nftables owner-match rules keep the agent UID denied if a process ever runs outside the managed launch path. The install is idempotent and rolls back applied steps after a failure.

The subcommands are:

| Subcommand | What it does | Mutates state |
|---|---|---|
| `install` | Create users, systemd unit, nftables rules, wrappers, sudoers entry, CA bundle, runtime contract | yes (root only) |
| `upgrade` | Download, verify, replace, re-pin integrity, restart, and verify in one fail-closed command | yes (root only) |
| `run` | Verify the containment boundary, emit a signed posture capsule, then launch a registered tool as `pipelock-agent` | writes proof + starts process |
| `verify` | Read-only probes that report pass / fail / skip for the invariants below | no |
| `doctor` | Live self-test that proves common tooling reaches the internet *through* the proxy, with per-check remediation | no |
| `rollback` | Idempotently undo `install`. Restores the prior state and removes wrappers, users, unit, rules | yes (root only) |
| `add-tool` | Register an additional tool wrapper under `/usr/local/bin/plk-<name>` after install | yes (root only) |
| `explain` | Explain a contain egress block event and print remediation | no |
| `grant-workspace` | Grant the contained agent user ACL access to one project workspace | yes (root only) |
| `revoke-workspace` | Revoke a previously granted workspace ACL and clean unused parent traversal ACLs | yes (root only) |
| `list-workspaces` | List recorded workspace grants (path, mode, owner, expiry, status) | no |
| `ca-refresh` | Rebuild the combined CA bundle at `/etc/pipelock/combined-ca.pem` after a CA rotation | yes (root only) |

Each mutating subcommand accepts `--dry-run` to print the planned actions without touching state.

## Why a separate user model

Single-user containment can't enforce egress at the kernel: the same user who runs the agent can also stop the proxy, edit the config, replace the binary, or rewrite the sudoers entry. Three users solve that:

- **`operator`**, the human. Owns the install. Reaches the internet directly.
- **`pipelock-proxy`**, runs `pipelock` itself. Owns the config, the CA bundle, the binary-integrity pin. The agent user cannot read its state directory.
- **`pipelock-agent`**, runs the AI agent process in a private network namespace. It has its own loopback interface and no external route. A namespace-bound socket at `127.0.0.1:<proxy-port>` forwards to `pipelock-proxy` in the host namespace.

The agent runs with reduced capabilities (no privileged ports, no raw sockets, no NET_ADMIN). Traffic owned by the agent UID cannot bypass the proxy: the kernel owner-match refuses to forward those packets anywhere else. The rule keys on the socket owner (UID), so keeping host setuid/sudo policy tight is still an operator responsibility, a setuid or file-capability helper reachable by the agent could egress under a different UID (see "Remaining operator responsibilities"). This is why a signed posture capsule grades `kernel_observed` (the boundary was kernel-refused at attestation time) rather than an airtight continuous `kernel_enforced`, which is reserved for a future eBPF/LSM kernel-gate.

## `pipelock contain run`

`contain run` is the recommended launch path once `contain install` has completed. Run it as root (typically via `sudo`) and pass the registered tool name after `--`:

```bash
sudo pipelock contain run -- claude
sudo pipelock contain run -- codex --ask-for-approval never
```

Before it starts the tool, `contain run` fails closed unless every containment probe passes:

- system users, systemd service, nftables owner-match rules, wrappers, CA bundle, loopback proxy, `NO_PROXY`, binary-integrity pin, allow-list enforcement, and registered tool targets must all be healthy;
- the direct-egress canary from `pipelock-agent` must fail while the operator can still reach the internet, proving the negative probe is meaningful rather than a generic outage;
- a transient service launched as `pipelock-agent` must not see operator canaries in either `/tmp` or `/var/tmp`, proving the launch has private temporary directories;
- the agent network namespace must differ from the host namespace, reject a host loopback canary, and reach the namespace-bound Pipelock proxy socket;
- `pipelock-agent` must not be able to run `sudo -n true`, so the launch path refuses a host where the agent can trivially sudo back out.

After preflight, and before it launches, `contain run` prints a **session contract**: the exact boundary the agent is about to receive, derived from the same preflight state the launch uses. It lists the agent user, the proxy egress posture, the posture-capsule destination, whether the agent's `/tmp` is private, the registered tools, and every workspace grant with its owner, creation time, expiry, and status:

```text
pipelock contain run: session contract for claude
  agent user:       pipelock-agent
  proxy egress:     http://127.0.0.1:8888 (loopback proxy only; direct egress denied by nftables)
  posture capsule:  /var/lib/pipelock/contain/posture/proof.json
  agent temp dirs:  /tmp and /var/tmp private (isolated from the operator)
  registered tools: claude, codex
  workspaces:
    /home/alice/src/proj  read-write  owner=alice  created=2026-06-01T12:00:00Z  expires=never  [active]
```

Use `--dry-run` to run preflight, print the contract, and exit without emitting a posture capsule or launching. This is the way to review what a launch would grant before running it. It applies the same expiry gate as a real launch, so an expired grant prints `[expired]` and exits non-zero.

If preflight passes and no recorded workspace grant has expired, the command emits a signed posture capsule using `flight_recorder.signing_key_path` from the config. It then starts `/usr/local/bin/plk-launch <tool> ...` in a transient systemd service as `pipelock-agent` with `PrivateTmp=true`, `PrivateNetwork=true`, and `JoinsNamespaceOf=pipelock-agent-netns.service`. An expired grant is refused fail-closed (re-grant or `revoke-workspace` first). Pipelock doesn't read or store the agent's API keys. The launched tool loads its own credentials from the contained user's environment and config, the same as the `plk-*` wrappers.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--config` | `/etc/pipelock/pipelock.yaml` | Config used to sign the posture capsule. Must include `flight_recorder.signing_key_path`. |
| `--port` | `8888` | Loopback proxy port to verify before launch. |
| `--posture-output` | `/var/lib/pipelock/contain/posture` | Directory where the signed posture capsule is written. |
| `--dry-run` | off | Run preflight and print the session contract, then exit without emitting a posture capsule or launching. |
| `--workspace-diff-cap-bytes` | `10485760` (10 MiB) | Per-file content-digest cap for the workspace change statement below. Files at or under the cap get a sha256 digest; larger files are recorded oversize with no digest. |

### Workspace change statement

The posture capsule proves what the agent was *allowed* to do. It does not say what the agent actually changed on disk. `contain run` closes that gap with a second, independent artifact: a signed **workspace change statement**, written next to the posture capsule as `workspace-change-statement.json`.

Before launch, `contain run` records a manifest of every granted workspace (the same grants shown in the session contract): each path's kind (file/dir/symlink/other), size, modification time, and a sha256 content digest for regular files at or under `--workspace-diff-cap-bytes`. The digest is read through a symlink-safe, identity-checked open, so a path swapped for a symlink or a different file between listing and reading is refused rather than silently hashed. Symlinks themselves are recorded by their target string and are never followed. When the kernel supplies mount IDs, any entry on a different mount than the granted root, file or directory, is recorded as unreadable/excluded with a reason and is never hashed or descended into. When mount IDs are unavailable, the statement records `boundary_check: "device-only"`, uses `st_dev` as a weaker fallback, and is incomplete with an explicit reason because same-device bind mounts cannot be excluded reliably. The walk also stops at a local entry-count and total-path-bytes budget (`internal/cli/contain/workspacediff.DefaultBudget`, currently 200,000 entries or 64 MiB of path bytes, a Pipelock operational default, not a standard) so a pathological tree cannot make evidence collection itself unbounded.

After the launched tool exits, whether it exited cleanly, crashed, or was refused, `contain run` takes the same manifest again and diffs the two, naming every path added, removed, or modified, plus an unreadable/excluded count. A path that is unreadable, mount-excluded, or identity-changed in either snapshot is excluded from added/removed/modified along with its entire subtree, a directory that merely became unreadable mid-session is never reported as if its still-present contents had been removed. Whenever any such exclusion exists, or a snapshot's walk budget was exceeded, or the granted workspace root itself disappeared during the session, the statement sets `incomplete: true` and names the reason, instead of reporting an empty, misleadingly-clean diff.

The signing key (`flight_recorder.signing_key_path`) is resolved once before launch, then that exact key signs both the posture capsule and the statement after launch. An operator rotating the signing key while the agent runs cannot change which key signs either artifact for that session. If the key cannot be loaded before launch, `contain run` says so up front (before starting the agent) and never attempts the statement afterward.

The statement binds itself to this exact session by carrying the sha256 digest of this run's posture capsule BYTES (`posture_capsule_sha256`). **This binding is checked only by `pipelock posture verify --workspace-statement <path>`, not by the statement's own signature.** A statement's signature alone proves only that the statement is authentic; it verifies just as well when paired with a capsule from an unrelated session. `--workspace-statement` additionally re-hashes the exact capsule file bytes at `--proof` and rejects the pair if that hash does not equal the statement's declared binding, so a mismatched capsule/statement pair, or a capsule file that was altered after the statement was bound to it, is caught rather than accepted as coherent evidence. An incomplete statement is authentic evidence of a partial observation, not a passing verification: the command reports its signed boundary-check mode and incomplete reason, then fails.

This is evidence, not backup: the statement carries paths, sizes, timestamps, and digests, never file content. There is no snapshot store, no restore path, no dedup, and no retention policy, Pipelock does not keep copies of what changed, only a signed record that it changed. A statement failure (for example, a missing signing key) does not fail the session or block the launch; the posture capsule and the launch outcome stand on their own. Every outcome is also printed as a single stable line an operator script can key on without parsing prose: `workspace_change_statement=written path=<path> boundary_check=<mode>`, `workspace_change_statement=incomplete reason="<why>" path=<path> boundary_check=<mode>`, or `workspace_change_statement=unavailable reason="<why>"`.

If there are no granted workspaces, no statement is written and no outcome line is printed.

Mount-boundary detection and the TOCTOU identity re-check rely on POSIX device/inode numbers and are available only where Go exposes them (Linux, and other unix targets); `contain run` itself is Linux-only today (see `containRunSupported`), so this is not a gap in current deployments.

Exit codes:

- **0**, preflight passed and either `--dry-run` printed the session contract, or the posture capsule was written and the agent process exited successfully.
- **1**, containment was broken, posture emission failed, or the launched agent exited non-zero.
- **2**, usage/precondition error, such as not running as root, an invalid tool name, or an invalid port.

Remaining operator responsibilities: register tools with `contain add-tool`, grant workspace ACLs with `contain grant-workspace`, keep the Pipelock service running as `pipelock-proxy`, and keep host-level setuid/sudo policy tight. The built-in sudo canary catches direct `pipelock-agent -> root` sudo access; it is not a full filesystem audit of every possible setuid helper on the host.

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
6. Install the private agent network namespace and its socket-activated proxy bridge, add the Pipelock CA to the contained agent's per-user NSS database so Chromium-family browsers trust it, then install the nftables containment ruleset: deny direct outbound traffic from the agent user while allowing the operator and `pipelock-proxy` to reach the internet. When `containment.agent_listener` is set, a preceding log-and-drop rule restricts its host loopback address and port to `pipelock-proxy` and root. Browser trust requires `certutil` (`libnss3-tools` on Debian/Ubuntu, `mozilla-nss-tools` on SUSE, `nss` on Arch, or `nss-tools` on Red Hat-family distributions); installation fails rather than reporting ready when it cannot be established. Raw-egress drops are classed in nft logs (`direct_dns_blocked` or `not_routing_through_pipelock`) and counted before the terminal drop.
7. Write `/etc/pipelock/contain/tools.list`, the runtime allow-list consumed by `plk-launch`.
8. Write the node undici proxy shim at `/etc/pipelock/contain/undici-shim.cjs` (see [Runtime contract](#runtime-contract)).
9. Drop the `plk-launch` wrapper, the root-owned contained launcher, and one wrapper per registered tool into `/usr/local/bin/`.
10. Drop the known-good `pipelock-curl` / `pipelock-python` / `pipelock-node` wrappers into `/usr/local/bin/`.
11. Write the login-shell runtime contract to `/etc/profile.d/pipelock-contain.sh`.
12. Write per-tool proxy + CA config (`git` / `npm` / `pip` / `cargo`) into the agent home, then merge the Chromium launch default into the agent's agent-browser user config (see [Browser launch default](#browser-launch-default)).
13. Write the wrapper inventory, then install the narrowly scoped sudoers entry that lets the operator invoke the root-owned contained launcher without a password prompt; it starts only the registered tool as `pipelock-agent` in the private network namespace.

On systemd 253 or newer, newly installed `pipelock.service` units are `Type=notify-reload`, so `sudo systemctl reload pipelock` sends SIGHUP and waits for the daemon to finish evaluating the config. Older systemd (Debian 12, RHEL 9 and Ubuntu 22.04 ship 252 or earlier) cannot load that unit type, so `contain install` renders the previous `Type=simple` unit there; its reload only confirms signal delivery, and the verdict is in the journal. The version that decides is the running manager's, read from PID 1, not the installed `systemctl` binary's, so a host that upgraded the systemd package without rebooting keeps the older unit until it reboots and `contain install` runs again. A version the installer cannot read gets the legacy unit too, because that shape loads on every systemd. On the notify-reload unit only, exit status 0 means evaluation finished, not that the candidate policy was applied; check `sudo systemctl status pipelock` for the `Status` line and `sudo journalctl -u pipelock` for the verdict. A rejected trust expansion leaves the active policy unchanged and requires `sudo systemctl restart pipelock` to take effect.

`contain install` writes the unit and runs `systemctl daemon-reload`; when it replaces a running managed unit or binary, it restarts the service. An old `Type=simple` unit with a new binary remains compatible (the notifier is a no-op because systemd does not provide `NOTIFY_SOCKET`). A new `Type=notify-reload` unit needs the matching new binary: an old binary never sends `READY=1`, so systemd waits until its start timeout.

Exit codes:

- **0**, all steps applied (or already in place).
- **1**, a step failed; earlier applied steps were rolled back.
- **2**, precondition error: not root, missing executable, bad `--config`.

### Post-install output

On success, `install` prints a **Next steps** block with:

- **sudo secure_path check** -- if `/usr/local/bin` is not in sudo's `secure_path`, a warning explains how to add it. Without this, `sudo pipelock ...` reports "command not found" even though the binary is installed. Install emits guidance rather than silently editing sudoers.
- **Agent registration** -- the exact command to register the first agent tool (`sudo pipelock contain add-tool <name> --target /path/to/<tool>`) and how to invoke it (`plk-<name> [args...]`).
- **Evidence paths** -- where audit logs and signed receipts are written (`/var/lib/pipelock/logs` and `/var/lib/pipelock/recorder`).

### nftables version compatibility

The nftables step checks the installed `nft` version before generating rules. The containment ruleset requires nftables >= 0.8 (for `meta skuid`, inline `counter log prefix ... drop` syntax, and the `-c`/`--check` validation mode used by the install and rollback paths). On hosts with an older `nft` (seen on some older enterprise Linux images), install fails with a clear error naming the minimum version and the distro-appropriate upgrade command, rather than a cryptic parse error at load time.

## `pipelock contain upgrade`

Upgrade performs a containment-aware binary update in one fail-closed command. It bridges the gap between `pipelock update` (which replaces the binary but leaves the containment integrity pin stale) and `contain install --pipelock-binary` (which re-pins but requires the operator to have already obtained and verified the candidate).

The sequence is:

1. Validate the managed config with the integrity-pinned deployed binary and require containment-safe metrics before any binary or service change.
2. Download and verify the candidate release by invoking the **deployed** binary's `pipelock update --yes` (Ed25519 manifest + checksums + optional cosign), which replaces the binary only after those checks pass.
3. Re-pin the SHA-256 integrity hash against the newly deployed binary at `/etc/pipelock/integrity/binary-pin.sha256`.
4. Add the containment marker to `/etc/systemd/system/pipelock.service` if it is absent, so a host installed before the containment runtime guard existed gains that protection on upgrade rather than only on reinstall. This edits one `Environment=` line inside `[Service]` and leaves the rest of the unit alone; it is a no-op on a unit that already carries the marker.
5. Restart the `pipelock.service` systemd unit and wait for readiness.
6. Run `contain verify` and repeat the managed-config check. Exit 0 means every probe passed.
   A failing probe exits 1 and a skipped or inconclusive probe exits 2, so
   both roll the upgrade back.

If any step after binary replacement fails, the command rolls back both the binary and its integrity pin to the pre-upgrade state, then best-effort restarts the service.

Release-signature verification is performed by the deployed binary at `/usr/local/bin/pipelock`, not by whichever copy of pipelock you invoke this command from. The command deliberately does not pre-check the invoking binary's embedded release keyring: that would decide against one artifact while the upgrade acts on another, and it would refuse a legitimate upgrade whenever an operator runs a custom or RC copy against a healthy deployed binary. A build with no embedded release keyring cannot verify a release, so its `update` step refuses; recover such a host with `contain install --pipelock-binary <path>` after independent signature, checksum, and attestation verification.

Must be run as root.

```bash
sudo pipelock contain upgrade              # upgrade to the latest release
sudo pipelock contain upgrade --version v3.2.0  # pin to a specific tag
```

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--version` | (latest) | Install a specific release tag instead of the latest. |

Exit codes:

- **0**, upgrade completed and all verification probes passed.
- **1**, upgrade failed; previous state was restored.
- **2**, precondition error (not root, deployed binary missing or not a regular file, or no integrity pin).

## `pipelock contain verify`

Verify normally makes no host changes. It walks 18 fixed probes (numbered 1-14, 16, 19, 20, and 21) plus the conditional workspace probe, numbered 15, when workspaces are configured. Probes 17 and 18 are published by `contain run`, not `verify`. It prints pass, fail, skip, or unknown for each probe.

```bash
pipelock contain verify
```

| # | Probe name | Reports |
|---|---|---|
| 1 | `system_users_exist` | `pipelock-proxy` and `pipelock-agent` UIDs exist. |
| 2 | `pipelock_systemd_unit` | `pipelock.service` is running as `pipelock-proxy`. |
| 3 | `nftables_containment_ruleset` | The exact managed nftables chain is loaded as the active output base chain and contains the required attributed owner-match rules. |
| 4 | `wrapper_scripts_installed` | `plk-launch` plus the registered tool wrappers exist with correct mode. |
| 5 | `ca_bundle_present` | `/etc/pipelock/combined-ca.pem` is readable by the agent user. |
| 6 | `pipelock_listening_loopback` | Pipelock is accepting connections on `127.0.0.1:<proxy-port>`. |
| 7 | `no_proxy_env_correct` | `plk-launch` sets `NO_PROXY` to the loopback set documented in policy. |
| 8 | `cc_agent_egress_denied` | A DNS-free direct outbound canary from `pipelock-agent` reports that its TCP dial did not complete and coincides with an increment in the exact managed catch-all nftables DROP counter. |
| 9 | `operator_egress_reachable` | The same canary from the operator user is allowed (proves the rule scopes correctly). |
| 10 | `binary_integrity_pin` | The installed pipelock binary hash matches `/etc/pipelock/integrity/binary-pin.sha256`. |
| 11 | `cc_launch_allow_list_enforced` | `plk-launch` rejects tools that are not in the registered allow-list. |
| 12 | `listed_tool_targets_resolvable` | Every entry in `tools.list` resolves to an executable absolute path in the agent user's PATH. |
| 13 | `managed_config_metrics` | The managed config keeps metrics on a dedicated numeric loopback port or verifies a current, source-scoped remote metrics exception. It skips only when the config file is missing or permission is denied, and reports unknown for any other read failure. |
| 14 | `launch_env_allow_list` | `plk-launch` clears the operator environment with `env -i` before exec, so operator variables sudo leaves standing (e.g. `DISPLAY`, `XAUTHORITY`, `SUDO_*`) do not reach the contained agent. Fails if the launcher reverted to plain `env` or dropped the posture-proof forward. |
| 15 | `workspace_access` (conditional) | Present when `--workspace` paths are passed or recorded grants exist: each path is readable/traversable by the agent user, and no recorded grant has expired. Its published number remains stable. |
| 16 | `private_tmp_isolation` | A transient service cannot see temporary canaries created in the operator's `/tmp` and `/var/tmp`. Requires root; the canaries are removed before the probe returns. |
| 19 | `pipelock_ca_export_current` | `/etc/pipelock/ca.pem` is a valid CA and exactly matches the CA selected in the contain-managed keystore. It fails with `contain ca-refresh` when a rotation left the export stale. |
| 21 | `agent_network_namespace` | The namespace anchor and socket-forwarder units match the managed definitions, the namespace differs from the host network namespace, a contained process can't reach a host loopback canary, the namespace proxy socket reaches Pipelock, and every live process under the managed agent UID occupies that same namespace. |
| 20 | `agent_browser_ca_trust` | The contained agent's per-user NSS database trusts the Pipelock CA with SSL CA trust `C`. It reports trust, not provenance: a matching certificate an operator added themselves passes, because the agent can browse either way. Fails when `certutil` is absent, when the nickname holds a different certificate, or when the trust flags were narrowed. Install and rollback consult the ownership marker so rollback removes only what install added. Probes 17 and 18 are published by `contain run`, not `verify`. |

### Managed metrics invariant

Containment keeps `metrics_listen` on a numeric loopback address and a port other than the agent-accessible proxy port by default. Keep the key present. Removing it registers `/metrics` and `/stats` on the proxy listener, where the contained agent can reach them.

Repair the managed config with a dedicated loopback listener such as:

```yaml
metrics_listen: 127.0.0.1:9091
```

Choose another unused non-proxy port if `9091` is unavailable. Do not delete `metrics_listen` to disable metrics.

When a Prometheus server must scrape from another host, declare a short-lived exception with the listener's assigned numeric address and the exact source CIDRs that may scrape it. `allow_full_metrics` is deliberately explicit because `/metrics` contains live enforcement data. `owner` and `reason` record who accepted that exposure and why. `expires_at` uses RFC3339 and must remain in the future.

```yaml
metrics_listen: 192.0.2.20:9091

containment:
  metrics_exposure:
    allow_full_metrics: true
    allowed_source_cidrs:
      - 192.0.2.42/32
    owner: observability
    reason: Prometheus scrape from the monitoring host
    expires_at: 2026-12-01T00:00:00Z
```

Replace the documentation addresses with addresses assigned to the host and scraper. Wildcard and hostname binds are rejected. An absent, malformed, or expired exception denies remote metrics requests, and probe 13 fails. `/metrics` returns 403 to every source outside `allowed_source_cidrs`. `/stats` remains loopback-only because it includes blocked domains and scanner categories.

The proxy also refuses to dial its configured metrics address and port. An `ssrf.ip_allowlist`, trusted domain, or grant cannot reopen this path through the agent's permitted proxy connection.

### Declared loopback services

The private namespace starts with one bridge to the host: the Pipelock proxy socket. An operator who needs the agent to reach another host loopback TCP service, such as a local search index, declares it in the managed config. Pipelock creates a socket with the same address and port inside the agent namespace and forwards accepted connections to the host service. The agent gets that socket, not a route to the host network.

## Dynamic listeners owned by the contained runtime

Some stock tools bind a loopback listener on a kernel-assigned TCP port and connect back to it. That works without a declared port because the tool and its child processes share the private namespace's loopback interface. A listener on the host's loopback interface remains unreachable, even when it runs under the same Unix account.

`pipelock contain install` creates and starts `pipelock-agent-netns.service`. The host-side `pipelock-agent-proxy.socket` creates the pathname doorway `/run/pipelock-agent-proxy.sock`; its `pipelock-agent-proxy.service` relay forwards connections to the host Pipelock listener. Inside the agent namespace, `pipelock-agent-netns-forward.service` creates the loopback proxy listener and connects it to that doorway. Pipelock doesn't add a veth pair, a gateway, or a default route. The proxy stays in the host namespace for network egress.

```yaml
containment:
  loopback_services:
    - host: 127.0.0.1
      port: 9200
      owner: search-team
      reason: agent needs a local search index for retrieval
      expires_at: 2026-12-01T00:00:00Z
```

Each entry uses the same reviewable lifecycle as `containment.metrics_exposure`. `host` must be `127.0.0.1` or `::1`, and `port` must be from 1 through 65535 without colliding with the proxy port. `owner`, `reason`, and a future RFC3339 `expires_at` value are required. Pipelock rejects malformed, expired, duplicate, and proxy-port entries during config validation.

`contain install` writes one socket and forwarder service pair for each declaration. It also writes a root-owned inventory containing the address, port, owner, reason, and expiry. `contain reload-nft-rules` re-reads the managed config and reconciles those units from the current declaration set. Removing an entry or letting it expire disables and removes its namespace socket at the next successful reconciliation. The host nftables rules never gain an allow for a declared service.

`pipelock contain install` prints a warning when a declared address has no reachable host TCP listener. It keeps the declaration because the host service may be temporarily stopped or start later. This still reserves the address inside the private namespace: if the contained tool is supposed to bind that port itself, remove the declaration instead of ignoring the warning.

Run `sudo pipelock contain reload-nft-rules` after changing `containment.loopback_services`. The boot-time persistence unit runs the same reconciliation on startup. If the managed config is missing or unreadable, or the declared set is malformed or expired, reconciliation uses zero declared forwarders and logs the reason. The base namespace and proxy socket stay in place, so the agent loses the extra service without gaining another path.

The boot-time persistence unit runs the same reconciliation command on every boot.

`contain install` also enables a privileged expiry timer. Its oneshot service runs `contain reload-nft-rules`, so an expired forwarder disappears on the next successful reconciliation. The timer's calendar cadence and accuracy slack bound the normal delay. `Persistent=true` catches a firing missed while the timer was inactive, but it doesn't make expiry exact to the second.

`contain verify` requires the expiry timer and service to have the managed
linkage and command, the timer to be enabled, and the service not to be
masked. If it reports a masked unit, unmask that unit and rerun `pipelock
contain install` as root.

An exclusive lock prevents `contain install` and `contain reload-nft-rules` from reconciling the same config at once. The root-owned lock file lives beside the persisted rules under `/etc/nftables.d/`. Reconciliation rejects a symlink, named pipe, or non-root owner at that path.

`contain verify` compares the declared set with the root-owned forwarder inventory and each managed unit file. It requires every declared socket to be persistently enabled and active. The live namespace probe fails when the namespace is missing, shares the host network namespace, reaches a host loopback canary, can't reach the Pipelock proxy socket, or finds a managed-agent process outside the namespace. The process check catches older and custom services that run under the correct user but never entered the managed namespace.

## Published agent services

`containment.published_services` publishes a listener that the contained agent runs on its own namespace loopback to one operator on the host, for example a viewer the agent runs for its own display. See "Published services (containment)" in `configuration.md` for the fields.

`containment.display.backend: xvnc` selects TigerVNC Xvnc instead of the existing Xvfb fallback. `contain install` requires the Xvnc binary and keeps RFB on an agent-owned `0600` Unix socket at `/home/pipelock-agent/.local/state/pipelock/display/rfb.sock`; TCP RFB is disabled. `contain verify` checks the display and RFB sockets separately. Install TigerVNC's Xvnc package if doctor reports it missing, then rerun `contain install` if the RFB socket is absent.

For each entry, `contain install` writes a socket unit, `pipelock-published-<name>.socket`, and a socket-activated relay, `pipelock-published-<name>.service`. systemd creates the host socket owned by `operator_user` with mode `0600`. The relay runs `pipelock contain netns-forward` as the proxy service user and joins the agent's network namespace, so it dials the agent's own loopback. It never runs as `pipelock-agent`, and the agent gets no host-side process and no new outbound route. The nftables rules don't change. An optional `host_listen` adds a `pipelock-published-<name>-tcp` socket and relay pair. `contain install` refuses an `operator_user` that doesn't exist or that names the agent account.

`contain reload-nft-rules`, the boot-time persistence unit, and the expiry timer reconcile publications from the managed config along with loopback services. A removed or expired entry has its socket disabled and its units removed at the next successful reconciliation, including after an earlier successful install. If the managed config declares a publication that Pipelock can't honor, reconciliation closes every publication and logs the reason. A failed install restores the previous units and their runtime state. `contain rollback` closes every recorded publication.

`contain verify` checks publications as part of the private-namespace probe. It reports these failures separately:

- **drift:** a unit file or the root-owned record at `/etc/pipelock/contain/published-services.json` doesn't match the declaration
- **bridge failed:** the host socket is missing, not persistently enabled, or inactive, or the relay has failed
- **access denied:** the host path isn't a socket owned by `operator_user` with mode `0600`
- **wrong namespace:** a running relay isn't in the agent's namespace
- **absent listener:** nothing in the agent namespace listens on the published address and port

A state the probe can't read counts as a failure. An idle relay is normal, because the next connection starts it.

Published content is untrusted agent content in both directions. Pipelock doesn't ship a viewer or serve the endpoint remotely. Remote access is your job, behind your own authentication.

### Launching a contained systemd service

Use a systemd drop-in to keep a continuously supervised agent unprivileged. Replace `agent-tool` and its arguments with a registered tool:

```ini
[Unit]
BindsTo=pipelock-agent-netns.service pipelock-agent-netns-forward.service
After=pipelock-agent-netns.service pipelock-agent-netns-forward.service

[Service]
User=pipelock-agent
Group=pipelock-agent
WorkingDirectory=/home/pipelock-agent
PrivateNetwork=true
JoinsNamespaceOf=pipelock-agent-netns.service
PrivateTmp=true
ExecStartPre=!/usr/local/bin/pipelock contain service-posture -- agent-tool
ExecStart=
ExecStart=/usr/local/bin/plk-launch agent-tool
Restart=on-failure
```

The dependencies stop the agent when the namespace or proxy forwarder is missing, masked, failed, or stopped. `PrivateNetwork=true` can create a separate empty namespace when no valid target is available, so it isn't enough on its own.

The short-lived `ExecStartPre` command runs with root credentials because of the `!` prefix, but retains the service's namespace restrictions. Before it signs anything, `service-posture` compares its own live kernel network-namespace identity with `pipelock-agent-netns.service`, requires loopback to be the only interface, and checks the Pipelock proxy doorway from inside that namespace. A mismatch or inconclusive check fails the pre-start command, so systemd never starts the agent. The signer exits before the agent starts and never receives agent input or output.

Immediately before it executes the tool, `plk-launch` checks its user, its real kernel namespace identity, the interfaces visible in that namespace, and the Pipelock health endpoint. The root preflight and probe 21 also compare the managed namespace with the host and inspect every live process under the agent user. The service settings state the intended isolation. These checks prove the running process received it.

The pre-start signer writes the same signed posture capsule path used by `contain run` and labels its signed `contain_launch.launcher` evidence as `systemd-service-prestart:/usr/local/bin/plk-launch`. That label means the signer directly observed the exact managed namespace and working proxy doorway before systemd admitted the pending unprivileged service launch. The tool and arguments on `ExecStartPre` must match `ExecStart`; they describe the pending launch, while the capsule doesn't claim that the agent process had already started.

`contain run` makes a different observation. Its root supervisor signs the host-side preflight and intended launch contract, then `plk-launch` independently refuses to execute the child unless the child is in the exact managed namespace. Because the `contain run` signer itself is outside the child namespace, its capsule doesn't claim signer membership in that namespace. The supervisor remains alive and additionally emits the post-session workspace change statement; the unprivileged service path has no long-lived supervisor and therefore emits no final workspace statement.

Both paths use the private key named by `flight_recorder.signing_key_path`. The key is operator-chosen; `pipelock init` normally places it under `/etc/pipelock/keys/`. It must not be readable by `pipelock-agent`, because an agent that holds the key can forge its own evidence. Before either path emits a containment capsule, Pipelock checks the real access decision as `pipelock-agent` and refuses to sign if the key is readable or the check is inconclusive.

Pipelock doesn't rewrite operator-owned service drop-ins during upgrade. Replace the earlier `ExecStartPre=+... contain run --dry-run` recipe with the `service-posture` line above, then run `sudo systemctl daemon-reload` and restart that service. An old drop-in still performs a preflight, but it doesn't emit a capsule.

The nftables probes fail closed when attribution is ambiguous. A regular
lookalike chain, a table-wide listing that happens to contain matching-looking
rules, or an unreadable managed DROP counter is reported as not enforced rather
than treated as probable containment.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--json` | false | Emit newline-delimited JSON records instead of text output. |
| `--port` | `8888` | Loopback port to probe for the listener check (matches `--proxy-port` from install). |

Exit code is 0 if every probe passed, 1 if any probe failed, and 2 if
verification was incomplete because one or more probes skipped or were
inconclusive (`unknown`). Probe 8 uses a literal TEST-NET IPv4 target and a
two-second ceiling so DNS/TLS failures cannot produce a pass. Its managed
counter is scoped to the contained UID rather than the individual curl process,
so unrelated simultaneous traffic under that same UID can still contribute a
counter increment; verify remains read-only and does not install a temporary
probe-specific rule.

## Runtime contract

The containment boundary is security-correct, but a tool that ignores the proxy environment looks *broken*, it dies with a generic network error and no hint that the firewall is the cause. To close that gap, `install` provisions a complete, proxy-correct runtime contract for the contained agent so common tooling works out of the box and stays routed through Pipelock.

The contract has four parts:

`plk-launch` builds this environment with `env -i`, it starts from an empty environment and rebuilds only the identity block, the matrix below, the posture-proof binding, and the agent PATH. This is deliberate: `plk-launch` runs after `sudo`, which leaves operator variables standing (`DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR`, `SUDO_*`), and plain `env` would pass every one of them through to the contained agent. `env -i` closes that leak, and it uses the same environment set as the `contain run` Go launcher so the two launch paths cannot drift (verify probe 14 fails if the launcher reverts to plain `env`). The tradeoff is that ambient niceties like `TERM`/`LANG` are not forwarded either; this already matched the `contain run` path, so it is not a new regression there.

1. **Full environment matrix.** `plk-launch` (and the login-shell script below) export the complete proxy + CA set, because different ecosystems read different variables:

   - Proxy (upper- and lower-case): `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` and their lowercase forms, all pointing at `http://127.0.0.1:<proxy-port>`.
   - `NO_PROXY` / `no_proxy` = `127.0.0.1,localhost,::1` (IPv6 loopback included so IPv6-first clients don't proxy a local dial).
   - CA trust for the Pipelock MITM CA: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`, `PIP_CERT`, and `NODE_EXTRA_CA_CERTS` → the combined bundle. Node appends it to its built-in store; using the shared bundle keeps all clients on the same rotated CA.
   - `NODE_OPTIONS=--require <undici-shim>` (see below).

2. **node undici shim** (`/etc/pipelock/contain/undici-shim.cjs`). Node's built-in `fetch()` and undici-based clients ignore `HTTPS_PROXY` unless a global dispatcher is installed. The shim installs an undici `ProxyAgent` at startup. It is best-effort: if undici cannot be required, `http`/`https`-module traffic still honors the proxy env, so the shim degrades silently rather than breaking node.

3. **Known-good wrappers** on the agent PATH: `pipelock-curl`, `pipelock-python`, `pipelock-node`. Each forces the full contract before exec'ing the real tool, so it is proxy- and CA-correct even when the caller's environment is incomplete (for example, a bare `sudo -u pipelock-agent <cmd>` that inherits no proxy env).

4. **Per-tool config files** written into the agent home (`~/.gitconfig`, `~/.npmrc`, `~/.config/pip/pip.conf`, `~/.cargo/config.toml`). These tools read their own config regardless of environment, so config-driven invocations are proxy-correct on every exec path. The managed `.npmrc` sets `ignore-scripts=true`, and the runtime environment sets `npm_config_ignore_scripts=1`, so an untrusted project `.npmrc` cannot re-enable `package.json` lifecycle scripts during dependency installation on the contained runtime path. This is an install default, not an execution boundary: a caller can deliberately unset the environment variable or pass a command-line override, and a bare non-login npm invocation outside `plk-launch` does not inherit the runtime environment. Packages that compile or download native components during install will need an explicit override. For a known dependency, run that install as `npm install --ignore-scripts=false`; the command-line override applies only to that npm command, and the containment boundary still applies. Existing installations receive this contract after `pipelock contain install` is rerun; `contain upgrade` updates the binary but does not rewrite agent tool configuration.

5. **Browser launch default** (`~/.agent-browser/config.json` in the agent home). See [Browser launch default](#browser-launch-default).

A login-shell script at `/etc/profile.d/pipelock-contain.sh` exports the same matrix so an interactive `sudo -iu pipelock-agent` session inherits it too. Because `/etc/profile.d` is sourced by all login shells, the script returns immediately for every user except `pipelock-agent`.

`containment.display.geometry` sets the display size as one `WxH` token (default `1280x1024`, width 320–65535, height 200–65535). Rerun `contain install` after changing it.

`pipelock contain view` starts a local Unix socket for a standard VNC client. Run it as the configured `operator_user`; add `--control` to allow keyboard and pointer input. The command prints the socket path and an SSH forwarding example.

### Xvfb display authorization

When the managed display is enabled, `pipelock contain install` creates a fresh 128-bit MIT-MAGIC-COOKIE-1 record in `/var/lib/pipelock-agent/Xauthority`. The root-owned state directory is mode `0711`; the cookie file belongs to `pipelock-agent` and has mode `0600`. Xvfb starts with `-auth` pointing at the file, and the contained launch environment sets `XAUTHORITY` to the same path. Re-running install rotates the cookie and restarts an active Xvfb. `pipelock contain rollback` removes the managed cookie file.

### Browser launch default

Under automation, Chromium advertises an automation marker that managed bot challenges can loop on. `pipelock contain install` adds `--disable-blink-features=AutomationControlled` to the `args` string in agent-browser's user config, `~/.agent-browser/config.json` in the contained agent's home. Every agent launched under containment runs as that one account, so every contained agent that drives Chromium through agent-browser gets the default, whichever agent it is. Existing keys and launch arguments are kept (comma- and newline-separated `args` both work), an existing file is backed up to `config.json.bak` before the change, and a flag that is already present is left alone. A file that is not valid JSON, an `args` value that is not a string, a symlink at `~/.agent-browser` or at the file itself, or a browser directory owned by another account stops the install before anything is written; repair it and rerun `pipelock contain install`. On Linux, install opens the browser directory without following symlinks and performs config and backup operations through that directory handle.

This is the lowest-precedence setting agent-browser reads. A project `agent-browser.json`, an `AGENT_BROWSER_ARGS` value, or a CLI flag the agent passes replaces it, so an agent that sets its own launch arguments keeps them. That is also why containment does not export `AGENT_BROWSER_ARGS`: the variable would replace the agent's own arguments. Agents that launch Playwright's or Puppeteer's bundled browser directly read neither this file nor an environment variable for launch arguments; only the agent's own launch code can add the flag there.

Install records what it added in `/etc/pipelock/contain/agent-browser-defaults.json`, a root-managed file the contained agent cannot write. `pipelock contain rollback` consults only that record: it removes Pipelock's copy of the flag, restores the previous `args` value exactly when nothing else changed, keeps edits made since install, and deletes the file only when install created it and nothing else was added. A flag that was already present before install has no record and is never removed. `contain verify` does not report this setting; it is a launch default, not part of the containment boundary.

This makes compatible tooling work; it does **not** widen egress. Direct (proxy-bypassing) connections from the agent user remain blocked by the nftables owner-match rule.

### Filesystem sharing

`contain run` requires systemd 254 or newer and starts the agent in a transient service with private `/tmp` and `/var/tmp`. `contain verify` creates and removes canaries in both host directories, then proves the transient service cannot see them before `contain run` advertises private temporary storage in its session contract. Do not use `/tmp` to hand secrets to or from the agent: it is intentionally not shared. The supported, audited way to share a directory with the agent is a workspace grant (`contain grant-workspace`), which is recorded, listable, and revocable.

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
| 5 | `dns_failure_clean` | An unresolvable host fails fast with a clean proxy error, no hang, no bypass. |
| 6 | `raw_egress_blocked` | A DNS-free direct, proxy-bypassing canary reports that its TCP dial did not complete and coincides with an increment in the positively attributed managed catch-all DROP counter. This is also the root cause a proxy-unaware tool surfaces, so the remediation names the fix. |
| 7 | `managed_chain_structure` | The live managed nftables chain can be read and has the installed structure. This is a qualified structural result only; check 6 observes packet enforcement. |
| 8 | `managed_doorway_sockets` | Every managed doorway socket, the proxy doorway plus one per declared `containment.loopback_services` entry, is persistently enabled and active. A socket that is not enabled or not active reports FAIL naming the socket and the `systemctl` command that restores it; a declared service set that cannot be honored reports FAIL. |

Checks print a one-line, class-tagged remediation when an operator action or compatibility note is useful; this can accompany either a non-passing result or a PASS that diagnoses expected containment behavior. For example, a proxy-unaware tool produces:

```text
  [PASS] check 6: direct (proxy-bypassing) egress is blocked for the agent, direct egress blocked at managed nftables DROP (curl exit 7, counter 12 -> 13); proxy-unaware tools fail here
          ↳ [proxy-compat] a tool that 'can't reach the internet' is ignoring the proxy, NOT broken, run it via pipelock-curl / pipelock-python / pipelock-node, or export HTTPS_PROXY=http://127.0.0.1:8888
```

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--json` | false | Emit newline-delimited JSON records (`check`, `name`, `status`, `detail`, `remediation`, `class`) instead of text. |
| `--port` | `8888` | Loopback proxy port to test (matches `--proxy-port` from install). |
| `--url` | `https://example.com/` | Allowed canary URL the agent should be able to reach. |

Exit code is 0 if every check passed, 1 if any check failed, and 2 if the
diagnosis was incomplete because a check skipped or was inconclusive. Missing
tools skip; unattributable raw-egress failures report `unknown` rather than
claiming containment.

After the result summary, `doctor` prints the resolved evidence paths so operators know where to find audit logs and signed receipts:

```text
Evidence paths:
  logs:     /var/lib/pipelock/logs
  receipts: /var/lib/pipelock/recorder
```

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

Idempotently undoes `install`. Safe to re-run on a partial install, every step checks state before mutating.

```bash
sudo pipelock contain rollback
```

Removes the `plk-*` and `pipelock-*` wrappers, the node undici shim, the `/etc/profile.d` runtime-contract script, the per-tool agent config, Pipelock's recorded agent-browser launch flag, the sudoers entry, nftables rules, systemd unit migration, and the `pipelock-proxy` / `pipelock-agent` users by default. It preserves `/etc/pipelock` and `/var/lib/pipelock` unless you pass `--keep-data=false`.

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

Each grant is recorded with lifecycle metadata: the owner (the operator behind `sudo`, else the current user), an optional `--reason`, the creation timestamp, and an optional expiry from `--expires`. `--expires` accepts either a Go duration (for example `720h`) or an absolute RFC3339 timestamp. An **expired** grant is refused fail-closed by `contain run` and fails the `workspace_access` verify probe; the ACL itself is not auto-removed, so `revoke-workspace` (or a fresh grant) is still how you take the access away. In other words, expiry gates the launch, it does not unset the ACL. Inventories written by an older Pipelock (path and mode only) still load and are shown as legacy grants with no metadata. Use `list-workspaces` to see every recorded grant and its status.

```bash
sudo pipelock contain grant-workspace /home/alice/src/my-project --mode read-write --reason "sprint-42 refactor" --expires 336h
```

Default ACLs are applied only below the granted directory, not on the directory root. That keeps config roots such as `~/.codex` or `~/.claude` traversable without making future root-level credential files inherit agent-read. During every grant, credential-shaped files named `auth.json`, `.claude.json`, `.credentials.json`, or `*.token` are stripped of the contained agent ACL and chmodded to `0600`.

`pipelock contain install` also installs a root-managed credential guard (`pipelock-cred-guard.path` / `.service`). The path unit uses `PathChanged` watches on exact credential-shaped files under the operator's home directory, `.claude`, `.claude-cc2`, and `.codex` roots so systemd can catch atomic temp-file plus rename rewrites through leaf-path watching. It also keeps `PathChanged` watches on those roots because systemd has no `PathChangedGlob`, and dynamic `*.token` files must still be discovered without level-triggered `PathExistsGlob` loops. The service filters each rescan to credential-shaped files only and re-applies the same credential lock if a later tool recreates, replaces, or widens them. The home-directory pass is depth-limited to top-level credential files such as `~/.claude.json`.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | false | Print planned ACL commands without mutating state. |
| `--mode` | `read-only` | Workspace ACL mode: `read-only` or `read-write`. |
| `--agent-user` | `pipelock-agent` | Contained agent user to grant access to. |
| `--allow-system-path` | false | Allow grants under protected system path prefixes. Use only for deliberate admin workflows. |
| `--reason` | (none) | Optional justification recorded with the grant. |
| `--expires` | (none) | Grant expiry as a Go duration (e.g. `720h`) or an RFC3339 timestamp. An expired grant is refused at launch and fails verify. |

## `pipelock contain list-workspaces`

Lists every recorded workspace grant so "what can the agent reach today, and why" is one command. Read-only; safe without root.

```bash
pipelock contain list-workspaces
```

Prints a table of path, mode, owner, creation time, expiry, and status (`active`, `expired`, `legacy`, or `invalid-expiry`). An `expired` grant still has its ACLs on disk, clear them with `revoke-workspace`.

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--agent-user` | `pipelock-agent` | Contained agent user whose grants to list. |

Grants recorded by this version carry the agent user they were granted to and are listed only for that `--agent-user`; grants written by an earlier version carry none and are listed for every agent user. The table includes the reason recorded at grant time.

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

Refreshes `/etc/pipelock/ca.pem` from the CA in the contain-managed keystore and rebuilds `/etc/pipelock/combined-ca.pem` after a Pipelock CA rotation or a system trust-store change. `contain verify` compares the single export with that keystore CA by certificate material rather than by subject name, and fails rather than reporting readiness when they differ. This is not a live handshake: a proxy that has been running since before a rotation still holds the previous CA in memory, and only a restart makes the selected CA the served one.

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

## Containment conformance artifact

The two direct-egress probes, probe 8 (`cc_agent_egress_denied`) and probe 9 (`operator_egress_reachable`), are also packaged as a publishable conformance artifact under `sdk/conformance/testdata/containment/`. The artifact proves the egress-denied test is *real*: it ships a deliberately-leaky fixture in which the agent's direct-egress canary succeeds (containment broken), and the gate **must** fail on it.

The probes run against a canned command-runner built from external JSON fixtures, with no real network, sudo, curl, or nftables. Each fixture is a pair:

- `<name>.probe.json`, the canned `(command → stdout, exit_code)` inputs.
- `<name>.expect.json`, the expected per-probe status and aggregate exit code.

Probe 8's DROP-counter evidence can come from either of two mutually exclusive fixture inputs. `drop_counter_reads` pre-bakes the raw before/after counter values probe 8 reads; it can express a corroborating counter delta (or its absence) but cannot express a *structural* problem in the chain itself. `nft_chain_text` (with `agent_uid` and `proxy_uid`, and optionally `operator_uid`/`proxy_port`) instead supplies the literal `nft -n -a list chain ...` output text and routes it through the SAME chain-text recognizer `pipelock contain verify` (probe 3) uses in production, `agentUIDBareAcceptBeforeDrop` and `chainLinesHaveUnsafeVerdictBeforeAgentDrop`, so a fixture can prove a structural containment hole that no counter-value pair could represent.

| Fixture | Input | Probe 8 | Overall exit | Role |
|---|---|---|---|---|
| `pass-all` | `drop_counter_reads` | `pass` (egress blocked) | 0 | clean baseline, gate must PASS |
| `leaky-egress` | `drop_counter_reads` | `fail` (egress leaked) | 1 | **must-fail**, gate must DETECT a leaked canary |
| `agent-accept-before-drop` | `nft_chain_text` | `fail` (structural hole) | 1 | **must-fail**, gate must DETECT a bare agent-UID accept rule ahead of the managed catch-all DROP, a distinct production outcome from a leaked canary (same status, different detail and root cause) |
| `dial-completed-then-failed` | `drop_counter_reads` | `fail` (dial completed before curl failed) | 1 | **must-fail**, gate must DETECT a canary whose TCP connect completed even though curl then failed; the dial-completion timer, not the counter, is the load-bearing signal |

The fixture schema, including the mutual-exclusion rule between `drop_counter_reads` and `nft_chain_text` and the compatibility guarantee for existing fixtures, is documented in `sdk/conformance/testdata/containment/README.md`. Run the artifact two ways:

```bash
# Go conformance test over every fixture pair.
go test -run TestContainmentConformance ./sdk/conformance/

# Standalone gate: runs the test and additionally proves the must-fail property
# (it flips the leaky fixture to expect a pass and confirms the test then fails).
bash sdk/conformance/containment-gate.sh
```

The test drives the probes through the exported `contain.RunContainmentConformance` seam, so it stays a thin, reproducible wrapper over the same probe logic `pipelock contain verify` runs in production. CI gates the artifact via the `containment-conformance` job in `.github/workflows/verifiers.yaml`, triggered by changes under `internal/cli/contain/**` or `sdk/conformance/**`.

## Operational notes

- **Binary integrity is TOFU.** The first `install` pins the binary hash. Verify compares the installed binary against that pin on every run. To install a new pipelock binary, run `install` again with `--pipelock-binary <new path>`; install rewrites the pin atomically.
- **The agent never gets `NET_ADMIN`.** Even if the agent runs as root inside a namespace, the host nftables ruleset blocks its egress. The proxy is the only egress path.
- **Workspace ACLs are explicit.** `install` does not automatically grant the agent user access to every repo the operator can read. Grant only the workspace needed for the current agent task, prefer read-only when possible, and revoke the grant when the work ends.
- **Dry-run is honest.** `--dry-run` prints exactly the commands install would run, with the same arguments. CI can dry-run an install change and review the diff before applying it.
- **Rollback uses guarded backups.** Managed file writes preserve prior content as `path.bak` when prior content existed. Rollback restores those backups where applicable, then removes managed artifacts.

For the deployment-tier threat model see [`security/per-deployment-ca-threat-model.md`](security/per-deployment-ca-threat-model.md). For the current unsupported-paths surface (raw sockets, browsers without explicit proxy config, processes that ignore CA bundle env vars) see [`security/current-unsupported-paths.md`](security/current-unsupported-paths.md).
