# Sandbox launch posture

`pipelock sandbox` applies three independent Linux containment layers at launch: a network namespace, Landlock filesystem rules, and a seccomp filter on `linux/amd64`. The launch status is evidence from the child after it applies those layers; a preflight result is only a capability probe.

## Outcomes

| Outcome | Meaning |
|---|---|
| `full` | Landlock, seccomp, and the network namespace applied. |
| `partial` | Landlock and the network namespace applied, but the build has no seccomp filter. This is the labelled `linux/arm64` state; it is not full containment. |
| `advisory-override` | An authorized `--best-effort` launch ran without a network namespace. Direct egress may bypass Pipelock. If seccomp is also unavailable, the status line reports both `ADVISORY-OVERRIDE (network)` and `PARTIAL (seccomp unavailable)` together. |
| `refused` | The child did not apply a required layer, so the target does not start. |

Landlock is mandatory for the normal Linux sandbox. A host that cannot apply it refuses the launch because the process would otherwise retain access to host files the sandbox claims to fence off. Use host-level `pipelock contain` when that is the deployment boundary available on an older kernel.

`--strict` requires seccomp and descendant cleanup (the Linux child subreaper) as well as the network namespace; it refuses to start without either. A non-strict launch prints one startup warning when descendant cleanup is degraded: a detached descendant can then outlive the session and hold proxy shutdown open. On `linux/arm64`, the normal non-strict launch can be `partial` because the seccomp filter is not built for that architecture. Do not describe that launch as fully contained.

## Ubuntu and AppArmor user-namespace restriction

Ubuntu 24.04 and later restrict unprivileged user namespaces with AppArmor by default (`kernel.apparmor_restrict_unprivileged_userns = 1`). On such a host `pipelock sandbox --dry-run` can report `CAPABILITIES_OK` with the network layer `available`, because the dry run only probes capabilities, and the real launch then fails after the network layer reports `ACTIVE`:

```text
[sandbox] loopback: netlink error: operation not permitted
exit status 1
```

Check the setting with `sysctl kernel.apparmor_restrict_unprivileged_userns`. A value of `1` means the restriction is on. There are two ways to let the sandbox start, and each one changes host policy:

- Give the `pipelock` binary an AppArmor profile that allows the `userns` permission. The rest of the host keeps the restriction, but AppArmor confinement carries across `exec`, so the agent the sandbox launches runs under the same profile and gets the same permission unless the profile moves it to a separate profile when it starts.
- Set `kernel.apparmor_restrict_unprivileged_userns=0` with `sysctl`. This lifts the restriction for every unprivileged program on the host, which gives up a hardening Ubuntu applies against user-namespace kernel exploits, so use it only on a machine you accept that for (a disposable test VM, for example).

## Advisory network override

The default for a missing network namespace is refusal. `--best-effort` is a temporary, explicit advisory override for environments such as containers that disable unprivileged user namespaces. It requires both an operator reason and a bounded expiry:

```bash
pipelock sandbox --best-effort \
  --best-effort-reason "container user namespaces disabled" \
  --best-effort-expiry 30m -- python agent.py
```

`--best-effort-expiry` accepts a duration or an RFC3339 timestamp. It bounds launch admission only: an expired override refuses that launch, it never stops an already running child, and every later launch must be re-authorized. YAML always requires RFC3339, so copying, touching, restoring, or rewriting its file cannot renew an authorization through filesystem metadata, and a YAML expiry may lie at most 30 days after the time the configuration is validated, so one edit cannot authorize the override for a year. Keep the override and both authorization fields in one source: all three command-line flags, or all three YAML fields. The status line explicitly warns that direct egress may bypass Pipelock; proxy environment variables still scan cooperative HTTP clients but are not a kernel network boundary.

The MCP subprocess equivalent is `--sandbox-best-effort`, `--sandbox-best-effort-reason`, and `--sandbox-best-effort-expiry`.
