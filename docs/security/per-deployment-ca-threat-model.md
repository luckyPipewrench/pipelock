# Per-deployment CA threat model

Threat model for the per-deployment Pipelock TLS interception CA. Audience: an integrator deciding whether to enable TLS interception on a given host, and what the blast radius is if the CA on that host is compromised.

## What the CA is

Running `pipelock tls init` on a host generates a P-256 ECDSA root CA private key and a self-signed root certificate. The root key signs short-lived leaf certificates for every intercepted upstream as connections arrive. Agent processes on the host must trust the root CA for interception to succeed without certificate errors. The `pipelock tls install-ca` helper prints platform-specific commands for adding the root certificate to a trust store; the operator or deployment automation runs those privileged commands.

The CA is per-deployment. One root per host, not one root per organisation. There is no shared central CA and no remote signer.

## Why per-deployment

A shared CA would mean a single private key whose compromise lets an attacker forge certificates for every Pipelock-protected host in the organisation. Per-deployment isolates the blast radius to one host. The operational cost is that the integrator cannot bulk-install a single root across the fleet and must run `pipelock tls init` on each host. The benefit, given Pipelock's defense-in-depth posture, outweighs the operational cost in environments where the inspected hosts hold material credentials.

If the threat model on a host does not warrant TLS interception, do not run `pipelock tls init` on that host. Pipelock's capability-separation properties hold without interception; only the in-band content inspection on HTTPS traffic requires it.

## Trust boundaries

Three boundaries:

1. The CA private key lives at the configured TLS material path with file mode 0o600. It never leaves the host.
2. The CA certificate is installed in the agent's CA bundle. The integrator may also install it in the host system trust store by running the privileged commands printed by `pipelock tls install-ca`.
3. Leaf certificates are generated on demand for each intercepted upstream. They are not persisted. They are signed by the CA at request time.

Any cross-boundary leak collapses the isolation. A CA private key copied to a long-lived backup, or a CA certificate that finds its way into a fleet-wide trust bundle, breaks the per-deployment property even if everything else is configured correctly.

## CA compromise blast radius

If the per-deployment CA private key is obtained by an attacker on the same host, the attacker can mint certificates that any process trusting the host's CA accepts as legitimate. The attacker can intercept the agent's traffic indistinguishably from Pipelock itself or impersonate any upstream to the agent.

The blast radius is bounded to processes that trust the host's CA. System processes that use the system trust store after the operator installs the Pipelock root are in scope. Other workstations in the organisation are out of scope; their CAs are independent.

Mitigation: restrict the CA private-key file to 0o600 with the parent directory limited to the Pipelock service account, place the CA on encrypted disk at rest, prefer ephemeral hosts where the CA is regenerated per provision, and limit which agent processes trust the CA. Installing the CA into the system trust store widens the blast radius from "the agent the CA was minted for" to "every process on the host that uses the system trust store"; the integrator decides whether that trade is correct for the deployment.

## Snapshot restoration risks

Restoring a host from a snapshot that includes the CA material restores the same root key into the new instance. Two consequences follow. First, two live hosts now share a CA. If both run Pipelock, interception cross-talk is possible because either host can sign certificates the other host's processes trust. Second, if the snapshot was taken before a compromise, the snapshot now contains the compromised key and brings it back online.

Mitigation: treat CA regeneration as a mandatory post-restore step. The current procedure is to remove the existing CA material under the configured TLS path, re-run `pipelock tls init` to generate a fresh root, and then update the relevant trust store by running the commands printed by `pipelock tls install-ca`. The integrator's snapshot orchestration is responsible for invoking the regeneration. Automated snapshot detection is not part of the current binary. Until regeneration runs, treat any snapshot-derived host as carrying a compromised CA: the snapshot's CA key is now reachable from a second running instance, and the integrator cannot tell from outside whether the snapshot was captured before or after a compromise.

## Backup and disaster recovery

Including the CA material in a routine backup is acceptable when the backup is encrypted at rest and access-controlled. The threat is unchanged from any other backup of secret material.

Including the CA material in a long-lived off-host backup that survives the host's lifecycle is not recommended. The CA's purpose is bounded to the host it serves; a long-lived copy violates that boundary and creates a path to resurrect a CA that should have been retired with the host.

On decommission, the CA material is destroyed with the host. Coordinate destruction with whatever secure-destruction policy applies to the storage.

## What is not in scope

The Pipelock CA is not a code-signing CA. It is not a CA for non-intercepted TLS traffic. It is not a CA whose certificates are accepted by anyone except the agent host that generated it.

Do not export the root private key. Do not distribute the root certificate into fleet-wide or unrelated host trust stores. Do not use the CA to sign anything other than leaf certificates generated by `pipelock` itself. The CA is not designed to do those jobs and reusing it that way would couple unrelated trust decisions.

## Operational checklist

The integrator confirms before enabling TLS interception:

- [ ] CA private-key file is 0o600 and its parent directory is limited to the Pipelock service account
- [ ] The host is in a defined trust scope, not a shared multi-tenant box
- [ ] CA regeneration is wired into the snapshot-restore workflow
- [ ] The agent's CA bundle is updated to include the Pipelock root
- [ ] No unrelated CA bundle on the host includes the Pipelock root by accident
- [ ] Decommission procedure removes the CA material before the disk is returned or reused
- [ ] Key rotation cadence is documented and scheduled
- [ ] Integrator-side audit log records the timestamp and operator of every `pipelock tls init` invocation and every privileged trust-store update

## See also

- [key-rotation-runbook.md](key-rotation-runbook.md): signing-key rotation procedure, which is independent of the CA rotation
- [current-unsupported-paths.md](current-unsupported-paths.md): what TLS interception covers and what it does not
- [SECURITY.md](../../SECURITY.md): reporting channel for CA-related vulnerabilities
