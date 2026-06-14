# CLI Reference

This index covers the commands with a dedicated page. Run `pipelock --help` for
the full command tree and `pipelock <command> --help` for any command's flags.

| Command | Purpose |
|---|---|
| [`pipelock baseline`](baseline.md) | Inspect, ratify, and relearn behavioral-baseline profiles through the admin API. |
| [`pipelock demo`](demo.md) | Run self-contained attack scenarios that show what Pipelock catches. |
| [`pipelock scan`](scan.md) | Scan files for invisible-Unicode and bidi-control injection. |
| [`pipelock skill-scan`](skill-scan.md) | Inventory skill files, compare lock drift, and flag conservative source-to-sink combinations. |
| [`pipelock doctor`](doctor.md) | Audit whether configured protections are actually enforceable in the current topology. |
| [`pipelock explain`](explain.md) | Explain a URL verdict and the exact, per-scanner remediation knob for a block. |
| [`pipelock verify-install`](verify-install.md) | Deterministic smoke checks that scanning is wired and (in containment) direct egress is blocked. |
| [`pipelock adaptive`](adaptive.md) | Operator CLI for adaptive-enforcement state and overrides. |
| [`pipelock session`](session.md) | Operator CLI for airlock session recovery. |
| [`pipelock keys status`](keys.md) | Unified view of every signing-key purpose: source, presence, readability, and validity. |
| [`pipelock mcp integrity manifest`](mcp-integrity.md) | Generate and verify MCP server binary-integrity manifests. |
| [`pipelock init sidecar`](init-sidecar.md) | Generate an enforced Pipelock companion proxy for a Kubernetes workload. |
| [`pipelock license`](license.md) | Install, inspect, and check the license that unlocks paid features. |
| [`pipelock update`](update.md) | Check for, verify, and install a newer Pipelock release; roll back to the previous binary. |
