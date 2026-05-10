# Audit Packet schema changelog

Schema versions are independent from pipelock binary releases. Producers stamp the schema
version into every packet under `schema_version`.

## v0 — initial release

`schema_version`: `pipelock.audit_packet.v0`

Locks:

- Top-level required: `schema_version`, `generated_at`, `run`, `policy`, `summary`,
  `verifier`, `posture`, `artifacts`. Top-level `additionalProperties: false`.
- Eight verdict buckets in `summary.totals`: `allow`, `block`, `warn`, `ask`, `strip`,
  `forward`, `redirect`, `other`. All eight are required, even when zero.
- Verifier verdict enum: `valid`, `invalid`, `error`, `not_run`, `self_consistent_only`.
- `verifier.trusted` is required. It is true only when `verdict` is `valid` AND a long-lived
  signer public key was pinned at verification time.
- Posture status enums for `raw_socket_status`, `docker_socket_status`, `dns_udp_status`,
  `browser_proxy_status`, and `websocket_frame_scanning` (each is required and includes
  an explicit value for "not probed" or "off"; the four status enums use `unknown`,
  `websocket_frame_scanning` uses `off`).
- `unsupported_paths` is required; emit an empty array when no unsupported paths are known.
- Artifact paths in the `artifacts` block must stay inside the packet directory. The
  validator rejects empty paths (where required), absolute paths, Windows-style paths
  (backslash or colon), and `..` traversal.
- `enforcement_mode` is free-form (linux_netns_iptables_setpriv is the v0 reference).
- `policy.policy_hashes` is plural because hot-reload can change policy mid-run.

v0 deliberately leaves these for later schema versions: multi-agent rollups, framework
mappings, embedded transparency-log inclusion proofs, OTel SemConv field name aliasing.
