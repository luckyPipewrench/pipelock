<!--
Copyright 2026 Pipelock contributors
SPDX-License-Identifier: Apache-2.0
-->

# Upgrading to 3.7

Upgrade the binary before loading configurations that use new fields. Keep older fleet members on compatible bundles until their binaries are updated. The [3.7.0 changelog](../../CHANGELOG.md#370---2026-10-12) covers the full release; this guide covers changes that need an operator action.

## Receipt verification and automation

An intact prefix proves the included signatures and links. It doesn't prove the writer finished. Chain commands now report `VALID PREFIX, END UNPROVEN` and exit 3 when the end is unproven. If checking a running writer is intentional, `--allow-prefix` accepts that case with exit 0 while keeping the prefix label. Don't use it to claim a complete run.

Use the end proof appropriate to the evidence: a verified transcript seal for a recorder, an independently retained expected head where supported, or a signed close for a receipt group. A restart link or recovery seal doesn't establish a clean end for the damaged predecessor. Keep the full directory, trusted public keys and any independently retained head or opening digest. A shard's success isn't a group verdict.

`verify-receipt --clean-report` writes schema version 2, including end-proof status. Dispatch JSON consumers by `schema_version` and reject unknown schemas instead of assuming the old shape. Offline Go, TypeScript, Rust and Python implementations share replay profile v5; historical profiles v1 through v4 retain their meanings. Typed receipt decoding now rejects noncanonical-case keys. Free-form maps remain case-sensitive data.

Use compatible, group-capable verifiers for `flight_recorder.receipt_chains` above 1, and confirm the actual installed artifact supports the command. Building a verifier from source doesn't establish that its version is published to npm, crates.io or PyPI. The installer manifest remains blocked until published versions and immutable identities are verified. Published older single-chain packages can't establish group completeness. See [receipt verification](receipt-verification.md#receipt-groups-with-multiple-chains).

## Recording and throughput

`receipt_chains` defaults to 1 and accepts 1 through 32. Multiple chains share signed group lifecycle records but have separate receipt sequences. Requests remain pinned to one chain. Automatic anchoring requires one chain; a multi-chain signing-key change closes the group and exits for supervised restart. Dashboard and display readers don't substitute for group verification.

With `flight_recorder.require_receipts: true`, covered effects wait for every configured receipt family's durable record. Failure stops the affected effect. A failed disk confirmation fails its stream; restart recovery or the documented single-chain fresh-run reload is required. A denied action still has best-effort receipt emission. This mode doesn't promise one receipt for every byte or clean streaming frame. See [transport coverage](receipt-transports.md#emit-failure-behavior).

Receipt scanning checks whole values before signing and uses a bounded fragment search. The faster implementation caches only exact clean text and narrows combinations involving fixed producer/operator values and formatted decision text. Splits needing multiple fixed pieces, dropped enum labels, or a decision-text piece out of field order can fall outside the search. This is a detection tradeoff. Review the [full content boundary](receipt-verification.md#receipt-content-boundary), including its field and work limits, before comparing performance. Caller-chosen IDs remain scanned.

The [million-request measurement](../benchmarks.md#million-request-receipt-run) recorded a valid eight-chain group with no missing expected records. It measures that workload and development build; it doesn't certify every deployment or bind a later release artifact by itself.

## Containment and sandbox launches

Run `pipelock contain install` with the new binary to refresh managed units and wrappers, then restart existing agent services and sessions. A binary swap alone doesn't change an already-running process's mounts. `contain doctor` identifies stale managed setup; `contain verify` checks the live posture.

New installs set `containment.filesystem.mode: enforce`. An existing configuration that omits the field stays off. Enforce mode mounts unexpired workspace grants and requires a successful launch canary. Its posture fields need compatible verifiers. Operator-written units remain outside automatic modification, and filesystem grants retain the documented Unix-socket boundary. See [host containment](../contain-cli.md).

Linux sandbox Unix-socket restrictions depend on Landlock support. Below ABI 9, amd64 uses a seccomp fallback that denies AF_UNIX socket creation, datagram pairs and receive-message calls. Connected stream/seqpacket pairs and the proxy bridge remain available, but Python multiprocessing forkserver and Node fork IPC can fail. Strict ARM64 below ABI 9 refuses; strict seccomp requirements also remain. Check the [sandbox guide](sandbox.md) for the platform conditions.

Explicit MCP/sandbox child overrides can't name code-loading variables such as `PYTHONHOME`, `NODE_PATH` or `CLASSPATH`. Remove those overrides or configure the program through an allowed mechanism. The authoritative list and inherited-environment behavior are in the [sandbox guide](sandbox.md#child-environment-restrictions). Verified local MCP service inspection also requires its declared launch environment; it won't silently verify a different one.

## Policy and client compatibility

`destination_grants` authorizes an exact host and TCP port while keeping scanning and protected-address checks. Prefer it for a specific local service over a host-wide trust exception. Fleet updates preserve the local grants, and strict-mode reloads reject trust expansion. See the [configuration reference](../configuration.md#exact-destination-grants).

The immutable core credential floor blocks in audit mode too. Ordinary audit policy continues to warn. A rewritten core credential requires a configured request-body trusted host before forwarding. A strip response must pass its deciding checks after rewriting or it blocks. Review audit integrations that depended on receiving content the core floor denies.

MCP clients can receive scanned eligible upstream `4xx` statuses and their permitted response headers, including authentication challenges and retry hints. Empty successful notifications are acknowledged. Unsafe or incomplete replies and `5xx` replies remain sanitized. Protocol-version headers follow successful initialize negotiation; malformed initialize requests don't reset the negotiated version.

Paid live connections close when their entitlement expires, is revoked or is proven lost. Unrelated reloads preserve surviving profiles and security state. Reconnect only after restoring the required entitlement. Media enforcement uses the effective type derived from response headers and leading body bytes; no OCR or audio transcription is added.
