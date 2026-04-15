# Changelog

All notable changes to Pipelock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Highlights

The v2.1.3 operationalization arc wires the receipt system into every transport, adds sidecar-injection deployment, and lands a full operator CLI for airlock recovery. The mediation envelope rides sideband metadata on every proxied request so downstream services see pipelock's verdict, action, actor identity, and receipt correlation ID without parsing logs — and now carries an optional RFC 9421 HTTP Message Signature with a canonical policy hash so verifiers can validate the envelope byte-for-byte and detect reformatting-vs-behavioural config changes. Media policy shuts down steganographic exfiltration by stripping EXIF/XMP/IPTC metadata from JPEG and PNG, rejecting audio/video by default, and hardening SVG active content. Posture capsule graduates into a full verify CLI with a scoring model and a CI gate. DLP patterns can now run in warn mode for safe rollout of new detections, with audit emission wired through the runtime lifecycle. Rules bundles gain tier classification, RequiredFeatures enforcement, and a new `pipelock rules status` subcommand. Taint-aware policy escalation spans all MCP transports with task boundaries scoping trust overrides to individual operations. Action receipt coverage extends into fetch error paths, the MCP proxy itself, WebSocket, and A2A, with a cross-implementation conformance suite and a reference Python verifier. Pre-tag hardening closed media policy parity gaps, made recorder resume atomic with tail-entry signature verification, tightened posture integrity checks, and polished CLI diagnostics for misconfigured public-key paths.

### New Features

#### Deployment and operator tooling
- **Sidecar injection init:** `pipelock init sidecar --inject-spec <manifest>` generates a companion-proxy sidecar patch for Deployment, StatefulSet, Job, and CronJob workloads. Three output formats: strategic-merge patch, Kustomize overlay, and Helm values fragment. Includes canary verification, diff preview, idempotent re-runs, HA defaults with PodDisruptionBudget, config hot reload, and enforced proxy-first network topology. (#400)
- **Bound default agent identity:** sidecar-generated deployments set `bind_default_agent_identity: true` with a derived `default_agent_identity`. Header/query-based agent identity (`X-Pipelock-Agent`, `?agent=`) is ignored for the bound workload, preventing agent spoofing in single-workload companion mode. Shared-proxy multi-agent identity remains deferred follow-up work (tracked in roadmap). (#400)
- **Exemption audit emission:** response-scan exemptions (exempt domains and suppressed findings) emit a `pipelock_response_scan_exempt_total` Prometheus counter with `reason` and `transport` labels across all proxy transports. (#400)
- **`pipelock session` operator CLI:** five subcommands (`list`, `inspect`, `explain`, `release`, `terminate`) plus an interactive `recover` wrapper for airlock recovery. Resolves the admin endpoint from `--api-url` / `--api-token` flags, `PIPELOCK_API_URL` / `PIPELOCK_KILLSWITCH_API_TOKEN` env vars, or the pipelock config file. `list` accepts `--tier=hard` to filter sessions by airlock tier. (#399)
- **Session admin API: inspect, explain, terminate endpoints.** `GET /api/v1/sessions/{key}` returns full session detail including airlock entry time, in-flight count, and recent events. `GET /api/v1/sessions/{key}/explain` returns the recorded trigger, evidence, and next auto-deescalation estimate. `POST /api/v1/sessions/{key}/terminate` performs a destructive full tear-down (cancel in-flight, reset enforcement, clear CEE state). Each endpoint has its own 10/minute rate-limit bucket. Session list accepts `?tier=hard`; `normal` is an alias for `none`. (#399)

#### Mediation envelope, media policy, taint
- **Mediation envelope** (`mediation_envelope.enabled: true`) attaches sideband metadata to every proxied HTTP request via a `Pipelock-Mediation` header (RFC 8941 Structured Fields Dictionary) and to MCP requests via `_meta["com.pipelock/mediation"]`. Wire fields: action, verdict, actor identity + auth level, policy hash (`ph`), receipt correlation ID, taint state, task ID, authority kind/ref, re-auth requirement. Inbound stripping removes any forged envelope or `pipelock`-prefixed signature members. Signing, SPIFFE actor format, and well-known key discovery are tracked for a follow-up release. (#374)
- **Media policy** (`media_policy`) enforces image/audio/video response handling. Audio and video are rejected by default; images are allowed with size limits (5 MiB default) and metadata stripped. JPEG surgery removes APP1 (EXIF, XMP), APP2 (ICC, FlashPix), APP13 (IPTC, Photoshop) markers while preserving APP0 (JFIF) and pixel data. PNG surgery removes tEXt, iTXt, zTXt, eXIf chunks while preserving IHDR/IDAT/PLTE/tRNS/IEND. Decompression-bomb defense runs before any parsing. (#382)
- **SVG active content hardening** handles `image/svg+xml` through the browser shield pipeline: strips `<foreignObject>` elements (including namespace-prefixed variants), `on*` event handlers (quoted and unquoted attrs), external `xlink:href` and `href` references (local `#id` fragments preserved), hidden `<text>` elements (`opacity:0`, `display:none`, `visibility:hidden`), `<script>` blocks, and animation injection via `<set>`/`<animate>` targeting href. (#382, #393)
- **Steganographic Unicode stripping** extends the normalization pipeline: zero-width characters (U+200B-U+200F, word joiners), variation selectors (U+FE00-U+FE0F, U+E0100-U+E01EF), Unicode Tags block, bidirectional overrides, and 18 exotic whitespace codepoints are stripped before DLP matching. `ZalgoDensity` detects 3+ stacked combining marks per base character as suspicious for taint signaling. (#382)
- **Taint-aware policy escalation across MCP transports:** Sessions classify inbound sources (URL, MCP tool result) for taint level, track contamination state across transports, and evaluate action sensitivity before allowing protected operations. Works identically on MCP stdio, MCP HTTP/SSE, WebSocket, and forward proxy paths. Configuration via `taint.*` with `allowlisted_domains`, `protected_paths`, `elevated_paths`, `trust_overrides`, `policy`, and `recent_sources`. (#383)
- **Task boundaries for taint-scoped trust overrides:** Trust overrides are scoped to an individual task ID rather than the whole session. When a task completes, its trust override expires automatically. Session taint level and recent taint sources are carried on every emitted receipt. (#384)
- **Edge-triggered airlock:** Airlock activation from adaptive-enforcement escalation is now edge-triggered. Airlock fires on the transition into elevated/high/critical, not on every request at the same level. Prevents drain→hard→drain loops when a session plateaus at an escalated level. (#388)

#### Envelope signing and canonical policy hash
- **RFC 9421 envelope signing:** the mediation envelope (Pipelock-Mediation header and the `com.pipelock/mediation` MCP `_meta` key) now supports Ed25519 HTTP Message Signatures over a per-request component list. Signing is opt-in via `mediation_envelope.sign: true` plus an Ed25519 signing key path. The pipelock signature uses the `pipelock1` dictionary label and the `pipelock-mediation` tag so it coexists with upstream `sig1` / Web Bot Auth signatures on the same request. New config fields: `sign`, `signing_key_path`, `key_id`, `signed_components`, `created_skew_seconds`, `max_body_bytes`. Fail-closed at startup if `sign: true` is set without a readable Ed25519 key; reload with an unreadable key aborts the entire config swap rather than silently downgrading to unsigned. (#403)
- **Canonical policy hash:** `ph` (the first 16 bytes of the policy hash dictionary key) now derives from a canonicalised, slice-order-preserving JSON projection of the effective config instead of the raw YAML bytes. Reformatting, comments, and reordering noise fields no longer shift `ph`, while behavioural rule reorders (DLP patterns, MCP tool policy rules, chain rules) still do. This makes `ph` admission-grade for downstream verifiers. Per-agent resolved configs each compute their own canonical hash and stamp it via `BuildOpts.PolicyHash` at the transport inject site. (#403)
- **Envelope redirect refresh:** on every allowed redirect through the fetch or forward proxy, pipelock rebuilds the Pipelock-Mediation header on the redirected request so `@target-uri`, `hop`, `ph`, and `action` reflect the redirected leg. Stale Content-Digest is dropped and the signature is re-attached (when signing is enabled). The new `hop` dictionary key counts refresh hops; original requests omit it. (#403)

#### Receipts
- **Extended signed-receipt coverage across every transport (#402):**
  - Fetch handler error paths: audit-mode escalation decisions, session profiling blocks, header DLP, budget exhaustion, cross-request exfiltration detection.
  - WebSocket: handshake-time blocks, frame-level DLP, injection, address-poisoning, CEE blocks, session close.
  - A2A in the forward proxy: header scan, stream scan, response body scan.
- **Fetch error-path receipt coverage:** Post-forward deny paths (redirect block, response scan block) now emit block receipts. Foundation for #402. (#377)
- **Action receipts from MCP proxy:** The MCP proxy emits signed action receipts for every tool call, tool response, and policy decision across stdio, HTTP, and HTTP reverse proxy transports. (#385)
- **Cross-implementation receipt conformance suite:** `sdk/conformance/` ships golden test vectors with deterministic seeds so any language implementation can verify byte-for-byte against the Go reference. Reference Python verifier at [pipelock-verify-python](https://github.com/luckyPipewrench/pipelock-verify-python). (#379)

#### Posture
- **Posture capsule verify CLI:** `pipelock posture verify` evaluates a signed capsule against a named policy (`strict` or `enterprise`), computes a weighted evidence score (0-100), and exits with distinct codes for policy failure vs integrity failure. Flags: `--policy`, `--min-score`, `--max-age`, `--max-receipt-age`, `--require-discovery`, `--json`. Strict policy now treats zero-discovered-MCP-servers as a hard failure (vacuous-truth gap closed). Policy version bumped to `"2"`. (#391, #397, #398)
- **Posture verify CI gate:** Exit code 0 means both policy and integrity pass; exit code 10 means policy failed (score or freshness); exit code 11 means integrity failed (signature or parse). `--json` output includes failure details for machine consumption.

#### DLP and rules
- **DLP per-pattern warn mode:** Individual DLP patterns can carry `action: warn`. Warn matches route to an `InformationalMatches` audit channel rather than triggering enforcement — useful for safely rolling out new detections in production traffic. Top-level `dlp.action` remains rejected (patterns-only override). (#392)
- **DLP warn audit emission in runtime:** The `DLPWarnHook` is wired through the runtime lifecycle so warn matches emit structured audit events with the matched pattern name, severity, and transport context. Works across URL DLP, text DLP, and fragment buffer scanning. (#396)
- **Rules tier and RequiredFeatures:** Rule bundles declare a `tier` (`standard`, `community`, `pro`) and a `required_features` list (e.g., `dlp`, `checksum`). Unknown features cause the bundle to fail to load with a clear error. Standard-tier rules can be loaded from disk via `rules.standard_dlp_source` / `rules.standard_response_source`. Core SSRF literal enforcement is unconditional regardless of bundle tier. (#373)
- **`pipelock rules status` command:** Reports health, core tier source, standard DLP/response counts, and a per-bundle breakdown (tier, version, rule counts, signed status). JSON output via `--json`. (#373)

#### Scanner and examples
- **Multipart DLP full coverage:** All multipart part bodies are scanned regardless of declared Content-Type. Parts declaring `image/png` or other binary types with text content are no longer skipped. Custom part headers are scanned. Content-Transfer-Encoding (base64, quoted-printable) is decoded before scanning. (#370)
- **Tool-response-injection example harness:** `examples/tool-response-injection/` is a runnable demo showing an MCP tool whose harmless name and description hide a prompt injection in the response body. Demonstrates the block + signed receipt flow across MCP stdio, MCP HTTP, and MCP HTTP reverse proxy with a single shared signing key. (#387)

### Security Hardening

- **Strict YAML config parsing:** `config.Load()` now rejects unknown top-level and nested fields with a clear error message naming the offending field and line. Typos like `sentinel_path` (real field: `sentinel_file`) or `threshold` (real field: `escalation_threshold`) previously silent-dropped and left security features inert; they now fail loud at startup. Multi-document YAML (`---` separators) is also rejected; a single policy document per file is required. **Breaking change** for any pipelock config that relied on the lenient parser — fix the typo or remove the stale field. (#390, 08cad765)
- **Typed LogContext refactor:** Structured log context fields split URL into semantic components (scheme, host, path, query) and route them through typed constructors. Eliminates an entire class of misrouted field bugs. (#378, #389)
- **Exposure-based policy escalation across MCP transports:** Hardened the taint classification and authority evaluation across stdio, HTTP, and HTTP reverse proxy so a contaminated session cannot bypass protected-path gates by switching transports. (#383)
- **Edge-triggered airlock regression test:** Dedicated test ensures airlock does not re-enter drain on plateaued escalated sessions. Closes the drain-hard-drain loop observed in adaptive enforcement testing. (#388)
- **Core SSRF literal unconditional:** Private-IP literal blocking is now part of the immutable core scanner and cannot be disabled by config or bundle configuration. (#373)
- **Session-admin API terminate gate:** `terminate` has its own 10/minute rate-limit bucket independent of other admin endpoints and requires the full kill-switch API token; cannot be issued via the main proxy port. (#399)
- **Structured-fields-safe inbound envelope strip:** `envelope.StripInbound` now parses `Signature` / `Signature-Input` as RFC 8941 dictionaries via httpsfv before dropping pipelock-labelled members. The previous `strings.Split(val, ",")` path treated commas inside quoted parameter values as member separators, corrupting surviving members and leaving dictionary residue that could bypass inbound sanitisation. (#403)
- **Reverse-proxy envelope signing after Director:** reverse-proxy envelope signing now runs in an `http.RoundTripper` wrapper installed on `httputil.ReverseProxy.Transport`, so `@target-uri` reflects the post-Director upstream URL rather than the inbound relative path. (#403)
- **Request body plumbing for signing:** transport inject sites hand the already-scanned body bytes to the signer so `Content-Digest` is computed without a second drain. When request body scanning is disabled but signing is enabled, the envelope emitter drains `req.Body` itself (bounded by `max_body_bytes`) and installs a fresh `GetBody` closure so stdlib can replay the body on 307/308 redirects. (#403)
- **Media policy all-field coverage:** MCP tool-result media payloads are now scanned across every populated `data`/`blob`/`raw` slot rather than stopping at the first non-empty field, closing a bypass where a benign value in `data` could shield blocked media stashed in `blob` or `raw`. (#404)
- **Pure-media tool results routed past prompt scanning:** `jsonrpc.ExtractText` returns only collected `Text` fields once a `ToolResult` parses, so base64 image/audio/video payloads no longer feed into response-injection scanning as raw text. (#404)
- **Recorder resume is atomic with tail-entry verification:** `resumeSessionLocked` now computes the resumed `sessionID`/`seq`/`prevHash` into local temporaries and only mutates the `Recorder` after `sessionFiles`/`ReadEntries` succeed, so a transient read error no longer leaves a half-initialised chain that restarts from genesis. The receipt-chain resume path additionally verifies the signature of the last persisted receipt before trusting it, and parses recorder sequence numbers as `uint64` (strconv.ParseUint) to keep file ordering correct on 32-bit builds or when sequences exceed `math.MaxInt`. (#404)
- **Posture strict-mode integrity:** posture verify under the strict policy rejects zero-discovered-MCP-server capsules rather than treating an empty discovery set as a vacuously passing score. (#404)
- **Optional-metrics guard in DLP warn emission:** `emitDLPWarn` guards the `*metrics.Metrics` handle with a nil check so the first warn-only DLP match in MCP runtime configs without session profiling emits audit/receipt output instead of panicking. (#404)

### Examples & Docs

- **Deployment recipes by enforcement tier:** `docs/guides/deployment-recipes.md` groups the standard deployment patterns (companion, shared, managed) by the enforcement posture they provide. (#390)
- **Mediation envelope, media policy, receipt verification guides** added to `docs/guides/`. Configuration reference expanded for both new sections.
- **Attacks-blocked gallery** adds SVG active content injection, steganographic metadata exfiltration, and tool response injection entries with config that blocks them.
- **Bypass-resistance matrix** adds media/SVG evasion, exotic whitespace, and zalgo rows.
- **README** restructured defense matrix with mediation envelope, media policy, taint escalation, and receipt conformance rows plus a tool-response-injection demo section.
- **Posture capsule guide** expanded with full `pipelock posture verify` reference (flags, exit codes, strict vs enterprise policies, scoring model, CI example).
- **Rules guide** expanded with `pipelock rules status`, tier taxonomy, RequiredFeatures, standard tier source overrides, and core SSRF literal note.
- **Configuration reference** adds Taint-Aware Policy Escalation section with full `taint:` block + task boundary + trust override semantics and a DLP Per-Pattern Warn Mode subsection.

### Fixed

- **Strict posture vacuous-truth gap:** Zero-discovered-MCP-servers under the strict policy now fails the verify gate rather than silently passing with a 100/100 score. Enterprise policy retains the warning semantics for non-MCP deployments. (#398)
- **Receipt emission for post-fetch deny paths:** Blocks at the fetch-handler redirect or response-scan stages now emit signed block receipts. Previously these paths returned errors with no receipt. (#377)
- **WebSocket DLP warn hook timing:** Race between hook registration and warn match emission in WebSocket relay paths closed. (98074d81)
- **MCP HTTP/stdio receipt parity:** Receipt emission state survives config reload across all MCP transports. (#385)
- **Log context field routing:** Typed constructors close routing bugs where URL fields landed in unrelated context keys. (#389)
- **Duplicate posture public-key error prefix:** `loadPublicKey` no longer wraps `"loading public key"` on errors that `postureVerifyCmd` already prefixes, so diagnostics render cleanly. (#404)
- **Transcript root derives session ID from evidence file:** `transcript-root` now reads the session ID from the evidence file's first entry when `--chain` is unset instead of defaulting to the `--session` flag, so JSONL captures from any session print the correct `SessionID`. Empty evidence sets fail with a non-zero exit code. (#404)
- **File-path diagnostics for public-key loading:** `signing.LoadPublicKey` surfaces the underlying `os.ErrNotExist` when the input looks like a filesystem path (contains a separator, starts with `.`, or has an extension), replacing the confusing `"invalid public key"` error that previously masked typo'd paths. (#404)

### Developer & CI

- **govulncheck bumped to Go 1.26.2** in CI. (#376)
- **Strict YAML validation of example configs** ensures every shipped preset loads cleanly under the new unknown-field rejection. (fae9e181)
- **Example configs no longer embed self-scan-triggering credential strings.** Examples use `Credential`-with-colon text that reads naturally without matching DLP patterns. (421b79c2)

## [2.1.2] - 2026-04-06

### Highlights

Every proxy decision now produces a cryptographically signed action receipt: verdict, policy hash, transport, and target recorded as a hash-chained evidence trail. New onboarding tools (`pipelock init`, Helm chart, false positive tuning guide) cut first-run setup to minutes. Runtime hardening adds connection-level admission control, browser-aware response scanning, and environment classification. An immutable core scanner layer runs before all configurable patterns and cannot be disabled.

### New Features

- **Action receipts:** every proxy decision produces an Ed25519-signed receipt recording the action type, verdict, policy hash, transport, method, and target. New `internal/receipt/` package. `pipelock verify-receipt` CLI command validates receipt signatures. Receipts are written to the flight recorder. (#351)
- **Hash-chained receipts and transcript roots:** receipts link to their predecessor via `chain_prev_hash` and `chain_seq`, forming a tamper-evident chain. `EmitTranscriptRoot()` seals the chain with a transcript root entry. `pipelock verify-receipt` validates individual receipts and chain integrity. (#354)
- **Onboarding stack:** `pipelock init` discovers IDE configs, generates a starter YAML config, and runs canary verification against the running proxy. Helm chart at `charts/pipelock/` for Kubernetes deployments. False positive tuning guide for common scanner adjustments. README restructured around getting-started flow. (#355)
- **Airlock admission control:** connection-level admission with a drain tier for graceful shutdown. New connections are rejected when the proxy enters drain state, while in-flight requests complete. (#356)
- **Browser Shield:** domain-aware response scanning exemptions for browser traffic. Domains serving rendered HTML (dashboards, documentation sites) skip injection scanning to avoid false positives on legitimate page content. (#356)
- **Posture Capsule:** runtime environment classification detects whether pipelock runs in a container, on bare metal, or in a cloud instance. Classification is exposed via metrics and audit logs. (#356)
- **Immutable core scanner:** built-in DLP and response injection patterns run before all configurable scanners and cannot be disabled or overridden by config. New `core_dlp` and `core_response` scanner labels. Bundle metadata v2 adds freshness checks, deprecation notices, and build-time pinning for pattern bundles. (#359)

### Security Hardening

- **TLS interception receipts:** TLS-intercepted traffic now produces action receipts across 19 emission points in the intercept pipeline. Previously, intercepted requests were scanned but not recorded in the receipt chain. (#362)
- **Flight recorder DLP redaction:** receipt fields containing target URLs and matched patterns are scrubbed by the DLP pipeline before writing to the flight recorder. Receipt structure fields (signature, signer_key, chain hashes) are preserved. Summary field no longer includes raw matched content. (#362)
- **Receipt emitter hot reload:** signing key can be added, removed, or rotated via SIGHUP without restarting the proxy. Receipt emission state survives config reloads. (#362)
- **A2A SSE streaming receipts:** Server-Sent Event streams in the A2A protocol path now produce per-event receipts. (#362)
- **Multipart body scanning:** all multipart part bodies are now scanned regardless of declared Content-Type. Parts declaring image/png or other binary types with text content are no longer skipped. Custom multipart part headers are scanned for DLP patterns. Content-Transfer-Encoding (base64, quoted-printable) is decoded before scanning. Structural header parameters (Content-Disposition, Content-Type values) are parsed and scanned. (#370)

### Fixed

- **Inline suppression in scan-diff:** `pipelock:ignore` inline comments are now respected in GitHub Action scan-diff mode. Previously, suppression comments were only processed in full-scan mode. (#365)
- **Airlock drain timeout:** drain timeout now reads from config instead of using a hardcoded default. (#371)
- **Browser Shield redirect hostname:** post-redirect hostname is used for domain matching instead of the original request hostname. (#371)
- **Session manager lock TOCTOU:** time-of-check-to-time-of-use race in the session manager lock acquisition path is closed. (#371)
- **Quarantined session eviction:** quarantined sessions are protected from LRU eviction. (#371)

### Other

- **Documentation cross-references:** README restored with full feature content, security matrix, and pipelab.org cross-references. OWASP coverage table added. (#363)
- **CI dependency updates:** GitHub Actions bumped across CI workflows. (#358)
- **Go dependency updates:** modernc.org/sqlite bumped from 1.48.0 to 1.48.1. (#357)

## [2.1.1] - 2026-04-03

### Highlights

Scanner hardening and internal quality release. Nine security fixes close gaps found during Gauntlet benchmark development. Recursive response decoding catches multi-layer encoding evasion. Continuous fuzzing via ClusterFuzzLite. Major refactors reduce parameter sprawl across the proxy and MCP packages. New Codex integration guide.

### Security Hardening

- **SSRF trust gap closed:** allowlisted domains resolving to internal IPs now correctly bypass SSRF checks only for DNS results, not for encoded IP literals in the URL. Prevents trust domain bypass via hex/octal IP encoding. (#334)
- **MCP batch request rejection:** JSON-RPC batch requests (JSON arrays) rejected at ingress. Batch requests could bypass per-request scanning by bundling multiple operations. (#335)
- **SSRF hex/octal IP decoding:** SSRF scanner decodes hex (`0x7f000001`), octal (`0177.0.0.1`), and decimal (`2130706433`) IP representations before private-range checks. Separate subdomain entropy threshold prevents false positives on short hostnames. (#336)
- **MCP input DLP hardening:** new DLP patterns for MCP tool arguments including path-based exfiltration and additional coverage for encoded payloads. (#337)
- **Chain detection and shell obfuscation:** expanded chain pattern matching and shell obfuscation normalization for additional evasion techniques. (#338)
- **Hangul Filler normalization:** Unicode codepoints U+115F, U+1160, U+3164 (Hangul Fillers) added to invisible character stripping. Prevents pattern matching evasion via these characters. (#339)
- **Recursive response decoding:** senary scanner pass now decodes up to 5 layers of nested base64/hex encoding. Previously a single layer was decoded, allowing multi-layer chains (base64→hex→URL) to evade detection. (#344)
- **DLP and tool scanner pattern widening:** broader DLP patterns and tool poisoning detection for improved Gauntlet benchmark coverage. (#348)
- **Injection pattern hardening:** Tool Invocation pattern widened to match varied phrasing ("urgently call a hidden function"). Instruction Boundary pattern now detects Llama 2 `<<SYS>>` closing tag. (#350)

### New Features

- **ClusterFuzzLite integration:** continuous fuzzing on every PR with 9 fuzz targets covering URL scanning, DLP, response scanning, normalization, tool extraction, chain classification, and config parsing. (#339)
- **Codex integration guide:** `docs/guides/codex.md` covers securing OpenAI Codex with pipelock's MCP proxy, forward proxy, and recommended config.
- **Stats drift guard:** `make stats` target and `TestCanonicalStats` verify pattern counts, dependency counts, and preset counts on every PR. (#342)

### Refactored

- **`LogContext` struct:** replaces 8+ repeated audit log parameters across all proxy and MCP packages with a single struct. Reduces parameter passing noise and makes future field additions non-breaking. (#340)
- **`InterceptContext` struct:** replaces repeated TLS intercept pipeline parameters with a structured context. (#340)
- **`BodyScanRequest` struct:** consolidates body scanning parameters, server timeout constants extracted, `OnClose` utility added. (#345)
- **Signal recording consolidation:** shared signal recording logic extracted, `mcp/input.go` split for maintainability. (#346)
- **Relay extraction:** tunnel relay and hop-by-hop header helpers extracted into `relay.go`. (#347)

### Other

- **PR review commands:** `/review tests`, `/review docs`, `/review stats` trigger focused review passes via GitHub Actions. (#339)
- **Numbered comment lists removed:** prevents cascading diff noise when inserting items. (#344)

## [2.1.0] - 2026-03-30

### Added

- **Sandbox `--best-effort` flag:** gracefully degrades when user namespace creation is blocked (e.g. k8s containers with default seccomp). Landlock and seccomp containment layers still apply. Network scanning uses proxy-based routing instead of kernel-enforced namespace isolation. (#289)
- **Sandbox `--env` flag:** pass environment variables to sandboxed processes (KEY or KEY=VALUE, repeatable). Validates against dangerous keys (LD_PRELOAD, NODE_OPTIONS, etc.) that could subvert containment. (#289)
- **MCP proxy `--sandbox-best-effort` flag:** parity with `pipelock sandbox --best-effort` for MCP stdio wrapping mode. (#292)
- **Pure Go netlink loopback:** sandbox uses raw netlink syscalls to bring up loopback inside network namespaces. No `ip` binary required. Works in minimal container images without iproute2. (#289)
- **`pipelock assess` command:** signed security assessments with evidence capture, secret redaction, and HTML report. `assess init` starts a session, `assess run` executes attack simulations and captures evidence, `assess finalize` produces a PDF-ready HTML report with visual hierarchy, remediation guidance, and an optional signed attestation bundle. Secrets and server names are redacted from evidence before output. (#296, #301, #306)
- **`pipelock assess finalize --attestation`:** produces `attestation.json` and a detached Ed25519 signature for the finalized report. `--badge` derives an SVG badge from the attestation. (#314)
- **Compliance evidence mappings:** `internal/report/compliance` maps pipelock controls against OWASP MCP Top 10, OWASP Agentic Top 15, NIST 800-53, EU AI Act, and SOC 2. Compliance atlas threads through `assess finalize` output. (#314)
- **`trusted_domains` for forward proxy:** allowlist domains whose DNS resolves to private IPs without disabling SSRF protection globally. Useful for local inference endpoints and internal services. Community contribution. (#297)
- **`exempt_domains` for response scanning:** per-domain opt-out from injection scanning with DLP still applied. Prevents false positives from high-volume API response traffic. (#305)
- **MCP redirect handlers (built-in):** two built-in redirect profiles — `fetch-proxy` routes matched tool calls through pipelock's fetch proxy with full injection scanning, `quarantine-write` captures file write arguments to a quarantine path for review. Handler output is scanned for injection before returning to the agent. (#307)
- **Session admin API:** `GET /api/v1/sessions` lists adaptive enforcement sessions; `POST /api/v1/sessions/{key}/reset` clears escalation state and allows autonomous block_all recovery after clean traffic. Operations are audit-logged. (#308)
- **Flight recorder:** hash-chained JSONL evidence log with configurable retention, signed checkpoints, DLP redaction, and optional X25519 key escrow for encrypted raw capture. New `flight_recorder` config section. (#309)
- **Agent Bill of Materials (aBOM):** CycloneDX 1.6 BOM generation with declared-vs-observed tool inventory, confidence scoring, and dormant/unexpected tool classification. New `internal/abom` package. (#309)
- **MCP binary integrity:** `internal/integrity` package generates and verifies file manifests (SHA-256, permissions) for MCP server directories. Detects modified, added, removed, and permission-changed files. (#310)
- **Denial-of-wallet detection:** `internal/proxy/dow.go` tracks tool call budgets per session — loop detection, runaway expansion, retry storms, fan-out limits, concurrent call limits, and wall-clock caps. New `denial_of_wallet` config section. (#310)
- **Session manifest and signed decision records:** `internal/manifest` captures versioned session snapshots (policy hash, tool inventory, verdict summary, behavioral fingerprint). `internal/recorder` writes signed decision records per enforcement event. (#312)
- **Canary token detection:** `canary_tokens` config section defines synthetic secrets injected via env vars. Detections trigger a block and audit event. `pipelock canary` CLI helper prints config snippets. (#313)
- **`pipelock simulate` expansion:** simulate command extended with new attack scenarios. Covers DLP exfiltration, prompt injection, tool poisoning, SSRF, and URL evasion. Known-limitation tagging distinguishes scanner gaps from failures. (#313)
- **A2A protocol scanning foundation:** `a2a_scanning` config section enables scanning of Google A2A (Agent-to-Agent) protocol traffic in forward proxy and MCP HTTP proxy paths. Field-aware scanning with agent card poisoning detection, card drift (rug-pull) detection, session smuggling detection, and configurable context caps. (#316)
- **SecureIQLab Docker Compose test harness:** `test/secureiqlab/` provides a ready-to-run environment for validating pipelock against adversarial AI agent attack scenarios. Includes mock LLM, mock MCP server, log collector, and pre-baked pipelock configs. (#318)

### Fixed

- **Sandbox best-effort seccomp:** `io_uring` handling changed from KILL_PROCESS to EPERM so runtimes like Node.js 22 that probe io_uring at startup can gracefully fall back to epoll instead of crashing. (#289)
- **Sandbox seccomp `readlink` syscall:** added `SYS_READLINK` (nr 89) to the allowlist. Node.js/libuv uses the legacy readlink syscall directly, not readlinkat. (#289)
- **Sandbox secret dir validation:** `secretDirs()` now only protects directories that actually exist. Prevents false validation errors in containers. (#289)
- **Sandbox bridge proxy dynamic port:** in best-effort mode, uses a dynamically allocated port instead of the hardcoded 8888. (#289)
- **Config reload — sandbox best-effort:** `sandbox.best_effort` changes are detected during hot reload. Per-agent `best_effort` propagated through enterprise merge. Config validation enforces mutual exclusivity of `sandbox.best_effort` and `sandbox.strict`. (#289)
- **File sentry best-effort mode:** file sentry in MCP proxy mode now respects `best_effort` flag and degrades gracefully when filesystem watching is unavailable rather than failing hard. (#292)
- **Scanner result classification:** scanner results carry a structured classification (category, transport, layer) that drives adaptive enforcement signal recording. Prevents the death spiral where every enforcement event generates a new escalation signal. (#295)
- **Autonomous block_all recovery:** adaptive enforcement sessions at `block_all` level now auto-deescalate after a configurable window of clean traffic. Previously, sessions could be permanently locked out with no recovery path outside of a config reload. (#304)
- **Suppress glob port matching:** strip standard ports (:443, :80) and cross-slash glob for URL patterns. Fixes suppress rules silently failing on TLS-intercepted URLs. (#328)
- **Config defaults via Load():** `applySecurityDefaults` for 8 security-critical booleans and `ApplyDefaults` for all v2.1.0 config structs. Prevents unsafe Go zero values when users partially configure new features. (#328)
- **Adaptive enforcement exempt domains:** exempt domains are now scanned for visibility (findings logged as warn) but adaptive scoring is skipped and actions are not upgraded. Prevents death spiral from LLM response false positives. All 5 transports. (#328)
- **DoW tracker wiring:** denial-of-wallet tracking wired into MCP stdio, HTTP, and WS proxy paths. `dow_action: warn` mode supported. Falls back to `_default` agent profile for free tier. (#328)
- **Behavioral baseline directory auto-creation** in `NewManager`. (#328)
- **License gate preserves `_default` profile** when rejecting unlicensed named agents. (#328)
- **Feature wiring:** FlightRecorder, BehavioralBaseline, MCPToolProvenance, and MCPBinaryIntegrity connected to proxy runtime. Previously config-only stubs. (#328)
- **Provenance audit logging** for block and warn-mode unsigned tools. (#328)
- **DoW metadata backfill** for scan-disabled configurations. (#328)

### Refactored

- **Shared escalation recording helper:** `decide.RecordEscalation` extracted as a shared helper used by all proxy and MCP enforcement paths. Eliminates duplicated escalation logic across fetch, forward, WebSocket, and MCP transports. (#290)
- **`MCPProxyOpts` struct:** long MCP proxy parameter lists replaced with a single `MCPProxyOpts` options struct. Reduces argument count from 13+ parameters to a single struct, making future additions non-breaking. (#294)
- **`RunHTTPListenerProxy` refactored** from 20-parameter function to `MCPProxyOpts` struct. (#328)
- **CLI god package split:** 91-file, 10,000+ line CLI package split into 10 focused subpackages: `assess`, `audit`, `canary`, `diag`, `generate`, `git`, `rules`, `runtime`, `setup`, `signing`. Each subpackage is independently testable. (#303)
- **`atomicfile` shared package:** `internal/atomicfile` extracted as a shared atomic write primitive used by signing, integrity, and recorder packages. Eliminates duplicate implementations. (#302)

### Testing & CI

- **Coverage boost — `atomicfile` package:** `internal/atomicfile` covered by dedicated tests including OS-level write error injection via a `WriteFile` dependency injection interface. (#302)
- **Scanner coverage — encoded payloads and cross-transport DLP:** new tests covering base64/hex-encoded payload detection, segment-level decode paths, and DLP scanning across fetch, forward proxy, and MCP stdio transports. (#315)
- **Comprehensive coverage boost:** (#317, #328)
- **GitHub Action references migrated from v1 to v2:** all `actions/checkout`, `actions/setup-go`, `actions/upload-artifact`, and third-party action refs updated to v2+ across CI workflows. (#291)
- **pip deps pinned with hashes:** Python test dependencies pinned with `--require-hashes` in requirements files. Makefile `fmt` and `lint` targets fixed. (#298)
- **`requests` dependency bumped.** (#300)
- **MCP tool provenance and profile-then-lock baseline:** (#311)
- **Policy capture and replay engine:** (#319)
- **Structured exit codes and subprocess error handling:** (#320)
- **v2.1.0 polish fixes:** (#321)
- **Config.Validate split, DRY audit logger, coverage boost:** (#322)
- **Scan redirect handler output through DLP pipeline:** (#323)
- **Grafana dashboard expanded to 45 metrics** across 14 rows with panels for cross-request detection, adaptive enforcement, scan API, TLS interception, address protection, file sentry, reverse proxy, and capture system.
- **Prometheus alert rules expanded to 28** covering all actionable metrics including DLP, TLS, cross-request, adaptive enforcement, address poisoning, file sentry, and kill switch state.
- **Unversioned release archives** for stable `/releases/latest/download/` curl installs. (#324)

## [2.0.0] - 2026-03-22

### Added
- **Process sandbox (Linux):** Landlock filesystem restriction, seccomp syscall filtering, and network namespace isolation for any agent process. Two modes: `pipelock mcp proxy --sandbox` for MCP servers, `pipelock sandbox -- COMMAND` for standalone agents. Agents run in a sandboxed child process with restricted filesystem visibility and no direct network access — HTTP traffic routes through pipelock's scanner pipeline via a bridge proxy. Requires kernel 5.13+ with Landlock and user namespace support. (#267)
- **Process sandbox (macOS):** sandbox-exec with dynamically generated SBPL profiles. Deny-all baseline with explicit allows. Same approach as Anthropic srt, Cursor, and OpenAI Codex. `pipelock sandbox diagnose` reports platform capabilities. (#275)
- **Per-agent sandbox profiles:** Named sandbox configurations with per-profile filesystem grants, network policy, and syscall allowlists. `--sandbox-strict` flag denies all filesystem access outside an explicit allowlist. Subreaper for descendant cleanup. Sandbox preflight and diagnostics. (#272)
- **Redirect policy action:** First-class `redirect` action for MCP tool policy that routes matched tool calls to audited handler programs instead of blocking. Redirect profiles define the handler executable, reason, and argument passing. Synthetic JSON-RPC success responses returned to the agent. Response scanning on handler output prevents injection. Fail-closed on handler failure or timeout. Action precedence: block > redirect > ask > warn. (#271)
- **Full-schema tool poisoning detection:** `collectAllSchemaText` recursively extracts text from nested `inputSchema` objects (properties, descriptions, enums, defaults, examples) for injection scanning. Previously only top-level tool description was scanned. (#270)
- **State and control response patterns:** 6 new injection detection patterns targeting state manipulation, control flow hijacking, and authority assertion with DOTALL matching for multiline payloads. Response pattern count 13 to 19. (#270)
- **Config security scoring:** `pipelock audit score` analyzes configuration for security posture with 12 category checks, 0-100 scoring, letter grades (A-F), and tool policy overpermission audit. JSON output for CI integration. (#273)
- **JetBrains/Junie MCP proxy integration:** `pipelock jetbrains install` wraps JetBrains IDE MCP server configs through pipelock's MCP proxy. Supports `--sandbox` and `--workspace` flags for sandboxed operation. (#260, #269)
- **Adaptive enforcement exempt_domains:** Per-domain exemption from cross-request entropy budget with wildcard matching. Prevents false entropy accumulation from repeated API calls to LLM providers. (#268)
- **OWASP MCP Top 10 coverage mapping:** Comprehensive mapping of pipelock's controls against the OWASP MCP Security Top 10 taxonomy. (#274)
- **NIST 800-53 control mapping:** 7 control families (AC, AU, CA, CM, IR, SC, SI) mapped with per-control coverage assessment. (#274)

- **Attack simulation:** `pipelock simulate` runs 24 synthetic attack scenarios against a config and reports a security scorecard. 5 categories: DLP exfiltration, prompt injection, tool poisoning, SSRF, URL evasion. Scanner attribution verifies the correct layer detected each attack. `--json` output for CI, exit code 1 on misses. (#277)
- **HTTP reverse proxy:** Generic reverse proxy mode for any HTTP service with bidirectional body scanning. Request bodies scanned for DLP (secret exfiltration), response bodies scanned for prompt injection. Fail-closed on compressed bodies, read errors, and ask mode. `pipelock run --reverse-proxy --reverse-upstream URL`. New `reverse_proxy` config section. (#278)
- **SSRF trusted domains:** `trusted_domains` config option allows internal services with public DNS records that resolve to private IPs. Agents connecting to localhost dev servers, local inference endpoints, or internal services with RFC1918 addresses can be explicitly allowed without disabling SSRF protection globally. (#281, closes #276, #279)

### Fixed
- **Reverse proxy fail-closed on oversized responses:** Responses exceeding `max_response_bytes` are now blocked instead of passing through unscanned. (#281)
- **Reverse proxy URL DLP scanning:** Request URL path and query string are now scanned for DLP patterns on the reverse proxy, matching forward proxy behavior. (#281)
- **Kill switch preemption on long-lived transports:** Kill switch state is checked per-read/frame/message on CONNECT tunnels, WebSocket, and MCP stdio/HTTP/WS transports. Previously only checked at connection setup. (#281)
- **SSE reconnect loop kill switch:** GET-mode SSE stream reconnect loop now exits when kill switch is active instead of retrying indefinitely. (#281)
- **Memory persistence pattern expansion:** Additional terminal phrases added to the memory persistence directive injection pattern for broader coverage. (#281)

### Changed
- Action precedence updated: block(4) > redirect(3) > ask(2) > warn(1). Unknown actions still fail closed to block.
- Direct dependencies increased from 15 to 17 (added go-landlock for sandbox, updated protobuf).
- Binary size increased from ~17MB to ~18MB (sandbox + SQLite runtime). Dev builds are ~24MB due to debug symbols.

### Deployment Notes
- **Linux sandbox** requires kernel 5.13+ with Landlock and user namespace support. Run `pipelock sandbox diagnose` to check prerequisites.
- **macOS sandbox** uses sandbox-exec (seatbelt profiles). Beta — CI-tested on GitHub Actions macOS runners.
- **Redirect profiles** reference handler executables that must exist on the host. Validate with `pipelock audit score`.
- New config sections: `sandbox` (profiles, strict mode), `redirect_profiles` (on `mcp_tool_policy`).

## [1.5.0] - 2026-03-20

### Added
- Adaptive enforcement v2: sessions that accumulate threat signals now escalate through three levels (elevated, high, critical), upgrading actions at every enforcement point across all proxy and MCP transports. Live escalation queries tighten enforcement mid-connection. New `internal/session/` package, `UpgradeAction()` in `internal/decide/`, configurable per-level behavior via `adaptive_enforcement.levels`. Prometheus metrics `pipelock_adaptive_upgrades_total` and `pipelock_adaptive_sessions_current`. 181 new tests. (#256)
- Financial DLP with checksum validation: credit card (Luhn) and IBAN (mod-97) detection with post-match checksum validation that eliminates 90-99% of false positives. New `Validator` field on `DLPPattern` for extensible validated patterns. Covers Visa, Mastercard (including 2221-2720), Amex, Discover, JCB, and 80+ IBAN countries. ABA routing number validator available as opt-in. DLP count 44 to 46. 70 new tests. (#258)
- Key-scoped tool policy matching: `arg_key` field scopes `arg_pattern` to specific top-level argument keys. Block `read_file` when `file_path` contains `/etc/shadow` without false positives on other arguments. Raw argument JSON threaded through all enforcement paths. (#257)
- Community rules rollout: `rules.KeyringHex` wired into build ldflags (Makefile, GoReleaser, Dockerfile) so release binaries verify official bundle signatures. Official registry URL set to `pipelab.org/rules/`. `docs/rules.md` user guide. Community Rules section in README. Commented `rules:` section in all 7 presets. (#255)
- Filesystem sentinel for subprocess MCP mode: real-time filesystem monitoring detects secrets written to disk by agent subprocesses that bypass the MCP pipe. Recursive directory watching with 50ms write debounce, DLP content scanning, process lineage attribution (Linux), and rename-into-place bypass prevention. Watches arm synchronously before child launch (no startup race). Fail-closed when enabled. (#261)
- OTLP log export sink: OpenTelemetry log export as a third emit sink alongside webhook and syslog. Events sent as OTLP LogRecords over HTTP/protobuf to a collector endpoint. No gRPC dependency (uses protowire). Async buffered queue with bounded retry on 429/5xx per OTLP spec. 15 new tests. (#262)

### Fixed
- Transport parity: WebSocket header DLP now scans all 7 forwarded headers (was 4 auth-only). Forward HTTP proxy now scans responses for prompt injection when response_scanning is enabled. Fail-closed on compressed responses that cannot be scanned. Closes the last transport parity gap. (#254)
- Shell normalization hardened against 3 evasion techniques: `$@`/`$*` positional parameter insertion, `${HOME:0:1}` path construction, and backtick command substitution now resolve before policy matching. Pipeline ordering fixed so indirect expansion resolves before slash replacement. (#259)
- Windows release builds: `pipelock rules` now uses an OS-specific lock implementation so the CLI cross-compiles cleanly for Windows targets. (#252)
- DLP action validation: `dlp.action` and per-pattern `action` fields were silently dropped by YAML unmarshaling. Now rejected at startup with an error message pointing to the correct transport-level settings. (#264)
- Adaptive enforcement death spiral: CONNECT hostname no longer counted toward CEE entropy budget (the destination hostname is not exfiltration data). Time-based de-escalation added so sessions at block level can recover after clean traffic. Prevents permanent lockout from repeated polling to the same host. (#266)

### Deployment Notes
- TLS interception with `cross_request_detection` enabled: set `bits_per_window` to 500,000+ and configure `exempt_domains` for LLM providers to avoid false entropy accumulation from repeated API calls.

### Tests
- WebSocket and TLS interception transport wiring: integration tests for address poisoning detection, cross-request exfiltration entropy, response scanning strip action, full CONNECT-hijack-SNI-intercept-scan integration, and injection blocking. Coverage: `clientToUpstream` 61% to 88%, `handleConnect` TLS branch 0% to 86%. (#253)

## [1.4.0] - 2026-03-17

### Added
- Community rule bundles (infrastructure): signed YAML detection pattern bundles with Ed25519 keyring verification, `pipelock rules install/update/list/verify/diff/remove` CLI, CalVer versioning, lock file tracking, and bundle provenance threading through all scanner match types. New `rules` config section with `trusted_keys` and `auto_update`. Public rule bundle and hosting will follow in a point release. (#247)
- Crypto address poisoning detection: validates ETH, BTC, SOL, and BNB blockchain addresses against a user-supplied allowlist and flags lookalike addresses using prefix/suffix similarity scoring. New `address_protection` config section. `internal/addressprotect/` package with chain-specific validators and Bech32/Base58/EIP-55 checksum support. (#233)
- Address similarity tracker: session-scoped fingerprinting with LRU eviction detects when multiple similar-looking addresses appear in the same session, a key indicator of address poisoning attacks. (#231)
- Response scanning pre-filter: keyword-gated regex skips expensive normalization and pattern matching when no injection keywords are present in the text. Cuts clean-text scan latency significantly. (#230)
- Response pre-filter extended to opt-space and vowel-fold passes: all three normalization passes now use keyword pre-filtering, not just the first pass. (#245)
- Delimiter-separated hex encoding detection: `normalizeHex()` strips 6 delimiter formats (`:`, `-`, ` `, `,`, `\x` prefix, `0x` prefix) across all DLP paths, catching secrets encoded as colon-separated, space-separated, or C-style hex notation. (#243)
- DLP patterns for Groq, xAI, GitLab, New Relic, and Stripe webhooks: built-in pattern count expanded from 36 to 41. (#246)
- Crypto secret DLP detection: BIP-39 seed phrase detection via dedicated `internal/seedprotect/` package with dictionary lookup, sliding window, and SHA-256 checksum validation. Three new regex patterns for Bitcoin WIF, extended private keys (xprv/yprv/zprv/tprv), and Ethereum private keys. DLP count now 44. New `seed_phrase_detection` config section. (#249)
- VS Code MCP proxy integration: `pipelock vscode install` wraps VS Code MCP server configs through pipelock's MCP proxy for bidirectional scanning. `pipelock vscode remove` cleanly unwraps. Supports project and global scope, dry-run preview, atomic writes with backup. (#248)
- Trial tier and one-time purchase support for license service: Polar webhook handler now processes trial and one-time purchase events alongside subscriptions. (#232)
- Scan API reference documentation (`docs/scan-api.md`): full API reference for the `POST /api/v1/scan` endpoint covering all four scan kinds, auth, rate limiting, error codes, and integration patterns.
- Address protection and scan API config reference sections added to `docs/configuration.md`.
- Hostile-model preset surfaced in README Security Matrix with feature callout.

### Changed
- Minimum Go version bumped from 1.24 to 1.25. CI matrix now tests Go 1.25 and 1.26. (#242)

### Fixed
- K8s Secret volume compatibility: license key and signing key file loading now follows symlinks (required for Kubernetes Secret volume mounts where files are symlinked through `..data/`). (#229)
- MCP `tools/list` false positive on empty responses: skip general response scanning when tools/list returns an empty or all-unnamed tool array. Malformed `tools` values still fall through to injection scanning. (#250)
- Keystore symlink escape: `generateAgent` now validates path containment after symlink resolution, preventing private key writes to attacker-controlled locations outside the keystore boundary. Containment check covers both leaf symlinks and symlinked parent directories.

### Docs
- Adversarial testing methodology section added to security assurance docs. Benchmark data refreshed for Go 1.25. Scanner pipeline description updated from 9 to 11 layers. (#228)
- Security claims hedged and coverage disclaimers added across docs. (#234)
- Demo assets, fleet dashboard screenshot, and egress report updated. (#235)

### CI
- sigstore/cosign-installer bumped from 4.0.0 to 4.1.0. (#237)
- docker/login-action bumped from 3.7.0 to 4.0.0. (#241)

## [1.3.0] - 2026-03-13

### Added
- Scan API endpoint (`POST /api/v1/scan`): evaluate URLs, text, and MCP payloads against the scanner pipeline via HTTP. Returns structured findings with MITRE ATT&CK technique IDs, severity, and per-layer results. Configurable via `scan_api` config section. (#223)
- SARIF output for `pipelock audit` and `pipelock git scan-diff`: `--format sarif` produces SARIF v2.1.0 for GitHub Code Scanning integration. Findings appear as inline annotations on PR diffs via the `upload-sarif` action. (#217)
- CRLF injection detection: blocks `%0d%0a`, double-encoded `%250d%250a`, and raw CR/LF in URL scheme, authority, path, and query components. Fragments excluded (never reach upstream). (#224)
- Path traversal detection: blocks `/../`, encoded variants (`%2e%2e/`, `..%2f`, `..%5c`), partial encoding, double-encoded `%252e%252e`, and mixed-boundary patterns using segment-bounded matching to avoid false positives. (#224)
- CONNECT header DLP scanning: scans Proxy-Authorization and other headers on CONNECT handshake for leaked secrets before tunnel establishment. (#224)
- Subdomain entropy exclusions: `subdomain_entropy_exclusions` config field whitelists domains with legitimately high-entropy subdomains (e.g., RunPod GPU instances). Wildcard matching (`*.runpod.net`) covers all subdomain depths. (#222)
- License service scaffold: cluster-only webhook handler for Polar subscription events. Alpine-based Docker image, SQLite entitlement store, append-only audit ledger. ELv2 licensed. (#218)
- License service build artifacts: GoReleaser pipeline builds linux/amd64+arm64 Docker images for the license service with multi-arch manifests and build provenance attestation. (#226)
- `pipelock license install` command: accepts a license token and writes it to the local license file for pipelock to read at startup. (#216)
- Runtime license loading: load license from `PIPELOCK_LICENSE_KEY` env var or `license_file` config path. (#213)
- License tier and subscription fields: `tier` and `subscription_id` in license tokens for entitlement gating. (#215)
- Sentry error tracking: opt-in Sentry integration for crash reporting in production deployments. (#211)
- OWASP LLM Top 10 mapping document: article-by-article coverage analysis against OWASP LLM Top 10 2025. (#220)

### Changed
- Scanner context threading: `Scanner.Scan` now accepts `context.Context` for DNS cancellation propagation. All proxy paths pass request context through. (#221)
- Metrics refactored: structured initialization, per-transport counters, scan API metrics. (#223)
- License token enrichment: `tier` and `subscription_id` fields are now populated during license service minting. (#226)

### Fixed
- Config fail-open on omitted security booleans: `response_scanning.enabled`, `mcp_input_scanning.enabled`, and `mcp_tool_scanning.enabled` now default to `true` when omitted from YAML (previously defaulted to Go zero value `false`). (#219)
- WebSocket header DLP bypass: headers on WebSocket upgrade requests are now scanned for DLP patterns. (#219)
- `secrets_file` permission gap: file permission check now enforces `0o600` on secrets files. (#219)
- Capability separation language in docs: corrected claims about enforcement vs. deployment guidance. (#220)
- Adaptive enforcement accuracy in docs: clarified that v1 is scoring-only, not enforcement-aware. (#220)
- MCP `tools/list` false positive: instruction-like tool descriptions no longer trigger injection detection. (#224)
- URL fragment DLP coverage: URL fragments containing credential-like parameters are now detected by DLP scanning. (#224)
- Webhook idempotency: concurrent Polar webhook deliveries no longer double-mint licenses. (#226)
- Founding cap honor: paid founding checkouts are honored when cap is reached instead of silently downgrading to regular Pro. (#226)
- CLI license ledger: `pipelock license issue` no longer stores raw signed tokens in the ledger file (stores truncated SHA-256 hash for correlation). (#226)
- License service email and config defaults: corrected domain references from stale addresses to current domains. (#226)

## [1.2.0] - 2026-03-11

### Added
- Cross-request exfiltration detection (CEE): per-session entropy budget tracking and fragment reassembly with DLP re-scan catch secrets split across multiple requests. Integrated across all proxy paths (fetch, forward, TLS intercept, WebSocket, MCP). Strict and hostile-model presets enable CEE by default. (#206)
- DLP pattern expansion from 22 to 36 built-in patterns: AI/ML provider keys (Hugging Face, Databricks, Replicate, Together AI, Pinecone), infrastructure tokens (DigitalOcean, HashiCorp Vault, Vercel, Supabase), package registry tokens (npm, PyPI), and developer platform keys (Linear, Notion, Sentry) (#208)
- DLP prefix pre-filter: fast literal-prefix screening skips regex evaluation on URLs that contain no credential-like substrings, reducing DLP overhead on clean traffic (#209)

### Changed
- Release artifacts (Homebrew, GitHub releases, Docker images) now include paid-tier features that activate with a valid license key. Building from source without the `enterprise` tag produces a Community-only binary. (#212)

### Fixed
- Agent listeners now shut down on config reload when the license is revoked, preventing policy-free traffic after license expiry (#205)
- License headers normalized across all source files; documentation updated for dual-license clarity (#204)

## [1.1.0] - 2026-03-09

### Added
- `pipelock discover` command: scans MCP server configs (Claude Code, Cursor, Windsurf, VS Code) and shows which servers lack pipelock wrapping (#194)
- Parallel scanner benchmarks and concurrent scaling tests with performance documentation (#201)
- Security, Pipelock Scan, and CodeRabbit badges to README (#193)

### Fixed
- IPv6 listener collision detection: `[::]:8888`, `0.0.0.0:8888`, and `:8888` now correctly collide in agent listener validation (dual-stack systems bind all three to the same port)
- Non-canonical IPv6 addresses (e.g. `[0000::1]`) normalized via `net.ParseIP` for consistent collision detection
- Config hot-reload preserves agent listener state across reloads: removing a listener-bearing agent re-adds its full profile (prevents policy downgrade on bound ports), and new agent listeners are stripped (can't bind without restart). License expiry timestamps also preserved (watchdog timer set at startup only).

### Changed
- Enterprise module split: multi-agent features (per-agent identity, budgets, config isolation) moved to `enterprise/` directory under Elastic License 2.0 (ELv2). Core remains Apache 2.0. (#202)
- Enterprise features require `//go:build enterprise` tag at compile time and a valid license key at runtime
- OSS builds silently ignore `agents` config section (no error, agents just don't activate)
- CI tests both OSS and enterprise build modes
- CI dependency updates: actions/checkout v6, docker/setup-buildx-action v4, docker/setup-qemu-action v4, actions/dependency-review-action v4.9, github/codeql-action v4.32.6

## [1.0.0] - 2026-03-07

Pipelock 1.0.0 is the production-ready release. All scanning layers, proxy modes, and MCP security features are stable and commercially supported.

### Added
- Per-agent identity profiles: named agent configurations with independent mode, enforce flag, API allowlist, DLP patterns, rate limits, and session profiling overrides
- Agent identity resolution chain: context override > `X-Pipelock-Agent` header > `?agent=` query param > `_default` fallback
- Per-agent request budgets: configurable request count, byte transfer, and unique domain limits with rolling window enforcement
- Dedicated listener ports per agent for spoof-proof identity without relying on headers
- Source CIDR matching for agent identity
- `--agent` flag for MCP proxy: select agent profile for MCP proxy sessions
- Agent identity threaded through audit logs, Prometheus metrics, and JSON `/stats` breakdown
- `X-Pipelock-Agent` header stripped before forwarding to upstream (prevents agent impersonation)
- Ed25519 license key system: `pipelock license keygen`, `pipelock license issue`, and `pipelock license inspect` CLI commands with build-time public key embedding
- MCP tool policy: audit log tamper protection (blocks rm/truncate/shred on log files, history clearing)
- MCP tool policy: persistence detection for cron, systemd, init.d, launchd, and shell profile write paths with destination-aware matching
- Chain detection: `write-persist` and `persist-callback` patterns with argument-aware exec-to-persist reclassification
- Read-indicator downgrade: introspection tools no longer trigger false-positive persistence alerts
- `request_body_scanning` defaults in programmatic config (previously only available via preset files)
- IPv4/IPv6 multicast ranges added to default SSRF protection
- Social Security Number DLP pattern added to all config presets
- `tool_chain_detection` section added to all config presets
- `--home` flag for signing/keygen/verify/TLS CLI commands (container and rootless environment support)
- Config-relative CA path resolution for TLS interception (paths resolve relative to config file, not CWD)

### Fixed
- TLS interception shared transport: single `http.Transport` with connection pooling across intercepted CONNECT tunnels
- TLS passthrough domain reload warnings: set-diff detection catches same-size domain list replacements during config hot-reload
- TLS `InstallCA` refactored for testable OS-specific branches (certgen coverage improved)
- Config preset sync: all 7 presets now match `Defaults()` for DLP patterns, tool chain detection, and policy rules

### Changed
- Minimum version bump from 0.x to 1.0: public API (config format, CLI flags, audit schema, Prometheus metrics) is now stable. Breaking changes will follow semver.

## [0.3.6] - 2026-03-06

### Added
- TLS interception for CONNECT tunnels: opt-in MITM decrypts tunnel traffic for full request body DLP, header DLP, and response injection scanning. ECDSA P-256 CA with bounded TTL certificate cache.
- `pipelock tls init` command: generates a local CA key pair for TLS interception
- `pipelock tls show-ca` command: displays the CA certificate (PEM) for manual trust
- `pipelock tls install-ca` command: installs the CA into the system trust store
- `tls_interception` config section with `enabled`, `ca_cert`, `ca_key`, `cert_ttl`, and `passthrough_domains` fields. Hot-reload wiring for CA config changes.
- TLS interception SSRF-safe upstream dialer prevents DNS rebinding during intercepted connections
- TLS interception status reported in `/health` endpoint
- `pipelock_tls_intercept_total`, `pipelock_tls_handshake_duration_seconds`, `pipelock_tls_request_blocked_total`, `pipelock_tls_response_blocked_total`, `pipelock_tls_cert_cache_size` Prometheus metrics
- `tls_authority_mismatch`, `tls_response_blocked` audit events with MITRE technique labels
- All 7 config presets updated with `tls_interception` section defaults
- `pipelock report` command: reads JSONL audit logs and produces HTML, JSON, or Ed25519-signed evidence bundle reports with risk rating, event categories, timeline histogram, and evidence appendix. Supports `--format`, `--output`, `--sign`, and `--config` flags.
- MCP tool poisoning: parameter schema scanning extracts parameter key names from `inputSchema` at all nesting depths, expands underscore/hyphen/camelCase names, and scans for exfiltration intent (catches the CyberArk attack variant where data theft is encoded in parameter names while descriptions stay clean)
- Exfiltration Parameter Name poison pattern: detects action+target combinations in tool parameter names (read+private_key, steal+credentials, fetch+access_token)
- MCP tool drift summaries now report which parameters were added or removed instead of generic "description changed" messages
- Audit schema: chain detection structured events, startup/reload config hash metadata, version tracking
- `Config.Hash()` for deterministic SHA256 of raw config file bytes (used in signed reports)
- Dependency review GitHub Actions workflow: blocks PRs that introduce dependencies with known vulnerabilities
- CI concurrency groups: in-progress runs cancelled when new commits push to the same branch
- SPDX Apache 2.0 license headers on all Go source files
- GitHub Sponsors funding configuration
- Contributor License Agreement (Apache ICLA) section in CONTRIBUTING.md
- SPONSORS.md for sponsor recognition

### Fixed
- Environment variable leak scanner: ~50 well-known non-secret variables (HOME, PATH, USER, PWD, SHELL, TERM, LANG, EDITOR, GOPATH, LS_COLORS, and others) are now skipped by name, reducing false positives when agents send standard environment values in tool arguments. Case-insensitive matching handles Windows-style mixed-case names.
- TLS interception: `ActionAsk` treated as block inside intercepted tunnels (no HITL terminal available in TLS context)
- TLS interception: `LoadCA` validates cert.IsCA, KeyUsageCertSign, and key correspondence. Rejects cert_ttl <= 0 and group/world-readable CA keys.
- MCP: skip general injection scanner for tools/list responses when tool scanning is enabled, preventing false positives on instructional tool descriptions (e.g. "you must call this tool")
- Report: chain detection severity derived from action (block=critical, warn=warn) instead of storing caller-provided value
- Report: hash raw client IP in audit session field when Mcp-Session-Id absent, preventing IP leak
- Report: plain blocked events without an action field now get high severity instead of medium
- Report: evidence appendix redacts connect_host and sni_host IP addresses
- Report: admin events (startup, shutdown, config_reload) excluded from timeline histogram
- Report: skipped JSONL lines tracked and surfaced in summary and HTML template
- Report: criticals KPI counter uses severity:critical count (was always 0)
- Report: exec summary uses traffic-only event count as denominator (excludes admin events)
- Report: multi-day timeline labels use "Jan 2" date format instead of "00:00" for all bars

### Changed
- Documentation version references use `v1`/`latest` instead of pinned version numbers so guides stay current across releases

## [0.3.5] - 2026-03-05

### Added
- Kill switch API token can now be set via `PIPELOCK_KILLSWITCH_API_TOKEN` environment variable, overriding the `kill_switch.api_token` config field. Enables Kubernetes deployments to source the token from a Secret instead of a ConfigMap.
- Request body DLP scanning for the forward HTTP proxy. Scans POST/PUT/PATCH bodies for secrets across JSON (recursive string extraction), form-urlencoded, multipart/form-data, and raw text. Unknown content types get a fallback raw-text scan to prevent Content-Type spoofing bypass. Fail-closed on oversized bodies, compressed bodies, parse errors, and multipart limit violations.
- Request header DLP scanning for the forward proxy and fetch handler. Two modes: `sensitive` (scan listed headers only) and `all` (scan everything except structural headers, including header names). Joined scan catches secrets split across multiple headers.
- `request_body_scanning` config section with `enabled`, `action`, `max_body_bytes`, `scan_headers`, `header_mode`, `sensitive_headers`, and `ignore_headers` fields
- `pipelock_body_dlp_hits_total` and `pipelock_header_dlp_hits_total` Prometheus counters
- `body_dlp` and `header_dlp` audit event types
- Shared JSON string extractor (`internal/extract`) used by both proxy body scanning and MCP input scanning
- `hostile-model` config preset for agents running uncensored or jailbroken models
- Windows build support: GoReleaser produces Windows amd64/arm64 binaries (zip archives). Kill switch signal toggle and config reload signal are no-ops on Windows; all other features work identically.
- CONNECT tunnel SNI verification: detects domain fronting (T1090.004) by comparing the CONNECT target hostname against the TLS SNI extension. Enabled via `forward_proxy.sni_verification: true`. `pipelock_sni_total` Prometheus counter tracks matches.
- `pipelock claude hook/setup/remove` commands for Claude Code hook integration
- MCP confused deputy protection: validates that MCP server response IDs match previously tracked request IDs. Blocks unsolicited responses that could hijack agent execution flow.
- IPv4 and IPv6 multicast CIDRs (`224.0.0.0/4`, `ff00::/8`) added to default SSRF internal address list

### Fixed
- IPv6 zone ID SSRF bypass: URLs like `http://[::1%25eth0]/` no longer skip CIDR checks. Zone IDs are stripped before IP parsing.

## [0.3.4] - 2026-03-04

### Fixed
- `pipelock cursor install` now writes Cursor's v1 hooks.json format (map keyed by event name with `version` field). Previously wrote a flat array that Cursor silently ignored, causing hooks to never fire.
- `pipelock cursor install` now preserves `args` fields on existing hooks during merge. Previously, non-pipelock hooks with `args` arrays lost their arguments after install or upgrade.
- `pipelock preflight` now scans both v1 and legacy hooks.json formats. Previously only understood the legacy format and would false-positive on v1 files.

## [0.3.3] - 2026-03-04

### Added
- `pipelock verify-install` command: 10 deterministic checks verifying scanning pipeline and network containment. Produces human-readable or `--json` output with optional Ed25519 `--sign` for tamper-evident reports. Supports `--output` to write results to file.
- `pipelock cursor hook` subcommand: Cursor IDE hook integration. Reads hook events from stdin, evaluates DLP, injection, and tool policy, writes allow/deny JSON to stdout. Always exits 0 with JSON `permission` field as the authoritative decision. Without `--config`, uses a security-focused default profile with 9 tool policy rules, MCP input scanning, and response scanning enabled.
- `pipelock cursor install` subcommand: writes `hooks.json` to register pipelock with Cursor. Supports `--global` (default, `~/.cursor/`) and `--project` (`.cursor/` in cwd). Atomic writes via temp file + rename, `.bak` backup, idempotent merge with existing hooks, upgrade-safe replacement of stale entries.
- `internal/decide` package: shared decision engine for evaluating agent actions against pipelock's scanning pipeline. Supports shell execution, MCP tool calls, and file read events with per-finding action semantics (block vs warn) and `enforce` flag override.
- Fail-closed on malformed MCP tool_input: invalid JSON in tool arguments is treated as block-level evidence. Legitimate MCP tool calls always have valid JSON; parse failure indicates tampering or corruption.
- `pipelock audit --preflight` scanner: detects dangerous IDE configuration files (`.cursor/mcp.json`, `.vscode/mcp.json`) in project directories that could override agent security settings. Reports threat level (critical/high/medium/low) with actionable remediation steps.

### Changed
- Replaced all `//nolint:gosec` G304 suppressions with `filepath.Clean()` across production and test code (84 occurrences in 26 files). No behavioral change.
- Eliminated all `//nolint:goconst` directives, extracted named constants

### Fixed
- Pre-existing lint issues in `tests/ws-helper/main.go`: errcheck on `conn.Close()`, noctx on `net.Listen`

## [0.3.2] - 2026-03-02

### Added
- `pipelock diagnose` command: fully local end-to-end configuration verification. Spins up a mock upstream and temp proxy, runs 6 checks (health, fetch allowed/blocked, hint presence, CONNECT allowed/blocked). Exit 0 on pass, 1 on failure, 2 on config error. Supports `--json` and `--config`.
- `explain_blocks` config field (opt-in, default false): blocked responses include actionable hints explaining why a request was blocked and how to fix it. Fetch proxy gets a JSON `hint` field, CONNECT and WebSocket get an `X-Pipelock-Hint` header. Hints are per-scanner (DLP, blocklist, SSRF, entropy, rate limit, etc.).
- Scanner label constants (`scanner.ScannerDLP`, `scanner.ScannerBlocklist`, etc.): 12 exported constants matching existing on-wire metric label values
- `proxy.Handler()` method: returns the composed HTTP handler for use with `httptest.NewServer` or custom listeners
- Docker Compose quickstart (`examples/quickstart/`): production-ready two-network architecture with `internal: true` isolation, opt-in verification suite (5 tests: network isolation, DLP, response injection, MCP tool poisoning), attacker container for reproducible demos

### Fixed
- `generate mcporter` now preserves per-server extra fields (`alwaysAllow`, `disabled`, `metadata`, `headers`, etc.) during wrapping. Previously only `command`, `args`, and `env` survived.
- WebSocket scanner label split: protocol enforcement events now correctly use `ws_protocol` label
- Grafana dashboard template variable syntax corrected for fleet filtering

### Changed
- Reusable scan workflow actions pinned to commit SHAs for OpenSSF Scorecard compliance

## [0.3.1] - 2026-03-01

### Added
- WebSocket MCP transport: `--upstream ws://` and `wss://` for MCP proxy connections, with the same 6-layer scanning pipeline as stdio and HTTP modes
- `pipelock generate mcporter` CLI: wraps MCP server configs with pipelock scanning. Reads any JSON with `mcpServers`, preserves env blocks, detects already-wrapped servers, idempotent
- `pipelock-init` container image: Alpine-based multi-arch image for K8s initContainer deployments, replaces multi-line wget/tar/chmod scripts with `cp /pipelock /shared-bin/pipelock`
- MITRE ATT&CK technique IDs mapped to all scanner labels (T1048, T1059, T1046, T1071.001, T1190, T1195.002, T1078, T1030) in blocked, anomaly, ws_scan, response_scan, session_anomaly, and mcp_unknown_tool audit events and emitted payloads
- `pipelock_kill_switch_active{source}` Prometheus gauge via custom collector (fresh state per scrape, four sources: config, api, signal, sentinel)
- `pipelock_info{version}` build information metric
- Metrics port isolation: `metrics_listen` config field runs `/metrics` and `/stats` on a dedicated port, preventing agents from scraping operational metadata. Changes rejected on hot-reload with a warning.
- Cosign signature verification in the GitHub Action: release checksums verified against Sigstore attestation before binary install. Graceful degradation when cosign is unavailable.
- Reusable GitHub Actions security scan workflow (`.github/workflows/reusable-scan.yml`) with 7 configurable inputs and `score`, `findings-count`, `critical-count` outputs
- 7 new docs: configuration reference, deployment recipes (Docker/K8s/iptables/macOS PF), bypass resistance matrix, attacks-blocked gallery, policy spec v0.1, transport modes guide, OpenClaw deployment guide
- Prometheus metrics reference (`docs/metrics.md`): all 20 metrics with scrape config and PodMonitor example
- 11 ready-to-use Prometheus alert rules (`examples/prometheus/pipelock-alerts.yaml`)
- Grafana dashboard rebuilt from 4-panel overview to 18-panel fleet monitor with per-source kill switch status, chain detection by pattern, session anomaly breakdown, escalation timeseries, and multi-instance `$instance` filter variable
- `filterAndActOnResponseScan` helper: extracted response scan action handling (suppress, block, ask, strip, warn) to eliminate duplication between raw HTML and extracted text scan paths
- Demo extended with base64-encoded secret detection, git diff scanning, and config generation steps

### Fixed
- `internal: []` in YAML config now correctly disables SSRF checks. Previously, `ApplyDefaults()` treated explicit empty slices the same as absent fields, filling in default CIDRs. This blocked legitimate Docker container traffic on private IPs (172.x.x.x).
- Reject WebSocket compressed frames (RSV1 bit): compressed bytes bypass DLP pattern matching entirely, now closed with StatusProtocolError on both relay directions
- Scan raw HTML body before go-readability extraction: injection hidden in HTML comments, script/style tags, and hidden elements was stripped before the response scanner could detect it
- Use Mozilla Public Suffix List for ccTLD-aware domain grouping: `baseDomain()` now correctly groups `evil.co.uk` instead of merging all `.co.uk` domains into one rate limit bucket
- Prompt injection detection regex broadened to catch determiner-before-modifier evasion variants (e.g. "ignore your previous instructions", "forget the prior rules")
- RFC 6455 compliance: WebSocket proxy now sends masked close frames to upstream connections (previously sent unmasked server-style frames)

### Changed
- **Telemetry label split:** WebSocket protocol enforcement events (binary frame rejection, fragment errors) now emit scanner label `ws_protocol` instead of `policy`. The `policy` label is now exclusively for MCP tool policy violations. MITRE mapping: `ws_protocol` maps to T1071 (Application Layer Protocol), `policy` remains T1059 (Command and Scripting Interpreter). Update any dashboards or alert rules that filter on `scanner="policy"` for WebSocket-specific events.
- `internal/wsutil` package extracted: shared WebSocket utilities (fragment reassembly, close frames, error classification) used by both the HTTP WS proxy and MCP WS transport
- Anomaly audit events now include `scanner` as a structured field with MITRE technique mapping (previously embedded in reason string)
- README slimmed from 829 to ~490 lines; full configuration YAML replaced with link to `docs/configuration.md`, forward proxy quick start moved to collapsible section
- Quick start updated to use `pipelock check` (works without running the proxy)
- `golang.org/x/net` promoted from indirect to direct dependency (publicsuffix for ccTLD handling)

## [0.3.0] - 2026-02-27

### Added
- Kill switch: emergency deny-all with four activation sources (config, SIGUSR1 signal, sentinel file, HTTP API), OR-composed so any single source blocks all proxy traffic
- Kill switch API: `POST /api/v1/killswitch` (activate/deactivate) and `GET /api/v1/killswitch/status` (per-source state) with bearer token auth, rate limiting, and input hardening (MaxBytesReader, DisallowUnknownFields, strict EOF enforcement)
- Kill switch port isolation: `api_listen` config field runs the kill switch API on a dedicated port, preventing agents from deactivating their own kill switch in sidecar deployments
- Event emission: fire-and-forget dispatch to webhook and syslog sinks with independent severity filters (`info`, `warn`, `critical`), configurable `instance_id`, and async buffered delivery
- Webhook sink: HTTP POST with bearer token auth, configurable timeout and queue size, background worker with graceful shutdown
- Syslog sink: UDP/TCP delivery with configurable facility, tag, and severity mapping to syslog priority levels
- Finding suppression: silence known false positives via config (`suppress` entries with rule name, path glob, and reason) or inline `// pipelock:ignore` source comments
- Tool call chain detection: subsequence matching on MCP tool call sequences with 8 built-in attack patterns (recon, credential theft, data staging, exfiltration), configurable window size, time-based eviction, and max-gap constraint
- Session profiling and adaptive enforcement config sections (scoring-only in v1, observability groundwork)
- Health endpoint now reports `kill_switch_active` field
- Preset configs (strict, balanced) updated with kill switch and emit examples (commented out)
- DLP: 6 new patterns: Fireworks API Key, Google API Key, Google OAuth Client Secret (GOCSPX), Slack App Token (`xapp-`), JWT Token, Google OAuth Client ID
- DLP: expanded AWS Access ID detection from AKIA-only to all 9 credential prefixes (AKIA, ASIA, AROA, AIDA, AIPA, AGPA, ANPA, ANVA, A3T)
- DLP: expanded GitHub Token detection to cover all 5 token types (ghp, gho, ghu, ghs, ghr)
- All 6 preset configs (balanced, strict, audit, claude-code, cursor, generic-agent) updated with expanded DLP pattern set (22 patterns)
- DLP `include_defaults` config field: when true (default), user-defined DLP patterns are merged with built-in defaults by name, so new default patterns are automatically added on binary upgrade without requiring config changes. Set `include_defaults: false` to use only user-defined patterns (previous behavior). Same field available for `response_scanning`.
- Finding suppression guide (`docs/guides/suppression.md`): documents all three suppression layers (inline comments, config entries, `--exclude` flag), available rule names, path matching styles, and GitHub Action integration

### Fixed
- Close WebSocket cross-message DLP bypass: secrets split across WebSocket text frames are now detected via fragment reassembly buffer scanning (PR #140)
- Close header rotation evasion: IP-level domain tracking prevents agents from rotating Host/Origin headers to bypass per-domain rate limits (PR #141)

### Changed
- MCP package refactored into sub-packages: `transport`, `tools`, `policy`, `jsonrpc` for clearer separation of concerns
- Audit logger enhanced with event emission dispatch: audit calls now route to configured webhook/syslog sinks based on severity
- Normalize package extracted as `internal/normalize` with `ForPolicy` variant for MCP tool policy command matching

## [0.2.9] - 2026-02-23

### Added
- WebSocket proxy: `/ws?url=ws://...` endpoint with bidirectional frame relay, DLP + injection scanning on text frames, fragment reassembly, message size limits, SSRF-safe upstream dialer, auth header forwarding with DLP scanning, concurrency limits, connection lifetime and idle timeout controls, and Prometheus metrics
- WebSocket configuration: `websocket_proxy` section in config with `max_message_bytes`, `scan_text_frames`, `allow_binary_frames`, `strip_compression`, `max_connection_seconds`, `idle_timeout_seconds`, `origin_policy`, and `max_concurrent_connections`
- WebSocket health reporting: `/health` endpoint includes `websocket_proxy_enabled` field
- All 6 preset configs updated with `websocket_proxy` defaults (disabled by default)
- `--exclude` flag for `pipelock audit` and `pipelock git scan-diff`: filter findings by path using globs (`*.generated.go`) or directory prefixes (`vendor/`). Repeatable for multiple patterns.
- GitHub Action `exclude-paths` input: newline-separated path patterns passed to both audit and scan-diff steps

## [0.2.8] - 2026-02-23

### Fixed
- Close 9 scanner evasion bypasses found during red team testing: hex/base64-encoded secrets in URL query params and path segments, vowel-fold flag corruption on `(?im)` patterns, strip mode fail-open when detection came from non-redactable passes, and missing normalization passes on decoded response content (PR #135)
- Close 3 DLP evasion bypasses in query parameter scanning: iterative URL-decode, noise-stripped values, and dot-collapsed subdomain splits now applied to individual query keys and values (PR #134)

### Changed
- Encoding attribution: segment-level DLP matches now carry correct encoding labels (hex, base64, base32) instead of always reporting "hex"
- Response scanning decoded-content path runs all normalization passes (primary, opt-space, vowel-fold), closing a gap where base64/hex-encoded vowel-substituted injection could bypass detection
- Logo tagline updated to "Agent Firewall"

## [0.2.7] - 2026-02-22

### Added
- MCP HTTP reverse proxy: `--mcp-listen` + `--mcp-upstream` flags on `pipelock run` create an HTTP-to-HTTP scanning proxy with bidirectional JSON-RPC 2.0 validation, Authorization header DLP scanning, and fail-closed parse error handling (PR #127)
- MCP standalone HTTP listener: `pipelock mcp proxy --listen :8889 --upstream http://host/mcp` for deployments that only need MCP scanning without the fetch/forward proxy (PR #127)
- JSON-RPC 2.0 structural validation on HTTP listener: rejects non-string method types, wrong/missing jsonrpc version, and missing method field with proper -32600 error codes; batch requests pass through to per-element scanning (PR #127)
- CI dogfooding: Pipelock's own GitHub Action runs on every PR, scanning diffs for exposed credentials and injection patterns (PR #126)

### Fixed
- Release workflow: semver-only tag filter (`v*.*.*`) prevents floating tags like `v1` from triggering spurious GoReleaser releases (PR #126)
- Auto-move `v1` floating tag after each semver release so the GitHub Action always resolves to the latest version (PR #126)

### Changed
- MCP auto-enable default: `mcp_input_scanning.action` changed from `warn` to `block` when auto-enabled in proxy mode, preventing credential forwarding in balanced configs (PR #127)
- Default response scanning and DLP patterns auto-populated when MCP listener enables scanning on an unconfigured section (PR #127)

## [0.2.6] - 2026-02-21

### Added
- HTTP forward proxy: standard CONNECT tunneling and absolute-URI HTTP forwarding on the same port as the fetch proxy. Set `HTTPS_PROXY=http://localhost:8888` and all agent HTTP traffic flows through the scanner pipeline. Configurable tunnel duration and idle timeout controls (PR #123)
- Tunnel observability: Prometheus metrics (tunnel count, bytes transferred, duration histogram, active gauge), JSON stats, and structured audit logs for tunnel open/close events (PR #123)
- GitHub Action (`luckyPipewrench/pipelock`): composite action for CI/CD agent security scanning with checksum-verified binary download, multi-arch (amd64/arm64) and multi-OS (Linux/macOS) support, fail-closed audit gate, PR diff secret scanning, inline GitHub annotations on findings, and job summary (PR #125)
- CI workflow examples for basic and advanced GitHub Action usage (PR #125)

### Changed
- Forward proxy enabled by default in all 6 preset configs: balanced, strict, audit, claude-code, cursor, generic-agent (PR #125)
- Action string constants extracted to `config` package (`ActionBlock`, `ActionWarn`, `ActionAsk`, `ActionStrip`, `ActionForward`), replacing ~70 hardcoded literals across 12 files (PR #124)
- README rewritten with forward proxy "zero code changes" quickstart as primary path, refreshed benchmarks and testing stats, honest security assessment section (PR #122, #125)
- Copyright updated to legal name in LICENSE (PR #122)

## [0.2.5] - 2026-02-20

### Added
- MCP `--env` flag: pass specific environment variables to child processes without exposing the full environment (PR #119)

### Fixed
- Tool poisoning detection: instruction tag patterns (`<IMPORTANT>`, `<system>`) and dangerous capability patterns (file exfil, cross-tool manipulation) hardened via adversarial testing (PR #117)

### Changed
- Rebrand from "security harness" to "agent firewall" across all user-facing surfaces: CLI, README, docs, demo, Homebrew formula (PR #120)
- Extract `internal/normalize` package: consolidate Unicode normalization pipeline, add `ForPolicy` variant for command matching (PR #116)
- Documentation refresh: updated comparison matrix, stale references, testing stats (PR #118)

## [0.2.4] - 2026-02-19

### Added
- MCP Streamable HTTP transport: `pipelock mcp proxy --upstream <url>` bridges stdio clients to remote MCP servers over HTTP with SSE stream support and session lifecycle management (PR #112)
- Pre-execution tool call policy: configurable `mcp_tool_policy` blocks dangerous commands (rm -rf, curl to external, chmod 777) before MCP tools execute, with pairwise token matching and whitespace normalization (PR #107)
- Known secret scanning: `dlp.secrets_file` config loads explicit secrets from file, scans URLs and MCP tool arguments for raw + base64/hex/base32 encoded variants including unpadded forms (PR #111)
- `pipelock test` CLI command: validates scanner coverage against loaded config with structured pass/fail output per scanner layer (PR #109)
- Framework integration guides: OpenAI Agents SDK, Google ADK, AutoGen (PR #110)
- GOVERNANCE.md, ROADMAP.md, and security assurance documentation for OpenSSF Silver (PR #108)
- OpenSSF Best Practices Silver badge (PR #114)

### Fixed
- Unicode bypass in injection and DLP scanning: full homoglyph normalization (Cyrillic, Greek, Armenian, Cherokee), combining mark stripping, leetspeak normalization, 6 new injection patterns (PR #105)
- govulncheck CI flake: pinned Go version to 1.24.13 to prevent runner cache inconsistency (PR #113)
- Codecov targets raised to 95% project / 90% patch (PR #113)

### Changed
- README Quick Start reordered: `pipelock check` before `pipelock run` since check doesn't need a running proxy (PR #113)
- CONTRIBUTING.md updated with complete CLI command list and project structure (PR #113)
- Demo script uses `DEMO_TMPDIR` instead of `TMPDIR` to avoid shadowing POSIX env var (PR #113)
- CI matrix tests Go 1.24 + 1.25 (PR #113)

## [0.2.3] - 2026-02-16

### Added
- MCP transport abstraction: `MessageReader`/`MessageWriter` interfaces decouple scanning from stdio framing, preparing for HTTP transport
- Demo command: 7 attack scenarios (was 5), adding MCP input secret leak and tool description poisoning demos
- Demo ANSI color output with `NO_COLOR` env var support and TTY detection
- Demo `--interactive` flag for live presentations (pauses between scenarios)
- CrewAI integration guide (`docs/guides/crewai.md`)
- LangGraph integration guide (`docs/guides/langgraph.md`)
- `WriteMessage` size guard (10 MB limit) prevents unbounded memory allocation on malformed input
- `maxLineSize` guard on stdio message reader for consistency with write path

### Fixed
- Strict-mode API allowlist enforcement: requests to non-allowlisted domains now blocked in strict mode (was warn-only)
- MCP no-params DLP bypass: requests with missing `params` field bypassed input scanning entirely
- Encoded secret bypass in MCP input: multi-layer percent-encoding could evade DLP patterns
- Display URL normalization: audit log URLs now consistently decoded for readability
- Three static analysis findings: `ViolationPermissions` field visibility, HITL reload-to-ask warning, stale comment

### Changed
- Demo "MCP Tool Poisoning" scenario renamed to "MCP Response Injection" for clarity
- `iterativeDecode` consolidated into single exported function (was duplicated across scanner paths)
- Write errors in `syncWriter` and `StdioWriter` now wrapped with context
- Bumped `sigstore/cosign-installer` from 3.10.1 to 4.0.0

## [0.2.2] - 2026-02-15

### Added
- MCP tool description scanning: detects poisoned tool descriptions containing hidden instructions (`<IMPORTANT>` tags, file exfiltration directives, cross-tool manipulation)
- MCP tool rug-pull detection: SHA256 baseline tracks tool definitions per session, alerts when descriptions change mid-session
- `mcp_tool_scanning` config section (action: warn/block, detect_drift: true/false)
- Auto-enabled in `mcp proxy` mode unless explicitly configured
- Unicode normalization (NFKC) and C0 control character stripping in tool description scanning
- Recursive schema extraction: scans `description` and `title` fields from nested `inputSchema` objects
- JSON-RPC batch response handling for tool scanning
- `CODEOWNERS` file for automatic review assignment
- Cosign keyless signing for release checksums (Sigstore transparency log)
- Manual trigger (`workflow_dispatch`) for OpenSSF Scorecard workflow

### Fixed
- Fetch proxy URL parameter truncation: unencoded `&` in target URLs silently truncated secrets from DLP scanner
- Fetch proxy control character bypass: `%00`, `%08`, `%09`, `%0a` in target URLs broke DLP regex matching
- Empty-name tool bypass: tools with no `name` field bypassed `tools/list` scanning entirely
- Baseline capacity DoS: malicious servers could force hash computation on unlimited unique tool names (added capacity cap with `ShouldSkip()`)

### Changed
- Branch protection: squash-only merges, stale review dismissal

## [0.2.1] - 2026-02-15

### Added
- SLSA build provenance attestation for all release binaries and container images
- CycloneDX SBOM generated and attached to every release
- OpenSSF Scorecard workflow with results published to GitHub Security tab
- `govulncheck` CI job scanning Go dependencies for known vulnerabilities
- `go mod verify` step in CI and release pipelines
- OpenSSF Scorecard badge in README
- OpenSSF Best Practices passing badge in README
- Release verification instructions in README (`gh attestation verify`)

### Changed
- All GitHub Actions pinned to commit SHAs (supply chain hardening)
- Release workflow now includes `id-token` and `attestations` permissions for provenance signing
- Explicit top-level `permissions: contents: read` in CI workflow (least privilege)
- Release attestation steps use `continue-on-error` with final verification (prevents cascading failures)
- Container digest resolution uses `::warning` annotation instead of silent fallback
- `govulncheck`, `cyclonedx-gomod`, and `crane` pinned to specific versions (not `@latest`)
- Docker base images pinned by SHA256 digest (Scorecard Pinned-Dependencies)
- Write permissions moved from workflow-level to job-level (Scorecard Token-Permissions)
- Branch protection: added PR requirement, lint as required check, strict status policy, review thread resolution

### Fixed
- Fetch proxy DNS subdomain exfiltration: dot-collapse scanning now applied to hostnames in `checkDLP` (was only on MCP text scanning side)
- MCP content block split bypass: `ExtractText` now joins blocks with space separator (was `\n`, allowing between-word injection splits to evade detection)
- Git DLP case sensitivity: `CompileDLPPatterns` now applies `(?i)` prefix, matching URL scanner behavior
- Rate limiter subdomain rotation: `checkRateLimit` now uses `baseDomain()` normalization, preventing per-subdomain rate limit evasion
- Response scanning Unicode whitespace bypass: added `normalizeWhitespace()` for Ogham space (U+1680), Mongolian vowel separator (U+180E), and line/paragraph separators
- Agent name path traversal: `ValidateAgentName` now rejects names containing `..` or equal to `.`
- URL DLP NFKC normalization: applied `norm.NFKC.String()` before DLP pattern matching, consistent with response scanning

## [0.2.0] - 2026-02-13

### Added
- MCP input scanning: bidirectional proxy now scans client requests for DLP leaks and injection in tool arguments
- `mcp_input_scanning` config section (action: warn/block, on_parse_error: block/forward)
- Auto-enabled in `mcp proxy` mode unless explicitly configured
- Iterative URL decoding in text DLP (catches double/triple percent-encoding)
- Method name and request ID fields included in DLP scan coverage
- OPENSSH private key format added to Private Key Header DLP pattern
- Split-key concatenation scanning: detects secrets split across multiple JSON arguments
- DNS subdomain exfiltration detection: dot-collapse scanning catches secrets split across subdomains
- Case-insensitive DLP pattern matching: prevents evasion via `.toUpperCase()` or mixed-case secrets
- Null byte stripping in scanner pipeline: prevents regex-splitting bypass via `\x00` injection
- 55+ new tests for input scanning, text DLP, and config validation

### Changed
- CI workflow: removed redundant `go vet` and `go mod verify` steps, combined duplicate test runs, added job timeouts
- Audit preset `on_parse_error` changed from `block` to `forward` (consistent with observe-only philosophy)
- Config validation rejects `ask` action for input scanning (no terminal interaction on request path)
- CLI auto-enable checks both `enabled` and `action` fields (unconfigured = both at zero values)

## [0.1.8] - 2026-02-12

### Added
- Audit log sanitization: ANSI escapes and control characters stripped from all log fields (`internal/audit/logger.go`)
- Data budget enforcement per registrable domain (prevents subdomain variation bypass)
- Hex-encoded environment variable leak detection
- Container startup warning when running as root
- HITL channel drain before each prompt (prevents stale input from prior timeout)
- DLP patterns for `github_pat_` fine-grained PATs and Stripe keys (`[sr]k_(live|test)_`)
- Fuzz test for audit log sanitizer
- Integrity manifest path traversal protection
- 970+ tests passing with `-race`

### Security
- MCP proxy fail-closed: unparseable responses now blocked in all action modes (was forwarding in warn/strip/ask)
- MCP batch scanning fail-closed: parse errors on individual elements now propagate as dirty verdict
- MCP strip recursion depth limit (`maxStripDepth=4`) prevents stack overflow from nested JSON arrays

### Fixed
- DLP pattern overlap: OpenAI Service Key narrowed to `sk-svcacct-` (was `sk-(proj|svcacct)-`, overlapping with existing `sk-proj-` pattern)
- Redirect-to-SSRF: blocked flag now set on redirect hops (redirect to private IP was not caught)
- Rate limiter returns HTTP 429 Too Many Requests (was returning 403)
- io.Pipe resource leak in HITL tests

### Removed
- SKILL.md (ClawHub listing discontinued)

## [0.1.6] - 2026-02-11

### Added
- `--json` flag for `git scan-diff` command (CI/CD integration)
- Fuzz tests for 8 security-critical functions across 4 packages
- 660+ tests passing with `-race`

### Security
- IPv4-mapped IPv6 SSRF bypass: `::ffff:127.0.0.1` now normalized via `To4()` before CIDR matching
- MCP ToolResult schema bypass: result field uses `json.RawMessage` with recursive string extraction fallback
- MCP zero-width Unicode stripping applied to response content scanning
- DNS subdomain exfiltration: DLP/entropy checks now run on hostname before DNS resolution
- `--no-prefix` git diff bypass: parser accepts `+++ filename` without `b/` prefix
- MCP error messages (`error.message` and `error.data`) now scanned for injection
- Double URL encoding DLP bypass: iterative decode (max 3 rounds) on path segments
- Default SSRF CIDRs: added `0.0.0.0/8` and `100.64.0.0/10` (CGN/Tailscale)
- CRLF line ending normalization in git diff parsing
- `ReadHeaderTimeout` added to HTTP server (Slowloris protection)
- Non-text MCP content blocks now scanned (was skipping non-`text` types)

### Fixed
- Homebrew formula push: use `HOMEBREW_TAP_TOKEN` secret for cross-repo access

## [0.1.5] - 2026-02-10

### Added
- `pipelock audit` command: scans projects for security gaps, generates score (0-100) and suggested config (`internal/projectscan/`)
- `pipelock demo` command: 5 self-contained attack scenarios (DLP, injection, blocklist, entropy, MCP) using real scanner pipeline
- OWASP Agentic AI Top 15 threat mapping (`docs/owasp-agentic-top15-mapping.md`, 12/15 threats covered)
- 14 scanner pipeline benchmarks with `make bench` target (~3 microseconds per allowed URL)
- Grafana dashboard JSON (`configs/grafana-dashboard.json`, 7 panels, 3 rows)
- SVG logo
- Public contributor guide (`CLAUDE.md`)
- CONTRIBUTING.md expanded with detailed development workflow
- 756+ tests passing with `-race`

### Fixed
- Audit score: critical finding penalty (-5 per leaked secret found)
- DLP pattern compilation deduplication
- Follow mode context-aware shutdown in `logs` command
- Blog links updated from GitHub Pages to pipelab.org
- OWASP mapping updated to 2026 final category names

## [0.1.4] - 2026-02-09

### Added
- MCP stdio proxy mode: `pipelock mcp proxy -- <command>` wraps any MCP server, scanning responses in real-time (`internal/mcp/proxy.go`)
- Human-in-the-loop terminal approvals: `action: ask` prompts for y/N/s with configurable timeout (`internal/hitl/`)
- Agent-specific config presets: `configs/claude-code.yaml`, `configs/cursor.yaml`, `configs/generic-agent.yaml`
- Claude Code integration guide (`docs/guides/claude-code.md`)
- Homebrew formula in GoReleaser config
- Asciinema demo recording embedded in README

### Fixed
- Makefile VERSION fallback: `git describe` failure no longer produces empty version string
- OpenAI API key DLP regex: now matches keys containing `-` and `_` characters
- HITL approver data race: single reader goroutine pattern eliminates concurrent `bufio.Reader` access on timeout
- GoReleaser v2: `folder` renamed to `directory` in Homebrew brews config

## [0.1.3] - 2026-02-09

### Added
- File integrity monitoring for agent workspaces (`pipelock integrity init|check|update`)
- SHA256 manifest generation with glob exclusion patterns (`**` doublestar support)
- Integrity check reports: modified, added, and removed file detection
- JSON output mode for integrity checks (`--json` flag)
- Custom manifest path support (`--manifest` flag)
- Atomic manifest writes (temp file + rename) to prevent corruption
- Manifest version validation and nil-files guard on load
- Ed25519 signing for file and manifest verification (`pipelock keygen|sign|verify|trust`)
- Key storage under `~/.pipelock/` with versioned format headers
- Trusted key management for inter-agent signature verification
- Path traversal protection in keystore operations
- MCP JSON-RPC 2.0 response scanning for prompt injection (`pipelock mcp scan`)
- MCP scanning: text extraction from content blocks, split-injection detection via concatenation
- MCP scanning: `--json` output mode (one verdict per line) and `--config` flag
- Blog at pipelab.org/blog/
- 530+ tests passing with `-race`

### Fixed
- DLP bypass: secrets in URL hostnames/subdomains now scanned (full-URL DLP scan)
- DLP bypass: secrets split across query parameters now detected
- README: corrected signing CLI syntax, agent types, health version example
- GoReleaser: added missing BuildDate/GitCommit/GoVersion ldflags
- Blog: fixed hallucinated product name, removed stale "coming next" reference

### Security
- `json.RawMessage` null bypass prevention (MCP result always scanned regardless of error field)

### Removed
- Stale Phase 1.5 planning doc (planning docs live outside the repo)

## [0.1.2] - 2026-02-08

### Added
- CodeQL security scanning workflow
- Codecov coverage integration and badge
- Go Report Card badge

### Fixed
- All 53 golangci-lint warnings resolved (zero-warning CI baseline)
- 363 tests passing with `-race`

## [0.1.1] - 2026-02-08

### Changed
- CLI commands write to `cmd.OutOrStdout()` instead of `os.Stdout` (cobra-idiomatic)
- `run` command uses `cmd.Context()` as signal parent for testability

### Added
- Run command integration test (config loading, flag overrides, health check, graceful shutdown)
- Docker Compose YAML syntax validation test (all agent templates parsed via `yaml.Unmarshal`)
- Base64url environment variable leak detection test
- Rate limiter window rollover test
- Healthcheck command test against running server
- 363 tests passing with `-race`

## [0.1.0] - 2026-02-08

### Added
- Fetch proxy server with `/fetch`, `/health`, `/metrics`, and `/stats` endpoints
- URL scanning pipeline: scheme check, SSRF protection, domain blocklist, rate limiting, URL length, DLP regex, Shannon entropy
- SSRF protection with configurable CIDR ranges (IPv4 + IPv6), fail-closed DNS resolution, DNS rebinding prevention via pinned DialContext
- DLP pattern matching for API keys, tokens, secrets (Anthropic, OpenAI, GitHub, Slack, AWS, Discord, private keys, SSNs)
- Shannon entropy analysis for detecting encoded/encrypted data in URL segments
- Environment variable leak detection: scans URLs for high-entropy env var values (raw + base64-encoded)
- Domain blocklist with wildcard support (`*.pastebin.com`)
- Per-domain rate limiting with sliding window and configurable `max_requests_per_minute`
- Response scanning: fetched page content scanned for prompt injection patterns (block/strip/warn actions)
- Multi-agent support: `X-Pipelock-Agent` header identifies calling agents; agent name included in audit logs and fetch responses
- Agent name sanitization to prevent log injection
- Structured JSON audit logging via zerolog (allowed, blocked, error, anomaly, redirect events)
- YAML configuration with validation and sensible defaults
- Config hot-reload via fsnotify file watching and SIGHUP signal (when using `--config`)
- Hot-reload panic recovery: invalid config reloads are caught and logged without crashing the proxy
- Three operating modes: strict, balanced (default), audit
- CLI commands: `run`, `check`, `generate config`, `generate docker-compose`, `logs`, `git scan-diff`, `git install-hooks`, `version`, `healthcheck`
- Config presets: `configs/balanced.yaml`, `configs/strict.yaml`, `configs/audit.yaml`
- Docker Compose generation for network-isolated agent deployments (`pipelock generate docker-compose`)
- HTML content extraction via go-readability
- Redirect following with per-hop URL scanning (max 5 redirects)
- Graceful shutdown on SIGINT/SIGTERM
- Prometheus metrics: `pipelock_requests_total`, `pipelock_scanner_hits_total`, `pipelock_request_duration_seconds`
- JSON stats endpoint: top blocked domains, scanner hits, block rate, uptime
- Build metadata injection via ldflags (version, date, commit, Go version)
- Docker support: scratch-based image (~15MB), multi-arch (amd64/arm64), GHCR via GoReleaser
- GitHub Actions CI (Go 1.24 + 1.25, race detector, vet)
- 345 tests with `-race`
