# Bypass Resistance

This page documents the evasion techniques pipelock handles and the ones it doesn't. Security reviewers: this is the honest picture.

## How Scanning Works

Every URL, tool argument, and response passes through a multi-layer pipeline. The order matters: DLP runs before DNS resolution (so secrets can't leak via DNS queries), and SSRF checks run after (so private IP detection works on resolved addresses).

Response scanning uses a 6-pass normalization pipeline. Each pass catches a different evasion class.

## Encoding Evasion

These techniques hide secrets or injection payloads inside encoded data.

| Technique | Example | Status | How |
|-----------|---------|--------|-----|
| Base64 (standard + URL-safe) | `c2stYW50LWFwaTA=` | Tested | Tries 4 base64 variants on every segment > 10 chars |
| Base32 | `ONQW2YLUMVWGY3DP` | Tested | Decoded and re-checked against DLP |
| Hex encoding | `736b2d616e742d` | Tested | Hex-decoded, case-insensitive |
| Delimiter-separated hex | `73:6b:2d:61:6e:74` | Tested | Strips 6 delimiter formats (`:`, `-`, ` `, `,`, `\x` prefix, `0x` prefix) before hex decode |
| URL encoding (multi-layer) | `%25%32%44` (5-10 layers deep) | Tested | `IterativeDecode()` runs up to 500 rounds |
| Mixed encoding chains | `base64(hex("secret"))` | Tested | Each layer decoded, re-normalized, re-checked |
| Field-split encoding | Secret spread across `?a=sk-&b=ant-&c=api03` | Tested | Query subsequence matching (ordered 2-4 param combos) |

## Unicode Evasion

These techniques use Unicode characters to break pattern matching.

| Technique | Example | Status | How |
|-----------|---------|----------|-----|
| Zero-width characters | `sk\u200b-ant` (ZW space in key) | Tested | 16 Unicode ranges stripped before matching |
| NFKC normalization bypass | `ﬁle` (fi ligature) | Tested | NFKC decomposition applied to all scanned text |
| Homoglyphs (Cyrillic) | `аpi_kеy` (Cyrillic a and e) | Tested | 80+ confusable character mappings |
| Homoglyphs (Greek/Armenian/Cherokee) | `αpi`, `օverride` | Tested | Extended confusable map covers major scripts |
| Combining marks | `e\u0306` (e + combining breve) | Tested | NFD decomposition then mark stripping |
| Control characters | `sk\x00-ant` (null byte) | Tested | C0, C1, DEL all stripped before matching |
| Leetspeak | `1GN0R3 4LL` | Tested | Digit-to-letter folding (response scanning) |
| Vowel substitution | `instrocktoons` | Tested | Vowel folding pass in response scanning |
| Regional indicators / emoji | Boxed letters, flag sequences | Tested | Stripped by zero-width/variation selector removal |
| Exotic whitespace | `\u00A0`, `\u2000`-`\u200A`, `\u3000`, etc. | Tested | `StripExoticWhitespace` removes 18 Unicode space codepoints before DLP matching |
| Zalgo text | `t̷̺̀e̸̜̅s̵̲̈́t̵̙̅` (stacked combining marks) | Tested | `StripCombiningMarks` removes all marks; `ZalgoDensity` detects 3+ consecutive marks as suspicious for taint signaling |

## DNS-Based Exfiltration

These techniques leak data through DNS queries rather than HTTP bodies.

| Technique | Example | Status | How |
|-----------|---------|----------|-----|
| Secret in subdomain | `aGVsbG8.evil.com` | Tested | Subdomain entropy check + DLP on hostname, pre-DNS |
| Secret split across labels | `sk-ant.AABB.CCDD.evil.com` | Tested | Dots stripped, labels concatenated before DLP |
| High-entropy subdomains | `jk3n4k5n.evil.com` | Tested | Shannon entropy > 4.0 on labels > 8 chars |
| Subdomain rotation | `a.evil.com`, `b.evil.com`, `c.evil.com` | Tested | Rate limiting on base domain (last 2 labels) |

**Key design choice:** DLP and subdomain entropy run at layers 3-4, before DNS resolution at layer 6. This means secrets are caught before any DNS query leaves the proxy.

## Slow/Chunked Exfiltration

These techniques exfiltrate data in small pieces over time.

| Technique | Example | Status | How |
|-----------|---------|----------|-----|
| Many small requests | 1 byte per request, 1000 requests | Tested | Per-domain rate limiting (default 60/min) |
| Data budget exhaustion | Stay under rate limit, send lots of data | Tested | Per-domain byte budget (sliding 60-second window) |
| Subdomain rotation for rate bypass | Different subdomains to reset counters | Tested | Rate limit keyed on base domain, not full hostname |
| Query parameter splitting | `?a=sk-&b=ant-&c=api03` across params | Tested | Ordered query subsequence matching (O(n^4), capped at 20 params) |
| Path segment splitting | `/sk-/ant-/api03/AAAA/evil.com` | Tested | Noise stripping + ordered concatenation |

## Prompt Injection Evasion

These techniques hide injection payloads in fetched content or MCP tool results.

| Technique | Example | Status | How |
|-----------|---------|----------|-----|
| Basic injection | "Ignore all previous instructions" | Tested | 25 built-in patterns, case-insensitive |
| Zero-width splitting | `ignore\u200ball\u200bprevious` | Tested | Pass 1: strip ZW chars |
| Word boundary collapse | Words merged after ZW removal | Tested | Pass 2: replace invisible with space, re-scan |
| Leetspeak substitution | `1GN0R3 4LL PR3V10US` | Tested | Pass 3: digit-to-letter folding |
| No-space concatenation | `ignoreallpreviousinstructions` | Tested | Pass 4: optional-whitespace pattern variants |
| Vowel confusion | `instrocktoons` | Tested | Pass 5: vowel folding (a,e,i,o,u mapped to same char) |
| Encoded injection | `base64("ignore all previous")` | Tested | Pass 6: base64/hex decode, re-normalize, re-scan |
| Homoglyph injection | `іgnore` (Cyrillic і) | Tested | Confusable mapping in normalization pipeline |

## MCP-Specific Evasion

These techniques target the MCP proxy layer.

| Technique | Example | Status | How |
|-----------|---------|----------|-----|
| Tool description poisoning | Injection in tool description text | Tested | Description scanned through response pipeline |
| Rug-pull (mid-session drift) | Tool description changes after first `tools/list` | Tested | SHA256 hash baseline per session |
| Cross-tool injection | Tool A result injected into Tool B input | Tested | All text extracted from results and scanned |
| Encoded payload in tool result | `base64("override system prompt")` in result | Tested | Decoded and re-scanned |
| Shell obfuscation in args | `r\m -rf`, `${IFS}-rf`, `$'\x6d'` | Tested | Shell escape decoding before policy matching |
| Unknown tool execution | Server returns tools not in initial inventory | Tested | Session binding validates against baseline |
| JSON key exfiltration | Secret encoded as JSON object key | Tested | Both keys and values extracted from JSON |
| Batch response poisoning | N clean + 1 injected response in batch | Tested | Each batch element scanned individually |

## Request Body and Header Evasion

These techniques try to exfiltrate secrets through request bodies or headers instead of URLs.

| Technique | Example | Status | How |
|-----------|---------|--------|-----|
| Secret in POST body (JSON) | `{"key": "sk-ant-..."}` | Tested | Recursive JSON string extraction, DLP scan per field + joined |
| Secret in JSON object key | `{"AKIA1234...": "value"}` | Tested | Both keys and values extracted from JSON |
| Secret in form field | `token=sk-ant-...` | Tested | Form-urlencoded parsed, keys + values scanned |
| Secret in multipart field | File upload form with secret in any part body | Tested | All multipart part bodies are scanned regardless of declared `Content-Type` |
| Secret in multipart filename | `Content-Disposition: ...; filename="sk-ant-..."` | Tested | Filenames extracted and scanned; oversized filenames blocked |
| Secret in custom multipart header | `X-Part-Token: sk-ant-...` on a part | Tested | Custom multipart part headers are extracted and scanned |
| Transfer-encoding bypass | Base64 or quoted-printable secret in a part body | Tested | Multipart `Content-Transfer-Encoding` is decoded before scanning |
| Content-Type spoofing | JSON body sent as `application/octet-stream` | Tested | Unknown types get fallback raw-text scan (never skipped) |
| Compressed body bypass | gzip-encoded body to evade regex matching | Tested | Any non-identity Content-Encoding is fail-closed blocked |
| Split secret across headers | `X-A: sk-ant-` + `X-B: api03-rest` | Tested | Joined scan concatenates all scanned header values |
| Split secret across name:value | `X-AKIA1234: EXAMPLE` | Tested | Header name + value concatenated and scanned (all mode) |
| Secret in Authorization header | `Bearer sk-ant-...` to allowlisted host | Tested | Headers scanned regardless of destination (no allowlist skip) |
| Malformed form body | Invalid urlencoded to trigger raw fallback | Tested | Fail-closed block on parse error (prevents parser differential) |
| Multipart boundary omission | `multipart/form-data` without boundary | Tested | Fail-closed block (missing boundary) |

**Scope note:** Request body and header scanning applies to forward HTTP proxy (absolute-URI requests), fetch handler headers, and intercepted CONNECT tunnels (when `tls_interception.enabled` is true). Unintercepted CONNECT tunnels carry TLS-encrypted traffic where bodies and headers are not visible.

## Cross-Request Exfiltration

These techniques spread secret data across multiple independent requests to stay below per-request detection thresholds.

| Technique | Variant | Status | How |
|-----------|---------|--------|-----|
| Split secret across requests | A: one piece per URL/body/payload, separate requests | Tested | Fragment reassembly buffers outbound payloads (URLs, request bodies, MCP JSON-RPC payloads, WebSocket frames) per session, re-scans concatenated content against DLP |
| Encode-then-split | B: base64 the secret, split the encoded form | Tested | Fragment buffer decodes reassembled content through the same multi-encoding pipeline as single-request DLP |
| Low-entropy drip | C1: small pieces that individually look benign | Tested | Entropy budget tracks cumulative Shannon entropy per session across a sliding window. Exceeding the budget triggers the configured action. |
| Covert channel exfiltration | C2: timing, header ordering, HTTP/2 frame flags | Not covered | These channels carry bits outside the URL/body content layer. Detecting them requires protocol-level analysis beyond content inspection. Documented gap. |

**Two detection mechanisms:**

- **Entropy budget:** tracks the cumulative information content (Shannon entropy bits) of all outbound payloads (URLs, request bodies, MCP JSON-RPC payloads, WebSocket frames) per session within a sliding time window. When total bits exceed the configured threshold (`bits_per_window`), the request triggers the configured action. This catches slow-drip exfiltration where each individual request looks clean.

- **Fragment reassembly:** buffers outbound payloads (URLs, request bodies, MCP JSON-RPC payloads, WebSocket frames) per session using two independent streams: one for query parameter values, bare tokens, and body content, and another for query parameter names. Both streams are re-scanned against DLP patterns on every request (synchronous, pre-forward). When a concatenated buffer matches a DLP pattern, the completing request triggers the configured CEE action before it leaves. Buffer size is capped per session to prevent memory exhaustion.

**Corroboration with adaptive enforcement:** Both entropy budget and fragment DLP hits feed into the per-session adaptive enforcement score. An agent that triggers both signals (high cumulative entropy AND a fragment DLP match) escalates faster than one triggering either alone. This stacking makes it harder for an attacker to stay below all thresholds simultaneously.

**Coverage gap:** Cross-request detection scans all outbound content visible to the proxy: URLs, request bodies, MCP JSON-RPC payloads, and WebSocket frames. For CONNECT tunnels without TLS interception, only the target hostname is visible (not the request body or path). Enable `tls_interception.enabled: true` to get full cross-request coverage on CONNECT traffic.

## Media and SVG Evasion

These techniques use media responses or SVG content to deliver payloads.

| Technique | Example | Status | How |
|-----------|---------|--------|-----|
| EXIF metadata exfiltration | Secret in JPEG EXIF comment field | Tested | JPEG APP1/APP2/APP13 segments stripped; PNG tEXt/iTXt/zTXt/eXIf chunks stripped |
| SVG foreignObject injection | `<foreignObject>` with embedded HTML instructions | Tested | All `<foreignObject>` elements removed (including namespace-prefixed) |
| SVG event handler injection | `<rect onload="fetch('evil.com')">` | Tested | All `on*` attributes stripped from SVG elements |
| SVG external reference | `<use xlink:href="https://evil.com/x.svg">` | Tested | External `xlink:href` and `href` references neutralized; local `#id` references preserved |
| SVG hidden text injection | `<text style="opacity:0">injection payload</text>` | Tested | Hidden text elements with `opacity:0`, `display:none`, or `visibility:hidden` stripped |
| SVG script injection | `<script>evil()</script>` in SVG | Tested | Script blocks stripped by browser shield SVG pipeline |
| SVG animation injection | `<set attributeName="href" to="evil.com">` | Tested | Animation elements targeting href attributes stripped |
| Audio/video as injection carrier | Prompt injection via ASR transcription of audio | Mitigated | Audio and video responses stripped by default (`strip_audio: true`, `strip_video: true`) |
| Decompression bomb | 1KB compressed image expands to 10GB | Tested | `max_image_bytes` enforced before any parsing (default 5 MiB) |
| SVG as image bypass | Serve SVG as `image/svg+xml` to bypass image-specific scanning | Tested | `image/svg+xml` rejected from `allowed_image_types`; SVG routed to browser shield pipeline |

## Known Limitations

These are things pipelock does not protect against. If your threat model includes these, you need additional controls.

### Out of Scope

| Limitation | Why | Mitigation |
|------------|-----|------------|
| **Process-level attacks** | Pipelock is a network proxy, not a sandbox. If the agent can exec arbitrary processes, those processes can bypass the proxy. | Pair with an OS sandbox (Docker, gVisor, Firecracker). See [comparison](comparison.md). |
| **Non-HTTP exfiltration** | Agent writes to cloud-synced folder, clipboard, stdout, or subprocess that doesn't use the proxy. | Container network isolation (see [deployment recipes](guides/deployment-recipes.md)). |
| **Model compromise** | If the model itself is fine-tuned to be malicious, pipelock can't distinguish legitimate from malicious intent. | Defense in depth. Pipelock catches the network-visible symptoms. |
| **Steganography (pixel-level)** | Data hidden in image pixels, timing channels, or LSBs of audio/video. | Beyond content inspection. Requires specialized analysis. Media policy strips EXIF/XMP/IPTC/ICC metadata from JPEG and text/eXIf chunks from PNG (eliminating metadata-based steganography), but pixel-level encoding remains out of scope. |

### Architectural Limits

| Limitation | Detail | Impact |
|------------|--------|--------|
| **Regex-based injection detection** | Injection patterns are syntactic, not semantic. An LLM-crafted injection that doesn't match known patterns will pass. | Add custom patterns for your domain. Future: pluggable detector interface. |
| **CONNECT tunnel body blindness** | Without TLS interception, CONNECT tunnels carry end-to-end TLS where pipelock only sees the hostname. | Enable `tls_interception.enabled: true` to decrypt, scan, and re-encrypt tunnel traffic. Bodies, headers, and responses are fully scanned. Domains that pin certificates can be excluded via `passthrough_domains`. |
| **DNS rebinding TOCTOU** | Hostname resolves to public IP at scan time, then to internal IP at connect time. Classic time-of-check/time-of-use race. | DNS pinning mitigates most cases. For high-security: use strict mode (allowlist only). |
| **Very slow exfiltration** | 1 byte per hour over days. Below any practical rate limit or entropy threshold. | Container isolation prevents this entirely. Without isolation, this is the residual risk. |
| **ReDoS in custom patterns** | User-supplied DLP or response patterns could have catastrophic backtracking. Built-in patterns are tested, but custom ones aren't analyzed for ReDoS. | Test custom patterns before deploying. |
| **HITL approval flooding** | Attacker generates many HITL prompts to overwhelm the human reviewer. | Use `block` action instead of `ask` in unattended environments. |

### Operational Risks

| Risk | Detail | Mitigation |
|------|--------|------------|
| **Misconfiguration** | Audit mode logs but doesn't block. If an operator forgets to switch to balanced/strict, nothing is enforced. | Start with balanced mode. Use `pipelock audit .` to generate a config tuned for your project. |
| **Agent identity spoofing** | Any process that can reach pipelock can claim any agent name via `X-Pipelock-Agent` header or `?agent=` query param. | Use listener binding (dedicated ports per agent) for spoof-proof identity. Header/query methods trust the caller. Network isolation adds defense in depth. |
| **IPv6 bypass** | If `internal` CIDR list doesn't include IPv6 ranges, agents could reach internal services via IPv6. Zone IDs (e.g. `::1%eth0`) could bypass `net.ParseIP` if not stripped. | Default config includes `::1/128`, `fc00::/7`, `fe80::/10`, `224.0.0.0/4` (IPv4 multicast), `ff00::/8` (IPv6 multicast). Zone IDs are stripped before IP parsing. |
| **MCP confused deputy** | A malicious MCP server sends JSON-RPC responses with IDs the client never used, hijacking the agent's execution flow. | Response ID validation tracks outbound request IDs and rejects unsolicited responses. One-shot consumption prevents replay. |

## Testing Your Setup

Pipelock ships with built-in test vectors. After configuring, verify:

```bash
# Should be BLOCKED (DLP catches the fake key)
pipelock check --config pipelock.yaml --url "https://example.com/?key=sk-ant-api03-fake1234567890"

# Should be BLOCKED (domain blocklist)
pipelock check --config pipelock.yaml --url "https://pastebin.com/raw/abc123"

# Should be ALLOWED (clean URL)
pipelock check --config pipelock.yaml --url "https://docs.python.org/3/"

# Validate scanning coverage with test vectors
pipelock test --config pipelock.yaml --fail-on-gap
```

For production deployments, also test from within your isolation layer (Docker, K8s, iptables) to verify the agent cannot bypass pipelock entirely.
