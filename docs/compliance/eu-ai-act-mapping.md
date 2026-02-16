# EU AI Act Compliance Mapping - Pipelock

How Pipelock's runtime security controls map to the [EU AI Act (Regulation 2024/1689)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ:L_202401689) requirements for high-risk AI systems, with a [NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf) crosswalk.

**Scope:** Pipelock is a runtime security layer for AI agent deployments. It covers network egress filtering, content inspection, audit logging, and human oversight. It doesn't cover model training, data governance, or full-lifecycle AI management. Coverage gaps are documented below.

**Disclaimer:** This document maps Pipelock's security features to EU AI Act requirements for informational purposes. It does not constitute legal advice or guarantee regulatory compliance. Organizations should consult qualified legal counsel for compliance obligations specific to their AI systems.

**Last updated:** v0.2.3 (February 2026)

---

## Coverage Summary

Coverage levels: **Full** = Pipelock feature directly implements the requirement with automated enforcement. **Partial** = feature contributes to the requirement but doesn't fully satisfy it alone. **Moderate** = multiple features partially address the requirement.

| Article | Topic | Coverage |
|---------|-------|----------|
| Art. 9 | Risk Management System | Partial (runtime controls only) |
| Art. 12 | Record-Keeping | Full (logging requirements) |
| Art. 13 | Transparency | Moderate |
| Art. 14 | Human Oversight | Moderate (terminal-only HITL) |
| Art. 15 | Accuracy, Robustness, Cybersecurity | Moderate |
| Art. 26 | Deployer Obligations | Moderate |

---

## EU AI Act Article Mapping

### Article 9 - Risk Management System

Article 9 requires a continuous, iterative risk management process throughout the AI system lifecycle. This includes risk identification, mitigation through design, prior-defined testing metrics, and post-market monitoring.

| Requirement | Pipelock Feature | Coverage |
|-------------|-----------------|----------|
| Identify and analyze known risks (Art. 9(2)(a)) | 9-layer scanner pipeline classifies network-level risks: scheme validation, SSRF, domain blocklist, rate limiting, DLP (inc. env leak), path entropy, subdomain entropy, URL length, data budget | Partial |
| Evaluate risks under foreseeable misuse (Art. 9(2)(b)) | Adversarial testing of bypass attempts (encoded secrets, DNS exfiltration, zero-width injection, split-key attacks) | Partial |
| Post-market monitoring data (Art. 9(2)(c)) | Prometheus metrics (`/metrics`), JSON stats (`/stats`), structured audit logs | Partial |
| Eliminate risks through design (Art. 9(5)(a)) | Capability separation eliminates network-based credential exfiltration: agent holds secrets with no network; proxy has network with no secrets | Partial |
| Mitigation and control measures (Art. 9(5)(b)) | Multi-layer scanning, domain blocklist, rate limiting, DLP patterns, HITL approval | Full |
| Residual risk information to deployers (Art. 9(5)(c)) | Audit logs document every scan decision; `/stats` endpoint surfaces top threats | Partial |
| Prior defined metrics and thresholds (Art. 9(8)) | Configurable thresholds per scanner layer; Prometheus counters for block rates by category | Full |
| Continuous lifecycle process (Art. 9(2)) | Hot-reload config (fsnotify + SIGHUP) for live policy updates without restart | Partial |

**Gap:** Art. 9 covers the full AI system lifecycle. Pipelock provides runtime network-level risk management. Lifecycle-wide risk identification (health, safety, fundamental rights impacts) and systematic misuse analysis require organizational processes beyond runtime controls.

---

### Article 12 - Record-Keeping

Article 12 requires automatic event logging in high-risk AI systems for risk identification, post-market monitoring, and deployer oversight.

| Requirement | Pipelock Feature | Coverage |
|-------------|-----------------|----------|
| Automatic recording of events (Art. 12(1)) | Structured JSON audit logging (zerolog) for every request: URL, domain, agent name, scan result, scanner reason, timestamp, duration | Full |
| Identify risk situations (Art. 12(2)(a)) | Categorized threat events: SSRF, DLP match, prompt injection, env leak, entropy anomaly, rate limit, redirect chain | Full |
| Support post-market monitoring (Art. 12(2)(b)) | Prometheus metrics with counters, histograms, and alerting integration; Grafana dashboard (`configs/grafana-dashboard.json`) | Full |
| Enable deployer monitoring (Art. 12(2)(c)) | Per-agent identification via `X-Pipelock-Agent` header; agent name in every log entry | Full |

**Gap:** None for the logging requirements Pipelock addresses. Full Art. 12 includes biometric system requirements (Art. 12(3)) that don't apply.

---

### Article 13 - Transparency

Article 13 requires sufficient operational transparency for deployers to understand system behavior, including documentation of capabilities, limitations, logging mechanisms, and human oversight measures.

| Requirement | Pipelock Feature | Coverage |
|-------------|-----------------|----------|
| System characteristics and capabilities documented | README, OWASP mapping docs, Claude Code integration guide, comparison doc | Full |
| Limitations documented | Each OWASP mapping doc includes explicit coverage gaps and "out of scope" sections | Full |
| Logging mechanism description | Audit log format, event types, and fields documented in CLAUDE.md and guides | Full |
| Human oversight measures described (Art. 14 ref) | HITL documentation in guides and config presets | Partial |
| Computational/hardware requirements | Single static binary (~12MB), documented in README | Full |

**Gap:** Full Art. 13 compliance requires system-level documentation that depends on the deployer's AI system, not just the security layer.

---

### Article 14 - Human Oversight

Article 14 requires AI systems to be designed for effective human oversight, including the ability to understand system operation, detect anomalies, override or reverse outputs, and intervene or interrupt via a "stop" mechanism.

| Requirement | Pipelock Feature | Coverage |
|-------------|-----------------|----------|
| Understand system operation (Art. 14(4)(a)) | Audit logs, Prometheus metrics, `/stats` endpoint, Grafana dashboard | Full |
| Detect anomalies and dysfunctions (Art. 14(4)(a)) | Real-time threat detection via pattern matching and entropy threshold analysis | Partial |
| Override or reverse output (Art. 14(4)(d)) | HITL `action: ask` lets the operator approve, deny, or strip on each flagged request | Full |
| Intervene or interrupt via "stop button" (Art. 14(4)(e)) | Fail-closed design: HITL timeout defaults to block; context cancellation stops operation | Full |
| Awareness of automation bias (Art. 14(4)(b)) | Configurable modes (audit/balanced/strict) force explicit enforcement decisions | Partial |
| Commensurate with risk level (Art. 14(3)) | Three preset modes map to different risk tolerances; per-scanner thresholds configurable | Full |
| Built into system by provider (Art. 14(3)) | HITL module compiled into binary; fail-closed defaults are structural, not configurable | Full |

**Gap:** HITL is terminal-only. No UI for non-terminal environments.

---

### Article 15 - Accuracy, Robustness, and Cybersecurity

Article 15 requires resilience against unauthorized alteration, with specific protections against data poisoning, model poisoning, adversarial examples (model evasion), confidentiality attacks, and model flaws (Art. 15(5)). It also requires technical redundancy and fail-safe plans (Art. 15(4)).

Note: Art. 15(5) uses "adversarial examples" and "model evasion," not "prompt injection." Pipelock's injection detection addresses a subset of the adversarial examples category through pattern-based content scanning, but doesn't cover model-level evasion attacks.

| Requirement | Pipelock Feature | Coverage |
|-------------|-----------------|----------|
| **Adversarial examples / model evasion** (Art. 15(5)) | Content scanning on responses and MCP tool results; zero-width char stripping; NFKC normalization; case-insensitive matching; null byte stripping. Covers text-based injection patterns, not model-level evasion. | Partial |
| **Confidentiality attacks** (Art. 15(5)) | DLP scanning (15 built-in credential patterns, extensible via config), env leak detection (raw + base64 + hex), Shannon entropy analysis, DNS subdomain exfiltration detection, split-key concatenation scanning | Full |
| **Data poisoning** (Art. 15(5)) | File integrity monitoring (SHA256 manifests), Ed25519 signing and verification, response scanning on fetched content | Partial |
| **Resilient against unauthorized alteration** (Art. 15(5)) | Capability separation prevents agent from being manipulated into exfiltrating data; SSRF blocks access to internal infrastructure | Full |
| **Technical redundancy / fail-safe** (Art. 15(4)) | Fail-closed architecture: scan error, HITL timeout, parse failure, DNS error, context cancellation all default to block | Full |
| **Resilient to errors and faults** (Art. 15(4)) | DNS rebinding protection (resolve-validate-dial); IPv4-mapped IPv6 normalization; CRLF normalization in diff parsing | Full |
| **Accuracy metrics declared** (Art. 15(1-3)) | Prometheus counters per scanner layer; false positive tuning via audit mode | Partial |

**Gap:** Data poisoning in Art. 15(5) refers to training data manipulation. Pipelock's integrity monitoring protects workspace files, not training datasets. Model poisoning and model flaws are out of scope.

---

### Article 26 - Deployer Obligations

Article 26 requires deployers to monitor AI system operation, keep automatically generated logs for at least 6 months, and use the system per instructions.

| Requirement | Pipelock Feature | Coverage |
|-------------|-----------------|----------|
| Monitor operation per instructions (Art. 26(1)) | Prometheus metrics, `/health` endpoint for K8s liveness probes, structured audit logs | Full |
| Keep logs for 6+ months (Art. 26(6)) | Persistent audit logs with configurable output (file, stdout, or both) | Partial |
| Use system per instructions of use (Art. 26(1)) | Config presets provide instructions for different deployment contexts | Full |

**Gap:** Pipelock writes persistent audit logs but doesn't enforce retention periods. Whether logs are kept for 6 months depends on the deployer's log infrastructure (rotation, storage, forwarding).

---

## What Pipelock Does Not Cover

These require other tools or organizational processes:

| EU AI Act Requirement | Article | Why Not Covered |
|----------------------|---------|----------------|
| Training data governance | Art. 10 | Pipelock operates at runtime, not training time |
| Conformity assessment | Art. 43 | Organizational process, not a tool feature |
| CE marking | Art. 48 | Regulatory formality |
| Technical documentation (full system) | Art. 11 | Pipelock documents itself; full system docs are the deployer's responsibility |
| Fundamental rights impact assessment | Art. 27 | Requires organizational assessment beyond runtime controls |
| EU database registration | Art. 71 | Administrative requirement |
| Incident reporting timelines | Art. 73 | Audit logs provide incident data; reporting process is organizational |
| Bias and fairness evaluation | Art. 10(2) | Pipelock applies rules uniformly but doesn't evaluate model fairness |
| Code execution sandboxing | Art. 15(4) | Pipelock controls egress, not process isolation. See [srt](https://github.com/anthropic-experimental/sandbox-runtime) or [agentsh](https://github.com/canyonroad/agentsh). |

---

## NIST AI RMF 1.0 Crosswalk

How Pipelock maps to NIST AI Risk Management Framework functions, with EU AI Act cross-references.

### GOVERN - Policies, Processes, and Accountability

| NIST Subcategory | Description | Pipelock Feature | EU AI Act |
|-----------------|-------------|-----------------|-----------|
| GOVERN 1.2 | Trustworthy AI characteristics integrated into organizational policies | Capability separation architecture; fail-closed design philosophy | Art. 9 |
| GOVERN 1.4 | Ongoing monitoring plans documented | Prometheus metrics, audit logging, Grafana dashboard | Art. 12 |
| GOVERN 2.1 | Roles and responsibilities for AI risk management | Per-agent identification (`X-Pipelock-Agent`); HITL assigns human approval responsibility | Art. 14 |
| GOVERN 4.2 | Organizational teams document AI risks and impacts | Structured audit logs, config files, OWASP mapping docs | Art. 11, 13 |
| GOVERN 6.1 | Third-party AI risks addressed in policy | MCP bidirectional scanning treats all MCP servers as untrusted; domain blocklists control external access | Art. 9, 15 |
| GOVERN 6.2 | Contingency processes for third-party risk | Fail-closed: scanning failure blocks traffic; HITL timeout blocks; MCP parse errors block | Art. 15 |

### MAP - Context, Risk Identification

| NIST Subcategory | Description | Pipelock Feature | EU AI Act |
|-----------------|-------------|-----------------|-----------|
| MAP 1.1 | Intended purposes and contexts documented | Capability separation documented; deployment guides per agent type | Art. 9, 13 |
| MAP 1.5 | Organizational risk tolerance defined | Config presets: `audit` (log only), `balanced` (default), `strict` (aggressive blocking) | Art. 9 |
| MAP 2.1 | System and potential harms classified | Scanner pipeline classifies: SSRF, DLP, injection, env leak, entropy, rate abuse | Art. 9 |
| MAP 4.1 | Risks prioritized by impact and likelihood | Pipeline ordering reflects priority: blocklist/DLP (critical) before DNS, SSRF before rate limit | Art. 9 |

### MEASURE - Metrics, Monitoring, Assessment

| NIST Subcategory | Description | Pipelock Feature | EU AI Act |
|-----------------|-------------|-----------------|-----------|
| MEASURE 1.1 | Metrics selected and documented | Prometheus: `pipelock_requests_total`, `pipelock_scanner_hits_total`, `pipelock_request_duration_seconds` | Art. 12 |
| MEASURE 2.5 | System demonstrated valid and reliable | CI: 3 required checks (test, lint, build), CodeQL analysis, 1,580+ tests with race detector | Art. 15 |
| MEASURE 2.6 | Evaluated for misuse and abuse | Scanning layers target misuse: DLP catches exfiltration, SSRF catches internal probing, injection detection catches hijacking | Art. 9, 15 |
| MEASURE 2.7 | Security and resilience evaluated | Security audit completed (26 of 32 items fixed); DNS rebinding protection; fail-closed architecture | Art. 15 |
| MEASURE 3.1 | Risks tracked on ongoing basis | Prometheus real-time tracking; zerolog persistent timeline; both queryable and alertable | Art. 12 |
| MEASURE 3.3 | Feedback mechanisms for improvement | HITL `ask` action: human decisions logged for policy refinement; audit mode measures before enforcing | Art. 14 |

### MANAGE - Risk Mitigation Controls

| NIST Subcategory | Description | Pipelock Feature | EU AI Act |
|-----------------|-------------|-----------------|-----------|
| MANAGE 1.1 | Risks mitigated, transferred, or accepted | Each scanning layer configurable: enabled (mitigate), audit-only (accept with monitoring), disabled (accept) | Art. 9 |
| MANAGE 1.3 | Risk responses documented | Every block/allow decision logged with timestamp, category, action, URL, reason | Art. 12 |
| MANAGE 2.2 | Mechanisms to disengage or deactivate | HITL override; config hot-reload to tighten controls; fail-closed timeout = safe default | Art. 14 |
| MANAGE 2.3 | Procedures for appeal and human review | HITL terminal approval: agent paused, human reviews with context, decides approve/deny/strip | Art. 14 |
| MANAGE 3.1 | Third-party AI risks managed | MCP bidirectional scanning: server responses scanned for injection, client requests scanned for DLP/injection | Art. 9, 15 |
| MANAGE 4.1 | Post-deployment monitoring with incident response | Audit logs, HITL override, hot-reload for change management, Prometheus alerts, `/health` for K8s liveness | Art. 12 |

---

## Control-Level Mapping

Mapping from individual Pipelock controls to both frameworks.

| Control | Description | EU AI Act | NIST AI RMF |
|---------|-------------|-----------|-------------|
| Capability separation | Agent has secrets, no network; proxy has network, no secrets | Art. 15(5) | GOVERN 1.2, MAP 1.1 |
| SSRF protection | Private IP blocking, DNS rebinding prevention, metadata endpoint blocking | Art. 15(4-5) | MAP 2.1, MEASURE 2.7 |
| Domain blocklist | Configurable deny/allow lists with wildcard support | Art. 9(5) | GOVERN 1.2, MANAGE 1.1 |
| Rate limiting | Per-domain sliding window, base domain normalization | Art. 15(4) | MANAGE 1.1 |
| DLP scanning | 15 built-in credential patterns, custom regex, severity classification | Art. 15(5) | GOVERN 1.2, MEASURE 2.6 |
| Env leak detection | Raw + base64 + hex, Shannon entropy > 3.0 | Art. 15(5) | MEASURE 2.6 |
| Entropy analysis | Shannon entropy on URL path segments and query parameters | Art. 15(5) | MAP 2.1 |
| Content scanning | Response scanning with zero-width stripping, NFKC, case-insensitive | Art. 15(5) | MAP 2.1, MEASURE 2.6 |
| MCP bidirectional scanning | Request DLP/injection + response injection scanning | Art. 9(5), 15(5) | GOVERN 6.1, MANAGE 3.1 |
| HITL terminal approval | Ask action, fail-closed timeout, approve/deny/strip | Art. 14(4)(d-e) | GOVERN 2.1, MANAGE 2.2, 2.3 |
| Structured audit logging | Zerolog JSON, event classification, agent attribution, log sanitization | Art. 12, 13, 26(6) | GOVERN 4.2, MEASURE 3.1, MANAGE 4.1 |
| Prometheus metrics | Custom registry, `/metrics`, `/stats`, Grafana dashboard | Art. 12, 26(1) | MEASURE 1.1, 3.1 |
| File integrity monitoring | SHA256 manifests, check/diff, glob exclusions | Art. 15(5) | MEASURE 2.7 |
| Ed25519 signing | Key management, file signing, verification, trust store | Art. 15(5) | GOVERN 1.2 |
| Config validation | Pre-load validation, mode enforcement | Art. 9(5) | GOVERN 6.2 |
| Hot-reload | fsnotify + SIGHUP, atomic config swap | Art. 9(2) | MANAGE 4.1 |
| Fail-closed defaults | Timeout/error/parse/DNS failure all block | Art. 15(4) | GOVERN 6.2 |
| Git diff scanning | Pre-push secret detection in unified diffs | Art. 15(5) | MAP 2.1 |

---

## High-Risk Classification Context

### Are AI coding agents high-risk under the EU AI Act?

AI coding agents aren't explicitly listed in [Annex III](https://artificialintelligenceact.eu/annex/3/). The eight high-risk categories cover biometrics, critical infrastructure, education, employment, essential services, law enforcement, migration, and justice administration.

Classification is context-dependent:

- An AI coding agent writing software for **medical devices or critical infrastructure** (Annex III, Category 2) could be classified as a safety component of a high-risk system.
- An agent used to **evaluate developer performance or allocate tasks** (Annex III, Category 4) could fall under employment-related high-risk classification.
- The underlying LLM likely qualifies as a **general-purpose AI model** under [Articles 51-55](https://artificialintelligenceact.eu/article/51/), with additional obligations if it has systemic risk (>10^25 FLOPs training compute).
- [Article 7](https://artificialintelligenceact.eu/article/7/) allows the Commission to expand Annex III categories via delegated acts. Agentic AI with autonomous action capabilities is actively discussed.

AI coding agents aren't formally high-risk in most cases. But organizations in regulated sectors may still choose to comply with Articles 9, 12-15 as a risk management best practice and to demonstrate due diligence.

---

## Enforcement Timeline

| Date | Milestone |
|------|-----------|
| August 1, 2024 | EU AI Act enters into force |
| February 2, 2025 | Prohibited AI practices (Art. 5) and AI literacy (Art. 4) take effect |
| August 2, 2025 | GPAI model obligations (Art. 51-55) take effect |
| February 2, 2026 | Commission publishes high-risk classification guidelines (Art. 6) |
| **August 2, 2026** | **High-risk AI system requirements take effect (Art. 9, 12-15, 26)** |
| August 2, 2027 | Extended transition for safety-component AI under Annex I harmonization legislation |

Penalties: up to EUR 35M or 7% global turnover (prohibited practices), EUR 15M or 3% (high-risk system violations), EUR 7.5M or 1% (misleading information to authorities). SME/startup fines capped at the lower of percentage or absolute amount.

---

## Related Frameworks

This document complements Pipelock's existing security framework mappings:

- **[OWASP Top 10 for Agentic Applications](../owasp-mapping.md)** - ASI01-ASI10 coverage (3 Strong, 3 Moderate, 4 Partial)
- **[OWASP Agentic AI Threats & Mitigations](../owasp-agentic-top15-mapping.md)** - T1-T15 coverage (7 Strong, 2 Moderate, 3 Partial)
- **[Competitive Comparison](../comparison.md)** - Feature matrix vs AIP, agentsh, srt

### OWASP → EU AI Act Compliance Chain

OWASP has an [official liaison partnership](https://owasp.org/blog/2025/05/06/AI-Exchage-Regulation) with CEN/CENELEC and ISO. The OWASP AI Exchange contributed 70 pages to [ISO/IEC 27090](https://www.iso.org/standard/56581.html) (the global AI security standard) and 40 pages to [prEN 18282](https://digital-strategy.ec.europa.eu/en/policies/ai-act-standardisation), the European cybersecurity standard for AI systems being developed under the EU AI Act. When prEN 18282 is published as a harmonized standard, compliance with it will provide a "presumption of conformity" with the relevant AI Act provisions.

Pipelock's existing OWASP mapping documents demonstrate alignment with frameworks that are being written into the EU's harmonized standards. Pipelock is one component of a defense-in-depth approach, not a complete compliance solution.

### NIST AI 600-1 - Generative AI Risk Profile

Six of twelve GAI-specific risks in [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) map to Pipelock controls:

| GAI Risk | Pipelock Feature |
|----------|-----------------|
| Data Privacy | DLP scanning, env leak detection, entropy analysis |
| Information Security | SSRF protection, rate limiting, capability separation |
| Information Integrity | Content scanning, MCP response scanning |
| Human-AI Configuration | HITL approval, fail-closed defaults |
| Confabulation (tangential) | Response scanning catches manipulated content; doesn't detect hallucinations |
| CBRN Information (partial) | Domain blocklist restricts access to dangerous content sources |

### NIST CAISI - AI Agent Security

In January 2026, NIST's Center for AI Standards and Innovation published a [Request for Information](https://www.federalregister.gov/documents/2026/01/08/2026-00206/request-for-information-regarding-security-considerations-for-artificial-intelligence-agents) on security considerations for AI agents. The RFI topics (agent hijacking, backdoor attacks, exploits of autonomous agents) align directly with Pipelock's scanner pipeline and OWASP threat mappings. Comment deadline: March 9, 2026.

---

## Sources

### EU AI Act
- [Full text (EUR-Lex)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ:L_202401689)
- [Article 9: Risk Management](https://artificialintelligenceact.eu/article/9/)
- [Article 12: Record-Keeping](https://artificialintelligenceact.eu/article/12/)
- [Article 13: Transparency](https://artificialintelligenceact.eu/article/13/)
- [Article 14: Human Oversight](https://artificialintelligenceact.eu/article/14/)
- [Article 15: Accuracy, Robustness, Cybersecurity](https://artificialintelligenceact.eu/article/15/)
- [Article 26: Deployer Obligations](https://artificialintelligenceact.eu/article/26/)
- [Annex III: High-Risk AI Systems](https://artificialintelligenceact.eu/annex/3/)
- [Implementation Timeline](https://artificialintelligenceact.eu/implementation-timeline/)

### NIST
- [AI RMF 1.0 (PDF)](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf)
- [AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/)
- [AI 600-1: Generative AI Risk Profile (PDF)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [SP 800-218A: Secure Software Development Practices for Generative AI and Dual-Use Foundation Models (PDF)](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [CAISI RFI: AI Agent Security (Federal Register)](https://www.federalregister.gov/documents/2026/01/08/2026-00206/request-for-information-regarding-security-considerations-for-artificial-intelligence-agents)

### OWASP
- [OWASP AI Exchange](https://owaspai.org/)
- [Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Agentic AI Threats & Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP-CEN/CENELEC Liaison](https://owasp.org/blog/2025/05/06/AI-Exchage-Regulation)
