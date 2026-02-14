---
layout: post
title: "283 ClawHub Skills Are Leaking Your Secrets. VirusTotal Can't Fix This."
date: 2026-02-09
author: luckyPipewrench
description: "Snyk found 283 ClawHub skills leaking API keys and passwords through the LLM context window. VirusTotal's static scanning can't catch runtime exfiltration. Here's what can."
---

[Snyk just published research](https://snyk.io/blog/openclaw-skills-credential-leaks-research/) showing that 283 out of 3,984 ClawHub skills, roughly 7.1% of the entire registry, contain critical security flaws that expose API keys, passwords, and even credit card numbers through the LLM context window.

These aren't malware. They're functional, popular skills that work exactly as designed. The problem is the design itself.

## What Snyk Found

The research identified four categories of credential leaks in real ClawHub skills:

**The verbatim output trap.** Skills like moltyverse-email tell the agent to save an API key to memory and share inbox URLs containing the key with the user. The LLM is explicitly instructed to output the secret. Ask the agent "what did you just do?" and it tells you the key in plaintext.

**Financial data in the context window.** The buy-anything skill collects credit card numbers and CVC codes, embedding them in curl commands. The raw financial data gets tokenized by the model provider and exists in verbose logs. A prompt injection could trivially extract it later.

**Log leakage.** Skills like prompt-log export session files without redaction. If the agent previously handled a secret, that secret now lives in a shareable markdown artifact.

**Plaintext storage.** Skills that tell agents to "save the API key in memory" are placing credentials in MEMORY.md or similar files. These are exactly the files that malicious skills target for exfiltration.

## OpenClaw's Response

OpenClaw [announced a partnership with VirusTotal](https://thehackernews.com/2026/02/openclaw-integrates-virustotal-scanning.html) to scan all skills uploaded to ClawHub. Every skill gets a SHA-256 hash checked against VirusTotal's database and analyzed by their [Code Insight](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html) capability, which uses AI to evaluate code behavior. Suspicious skills get flagged. Malicious ones get blocked. Active skills are re-scanned daily.

This is a good move. But OpenClaw maintainers themselves [said it](https://thehackernews.com/2026/02/openclaw-integrates-virustotal-scanning.html): VirusTotal scanning is "not a silver bullet."

Here's what that means in practice.

## Static Scanning Can't Catch Runtime Exfiltration

VirusTotal, [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan), and tools like Snyk's Evo Agent Security Analyzer look at skill files before they run. They catch known malware patterns, prompt injection payloads, and suspicious code. That's the "before" problem, and it matters. Researchers have already identified [hundreds of deliberately malicious skills](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) designed for credential theft and data exfiltration.

But the Snyk research describes a different problem. These 283 skills aren't malicious in the traditional sense. They're poorly designed tools that handle secrets incorrectly at runtime. No static scanner, even one powered by AI code analysis, can predict every way an agent might leak a secret while executing a legitimate task.

Say an agent uses a legitimate API skill and makes a request with your key embedded in the URL:

```bash
curl "https://api.service.com/v1/data?key=sk-ant-api03-REAL-KEY-HERE"
```

Or worse: the agent stores your API key in its memory file, and a different skill reads that file and sends it to an external server. Neither skill is malicious on its own. The leak only happens at runtime when both execute in sequence.

## What Runtime Protection Looks Like

You need something inspecting what actually leaves your machine while the agent is running. Not before. During.

I built [Pipelock](https://github.com/luckyPipewrench/pipelock) for exactly this. It's early-stage but functional: a security harness that sits between your agent and the internet as a proxy, running a 9-layer scanner pipeline on every outbound request:

1. **Scheme validation** enforces http/https only
2. **SSRF protection** blocks requests to internal IPs and catches DNS rebinding
3. **Domain blocklist** blocks known exfiltration targets like pastebin and transfer.sh
4. **Rate limiting** catches unusual bursts of requests to new domains
5. **DLP pattern matching** detects API key formats (Anthropic, OpenAI, AWS, GitHub tokens) in URLs, plus env variable leak detection
6. **Path entropy analysis** flags high-entropy strings that look like encoded or encrypted secrets
7. **Subdomain entropy analysis** catches secrets split across DNS subdomains
8. **URL length limits** catch unusually long URLs that suggest data exfiltration
9. **Data budget enforcement** per-domain byte limits prevent slow-drip exfiltration

Pipelock also uses capability separation. The process that has your secrets (the agent) is network-restricted. A separate fetch proxy process (which has no secrets) handles internet access. In Docker Compose mode, the agent literally cannot reach the internet except through the proxy, making direct secret exfiltration impossible.

When Pipelock catches something, it takes one of four actions depending on your config: **block** the request entirely, **strip** the matched pattern and forward the cleaned request, **warn** by logging the detection and passing through, or **ask** with a terminal prompt that lets you approve, deny, or strip in real time.

The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) identifies these classes of risk, covering insecure output handling and excessive agent capabilities. Pipelock's [OWASP mapping](https://github.com/luckyPipewrench/pipelock/blob/main/docs/owasp-mapping.md) covers all 10 threats.

## Defense in Depth

This isn't either/or. You want both layers:

**Before install:** Use VirusTotal scanning, [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan), or Snyk's tools to catch known malware and suspicious patterns in skill files.

**At runtime:** Use an egress proxy like Pipelock to catch credential leaks, secret exfiltration, and prompt injection in real time.

Static scanning catches the [hundreds of known-malicious skills](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) that researchers have identified. Runtime scanning catches the 283 "leaky" skills that Snyk found, plus whatever comes next.

## Try It

Pipelock is open source and takes about a minute to set up:

```bash
# Install
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

# Or Homebrew
brew install luckyPipewrench/tap/pipelock

# Generate config and start
pipelock generate config --preset balanced -o pipelock.yaml
pipelock run --config pipelock.yaml
```

Demo: [asciinema.org/a/I1UzzECkeCBx6p42](https://asciinema.org/a/I1UzzECkeCBx6p42)

OWASP Agentic Top 10 mapping: [docs/owasp-mapping.md](https://github.com/luckyPipewrench/pipelock/blob/main/docs/owasp-mapping.md)

Repo: [github.com/luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock)

---

*Pipelock is open source (Apache 2.0). 1,300+ tests, 94%+ coverage. Single static binary.*
