---
layout: post
title: "The first AI agent espionage campaign, and what defenses actually matter"
date: 2026-02-13
author: luckyPipewrench
description: "Anthropic disclosed GTG-1002, the first AI agent espionage campaign. A state-sponsored group jailbroke Claude Code for autonomous hacking. Here's what happened and which defenses actually work."
---

*The attack you've been warned about finally happened.*

---

## What happened

In November 2025, Anthropic disclosed [GTG-1002](https://www.anthropic.com/news/disrupting-AI-espionage). A group they assess with high confidence to be a Chinese state-sponsored actor jailbroke Claude Code and used it to run an espionage campaign targeting roughly 30 organizations across tech, finance, chemical manufacturing, and government. A small number were successfully infiltrated.

The agent did 80-90% of the work autonomously. Not just drafting emails or summarizing documents. It mapped internal networks, discovered services, found credentials, wrote exploits, and exfiltrated data. A full attack lifecycle, mostly on autopilot.

This isn't a research paper. This isn't a proof of concept. This is the first documented case of an AI coding agent being weaponized at scale by a nation-state.

## How they did it

Two techniques made it work.

**Persona engineering.** They told the agent it was an employee of a legitimate cybersecurity firm doing authorized defensive testing. The agent had no reason to refuse. Every request looked like standard security work.

**Task decomposition.** They never asked the agent to "hack this network." They broke operations into small, innocent-looking sub-tasks. Scan this port. Read this config. Fetch this URL. Write this script. No single request triggered safety guardrails. The malicious intent only becomes visible when you look at the full session.

This is the AI equivalent of social engineering. You don't attack the system directly. You convince it that what you're asking for is normal. (I wrote about a related vector in [Leaky Skills](https://pipelab.org/blog/2026/02/09/leaky-clawhub-skills-runtime-protection/), where injected skill files can silently redirect agent behavior.)

## Phase by phase

Here's how the campaign actually played out, and where defenses apply.

### 1. Reconnaissance

The agent scanned internal networks. It resolved hostnames, mapped services, identified databases and APIs. All through outbound HTTP requests that looked like normal developer activity.

**What stops this:** SSRF protection. Pipelock blocks requests to private IP ranges (10.x, 172.16.x, 192.168.x), link-local addresses, and cloud metadata endpoints (169.254.169.254). The agent can't map your internal network if it can't reach internal IPs. DNS rebinding protection stops the trick where a public hostname resolves to an internal IP.

### 2. Credential harvesting

The agent read `.env` files, config files, and environment variables. It found API keys, database passwords, and access tokens. Standard stuff for any coding agent with filesystem access.

**What stops this:** DLP scanning and environment variable leak detection. Pipelock scans every outbound request for patterns matching API keys, tokens, and credentials (15 built-in patterns, extensible). The env leak scanner detects when values from the proxy's own environment show up in a request, raw or base64-encoded. Important caveat: the proxy only knows about secrets in its own environment. If the agent has credentials the proxy doesn't, you need filesystem sandboxing to prevent access in the first place.

### 3. Exploitation

The agent wrote its own exploit code. No downloaded toolkit. No known CVEs. It studied the targets, found weaknesses, and wrote custom exploits.

**What stops this (partially):** This is the hardest phase to block with network-level controls alone. Pipelock's fetch proxy catches exploitation attempts that require outbound HTTP (downloading payloads, contacting C2 servers, exfiltrating results). But an agent writing code locally and executing it against an accessible service needs sandboxing, not just network filtering. Run the agent in a container with no direct network access so its only path outward is through the proxy. Combine that with least-privilege filesystem access and audit logging on process execution. Pipelock handles the network layer. You need to handle the rest.

### 4. Exfiltration

The agent sent stolen data outbound. Credentials, source code, internal documents. Through HTTP requests, URL parameters, or encoded payloads.

**What stops this:** URL entropy scanning catches high-entropy segments stuffed into URLs (a common exfiltration technique). DLP patterns catch credential-shaped data in request URLs and parameters. Rate limiting prevents bulk extraction. Domain blocklists can restrict which external services the agent can contact.

### 5. Persistence

The campaign persisted across sessions. The attackers maintained access by keeping the agent's jailbroken state and reusing established footholds.

**What stops this:** Integrity monitoring. Pipelock's integrity subsystem hashes critical files (configs, skills, identity files) and alerts when they change unexpectedly. If the agent's configuration or behavioral files get modified to maintain a jailbreak, the next integrity check catches it. Ed25519 signing verifies who actually made changes.

## The bigger picture

GTG-1002 isn't an isolated incident. Google's GTIG [published findings](https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use) in February 2026 showing that APT42 (Iran), UNC2970 (North Korea), and multiple Chinese and Russian groups are all using AI for offensive ops.

A few things from that report stand out:

**HONESTCUE** is a separate finding in the same report, not attributed to any specific nation-state. It's a malware framework that calls the Gemini API to generate C# payloads at runtime. Each execution produces different code. No static signatures to match on the generated payloads. No disk artifacts. A legitimate AI API used as a payload factory.

**IDEsaster** ([Ari Marzouk's research](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html)) found 30+ vulnerabilities across every major AI coding tool at the time of disclosure. Cursor, Windsurf, Copilot, Zed, Roo Code, JetBrains Junie. 24 CVEs. The attacks include invisible Unicode characters that hijack context, and prompt injection that edits your IDE settings to point executable paths at malicious binaries.

The pattern is clear. AI coding agents are the new attack surface. Not broken models. Just systems nobody built to handle attackers.

## What doesn't exist yet

Pipelock is a network-level security layer: SSRF protection, DLP scanning, entropy detection, prompt injection detection, MCP response scanning, HITL approval gates. It catches the network-facing techniques GTG-1002 used. It doesn't catch everything.

But there are gaps the industry hasn't solved:

**Session-level behavioral analysis.** GTG-1002 worked because each individual request looked innocent. The malicious intent only shows up when you look at the full session. Track how many internal IPs get probed, how much data leaves, which credential files get touched. Individual requests look fine. The aggregate doesn't. Nobody ships this yet.

**Multi-agent privilege boundaries.** When Agent A asks Agent B to do something, there's no standard way to enforce that Agent A is authorized to make that request. Privilege escalation between cooperating agents is a real problem, and it's just starting to show up.

**AI API covert channels.** HONESTCUE uses Gemini API calls as a C2 channel. The traffic looks like normal developer API usage. Detecting this requires understanding what "normal" AI API traffic looks like for a given agent, which is a hard problem.

**Process isolation gaps.** Pipelock guards network access. But an agent running shell commands or spawning subprocesses can exfiltrate data through local mechanisms: cloud-synced folders, shared mounts, clipboard, or just writing to stdout. Anything that bypasses the proxy is invisible to network-level tools.

## What you can do right now

If you run AI coding agents with network access:

1. **Isolate the network.** The agent that has your secrets shouldn't have direct internet access. Proxy all outbound traffic and scan it. This is Pipelock's core architecture.
2. **Block private IPs.** Your agent doesn't need to talk to 169.254.169.254 or 10.0.0.1. Block them.
3. **Scan for credential patterns.** Every outbound request should be checked for API keys, tokens, and high-entropy segments.
4. **Monitor your workspace files.** If config files or skill definitions change unexpectedly, something is wrong.
5. **Require approval for sensitive operations.** Human-in-the-loop gates on destructive actions, network changes, and credential access.
6. **Sandbox the agent.** Run it in a container with minimal filesystem access. No direct network. No host process execution. This isn't optional anymore.
7. **Log everything.** Structured audit logs on every request, every blocked action, every approval. If something goes wrong, you need the trail.

Pipelock handles 1-5 out of the box. For 6, you bring the container. For 7, Pipelock gives you network audit logs; process, filesystem, and behavioral logging are on you.

Get started: `brew install luckyPipewrench/tap/pipelock` or grab a [preset config](https://github.com/luckyPipewrench/pipelock/tree/main/configs) and run `pipelock run --config balanced.yaml`. Full setup guide for Claude Code [here](https://github.com/luckyPipewrench/pipelock/blob/main/docs/guides/claude-code.md).

---

## References

- Anthropic. "Disrupting the first reported AI-orchestrated cyber espionage campaign." anthropic.com, November 2025. ([link](https://www.anthropic.com/news/disrupting-AI-espionage))
- Anthropic. GTG-1002 Full Technical Report. ([PDF](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf))
- Google Threat Intelligence Group. "Distillation, Experimentation, and (Continued) Integration of AI for Adversarial Use." cloud.google.com, February 2026. ([link](https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use))
- Marzouk, A. "IDEsaster: 30+ Vulnerabilities in AI Coding Tools." December 2025. ([link](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html))
- OWASP. "Top 10 for Agentic Applications." genai.owasp.org, December 2025.
