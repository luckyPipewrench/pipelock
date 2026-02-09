---
layout: post
title: "Lateral movement in multi-agent LLM systems"
date: 2026-02-08
author: Josh Waldrep
description: "A security gap nobody is patching — how compromised AI agents spread to other agents through shared files, and what you can do about it."
---

*A security gap nobody is patching*

---

## The setup

I run two AI agents. One manages my infrastructure. The other writes code. They share a workspace: config files, memory, task lists. They talk to each other through a shared git repo and file drops.

This isn't unusual anymore. OpenClaw users pair it with Claude Code. Dev teams run multiple specialized agents. Homelab people (myself included) have agents managing different parts of their stack.

The problem is simple. If one agent gets compromised, it can silently take over every other agent it talks to.

## The attack

Researchers have already shown this works. Lee and Tiwari published "Prompt Infection" in October 2024, showing that malicious prompts self-replicate across connected LLM agents. A compromised agent spreads the infection to other agents through their normal communication channels ([arxiv.org/abs/2410.07283](https://arxiv.org/abs/2410.07283)). Gu et al. showed in "Agent Smith" that a single poisoned image can jailbreak agents exponentially fast in multi-agent setups.

Those papers focus on direct message passing between LLMs. In the real world, the attack surface is bigger and harder to see.

### How agents actually talk to each other

Real multi-agent setups don't use clean protocols. They share:

- Config files that define how agents behave (loaded at startup)
- Memory files where agents record notes (read by other agents later)
- Skill definitions that run when triggered
- Git repos that sync between agents
- File drops for task handoffs

None of these channels have integrity checking. None use signatures. There's no way to tell the difference between a file written by a healthy agent and one written by a compromised agent.

### What this looks like in practice

1. Agent A visits a webpage with a hidden prompt injection
2. Agent A gets compromised. It still looks normal, still responds correctly
3. Agent A writes a "task update" to the shared workspace with embedded instructions
4. Agent B reads the handoff as part of its normal routine
5. Agent B follows the instructions because they came from a trusted source
6. Both agents are compromised. The poisoned files stay in the workspace across restarts

That's lateral movement. Same idea as in traditional network security, where an attacker hops from one compromised machine to another. Except here the hop goes through shared files instead of network connections.

### Why this is worse than regular lateral movement

On a traditional network, moving laterally means exploiting vulnerabilities or stealing credentials at each step. With agents:

- Agents trust shared files by design. There's no auth layer on a config file.
- The "exploit" is just text. No binary payload, no CVE number. Just instructions in a markdown file.
- It persists on its own. Poisoned files survive restarts, context resets, even redeployments if the storage persists.
- Detection is extremely hard with current tools. A poisoned file looks identical to a normal handoff or memory note.

## What's missing from the ecosystem

People have responded to individual agent threats:

- Sandbox tools (Docker sandboxes, bubblewrap, Anthropic's sandbox-runtime) lock down filesystem and process access
- Egress firewalls (Pipelock) block credential exfiltration over the network
- Prompt injection filters (Lakera, NeMo Guardrails) catch malicious inputs to single agents
- Identity protocols (Visa's Trusted Agent Protocol) give agents cryptographic identity for commerce

But nobody has built anything to secure the communication between cooperating agents in a dev or self-hosted environment. AutoGen, CrewAI, LangGraph, and similar frameworks have zero security for inter-agent communication. OWASP's agentic AI guidance acknowledges the risk of prompt injection spreading between agents but doesn't provide a technical fix for shared-workspace attacks.

Benchmarks confirm the problem is real. InjecAgent (Zhan et al., 2024) showed roughly 50% injection success rates against GPT-4 and Claude in agent scenarios. AgentDojo (Debenedetti et al., 2024) showed injections succeed even when agents use defensive prompting.

## What we built

Pipelock now includes integrity monitoring for agent workspaces. It's the first layer of defense against lateral movement through shared files.

### How it works

```bash
# Hash all critical files in the workspace
pipelock integrity init ./workspace --exclude "logs/**" --exclude "temp/**"

# Verify nothing changed
pipelock integrity check ./workspace
# Exit 0 = clean, non-zero = something changed

# Re-hash after you approve changes
pipelock integrity update ./workspace
```

The manifest stores SHA256 hashes for every protected file. When an agent starts up, it checks that config files, skill definitions, and identity files haven't been changed outside of a normal workflow.

This doesn't stop every lateral movement attack. A compromised agent can still write to files that aren't in the manifest, and we need signing to verify who actually made a change. But it catches the most dangerous thing: someone (or something) quietly editing the files that control how your agents behave.

### Now available

- **Ed25519 signing** — verify which agent or person changed each file (`pipelock keygen|sign|verify|trust`)
- **MCP response scanning** — scan MCP tool responses for prompt injection before they reach the agent (`pipelock mcp scan`)

### Coming next

- Communication policies, so you can define which agents are allowed to modify which files
- Content scanning for shared workspace files (extending MCP scanning to file-based communication)

## What you can do right now

If you run more than one agent on shared storage:

1. Keep data separate from instructions. Agent notes and memory shouldn't live next to config files and skill definitions.
2. Use read-only mounts where you can. If Agent B only reads Agent A's config, mount it read-only.
3. Know your attack surface. List every way your agents communicate. Every channel is a potential path for lateral movement.
4. Check for unexpected changes to behavioral files. Even running diff manually is better than nothing.

Or try Pipelock's integrity monitoring: [github.com/luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock).

---

## References

- Lee, Y. and Tiwari, A. "Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems." arXiv:2410.07283, October 2024.
- Gu, X. et al. "Agent Smith: A Single Image Can Jailbreak One Million Multimodal LLM Agents Exponentially Fast." arXiv:2402.08567, February 2024.
- Zhan, Q. et al. "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents." arXiv:2403.02691, March 2024.
- Debenedetti, E. et al. "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses in LLM Agents." arXiv:2406.13352, June 2024.
- Ferrag, M.A. et al. "From Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agents Workflows." arXiv:2506.23260, June 2025.
- OWASP. "Top 10 for Agentic Applications." genai.owasp.org, December 2025.
- Maloyan, N. and Namiot, D. "Prompt Injection Attacks on Agentic Coding Assistants." arXiv:2601.17548, January 2026.
- NVIDIA AI Red Team. "Practical Security Guidance for Sandboxing Agentic Workflows and Managing Execution Risk." developer.nvidia.com, January 30, 2026.
- Visa. "Trusted Agent Protocol: An Ecosystem-Led Framework for AI Commerce." October 2025.
