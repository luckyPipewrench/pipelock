---
layout: default
title: Home
---

# Pipelock Blog

Security research and practical guidance for AI agent systems.

Pipelock is an open-source security harness that sits between AI agents and the outside world — scanning for secrets, blocking exfiltration, and monitoring file integrity in multi-agent workspaces.

{% for post in site.posts %}
### [{{ post.title }}]({{ post.url | relative_url }})
<small>{{ post.date | date: "%B %d, %Y" }}</small>

{{ post.excerpt }}

---
{% endfor %}

[View on GitHub](https://github.com/luckyPipewrench/pipelock)
