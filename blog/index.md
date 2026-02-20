---
layout: default
title: Pipelock Blog
description: "Security research and practical guidance for AI agent systems."
---

# Pipelock Blog

Security research and practical guidance for AI agent systems.

Pipelock is an open-source firewall for AI agents. It sits between agents and the outside world, scanning for secrets, blocking exfiltration, detecting prompt injection, and monitoring workspace integrity.

{% for post in site.posts %}
### [{{ post.title }}]({{ post.url | relative_url }})
<small>{{ post.date | date: "%B %d, %Y" }}</small>

{{ post.excerpt }}

---
{% endfor %}

[View on GitHub](https://github.com/luckyPipewrench/pipelock)
