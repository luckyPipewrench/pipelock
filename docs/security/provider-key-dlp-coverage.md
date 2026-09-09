# Provider-Key DLP Coverage

Pipelock's built-in provider-key DLP is prefix-first, not entropy-first. A
default rule is added only when the key shape has a distinctive provider prefix
and a useful length/charset boundary. This avoids blocking normal UUIDs, digests,
session IDs, request IDs, and opaque model/provider IDs.

## Covered By Default

Each row has a compiled credential-audience host set. Pipelock allows the matching credential only when the proxy's verified destination host is in that set. The decision applies to URL, request-body, request-header, and outbound WebSocket-frame DLP, and records `dlp_credential_audience_allow`. A match for the same credential at another host remains blocked. These entries do not trust a whole provider host or use `exempt_domains` or `suppress`.

| Rule | Shape | Immutable audience hosts | Source |
|------|-------|--------------------------|--------|
| Anthropic API Key | `sk-ant-` + 20+ token chars | `*.anthropic.com` | [Anthropic API overview](https://platform.claude.com/docs/en/api/overview) |
| OpenAI API Key | `sk-proj-` + 20+ token chars | `*.openai.com` | [OpenAI API overview](https://developers.openai.com/api/reference/overview) |
| OpenAI Service Key | `sk-svcacct-` + 20+ token chars | `*.openai.com` | [OpenAI API overview](https://developers.openai.com/api/reference/overview) |
| Fireworks API Key | `fw_` + 22 alphanumeric chars | `*.fireworks.ai` | [Fireworks authentication](https://docs.fireworks.ai/api-reference/authentication); unverified binding carried from prior defaults |
| LLM Router API Key | `sk-or-v1-` + 20+ hex chars | `*.openrouter.ai` | [OpenRouter API overview](https://openrouter.ai/docs/api_reference/overview) |
| Answer Engine API Key | `pplx-` + 20+ alphanumeric chars | `*.perplexity.ai` | [Perplexity quickstart](https://docs.perplexity.ai/docs/getting-started/quickstart) |
| Web Research API Key | `tvly-` + 20+ token chars | `*.tavily.com` | [Tavily quickstart](https://docs.tavily.com/documentation/quickstart) |
| Google API Key | `AIza` + 35 token chars | `*.googleapis.com` | [Google API keys](https://cloud.google.com/docs/authentication/api-keys) |
| Discord Bot Token | three base64url segments | `discord.com` | [Discord developer reference](https://docs.discord.com/developers/reference) |
| Hugging Face Token | `hf_` + bounded alphanumeric suffix | `*.huggingface.co` | [Hugging Face tokens](https://huggingface.co/docs/hub/security-tokens) |
| Databricks Token | `dapi` + 32+ hex chars | `*.databricks.com` | [Databricks PAT authentication](https://docs.databricks.com/aws/en/dev-tools/auth/pat) |
| Replicate API Token | `r8_` + 40 hex chars | `*.replicate.com` | [Replicate authentication](https://replicate.com/docs/topics/authentication); unverified binding carried from prior defaults |
| Together AI Key | `tok_` + 40+ lowercase alphanumeric chars | `*.together.ai` | [Together authentication](https://docs.together.ai/docs/authentication); unverified binding carried from prior defaults |
| Pinecone API Key | `pcsk_` + 36+ alphanumeric chars | `*.pinecone.io` | [Pinecone authentication](https://docs.pinecone.io/guides/get-started/authentication) |
| Groq API Key | `gsk_` + 48+ alphanumeric chars | `*.groq.com` | [Groq API keys](https://console.groq.com/docs/api-keys) |
| xAI API Key | `xai-` + 80+ token chars | `*.x.ai` | [xAI API reference](https://docs.x.ai/docs/api-reference) |

## Intentionally Not Covered By Default

These providers are excluded until their public docs or secret-scanning partner
metadata exposes a distinctive, stable, low-FP key shape:

| Provider family | Reason |
|-----------------|--------|
| Bare `sk-` providers | A generic `sk-` token is indistinguishable from many unrelated provider keys and customer tokens. |
| Raw 32/40/64 hex providers | Collides with hashes, IDs, checksums, and trace/session values. |
| AWS Bedrock API keys | Public docs describe API-key authentication but not a distinctive stable shape. |
| Cohere, Mistral, DeepSeek, Voyage, Hume, Vapi, Cerebras | Public docs describe bearer/API-key authentication but do not provide a shape that is safe enough for a default regex. |
| Baseten, Modal, Novita, DeepInfra, Hyperbolic, SambaNova, Nebius | No stable, provider-distinctive prefix was found in public docs during the 2026-06-20 review pass. |
| `sk_car_` / `jina_`-style providers | Key format is undisclosed in vendor docs and the prefix collides with common identifiers (`sk_car_` with car/cart snake_case; `jina_` with ordinary identifiers), so a default pattern would false-positive; add a custom pattern + exempt host if you use these. |

## Adding A Local Provider Shape

If your deployment knows a provider's internal key shape, add a custom pattern
with both controls:

```yaml
dlp:
  patterns:
    - name: "Internal Provider API Key"
      regex: '\bintprov_[A-Za-z0-9_-]{32,}\b'
      severity: critical
      exempt_domains:
        - "api.provider.example"

suppress:
  - rule: "Internal Provider API Key"
    path: "https://api.provider.example/*"
    reason: "provider-bound credential"
```

`exempt_domains` prevents URL DLP from blocking a custom key on the provider's own host. `suppress` covers request-body and request-header findings on the same provider route. The same key remains blocked on every other destination.

The compiled audience entries do not use suppressions. Immutable core DLP names cannot be suppressed.

## Provider-Opaque Fields

Some provider APIs legitimately carry long opaque identifiers or provider-bound
token-like values inside known JSON fields. Pipelock scans those fields with
their provider provenance intact: a match that is valid only inside that
provider-opaque field is capped at warn, while the same token shape in ordinary
content still blocks according to its severity. Malformed JSON, multiple JSON
roots, or a critical match outside the validated opaque field fail closed rather
than inheriting the downgrade.
