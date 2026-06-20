# Provider-Key DLP Coverage

Pipelock's built-in provider-key DLP is prefix-first, not entropy-first. A
default rule is added only when the key shape has a distinctive provider prefix
and a useful length/charset boundary. This avoids blocking normal UUIDs, digests,
session IDs, request IDs, and opaque model/provider IDs.

## Covered By Default

These rules are enforced on every destination except the provider's own API host,
where URL DLP is exempted and matching body/header findings are suppressed as
provider-bound credentials:

| Rule | Shape | Provider host exemption |
|------|-------|-------------------------|
| Anthropic API Key | `sk-ant-` + 20+ token chars | `*.anthropic.com` |
| OpenAI API Key | `sk-proj-` + 20+ token chars | `*.openai.com` |
| OpenAI Service Key | `sk-svcacct-` + 20+ token chars | `*.openai.com` |
| Fireworks API Key | `fw_` + 22 alphanumeric chars | `*.fireworks.ai` |
| LLM Router API Key | `sk-or-v1-` + 20+ hex chars | `*.openrouter.ai` |
| Answer Engine API Key | `pplx-` + 20+ alphanumeric chars | `*.perplexity.ai` |
| Web Research API Key | `tvly-` + 20+ alphanumeric chars | `*.tavily.com` |
| Google API Key | `AIza` + 35 token chars | `*.googleapis.com` |
| Hugging Face Token | `hf_` + bounded alphanumeric suffix | `*.huggingface.co` |
| Databricks Token | `dapi` + 32+ hex chars | `*.databricks.com` |
| Replicate API Token | `r8_` + 40 hex chars | `*.replicate.com` |
| Together AI Key | `tok_` + 40+ lowercase alphanumeric chars | `*.together.ai` |
| Pinecone API Key | `pcsk_` + 36+ alphanumeric chars | `*.pinecone.io` |
| Groq API Key | `gsk_` + 48+ alphanumeric chars | `*.groq.com` |
| xAI API Key | `xai-` + 80+ token chars | `*.x.ai` |

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

`exempt_domains` prevents URL DLP from blocking a key on the provider's own host.
`suppress` covers request-body and request-header findings on the same provider
route. The same key remains blocked on every other destination.
