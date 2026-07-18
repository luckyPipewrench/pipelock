# Request Policy

Request policy is an allow-by-default deny/warn safety rail over outbound HTTP API
**operations**. Where DLP matches on content and the domain blocklist matches on
host, request policy matches on what the request is *trying to do*: a GraphQL
mutation root field, a JSON-RPC command, or an admin `DELETE`. It blocks the
dangerous operations while everything else forwards untouched.

It is not a DLP scanner and not a behavioral allowlist; it composes with both. It
runs **before** the learn-and-lock contract gate, so a contract allow can never
suppress an operation-policy block, and it is independent of
`request_body_scanning` (it reads a body itself only when a route-matched
operation predicate or batch endpoint needs one).

This guide is the task-oriented walkthrough. For the exhaustive field reference,
see [Request Policy in the configuration reference](../configuration.md#request-policy).

## The model

A request **forwards unless a rule matches**. There is deliberately no
section-level `default_action` knob, so the section can never be configured into a
default-deny posture by accident. Each rule is `block` or `warn`, per rule.

Every rule has a **route** (which requests it applies to) and, optionally, an
**operation predicate**: either `graphql` or `discriminator`. When a rule carries
both a route and a predicate, **both must match**: the route selects the request,
then the predicate is evaluated against the operation extracted from its body.

## Quick start: block dangerous GraphQL mutations

```yaml
request_policy:
  enabled: true
  on_parse_error: block         # block (default) | warn | allow
  on_opaque_operation: block    # block (default) | warn | allow
  rules:
    - name: "block-graphql-account-mutations"
      action: block
      reason: "account-state mutations require human review"
      route:
        hosts: ["api.example.com", "*.example.net"]
        methods: ["POST"]
        path_prefixes: ["/graphql"]
      graphql:
        operation_types: ["mutation"]
        root_field_patterns: ["^delete", "^transfer"]
```

This blocks any `POST` to the GraphQL endpoint whose document contains a mutation
whose root field starts with `delete` or `transfer`. A query that only reads, or a
mutation on an unrelated field, forwards.

The extractor resolves **aliases to the real field** and expands top-level
**fragment spreads and inline fragments**, so a deny rule matches the field that
actually executes, not a cosmetic alias or a field hidden inside a fragment.
**Every operation in a document or batch is evaluated, never just the first**, so a
dangerous operation cannot hide behind a benign sibling.

> **Scope GraphQL rules by path, not content type.** A GraphQL-over-GET request
> (`?query=...`) carries no body and therefore no `Content-Type`, so a rule whose
> route sets `content_types: ["application/json"]` silently never matches the GET
> form, even though the engine still extracts the operation from the query string.
> Constrain GraphQL rules with `path_prefixes` / `path_patterns`, or leave
> `content_types` empty, so one rule covers both the POST-body and GET-query forms.

## The fail-closed model (the important part)

The two top-level knobs decide what happens when a rule's route matches but the
operation **cannot be inspected**. Both default to `block`.

| Knob | Fires when | Default |
|------|------------|---------|
| `on_parse_error` | The body is read but is not valid JSON for the configured predicate, or a contained GraphQL query fails to parse. | `block` |
| `on_opaque_operation` | The route matches but there is no inspectable operation: a GraphQL Automatic Persisted Query that ships only a hash, an empty/missing `query`, or a non-string discriminator value. | `block` |

Leaving these at `block` is the safe posture: an attacker cannot smuggle a
dangerous operation past a rule by making it unparseable or opaque. Set them to
`warn` only during rollout, and to `allow` only for an endpoint you have decided is
out of scope.

Several conditions are **always** unclassifiable and fail closed regardless of the
two knobs: duplicate GraphQL fragment names, fragment cycles, unresolved fragment
spreads, expansion-budget exhaustion, and a duplicated top-level discriminator key
(where JSON parsers disagree on which value wins). If a route-matched body is
**uninspectable** (unread, over `request_body_scanning.max_body_bytes` default
5 MiB, or a read error), it is blocked outright before the two knobs even apply.

## Non-GraphQL JSON APIs: the discriminator predicate

For JSON APIs that signal the operation through a top-level key (an `action`,
`type`, or `command` field), use a `discriminator` predicate instead of `graphql`:

```yaml
  rules:
    - name: "block-account-close-commands"
      action: block
      reason: "account-close commands require human review"
      route:
        hosts: ["api.example.com"]
        methods: ["POST"]
        path_prefixes: ["/rpc"]
        content_types: ["application/json"]
      discriminator:
        field: "action"
        value_patterns: ["^account\\.close$", "^account\\.delete$"]
```

The predicate matches when the string value at `field` matches any pattern. An
absent field does not match (the rail forwards). A present-but-non-string value, a
non-object top-level body, or a duplicated `field` key is opaque and fails closed
via `on_opaque_operation`. A rule may carry both `graphql` and `discriminator`, in
which case both must match.

## Batch endpoints

A JSON batch endpoint wraps several sub-requests in one outer request. Declare it
under `batch:` and request policy unwraps the envelope and evaluates **every**
sub-request against the full rule set, with the **strictest decision winning**, so
a dangerous operation cannot evade a rule by being wrapped in a batch.

```yaml
  batch:
    - route:
        hosts: ["api.example.com"]
        methods: ["POST"]
        path_prefixes: ["/$batch"]
      requests_field: "requests"   # OData-style defaults; override per envelope shape
      method_field: "method"
      url_field: "url"
      body_field: "body"
      max_sub_requests: 64         # over the cap, the envelope fails closed
```

A sub-request whose method or URL field is missing or non-string fails closed (it
must not silently evaluate as `method="" path="/"`). Nested batches are expanded to
a fixed depth; beyond it, a sub-request that itself targets a batch endpoint fails
closed.

## Method-override handling

A request that tunnels a different verb through `X-HTTP-Method-Override`,
`X-Method-Override`, or `X-HTTP-Method` is evaluated against **both** the base
method and the overridden method, and the stricter result wins. This stops a `POST`
with `X-HTTP-Method-Override: DELETE` from dodging a `DELETE`-scoped rule, and
equally stops a real `POST` from being downgraded by an override the upstream
ignores. The recognized verbs include the HTTP `QUERY` method
(draft-ietf-httpbis-safe-method-w-body), a safe method that carries a request
body; `methods: ["QUERY"]` is valid in a route and its body is scanned like any
other body-bearing request.

## Transport coverage

Request policy is enforced on the fetch proxy, forward proxy, CONNECT, TLS
interception, reverse proxy, and redirect hops. On every HTTP transport it runs
before the contract gate. WebSocket is covered on two surfaces: the upgrade
handshake is matched route-only (host, `GET` method, path, content type), and once
the socket is open each complete, UTF-8-validated client **text message** is
evaluated per message as an operation body. Fragmented text messages are
reassembled before evaluation; partial fragments are buffered, not forwarded or
classified on their own. The per-message gate is checked against the live matcher,
so a hot-reloaded rule applies to already-open sockets. Binary frames are not
operation bodies.

## Rolling out safely

Start a new rule in shadow before you enforce it:

```yaml
    - name: "warn-on-admin-deletes"
      action: warn
      shadow: true                 # log the would-be action, forward anyway
      reason: "shadow rollout of admin DELETE guard"
      route:
        hosts: ["api.example.com"]
        methods: ["DELETE"]
        path_patterns: ['^/admin/']
```

A `shadow` match never enforces; an enforced match always wins over a shadow match
of equal strictness. Promote to `action: block` (and drop `shadow`) once the logs
show the rule matches only what you intend.

## Enforcement, audit, and receipts

A matched rule records a decision metric and an audit event with bounded,
operator-defined labels only, never body or matched content. An enforced
(non-shadow) `block` returns **HTTP 403** with the `request_policy_deny` block
reason on `X-Pipelock-Block-Reason` and, when a receipt emitter is configured, a
correlated receipt id. `warn` and `shadow` matches are logged, counted, and
forwarded.

## See also

- [Request Policy configuration reference](../configuration.md#request-policy): every field, defaults, and route-matching semantics
- [Block-reason header](block-reason-header.md): the `request_policy_deny` reason and the full block-reason vocabulary
- [Request redaction](redaction.md): rewriting matched values instead of blocking the request
