# Tool-call policy argument sources

Tool-call policy rules can match a tool name and, optionally, strings in its arguments. Use `arg_source: patch_targets` when a rule should inspect the files named by a patch instead of matching text in the patch body.

For example, this rule blocks a patch that targets a shell startup file even when the patch body contains no mention of that file:

```yaml
mcp_tool_policy:
  enabled: true
  action: warn
  rules:
    - name: Block shell startup file edits
      tool_pattern: '^apply_patch$'
      arg_pattern: '\.bashrc$'
      arg_source: patch_targets
      action: block
```

`patch_targets` extracts paths from recognized Git diffs, unified diffs, and `apply_patch` headers. It checks the extracted target paths, so a path mentioned only in patch content does not match this rule. If an argument looks like a patch but Pipelock cannot reliably inspect its targets, the rule is treated as a match and its action applies.

`arg_source` accepts only `patch_targets` and requires `arg_pattern`. Add `arg_key` to scope structured path values alongside the parsed patch targets. Pipelock still inspects patch headers regardless of their argument key; descriptions and replacement content outside matching keys are excluded. Calls without patch headers use the scoped values. If a rule omits `action`, it inherits `mcp_tool_policy.action`.

Built-in credential destination rules cover recognized file writes, edits, moves, copies and patches, including NTFS stream destinations. They inspect target fields and patch headers, preserving each preset's configured credential action. Ordinary `.env` writes and document content that mentions a credential path remain allowed by these rules. Custom tool names, custom credential locations and a remote server's filesystem aliases need operator-specific rules or filesystem containment.

See the [MCP development listener guide](mcp-inspector-front.md) for a reverse proxy example and the [false-positive tuning guide](false-positive-tuning.md) for DLP warn-mode patterns.
