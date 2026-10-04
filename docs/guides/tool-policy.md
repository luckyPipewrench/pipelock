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

`arg_source` accepts only `patch_targets`. It requires `arg_pattern` and cannot be combined with `arg_key`; invalid combinations are rejected while loading the configuration. If a rule omits `action`, it inherits `mcp_tool_policy.action`.

See the [MCP development listener guide](mcp-inspector-front.md) for a reverse proxy example and the [false-positive tuning guide](false-positive-tuning.md) for DLP warn-mode patterns.
