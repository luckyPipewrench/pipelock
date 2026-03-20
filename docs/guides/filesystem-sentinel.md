# Filesystem Sentinel

The filesystem sentinel monitors directories where agent subprocess processes write files. When pipelock wraps an MCP server in subprocess mode (`pipelock mcp proxy -- COMMAND`), it can watch the agent's working directories for secrets written to disk.

This catches a class of exfiltration that the network proxy cannot see: an agent writing credentials to a file, then a later process reading and exfiltrating them through a channel pipelock doesn't monitor.

## When to Use It

- Your MCP server subprocess writes files to a working directory
- You want to detect leaked credentials in agent output files

## Scope

File sentry applies to **subprocess MCP mode only**. HTTP upstream, WebSocket, and listener modes have no local child process and are out of scope.

This is **detection, not prevention**. File sentry alerts when secrets are written. It cannot block the write. Phase 2 (seccomp-based enforcement) will add write blocking.

## Configuration

```yaml
file_sentry:
  enabled: true
  watch_paths:
    - "/workspace"           # agent working directory
    - "/tmp/agent-output"    # temp output directory
  scan_content: true
  ignore_patterns:
    - "node_modules/**"
    - ".git/**"
    - "*.o"
    - "*.so"
    - "*.pyc"
```

### Watch Paths

Directories are watched recursively. New subdirectories created after startup are automatically added to the watch. Paths are resolved to absolute paths at startup.

### Ignore Patterns

Glob patterns match against the file or directory base name. Common patterns to ignore:

- Build artifacts: `*.o`, `*.so`, `*.pyc`, `*.class`
- Package managers: `node_modules/**`, `.venv/**`
- Version control: `.git/**`

### Content Scanning

When `scan_content` is true (the default), file sentry reads each modified file and runs pipelock's DLP scanner on the content. The same 46 credential patterns used for network traffic apply to file content.

Files larger than 10MB are skipped to avoid unbounded memory use.

## How It Works

1. On startup, pipelock walks each `watch_paths` directory and adds recursive inotify (Linux) or fsnotify watches
2. When a file write event fires, pipelock debounces for 50ms (waits for the write to complete)
3. After the quiet window, pipelock reads the file and runs DLP pattern matching
4. If a match is found, a finding is reported as:
   - A stderr log line: `pipelock: [file_sentry] DLP match in /path: Pattern Name (severity=critical)`
   - A Prometheus counter increment: `pipelock_file_sentry_findings_total{pattern, severity, agent}`

## Process Attribution (Linux)

On Linux, pipelock uses `PR_SET_CHILD_SUBREAPER` to track the agent's process tree. When a file write is detected, pipelock checks `/proc/[pid]/fd` for all tracked processes to determine if the write came from the agent.

If attribution succeeds, the finding includes `is_agent: true` and the `agent` Prometheus label is set to `"true"`.

Attribution is probabilistic: if the writing process has already closed the file descriptor by the time pipelock checks, attribution will not succeed. This is a detection heuristic, not forensic proof.

## Relationship to `pipelock integrity`

`pipelock integrity` is a point-in-time snapshot scan. It checks files once and reports. File sentry is real-time continuous monitoring. They are complementary:

| Feature | `pipelock integrity` | File Sentry |
|---------|---------------------|-------------|
| Timing | On-demand snapshot | Continuous real-time |
| Scope | Any directory | Subprocess MCP mode only |
| Detection | File hashes + DLP | DLP on write events |
| Attribution | None | Process tree (Linux) |
