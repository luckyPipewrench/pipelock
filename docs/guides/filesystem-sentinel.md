# Filesystem Sentinel

The filesystem sentinel monitors directories where agent subprocesses write files. When pipelock wraps an MCP server in subprocess mode (`pipelock mcp proxy -- COMMAND`), it can watch the agent's working directories for secrets written to disk.

This catches a class of exfiltration that the network proxy cannot see: an agent writing credentials to a file, then a later process reading and exfiltrating them through a channel pipelock doesn't monitor.

## When to Use It

- Your MCP server subprocess writes files to a working directory
- You want to detect leaked credentials in agent output files

## Scope

File sentry applies to **subprocess MCP mode only**. HTTP upstream, WebSocket, and listener modes have no local child process and are out of scope.

File sentry detects writes; it does not intercept them. The write reaches disk before the scan completes. With `action: warn` (default), findings are alerted and the agent keeps running. With `action: block`, the proxy context is cancelled on the first agent-attributed finding, terminating the MCP child so the agent cannot continue acting on the leak. For write-time interception, layer Landlock or the process sandbox (`--sandbox`) on top.

## Configuration

```yaml
file_sentry:
  enabled: true
  action: warn               # warn (default) or block
  watch_paths:
    - "/workspace"           # optional by default; degraded if unavailable
    - path: "/tmp/agent-output"
      required: true         # startup fails if this watch cannot be installed
  scan_content: true
  max_file_bytes: 0           # 0 = built-in 10 MiB default
  ignore_patterns:
    - "node_modules/**"
    - ".git/**"
    - "*.o"
    - "*.so"
    - "*.pyc"
```

### Action

- `warn` (default): every finding is logged to stderr and recorded as a Prometheus metric. The MCP child keeps running.
- `block`: same logging + metrics, AND on the first finding attributed to a process in the agent tree (`IsAgent=true`), the proxy context is cancelled, which terminates the MCP child. Non-agent writes (editor saves, build output, other system processes touching the watched directory) never trigger the block path. The cancel fires exactly once per session.

### Watch Paths

Directories are watched recursively. New subdirectories created after startup are automatically added to the watch. Paths are resolved to absolute paths at startup.

Each entry can be either a bare string or a mapping:

```yaml
watch_paths:
  - "/workspace"             # required:false
  - path: "/var/agent-secrets"
    required: true
```

Bare string entries default to `required: false`. If a non-required watch cannot be installed, pipelock logs a degraded path and continues arming the remaining paths. Use `required: true` for directories whose monitoring is part of the security boundary; startup fails closed if that watch cannot be installed. Unknown mapping fields are rejected so typos do not silently disable the hard-fail opt-in.

### Ignore Patterns

Glob patterns match against the file or directory base name. Common patterns to ignore:

- Build artifacts: `*.o`, `*.so`, `*.pyc`, `*.class`
- Package managers: `node_modules/**`, `.venv/**`
- Version control: `.git/**`

### Content Scanning

When `scan_content` is true (the default), file sentry reads each modified file and runs pipelock's DLP scanner on the content. The same 65 credential patterns used for network traffic apply to file content.

`max_file_bytes` caps how much file content the scanner will read. `0` uses the built-in 10 MiB default; set a positive byte value to override it. Negative values are rejected during config validation.

Files larger than the cap are skipped to avoid unbounded memory use, and the skip is surfaced through the watcher's error path instead of being silently dropped. Stat and read failures are surfaced the same way, so operators can distinguish "clean file" from "file was not inspected."

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
