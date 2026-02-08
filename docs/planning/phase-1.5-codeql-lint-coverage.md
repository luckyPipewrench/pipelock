# Phase 1.5: CodeQL, Lint Cleanup, Code Coverage

**Date:** 2026-02-08
**Status:** Complete (v0.1.2)
**PRs:** #28 (lint cleanup), #29 (CodeQL + Codecov) — both merged

## Context

Pipelock v0.1.1 is deployed and stable with 363 tests. The CI pipeline has tests + golangci-lint (new-issues-only) + build. Three gaps remain before the repo is community-ready:

1. No security scanning (CodeQL/SAST)
2. 53 existing lint warnings masked by `only-new-issues`
3. No code coverage tracking (currently ~90% but invisible)

## PR #28: Zero-Warnings Lint Cleanup

**Branch:** `fix/lint-zero-warnings`

### Issue Breakdown (53 total)

| Linter | Count | Files |
|--------|-------|-------|
| usestdlibvars | 12 | proxy_test.go |
| goconst | 12 | config.go, scanner_test.go, logger_test.go, response_test.go, generate.go |
| gosec | 11 | logger.go, logger_test.go, cli_test.go, generate.go, scanner_test.go |
| errcheck | 8 | proxy_test.go, logs.go, proxy.go |
| revive | 7 | main.go, proxy_test.go, ratelimit_test.go, scanner_test.go |
| gofumpt | 1 | logger_test.go |
| godot | 1 | scanner.go |
| noctx | 1 | scanner.go |

### Step 1: Mechanical fixes (no behavior changes)

**usestdlibvars (12)** — `internal/proxy/proxy_test.go`
- Replace string/int literals with `http.Method*` and `http.Status*` constants

**errcheck in tests (6)** — `internal/proxy/proxy_test.go`
- `fmt.Fprint(...)` → `_, _ = fmt.Fprint(...)`
- `conn.Close()` → `_ = conn.Close()`

**errcheck in prod (2)**
- `logs.go:40` — `defer f.Close()` → add `//nolint:errcheck // read-only file`
- `proxy.go:325` — `defer resp.Body.Close()` → add `//nolint:errcheck // response body`

**revive — unused params (6)** — rename to `_`

**gosec G306 — permissions (5)**
- `cli_test.go` (4) and `generate.go` (1) — `0644` → `0o600`

**gosec G304 — file inclusion (5)**
- `logger.go:48` — add `//nolint:gosec // G304: path from config`
- `logger_test.go` (4 lines) — add `//nolint:gosec // test file paths`

**gosec G101 — hardcoded creds (1)**
- `scanner_test.go:201` — add `//nolint:gosec // G101: test fake key`

**gofumpt (1)** — run gofumpt on `logger_test.go`

**godot (1)** — `scanner.go:441` — add period to comment

**revive — package comment (1)** — `cmd/pipelock/main.go`

### Step 2: Production code fixes

**noctx (1)** — `scanner.go:203`
- `net.LookupHost(hostname)` → `net.DefaultResolver.LookupHost(context.TODO(), hostname)`

**goconst in config.go (6 occurrences)**
- Extract: `ModeBalanced`, `ModeStrict`, `ModeAudit`
- Extract: `defaultListen`, `defaultLogFormat`, `defaultLogOutput`, `OutputBoth`

**goconst in generate.go**
- Reuse mode constants from config package

### Step 3: Remove only-new-issues

- Edit `.github/workflows/ci.yaml`: remove `only-new-issues: true`

### Step 4: Suppress remaining goconst in tests

Add `//nolint:goconst` for test-only repeated strings:
- `logger_test.go`: `"10.0.0.1"`, `"pipelock"`
- `scanner_test.go`: `"dlp"`, `"entropy"`
- `response_test.go`: `"strip"`

## PR #29: CodeQL + Codecov + Badges

**Branch:** `feat/security-and-coverage`

### CodeQL Security Scanning

Create `.github/workflows/security.yaml`:
- Runs on push to main, PRs, and weekly schedule
- Uses `security-and-quality` query suite (covers SSRF, path traversal, ReDoS)
- Go autobuild (no custom config needed)

### Codecov Integration

Modify `.github/workflows/ci.yaml`:
- Add `-coverprofile=coverage.out` to test step (Go 1.24 matrix only)
- Add `codecov/codecov-action@v5` upload step

Create `codecov.yml`:
- Project target: 85% (current ~90%, 5% breathing room)
- Patch target: 80% (new code should be well-tested)
- PR comments with coverage diff

### README Badges

Add after existing License badge:
- CodeQL badge
- Codecov badge

## Verification

### After PR #28
```bash
golangci-lint run ./...          # Expect: 0 issues
go test -race -count=1 ./...    # Expect: 363+ pass
```

### After PR #29
- Push → verify CodeQL workflow in Actions tab
- Verify codecov comment on PR
- Merge → verify badges render on README
- Check GitHub Security tab for CodeQL results

## Files Modified

### PR #28
| File | Changes |
|------|---------|
| `internal/proxy/proxy_test.go` | usestdlibvars, errcheck, revive |
| `internal/scanner/ratelimit_test.go` | revive (unused params) |
| `internal/scanner/scanner_test.go` | revive, gosec, goconst |
| `internal/scanner/scanner.go` | noctx, godot |
| `internal/scanner/response_test.go` | goconst |
| `internal/audit/logger.go` | gosec |
| `internal/audit/logger_test.go` | gosec, gofumpt, goconst |
| `internal/cli/logs.go` | errcheck |
| `internal/cli/cli_test.go` | gosec |
| `internal/cli/generate.go` | gosec, goconst |
| `internal/config/config.go` | goconst |
| `cmd/pipelock/main.go` | revive |
| `.github/workflows/ci.yaml` | remove only-new-issues |

### PR #29
| File | Changes |
|------|---------|
| `.github/workflows/security.yaml` | New (CodeQL) |
| `codecov.yml` | New |
| `.github/workflows/ci.yaml` | Add coverage step |
| `README.md` | Add 2 badges |
