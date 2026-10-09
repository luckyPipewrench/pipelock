// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Command receipt-load drives a real Pipelock forward proxy and a local sink
// and reports two separate verdicts: performance (rates and latency to a fully
// read response body) and integrity (every request left exactly the receipts
// its mode requires, matched by identity).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	exitOK        = 0
	exitIntegrity = 1
	exitUsage     = 2
	exitPerf      = 3
)

func main() { os.Exit(realMain(os.Args[1:])) }

// logf writes a timestamped status line to stderr. Values from flags, the
// proxy log, and error text are quoted by the callers' verbs, so a hostile
// string cannot forge a second status line.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", time.Now().Format("2006/01/02 15:04:05"), fmt.Sprintf(format, args...))
}

func realMain(args []string) int {
	if len(args) > 0 && args[0] == "summarize" {
		path, err := summarizeCommand(args[1:])
		if err != nil {
			logf("summarize: %v", err)
			return exitUsage
		}
		logf("matrix summary: %q", path)
		return exitOK
	}
	opt, modes, lockFile, err := parseFlags(args)
	if err != nil {
		logf("%v", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if lockFile != "" {
		logf("waiting for %q", lockFile)
		release, lockErr := holdLock(lockFile)
		if lockErr != nil {
			logf("lock %q: %v", lockFile, lockErr)
			return exitUsage
		}
		defer release()
	}
	return runModes(ctx, opt, modes)
}

// runModes runs every requested mode even after one fails, so a single
// invocation reports every verdict, and returns the most serious exit code.
func runModes(ctx context.Context, opt options, modes []string) int {
	code := exitOK
	for _, mode := range modes {
		res, err := runMode(ctx, opt, mode)
		switch {
		case res == nil:
			logf("%q: %v", mode, err)
			return exitIntegrity
		case res.Integrity.Verdict != verdictPass || err != nil:
			code = exitIntegrity
		case res.Performance.Verdict != perfMeasured && code == exitOK:
			code = exitPerf
		}
		if ctx.Err() != nil {
			break
		}
	}
	return code
}

func parseFlags(args []string) (options, []string, string, error) {
	fs := flag.NewFlagSet("receipt-load", flag.ContinueOnError)
	binary := fs.String("binary", "./pipelock", "pipelock binary")
	out := fs.String("out", "", "unique output directory")
	n := fs.Int("requests", 1000000, "measured requests per mode")
	warmup := fs.Int("warmup", 1000, "warmup requests per mode, sent through the same proxy process and excluded from performance")
	concurrency := fs.Int("concurrency", 128, "concurrent clients")
	modes := fs.String("modes", "off,best,required", "comma-separated modes")
	chains := fs.Int("chains", 1, "number of signed receipt chains (1 to 32)")
	rules := fs.String("rules", rulesEmpty, `rule bundles to load: "empty" for none, or a directory that is copied and hashed`)
	seed := fs.Uint64("seed", 1, "workload seed; fixes request keys and which requests are blocked")
	window := fs.Duration("window", 5*time.Second, "width of each per-window rate")
	shutdown := fs.Duration("shutdown-timeout", time.Minute, "how long the proxy gets to exit after SIGTERM before it is killed")
	lock := fs.String("lock-file", "", "advisory lock file held for the whole invocation, to serialize runs on one machine")
	if err := fs.Parse(args); err != nil {
		return options{}, nil, "", err
	}
	if *out == "" || *n < 1 || *warmup < 0 || *concurrency < 1 || *chains < 1 || *chains > 32 || *window <= 0 || *shutdown <= 0 {
		return options{}, nil, "", fmt.Errorf("--out, positive --requests, non-negative --warmup, positive --concurrency, --chains from 1 to 32, and positive --window and --shutdown-timeout are required")
	}
	absBinary, err := filepath.Abs(*binary)
	if err != nil {
		return options{}, nil, "", err
	}
	if info, statErr := os.Stat(absBinary); statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return options{}, nil, "", fmt.Errorf("binary %q is %w", absBinary, errNotExecutable)
	}
	absOut, err := filepath.Abs(*out)
	if err != nil {
		return options{}, nil, "", err
	}
	if err := os.MkdirAll(absOut, 0o750); err != nil {
		return options{}, nil, "", err
	}
	var list []string
	for _, mode := range strings.Split(*modes, ",") {
		if mode != modeOff && mode != modeBest && mode != modeRequired {
			return options{}, nil, "", fmt.Errorf("invalid mode %q", mode)
		}
		list = append(list, mode)
	}
	return options{
		binary: absBinary, out: absOut, rules: *rules, requests: *n, warmup: *warmup, concurrency: *concurrency,
		chains: *chains, seed: *seed, window: *window, shutdownTimeout: *shutdown,
	}, list, *lock, nil
}
