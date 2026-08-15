// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const rlimitNProcRegressionEnv = "__PIPELOCK_RLIMIT_NPROC_REGRESSION"

func TestSharedUIDNProcLimit(t *testing.T) {
	tests := []struct {
		name         string
		tasks        uint64
		inheritedMax uint64
		want         uint64
		wantErr      string
	}{
		{
			name:         "preserves full sandbox headroom",
			tasks:        rlimitNProc + 1,
			inheritedMax: unix.RLIM_INFINITY,
			want:         2*rlimitNProc + 1,
		},
		{
			name:         "uses usable inherited hard cap",
			tasks:        rlimitNProc + 1,
			inheritedMax: rlimitNProc + 2,
			want:         rlimitNProc + 2,
		},
		{
			name:         "rejects inherited cap already exhausted",
			tasks:        rlimitNProc + 1,
			inheritedMax: rlimitNProc + 1,
			wantErr:      "already has",
		},
		{
			name:         "rejects task-count overflow",
			tasks:        math.MaxUint64,
			inheritedMax: unix.RLIM_INFINITY,
			wantErr:      "overflows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sharedUIDNProcLimit(tt.tasks, tt.inheritedMax)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("sharedUIDNProcLimit(%d, %d) error = %v, want %q", tt.tasks, tt.inheritedMax, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("sharedUIDNProcLimit(%d, %d): %v", tt.tasks, tt.inheritedMax, err)
			}
			if got != tt.want {
				t.Fatalf("sharedUIDNProcLimit(%d, %d) = %d, want %d", tt.tasks, tt.inheritedMax, got, tt.want)
			}
		})
	}
}

func TestProcessRealUID(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		want    int
		wantErr string
	}{
		{name: "valid", status: "Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n", want: 1000},
		{name: "missing", status: "Name:\ttest\n", wantErr: "missing"},
		{name: "malformed", status: "Uid:\tnope\t1000\n", wantErr: "invalid syntax"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := processRealUID([]byte(tt.status))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("processRealUID(%q) error = %v, want %q", tt.status, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("processRealUID(%q): %v", tt.status, err)
			}
			if got != tt.want {
				t.Fatalf("processRealUID(%q) = %d, want %d", tt.status, got, tt.want)
			}
		})
	}
}

func TestCurrentUIDTaskCount(t *testing.T) {
	tasks, err := currentUIDTaskCount()
	if err != nil {
		t.Fatalf("currentUIDTaskCount: %v", err)
	}
	if tasks == 0 {
		t.Fatal("currentUIDTaskCount = 0, want current test-process task")
	}
}

func TestApplyRlimits_BestEffortAvoidsSubCurrentNProcAbort(t *testing.T) {
	if mode := os.Getenv(rlimitNProcRegressionEnv); mode != "" {
		runNProcRegressionChild(mode)
	}

	for _, tt := range []struct {
		name string
		mode string
		want string
	}{
		{name: "fixed sub-current cap blocks child", mode: "fixed", want: "fixed cap child: resource temporarily unavailable"},
		{name: "best effort dynamically leaves child headroom", mode: "best-effort", want: "best-effort child succeeded"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestApplyRlimits_BestEffortAvoidsSubCurrentNProcAbort$")
			cmd.Env = append(os.Environ(), rlimitNProcRegressionEnv+"="+tt.mode)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("%s child timed out: %v\n%s", tt.name, ctx.Err(), out)
			}
			if err != nil {
				t.Fatalf("%s child failed: %v\n%s", tt.name, err, out)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Fatalf("%s child output = %q, want %q", tt.name, out, tt.want)
			}
		})
	}
}

func runNProcRegressionChild(mode string) {
	switch mode {
	case "fixed":
		if err := unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{}); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "set fixed RLIMIT_NPROC: %v\n", err)
			os.Exit(1)
		}
		if err := exec.CommandContext(context.Background(), "/bin/true").Run(); !errors.Is(err, syscall.EAGAIN) {
			_, _ = fmt.Fprintf(os.Stderr, "fixed cap child error = %v, want EAGAIN\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintln(os.Stdout, "fixed cap child: resource temporarily unavailable")
	case "best-effort":
		if err := ApplyRlimits(false); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "apply best-effort rlimits: %v\n", err)
			os.Exit(1)
		}
		if err := exec.CommandContext(context.Background(), "/bin/true").Run(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "best-effort child: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintln(os.Stdout, "best-effort child succeeded")
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown regression mode %q\n", mode)
		os.Exit(1)
	}
	os.Exit(0)
}
