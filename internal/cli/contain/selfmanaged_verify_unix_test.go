// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package contain

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

type rootFileInfo struct{ mode fs.FileMode }

func (rootFileInfo) Name() string { return "nft" }
func (rootFileInfo) Size() int64  { return 1 }
func (f rootFileInfo) Mode() fs.FileMode {
	if f.mode == 0 {
		return 0o755
	}
	return f.mode
}
func (rootFileInfo) ModTime() time.Time { return time.Time{} }
func (rootFileInfo) IsDir() bool        { return false }
func (rootFileInfo) Sys() any           { return fakeFileSysWithUID(0) }

func TestVerifySelfManagedNFTRulesWithDependencies(t *testing.T) {
	t.Parallel()
	canonical := renderNFTRules(1000, 1001, 10001, 8888, defaultNFTTable, defaultNFTChain)
	statSecondPath := func(path string) (fs.FileInfo, error) {
		if path == "/usr/sbin/nft" {
			return nil, os.ErrNotExist
		}
		return rootFileInfo{}, nil
	}

	var gotPath string
	run := func(ctx context.Context, path string, args ...string) ([]byte, error) {
		gotPath = path
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		if strings.Join(args, " ") != "-n -a list chain inet pipelock_containment output_filter" {
			t.Fatalf("args = %q", args)
		}
		return []byte(canonical), nil
	}
	baseOpts := selfManagedNFTVerifyOptions{
		ctx: context.Background(), operatorUID: 1000, proxyUID: 1001,
		agentUID: 10001, proxyPort: 8888, statFn: statSecondPath, run: run,
	}
	if err := verifySelfManagedNFTRules(baseOpts); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if gotPath != "/usr/bin/nft" {
		t.Fatalf("nft path = %q", gotPath)
	}

	t.Run("command failure includes output", func(t *testing.T) {
		runErr := func(context.Context, string, ...string) ([]byte, error) {
			return []byte("permission denied\n"), errors.New("exit 1")
		}
		opts := baseOpts
		opts.run = runErr
		err := verifySelfManagedNFTRules(opts)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("trusted executable absent", func(t *testing.T) {
		missing := func(string) (fs.FileInfo, error) { return nil, os.ErrNotExist }
		opts := baseOpts
		opts.statFn = missing
		if err := verifySelfManagedNFTRules(opts); err == nil {
			t.Fatal("missing nft executable accepted")
		}
	})

	t.Run("untrusted executable rejected", func(t *testing.T) {
		writable := func(string) (fs.FileInfo, error) { return rootFileInfo{mode: 0o777}, nil }
		opts := baseOpts
		opts.statFn = writable
		if err := verifySelfManagedNFTRules(opts); err == nil {
			t.Fatal("world-writable nft executable accepted")
		}
	})

	t.Run("command receives bounded context", func(t *testing.T) {
		opts := baseOpts
		opts.run = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > selfManagedNFTTimeout {
				t.Fatalf("bounded deadline missing or too long: %v, %v", deadline, ok)
			}
			return []byte(canonical), nil
		}
		if err := verifySelfManagedNFTRules(opts); err != nil {
			t.Fatalf("verify with bounded context: %v", err)
		}
	})
}

func TestRunNFTCommand(t *testing.T) {
	t.Parallel()
	out, err := runNFTCommand(context.Background(), "/bin/sh", "-c", "printf nft-ok")
	if err != nil || string(out) != "nft-ok" {
		t.Fatalf("runNFTCommand output=%q err=%v", out, err)
	}
}
