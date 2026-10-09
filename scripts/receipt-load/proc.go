// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type procSample struct {
	at    time.Time
	ticks uint64
	rss   int64
}

// localCommand builds a command for the validated local test binary. The
// context is attached through exec.CommandContext with a constant name; the
// resolved path and arguments are then set explicitly. The command runs in a
// pinned directory with a pinned environment.
func localCommand(ctx context.Context, binary, dir string, env []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "pipelock")
	cmd.Err = nil
	cmd.Path = binary
	cmd.Args = append([]string{binary}, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.WaitDelay = time.Second
	return cmd
}

func freePort(ctx context.Context) (int, error) {
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	tcp, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		_ = l.Close()
		return 0, errors.New("listener address is not TCP")
	}
	return tcp.Port, l.Close()
}

func awaitProxy(ctx context.Context, addr string, p *proxyProc) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.exited:
			if p.exitErr == nil {
				return fmt.Errorf("proxy exited before listening on %s", addr)
			}
			return fmt.Errorf("proxy exited before listening on %s: %w", addr, p.exitErr)
		case <-deadline.C:
			return fmt.Errorf("proxy did not listen on %s", addr)
		case <-ticker.C:
		}
	}
}

func readProc(pid int) (procSample, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procSample{}, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return procSample{}, errors.New("invalid proc stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 22 {
		return procSample{}, errors.New("short proc stat")
	}
	u, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return procSample{}, err
	}
	s, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return procSample{}, err
	}
	rssPages, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return procSample{}, err
	}
	return procSample{at: time.Now(), ticks: u + s, rss: rssPages * int64(os.Getpagesize())}, nil
}

func evidenceBytes(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			if info, statErr := entry.Info(); statErr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}
