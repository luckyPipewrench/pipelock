// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestVerifyConnRechecksOwnerState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*fakeProc)
		want   error
	}{
		{"executable replaced without PID reuse", func(f *fakeProc) {
			f.write(strconv.Itoa(fakePID)+"/exe", "different executable")
		}, ErrOwnerChanged},
		{"another process acquires the socket", func(f *fakeProc) {
			f.addProcess(fakePID + 1)
		}, ErrMultipleOwners},
		{"effective principal changes", func(f *fakeProc) {
			f.write(strconv.Itoa(fakePID)+"/status", fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d\n", fakeUID, fakeUID+1, fakeUID, fakeUID))
		}, ErrPrincipalMismatch},
		{"control environment changes", func(f *fakeProc) {
			f.write(strconv.Itoa(fakePID)+"/environ", "NODE_OPTIONS=--require=other.js\x00")
		}, ErrControlEnvironment},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeProc(t)
			if _, err := f.verify(); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			f.v.beforeRecheck = func() { tt.change(f) }
			ev, err := f.verify()
			if !errors.Is(err, tt.want) {
				t.Fatalf("VerifyConn = %v, want %v; evidence %+v", err, tt.want, ev)
			}
			if ev.PID != 0 {
				t.Fatalf("refusal returned evidence %+v", ev)
			}
		})
	}
}

func TestVerifyConnRechecksHeldFile(t *testing.T) {
	f := newFakeProc(t)
	p := f.pinnedFile(pinnedContent)
	f.pin.MappedFiles = []FilePin{{Path: p, SHA256: sha256Hex([]byte(pinnedContent))}}
	f.symlink(p, strconv.Itoa(fakePID)+"/fd/4")
	if _, err := f.verify(); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	f.v.beforeRecheck = func() { f.remove(strconv.Itoa(fakePID) + "/fd/4") }
	if ev, err := f.verify(); !errors.Is(err, ErrApplicationMismatch) {
		t.Fatalf("VerifyConn = %v, want ErrApplicationMismatch; evidence %+v", err, ev)
	}
}

func TestObserveRechecksOwnerState(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeProc)
		want   error
	}{
		{"executable changes", func(f *fakeProc) {
			f.write(strconv.Itoa(fakePID)+"/exe", "different executable")
		}, ErrOwnerChanged},
		{"another process acquires the socket", func(f *fakeProc) {
			f.addProcess(fakePID + 1)
		}, ErrMultipleOwners},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeProc(t)
			if _, err := f.observe(); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			f.v.beforeRecheck = func() { tt.change(f) }
			if obs, err := f.observe(); !errors.Is(err, tt.want) {
				t.Fatalf("Observe = %v, want %v; observation %+v", err, tt.want, obs)
			}
		})
	}
}

func TestVerifyConnRejectsExecDuringVerification(t *testing.T) {
	h := startServer(t, modeExec, loopbackAny)
	conn := dialAccepted(t, h, "")
	v := NewVerifier()
	pin := basePin(t)
	before, err := v.readIncarnation(h.cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	v.beforeRecheck = func() {
		if _, err := io.WriteString(h.stdin, helperExecCmd+"\n"); err != nil {
			t.Fatal(err)
		}
		testwait.For(t, 10*time.Second, func() bool {
			_, _, sum, err := v.executableDigest(h.cmd.Process.Pid)
			return err == nil && sum != pin.ExecutableSHA256
		}, "helper to exec cat")
		if after, err := v.readIncarnation(h.cmd.Process.Pid); err != nil || after != before {
			t.Fatalf("exec changed incarnation: %+v, %v", after, err)
		}
		if _, err := os.Stat(v.pidPath(h.cmd.Process.Pid, "fd")); err != nil {
			t.Fatal(err)
		}
	}
	if ev, err := v.VerifyConn(conn, pin); !errors.Is(err, ErrOwnerChanged) {
		t.Fatalf("VerifyConn after exec = %v, want ErrOwnerChanged; evidence %+v", err, ev)
	}
}
