// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package localservice

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestPinValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pin     Pin
		wantErr string
	}{
		{name: "minimal", pin: Pin{ExecutableSHA256: testHashA}},
		{
			name: "full",
			pin: Pin{
				ExecutableSHA256:   testHashA,
				MappedFiles:        []FilePin{{Path: "/opt/app/bundle.mjs", SHA256: testHashB}},
				ControlEnvironment: map[string]string{"NODE_OPTIONS": ""},
			},
		},
		{name: "empty digest", pin: Pin{}, wantErr: "verified_local_service.executable_sha256"},
		{name: "short digest", pin: Pin{ExecutableSHA256: "abc"}, wantErr: "verified_local_service.executable_sha256"},
		{name: "upper case digest", pin: Pin{ExecutableSHA256: strings.ToUpper(testHashA)}, wantErr: "verified_local_service.executable_sha256"},
		{name: "non hex digest", pin: Pin{ExecutableSHA256: strings.Repeat("g", 64)}, wantErr: "verified_local_service.executable_sha256"},
		{
			name:    "relative mapped path",
			pin:     Pin{ExecutableSHA256: testHashA, MappedFiles: []FilePin{{Path: "bundle.mjs", SHA256: testHashB}}},
			wantErr: "verified_local_service.mapped_files[0].path",
		},
		{
			name: "bad mapped digest",
			pin: Pin{ExecutableSHA256: testHashA, MappedFiles: []FilePin{
				{Path: "/a", SHA256: testHashB}, {Path: "/b", SHA256: "zz"},
			}},
			wantErr: "verified_local_service.mapped_files[1].sha256",
		},
		{name: "empty env name", pin: Pin{ExecutableSHA256: testHashA, ControlEnvironment: map[string]string{"": "x"}}, wantErr: "verified_local_service.control_environment"},
		{name: "env name with equals", pin: Pin{ExecutableSHA256: testHashA, ControlEnvironment: map[string]string{"A=B": "x"}}, wantErr: "verified_local_service.control_environment"},
		{name: "env name with NUL", pin: Pin{ExecutableSHA256: testHashA, ControlEnvironment: map[string]string{"A\x00": "x"}}, wantErr: "verified_local_service.control_environment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.pin.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidPin) {
				t.Fatalf("validate() = %v, want ErrInvalidPin", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validate() = %q, want it to name %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), "--server-name") {
				t.Fatalf("validate() = %q names --server-name", err)
			}
		})
	}
}

func TestControlEnvironmentDenyList(t *testing.T) {
	t.Parallel()
	list := ControlEnvironmentDenyList()
	if !sort.StringsAreSorted(list) {
		t.Fatalf("deny list is not sorted: %v", list)
	}
	seen := make(map[string]bool, len(list))
	for _, name := range list {
		if seen[name] {
			t.Fatalf("deny list repeats %q", name)
		}
		seen[name] = true
		if _, ok := controlEnvironmentSet[name]; !ok {
			t.Fatalf("%q missing from the lookup set", name)
		}
		if name == "" || strings.ContainsAny(name, "=\x00") {
			t.Fatalf("deny list holds invalid name %q", name)
		}
	}
	if len(list) != len(controlEnvironmentSet) {
		t.Fatalf("list has %d names, set has %d", len(list), len(controlEnvironmentSet))
	}
	for _, must := range []string{"LD_PRELOAD", "NODE_OPTIONS", "PYTHONPATH", "JAVA_TOOL_OPTIONS", "GLIBC_TUNABLES"} {
		if !seen[must] {
			t.Errorf("deny list lacks %s", must)
		}
	}
	// The exported value is a copy: mutating it must not change the policy.
	list[0] = "MUTATED"
	if _, ok := controlEnvironmentSet["MUTATED"]; ok {
		t.Fatal("mutating the returned slice changed the lookup set")
	}
	if got := ControlEnvironmentDenyList(); got[0] == "MUTATED" {
		t.Fatal("mutating the returned slice changed the list")
	}
}

type stubConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *stubConn) Close() error {
	c.closed.Store(true)
	return nil
}

func TestVerifyingDialContext(t *testing.T) {
	t.Parallel()
	errDial := errors.New("dial failed")
	errVerify := errors.New("verify failed")
	ctx := context.Background()

	t.Run("verify error closes the connection and returns nil", func(t *testing.T) {
		t.Parallel()
		conn := &stubConn{}
		dial := VerifyingDialContext(
			func(context.Context, string, string) (net.Conn, error) { return conn, nil },
			func(context.Context, net.Conn) error { return errVerify },
		)
		got, err := dial(ctx, "tcp", "127.0.0.1:1")
		if !errors.Is(err, errVerify) {
			t.Fatalf("err = %v, want %v", err, errVerify)
		}
		if got != nil {
			t.Fatalf("returned an unverified connection: %v", got)
		}
		if !conn.closed.Load() {
			t.Fatal("connection was not closed after failed verification")
		}
	})

	t.Run("inner dial error passes through", func(t *testing.T) {
		t.Parallel()
		var verified atomic.Bool
		dial := VerifyingDialContext(
			func(context.Context, string, string) (net.Conn, error) { return nil, errDial },
			func(context.Context, net.Conn) error { verified.Store(true); return nil },
		)
		got, err := dial(ctx, "tcp", "127.0.0.1:1")
		if !errors.Is(err, errDial) {
			t.Fatalf("err = %v, want %v", err, errDial)
		}
		if got != nil {
			t.Fatalf("returned a connection on dial error: %v", got)
		}
		if verified.Load() {
			t.Fatal("verify ran without a connection")
		}
	})

	t.Run("success returns the connection", func(t *testing.T) {
		t.Parallel()
		conn := &stubConn{}
		var seen net.Conn
		var seenCtx context.Context
		dial := VerifyingDialContext(
			func(context.Context, string, string) (net.Conn, error) { return conn, nil },
			func(c context.Context, nc net.Conn) error { seenCtx, seen = c, nc; return nil },
		)
		got, err := dial(ctx, "tcp", "127.0.0.1:1")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if got != net.Conn(conn) || seen != net.Conn(conn) {
			t.Fatal("verify and caller must see the dialed connection")
		}
		if seenCtx != ctx {
			t.Fatal("verify must receive the dial context")
		}
		if conn.closed.Load() {
			t.Fatal("verified connection was closed")
		}
	})

	t.Run("missing hooks refuse", func(t *testing.T) {
		t.Parallel()
		okDial := func(context.Context, string, string) (net.Conn, error) { return &stubConn{}, nil }
		okVerify := func(context.Context, net.Conn) error { return nil }
		for name, dial := range map[string]DialContextFunc{
			"nil inner":  VerifyingDialContext(nil, okVerify),
			"nil verify": VerifyingDialContext(okDial, nil),
		} {
			got, err := dial(ctx, "tcp", "127.0.0.1:1")
			if !errors.Is(err, errNilDialHook) || got != nil {
				t.Errorf("%s: got (%v, %v), want (nil, errNilDialHook)", name, got, err)
			}
		}
	})
}

func TestVerifyConnUnsupportedPlatform(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "linux" {
		t.Skip("Linux verifies; the refusal applies to every other platform")
	}
	_, err := NewVerifier().VerifyConn(&stubConn{}, Pin{ExecutableSHA256: testHashA})
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("VerifyConn = %v, want ErrUnsupportedPlatform", err)
	}
	_, err = NewVerifier().VerifyConnContext(context.Background(), &stubConn{}, Pin{ExecutableSHA256: testHashA})
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("VerifyConnContext = %v, want ErrUnsupportedPlatform", err)
	}
}

func TestObserveUnsupportedPlatform(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "linux" {
		t.Skip("Linux observes; the refusal applies to every other platform")
	}
	obs, err := NewVerifier().Observe(context.Background(), &stubConn{})
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Observe = %v, want ErrUnsupportedPlatform", err)
	}
	if obs.PID != 0 || len(obs.Files) != 0 {
		t.Fatalf("refusal returned %+v", obs)
	}
}
