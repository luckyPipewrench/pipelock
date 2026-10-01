// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package dialfallback

import (
	"context"
	"errors"
	"net"
	"testing"
)

var errRefused = errors.New("refused")

// stubDialer ignores its context, as a dial function is free to, and records
// the addresses it was asked for.
type stubDialer struct {
	tried   []string
	succeed string
	onCall  func()
}

func (s *stubDialer) dial(_ context.Context, addr string) (net.Conn, error) {
	s.tried = append(s.tried, addr)
	if s.onCall != nil {
		s.onCall()
	}
	if addr == s.succeed {
		c, _ := net.Pipe()
		return c, nil
	}
	return nil, errRefused
}

func TestDial_FirstReachableWins(t *testing.T) {
	s := &stubDialer{succeed: "b"}
	conn, err := Dial(context.Background(), []string{"a", "b", "c"}, s.dial)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(s.tried) != 2 || s.tried[0] != "a" || s.tried[1] != "b" {
		t.Errorf("tried %v, want [a b] in resolver order", s.tried)
	}
}

func TestDial_AttemptsAreBounded(t *testing.T) {
	s := &stubDialer{succeed: "e"}
	_, err := Dial(context.Background(), []string{"a", "b", "c", "d", "e"}, s.dial)
	if !errors.Is(err, errRefused) {
		t.Fatalf("err = %v, want the last attempt's error", err)
	}
	if len(s.tried) != MaxAttempts {
		t.Errorf("attempts = %d (%v), want %d", len(s.tried), s.tried, MaxAttempts)
	}
}

func TestDial_ThirdAddressStillTried(t *testing.T) {
	s := &stubDialer{succeed: "c"}
	conn, err := Dial(context.Background(), []string{"a", "b", "c", "d"}, s.dial)
	if err != nil {
		t.Fatalf("address %d of %d must be reachable: %v", MaxAttempts, MaxAttempts, err)
	}
	_ = conn.Close()
}

// The dial function ignores its context, so only the explicit check between
// attempts stops the loop once the context is done.
func TestDial_DoneContextStopsFurtherAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &stubDialer{onCall: cancel}
	_, err := Dial(ctx, []string{"a", "b", "c"}, s.dial)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(s.tried) != 1 {
		t.Errorf("attempts = %d, want 1: a done context must stop the loop", len(s.tried))
	}
}

func TestDial_DoneContextBeforeFirstAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &stubDialer{}
	_, err := Dial(ctx, []string{"a"}, s.dial)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(s.tried) != 0 {
		t.Errorf("attempts = %d, want 0", len(s.tried))
	}
}

func TestDial_NoAddresses(t *testing.T) {
	s := &stubDialer{}
	if _, err := Dial(context.Background(), nil, s.dial); err == nil {
		t.Fatal("expected an error for an empty address list")
	}
}
