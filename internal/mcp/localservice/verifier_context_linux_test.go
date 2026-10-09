// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"context"
	"errors"
	"testing"
)

func TestOwnerCheckCanceledContext(t *testing.T) {
	for _, observe := range []bool{false, true} {
		for _, during := range []bool{false, true} {
			t.Run(testContextCase(observe, during), func(t *testing.T) {
				f := newFakeProc(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if during {
					f.v.beforeRecheck = cancel
				} else {
					cancel()
				}
				var err error
				if observe {
					_, err = f.v.Observe(ctx, f.client)
				} else {
					_, err = f.v.VerifyConnContext(ctx, f.client, f.pin)
				}
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("owner check = %v, want context.Canceled", err)
				}
			})
		}
	}
}

func testContextCase(observe, during bool) string {
	name := "verify"
	if observe {
		name = "observe"
	}
	if during {
		return name + "/canceled during check"
	}
	return name + "/already canceled"
}
