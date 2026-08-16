// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/http"
	"testing"
)

func TestWithDLPWarnContextNilUsesBackground(t *testing.T) {
	t.Parallel()

	wc := DLPWarnContext{
		Method:    http.MethodGet,
		URL:       "https://api.vendor.example/collect",
		Transport: "fetch",
		ClientIP:  "192.0.2.10",
	}
	var parent context.Context
	ctx := WithDLPWarnContext(parent, wc)
	if ctx == nil {
		t.Fatal("WithDLPWarnContext(nil parent) returned nil context")
	}
	got := DLPWarnContextFromCtx(ctx)
	if got != wc {
		t.Fatalf("round-trip from nil parent = %+v, want %+v", got, wc)
	}
}

func TestDLPWarnContextFromCtxNilAndUnset(t *testing.T) {
	t.Parallel()

	var unset context.Context
	if got := DLPWarnContextFromCtx(unset); got != (DLPWarnContext{}) {
		t.Fatalf("nil context = %+v, want zero value", got)
	}
	if got := DLPWarnContextFromCtx(context.Background()); got != (DLPWarnContext{}) {
		t.Fatalf("unset context = %+v, want zero value", got)
	}
}
