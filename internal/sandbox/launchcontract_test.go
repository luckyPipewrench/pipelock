// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/launchcontract"
)

func TestBridgeProxySharedParity(t *testing.T) {
	t.Parallel()
	want := launchcontract.Entries(launchcontract.Vars(launchcontract.Sandbox, "http://127.0.0.1:8888", "", "", ""))
	got := bridgeProxyEnv("127.0.0.1:8888")
	legacy := []string{"HTTP_PROXY=http://127.0.0.1:8888", "HTTPS_PROXY=http://127.0.0.1:8888", "http_proxy=http://127.0.0.1:8888", "https_proxy=http://127.0.0.1:8888", "NO_PROXY=", "no_proxy="}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(got, legacy) {
		t.Fatalf("bridge proxy environment changed: %v, shared=%v legacy=%v", got, want, legacy)
	}
}
