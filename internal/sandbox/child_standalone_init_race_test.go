// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"testing"
)

func TestBridgeLifecycle_PreservesReadyBridgeFailure(t *testing.T) {
	for range 10_000 {
		bridgeErr := make(chan error, 1)
		agentDone := make(chan error, 1)
		bridgeErr <- errors.New("parent socket lost")
		agentDone <- nil

		agentErr, bridgeFailure := waitStandaloneAgentAndBridge(agentDone, bridgeErr, func() {})
		if agentErr != nil || bridgeFailure == nil {
			t.Fatalf("agent error = %v, bridge failure = %v; want nil agent error and bridge failure", agentErr, bridgeFailure)
		}
	}
}

func TestBridgeLifecycle_StopsBridgeAfterAgentExit(t *testing.T) {
	bridgeErr := make(chan error, 1)
	agentDone := make(chan error, 1)
	agentDone <- nil
	stopped := false

	agentErr, bridgeFailure := waitStandaloneAgentAndBridge(agentDone, bridgeErr, func() {
		stopped = true
		bridgeErr <- nil
	})
	if agentErr != nil || bridgeFailure != nil || !stopped {
		t.Fatalf("agent error = %v, bridge failure = %v, stopped = %t; want clean stopped bridge", agentErr, bridgeFailure, stopped)
	}
}
