// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
)

// testCEEIdentity models a server-owned test session. HTTP identity tests use
// NewCEEIdentity directly so their authentication grade remains explicit.
func testCEEIdentity(key string) identitykey.CEEIdentity {
	return identitykey.NewCEEIdentity("", key, envelope.ActorAuthSelfDeclared)
}

func testCEEStream(key string) identitykey.CEEStream {
	return testCEEIdentity(key).Stream("")
}
