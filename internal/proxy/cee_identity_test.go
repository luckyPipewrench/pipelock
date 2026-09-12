// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
)

func testCEEIdentity(key string) identitykey.CEEIdentity {
	return identitykey.NewCEEIdentity("", key, envelope.ActorAuthSelfDeclared)
}

func testCEEStream(key string) identitykey.CEEStream {
	return testCEEIdentity(key).Stream("")
}
