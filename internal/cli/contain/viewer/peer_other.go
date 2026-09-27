// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package viewer

import (
	"errors"
	"net"
)

func peerUID(net.Conn) (uint32, error) { return 0, errors.New("RFB peer credentials unavailable") }
