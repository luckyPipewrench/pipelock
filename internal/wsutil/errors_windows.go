// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package wsutil

import (
	"errors"
	"syscall"
)

// isPlatformClosedErr recognizes the Windows Winsock errnos that are the
// platform equivalents of the Unix "connection reset by peer" / "broken
// pipe" teardown conditions IsExpectedCloseErr already treats as a clean
// close. An abortive close on Windows surfaces as WSAECONNABORTED ("An
// established connection was aborted by the software in your host machine")
// or WSAECONNRESET ("forcibly closed by the remote host"); without this the
// proxy reports a read error on a peer hangup that Unix reports as io.EOF.
// Matching by errno via errors.Is avoids depending on locale-sensitive
// error text.
func isPlatformClosedErr(err error) bool {
	return errors.Is(err, syscall.WSAECONNABORTED) ||
		errors.Is(err, syscall.WSAECONNRESET)
}
