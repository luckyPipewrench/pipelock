// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

// sdNotify sends a message using the protocol documented by sd_notify(3) and
// systemd.service(5). It deliberately has no dependency on go-systemd.
func sdNotify(state string) (bool, error) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return false, nil
	}

	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	conn, err := dialer.Dial("unixgram", socket)
	if err != nil {
		return false, fmt.Errorf("dial NOTIFY_SOCKET: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return false, fmt.Errorf("set NOTIFY_SOCKET deadline: %w", err)
	}
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, fmt.Errorf("write NOTIFY_SOCKET: %w", err)
	}
	return true, nil
}

func sdNotifyOrLog(stderr io.Writer, state string) {
	if _, err := sdNotify(state); err != nil {
		_, _ = fmt.Fprintf(stderr, "pipelock: systemd notification failed: %v\n", err)
	}
}

func sdNotifyReloading(stderr io.Writer) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		_, _ = fmt.Fprintf(stderr, "pipelock: systemd notification failed: read monotonic clock: %v\n", err)
		return
	}
	sdNotifyOrLog(stderr, fmt.Sprintf("RELOADING=1\nMONOTONIC_USEC=%d", ts.Nano()/int64(time.Microsecond)))
}

// sdNotifyStatusMaxBytes bounds the reason text that rides in the completion
// datagram. The reason is derived from configuration the operator controls, so
// it is unbounded at the source; a datagram too large for the socket fails to
// send, and READY travels in that same datagram, so an oversized status would
// cost the completion systemd is waiting on. The operator log keeps the
// untruncated error either way.
const sdNotifyStatusMaxBytes = 256

func sdNotifyReloadComplete(stderr io.Writer, reloadErr error) {
	status := "config reload applied"
	if reloadErr != nil {
		status = "config reload rejected: " + sdNotifyStatusReason(reloadErr)
	}
	if _, err := sdNotify("READY=1\nSTATUS=" + status); err != nil {
		_, _ = fmt.Fprintf(stderr, "pipelock: systemd notification failed: %v\n", err)
		// Belt and braces: retry the completion on its own. Whatever made the
		// combined datagram unsendable, systemd is still waiting for READY and
		// the reload job must not hang on a status string.
		sdNotifyOrLog(stderr, "READY=1")
	}
}

// sdNotifyStatusReason renders an error as one bounded, control-character-free
// line fit for a systemd status field.
func sdNotifyStatusReason(err error) string {
	reason := strings.SplitN(err.Error(), "\n", 2)[0]
	reason = strings.TrimPrefix(reason, "rejected: ")
	// Printability, not a byte range. A range check that keeps everything at or
	// above 0x20 lets the C1 controls through (U+0080-U+009F, including the
	// U+009B escape introducer), along with NEL and the Unicode line and
	// paragraph separators, all of which can still steer a terminal reading
	// systemd status or an audit log. unicode.IsPrint excludes every control
	// character in both ranges and keeps ordinary ASCII space.
	reason = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, reason)
	reason = strings.TrimSpace(reason)
	if len(reason) > sdNotifyStatusMaxBytes {
		reason = strings.ToValidUTF8(reason[:sdNotifyStatusMaxBytes], "") + "..."
	}
	return reason
}
