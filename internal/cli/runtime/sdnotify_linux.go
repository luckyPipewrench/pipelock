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

func sdNotifyReloadComplete(stderr io.Writer, reloadErr error) {
	status := "config reload applied"
	if reloadErr != nil {
		status = "config reload rejected: " + sdNotifyStatusReason(reloadErr)
	}
	sdNotifyOrLog(stderr, "READY=1\nSTATUS="+status)
}

func sdNotifyStatusReason(err error) string {
	reason := strings.SplitN(err.Error(), "\n", 2)[0]
	reason = strings.TrimPrefix(reason, "rejected: ")
	return strings.TrimSpace(strings.ReplaceAll(reason, "\r", " "))
}
