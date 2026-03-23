// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

// Netlink message types and flags for RTM_NEWLINK.
const (
	nlmsgHdrLen  = 16 // sizeof(nlmsghdr)
	ifInfoMsgLen = 16 // sizeof(ifinfomsg)
)

// loopbackUp brings up the loopback interface using raw netlink syscalls.
// This avoids requiring the `ip` binary in minimal container images.
func loopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	// Build RTM_NEWLINK message to set IFF_UP on loopback (index 1).
	msgLen := nlmsgHdrLen + ifInfoMsgLen
	buf := make([]byte, msgLen)

	// nlmsghdr
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))                          // nlmsg_len
	binary.LittleEndian.PutUint16(buf[4:6], syscall.RTM_NEWLINK)                     // nlmsg_type
	binary.LittleEndian.PutUint16(buf[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK) // nlmsg_flags
	binary.LittleEndian.PutUint32(buf[8:12], 1)                                      // nlmsg_seq
	binary.LittleEndian.PutUint32(buf[12:16], 0)                                     // nlmsg_pid

	// ifinfomsg
	buf[nlmsgHdrLen+0] = syscall.AF_UNSPEC                                            // ifi_family
	binary.LittleEndian.PutUint16(buf[nlmsgHdrLen+2:nlmsgHdrLen+4], 0)                // pad / ifi_type
	binary.LittleEndian.PutUint32(buf[nlmsgHdrLen+4:nlmsgHdrLen+8], 1)                // ifi_index (lo = 1)
	binary.LittleEndian.PutUint32(buf[nlmsgHdrLen+8:nlmsgHdrLen+12], syscall.IFF_UP)  // ifi_flags
	binary.LittleEndian.PutUint32(buf[nlmsgHdrLen+12:nlmsgHdrLen+16], syscall.IFF_UP) // ifi_change

	if err := syscall.Sendto(fd, buf, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}

	// Read ACK.
	ack := make([]byte, 1024)
	n, _, err := syscall.Recvfrom(fd, ack, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}

	// Parse the nlmsghdr to check for NLMSG_ERROR.
	if n >= nlmsgHdrLen {
		msgType := binary.LittleEndian.Uint16(ack[4:6])
		if msgType == syscall.NLMSG_ERROR {
			// Error code is a negative errno (int32) at offset 16 (after nlmsghdr).
			if n >= nlmsgHdrLen+4 {
				errInt := int32(binary.LittleEndian.Uint32(ack[nlmsgHdrLen : nlmsgHdrLen+4])) //nolint:gosec // G115: reinterpreting uint32 as int32 for netlink signed errno
				if errInt < 0 {
					return fmt.Errorf("netlink error: %w", syscall.Errno(-errInt)) //nolint:gosec // G115: negated int32 fits in syscall.Errno
				}
			}
		}
	}

	return nil
}
