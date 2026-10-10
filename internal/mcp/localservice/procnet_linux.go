// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// tcpStateEstablished is TCP_ESTABLISHED in include/net/tcp_states.h.
	tcpStateEstablished = 0x01
	// minNetTCPFields is the column count up to and including the inode.
	minNetTCPFields = 10
	netTCPAddrV4Len = 4
	netTCPAddrV6Len = 16
	netTCPWordLen   = 4
)

// sockRow is one parsed line of /proc/net/tcp or /proc/net/tcp6.
type sockRow struct {
	local  netip.AddrPort
	remote netip.AddrPort
	state  uint8
	uid    uint32
	inode  uint64
}

// parseNetTCP parses the text of /proc/net/tcp or /proc/net/tcp6. Header and
// malformed lines are skipped: a line that cannot be understood must not match
// a connection.
func parseNetTCP(data []byte) []sockRow {
	var rows []sockRow
	for _, line := range strings.Split(string(data), "\n") {
		if row, ok := parseNetTCPLine(line); ok {
			rows = append(rows, row)
		}
	}
	return rows
}

// parseNetTCPLine reads columns local_address (1), rem_address (2), st (3),
// uid (7) and inode (9) as documented in proc_net_tcp(5).
func parseNetTCPLine(line string) (sockRow, bool) {
	fields := strings.Fields(line)
	if len(fields) < minNetTCPFields {
		return sockRow{}, false
	}
	local, ok := parseNetTCPAddr(fields[1])
	if !ok {
		return sockRow{}, false
	}
	remote, ok := parseNetTCPAddr(fields[2])
	if !ok {
		return sockRow{}, false
	}
	state, err := strconv.ParseUint(fields[3], 16, 8)
	if err != nil {
		return sockRow{}, false
	}
	uid, err := strconv.ParseUint(fields[7], 10, 32)
	if err != nil {
		return sockRow{}, false
	}
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return sockRow{}, false
	}
	return sockRow{local: local, remote: remote, state: uint8(state), uid: uint32(uid), inode: inode}, true
}

// parseNetTCPAddr parses "ADDR:PORT". The kernel prints each 32-bit address
// word as a host-order integer in hex, so the text is read as a big-endian
// number and stored back with the host byte order to recover network-order
// bytes on any architecture. The result is unmapped, so a dual-stack socket
// bound to ::ffff:127.0.0.1 compares equal to 127.0.0.1.
func parseNetTCPAddr(s string) (netip.AddrPort, bool) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != netTCPAddrV4Len && len(raw) != netTCPAddrV6Len) {
		return netip.AddrPort{}, false
	}
	var b [netTCPAddrV6Len]byte
	for i := 0; i < len(raw); i += netTCPWordLen {
		binary.NativeEndian.PutUint32(b[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	var addr netip.Addr
	if len(raw) == netTCPAddrV4Len {
		addr = netip.AddrFrom4([netTCPAddrV4Len]byte(b[:netTCPAddrV4Len]))
	} else {
		addr = netip.AddrFrom16(b)
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}
