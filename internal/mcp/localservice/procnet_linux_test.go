// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// procAddr renders an address the way the kernel prints it in /proc/net/tcp:
// each 32-bit word of the network-order address as a host-order integer.
func procAddr(ap netip.AddrPort) string {
	var raw []byte
	if ap.Addr().Is4() {
		b := ap.Addr().As4()
		raw = b[:]
	} else {
		b := ap.Addr().As16()
		raw = b[:]
	}
	var sb strings.Builder
	for i := 0; i < len(raw); i += netTCPWordLen {
		_, _ = fmt.Fprintf(&sb, "%08X", binary.NativeEndian.Uint32(raw[i:]))
	}
	_, _ = fmt.Fprintf(&sb, ":%04X", ap.Port())
	return sb.String()
}

// procRow renders one line of /proc/net/tcp.
func procRow(idx int, local, remote netip.AddrPort, state, uid, inode uint64) string {
	return fmt.Sprintf("%4d: %s %s %02X 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0",
		idx, procAddr(local), procAddr(remote), state, uid, inode)
}

const procNetHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func TestParseNetTCPAddr(t *testing.T) {
	t.Parallel()
	little := binary.NativeEndian.Uint16([]byte{1, 0}) == 1
	tests := []struct {
		name    string
		in      string
		want    string
		wantOK  bool
		needsLE bool
	}{
		{name: "v4 loopback literal", in: "0100007F:0050", want: "127.0.0.1:80", wantOK: true, needsLE: true},
		{name: "v6 loopback literal", in: "00000000000000000000000001000000:1F90", want: "[::1]:8080", wantOK: true, needsLE: true},
		{name: "v4 mapped literal", in: "0000000000000000FFFF00000100007F:0050", want: "127.0.0.1:80", wantOK: true, needsLE: true},
		{name: "v4 round trip", in: procAddr(netip.MustParseAddrPort("127.9.8.7:4242")), want: "127.9.8.7:4242", wantOK: true},
		{name: "v6 round trip", in: procAddr(netip.MustParseAddrPort("[2001:db8::7]:4242")), want: "[2001:db8::7]:4242", wantOK: true},
		{name: "mapped round trip", in: procAddr(netip.MustParseAddrPort("[::ffff:127.0.0.1]:9")), want: "127.0.0.1:9", wantOK: true},
		{name: "no colon", in: "0100007F0050"},
		{name: "bad port", in: "0100007F:ZZZZ"},
		{name: "port too large", in: "0100007F:10000"},
		{name: "bad host hex", in: "0100007G:0050"},
		{name: "odd host length", in: "0100007:0050"},
		{name: "wrong host length", in: "0100007F00:0050"},
		{name: "empty", in: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.needsLE && !little {
				t.Skip("literal is little-endian")
			}
			got, ok := parseNetTCPAddr(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got %v)", ok, tt.wantOK, got)
			}
			if ok && got.String() != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseNetTCP(t *testing.T) {
	t.Parallel()
	local := netip.MustParseAddrPort("127.0.0.1:40000")
	remote := netip.MustParseAddrPort("127.0.0.1:41000")
	good := procRow(0, local, remote, 1, 1000, 777)

	tests := []struct {
		name string
		data string
		want []sockRow
	}{
		{name: "empty", data: ""},
		{name: "header only", data: procNetHeader},
		{
			name: "one row",
			data: procNetHeader + good + "\n",
			want: []sockRow{{local: local, remote: remote, state: 1, uid: 1000, inode: 777}},
		},
		{
			name: "malformed lines are skipped",
			data: procNetHeader +
				"garbage\n" +
				"   1: 0100007F:ZZ 0100007F:0050 01 00000000:00000000 00:00000000 00000000 1000 0 5\n" +
				"   2: 0100007F:0050 nocolon 01 00000000:00000000 00:00000000 00000000 1000 0 5\n" +
				procRow(3, local, remote, 1, 1000, 1)[:40] + "\n" +
				"   4: " + procAddr(local) + " " + procAddr(remote) + " ZZ 00000000:00000000 00:00000000 00000000 1000 0 5\n" +
				"   5: " + procAddr(local) + " " + procAddr(remote) + " 01 00000000:00000000 00:00000000 00000000 -1 0 5\n" +
				"   6: " + procAddr(local) + " " + procAddr(remote) + " 01 00000000:00000000 00:00000000 00000000 1000 0 NaN\n" +
				"   7: " + procAddr(local) + " " + procAddr(remote) + " 1FF 00000000:00000000 00:00000000 00000000 1000 0 5\n" +
				good + "\n",
			want: []sockRow{{local: local, remote: remote, state: 1, uid: 1000, inode: 777}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseNetTCP([]byte(tt.data))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d rows %+v, want %d", len(got), got, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("row %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
