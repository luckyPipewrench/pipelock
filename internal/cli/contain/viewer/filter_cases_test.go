// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestFilterRejectsMalformedClientTraffic(t *testing.T) {
	handshake := []byte("RFB 003.008\n\x01\x01")
	for _, tc := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"version", []byte("RFB 003.003\n"), "unsupported RFB version"},
		{"security", []byte("RFB 003.008\n\x02"), "unsupported RFB security"},
		{"unknown type", append(bytes.Clone(handshake), 99), "unknown RFB client message"},
		{"oversized clipboard", append(bytes.Clone(handshake), 6, 0, 0, 0, 0, 4, 0, 1), "RFB cut text too large"},
		{"input buffer", bytes.Repeat([]byte{'x'}, maxFrame+maxCutText+33), "RFB input exceeds buffer limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilter(func() bool { return false }, false)
			out, err := f.feed(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) || len(out) != 0 {
				t.Fatalf("output=%x error=%v, want rejection %q", out, err, tc.want)
			}
		})
	}
}

func TestFilterBuffersPartialFramesAndDropsInput(t *testing.T) {
	f := newFilter(func() bool { return false }, false)
	for i, fragment := range [][]byte{[]byte("RFB 003."), []byte("008\n\x01\x01\x03\x00\x00")} {
		if out, err := f.feed(fragment); err != nil {
			t.Fatal(err)
		} else if i == 0 && len(out) != 0 || i == 1 && !bytes.Equal(out, []byte("RFB 003.008\n\x01\x01")) {
			t.Fatalf("partial frame handling: %x", out)
		}
	}
	frame := []byte{0, 0, 0, 0, 1, 0, 1}
	out, err := f.feed(frame)
	if err != nil || !bytes.Equal(out, append([]byte{3, 0, 0}, frame...)) {
		t.Fatalf("completed handshake and request: %x, %v", out, err)
	}
	for _, input := range [][]byte{{4, 1, 0, 0, 0, 0, 0, 65}, {5, 1, 0, 1, 0, 1}, {6, 0, 0, 0, 0, 0, 0, 1, 'x'}} {
		out, err := f.feed(input)
		if err != nil || len(out) != 0 {
			t.Fatalf("view-only input forwarded: %x, %v", out, err)
		}
	}
}

func TestFilterSetEncodingsKeepsOnlyDisplayValues(t *testing.T) {
	f := newFilter(func() bool { return false }, false)
	if _, err := f.feed([]byte("RFB 003.008\n\x01\x01")); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4+3*4)
	frame[0] = 2
	binary.BigEndian.PutUint16(frame[2:4], 3)
	binary.BigEndian.PutUint32(frame[4:8], 0)
	binary.BigEndian.PutUint32(frame[8:12], ^uint32(257))  // QEMU extended key events
	binary.BigEndian.PutUint32(frame[12:16], ^uint32(238)) // cursor
	out, err := f.feed(frame)
	if err != nil || len(out) != 12 || binary.BigEndian.Uint16(out[2:4]) != 2 || binary.BigEndian.Uint32(out[4:8]) != 0 || binary.BigEndian.Uint32(out[8:12]) != ^uint32(238) {
		t.Fatalf("encoding offer=%x, err=%v", out, err)
	}
}
