// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package viewer

import "testing"

// The filter parses bytes from an untrusted browser; no input may panic it.
// Output must never be longer than the input it was fed, since the filter
// only drops or narrows messages.
func FuzzFilter(f *testing.F) {
	handshake := append([]byte("RFB 003.008\n"), 1, 0)
	f.Add(handshake, true)
	f.Add(append(append([]byte{}, handshake...), 2, 0, 0, 2, 0, 0, 0, 0, 0xff, 0xff, 0xfe, 0xfe), false)
	f.Add(append(append([]byte{}, handshake...), 6, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c'), true)
	f.Fuzz(func(t *testing.T, data []byte, control bool) {
		fl := newFilter(func() bool { return control }, control)
		total, emitted := 0, 0
		for len(data) > 0 {
			n := 1 + int(data[0])%17
			if n > len(data) {
				n = len(data)
			}
			out, err := fl.feed(data[:n])
			total += n
			if err != nil {
				return
			}
			emitted += len(out)
			if emitted > total {
				t.Fatalf("filter emitted %d bytes from %d input bytes", emitted, total)
			}
			data = data[n:]
		}
	})
}
