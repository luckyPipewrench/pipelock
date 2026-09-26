// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"encoding/binary"
	"errors"
)

// filter parses RFB 3.8 client messages. RFC 6143 §§7.1.1, 7.1.2, 7.3.1
// define the client handshake; §§7.5.1–7.5.6 define the supported messages.
// Undocumented extensions are rejected because their lengths are not known.
type filter struct {
	pending   []byte
	stage     uint8
	control   func() bool
	clipboard bool
}

func newFilter(control func() bool, clipboard bool) *filter {
	return &filter{control: control, clipboard: clipboard}
}

func (f *filter) feed(p []byte) ([]byte, error) {
	if len(f.pending)+len(p) > maxFrame+maxCutText+32 {
		return nil, errors.New("RFB input exceeds buffer limit")
	}
	f.pending = append(f.pending, p...)
	out := make([]byte, 0, len(p))
	for len(f.pending) > 0 {
		// Capture the stage before next advances it: the ClientInit byte
		// completes the handshake and must never be read as a message type.
		messages := f.stage > 2
		n, forward, err := f.next()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		if forward {
			if messages && f.pending[0] == msgSetEncodings {
				out = append(out, rewriteSetEncodings(f.pending[:n])...)
			} else {
				out = append(out, f.pending[:n]...)
			}
		}
		f.pending = f.pending[n:]
	}
	return out, nil
}

const msgSetEncodings = 2

// displayOnlyEncoding reports whether an encoding only changes how the server
// draws, never which messages the client may send. SetEncodings is how a
// client asks the server to enable protocol extensions, and several of them
// (QEMU extended key events -258, ExtendedDesktopSize -308, Xvp -309,
// Fence -312, ContinuousUpdates -313, ExtendedClipboard 0xC0A1E5CE) make the
// client send message types this filter cannot frame and therefore closes on.
// Offering the server only these keeps it from ever agreeing to them.
// Values: RFC 6143 §7.7 (Raw 0, CopyRect 1, RRE 2, Hextile 5, ZRLE 16,
// Cursor -239, DesktopSize -223) and the community RFB protocol registry
// (Tight 7, JPEG 21, TightPNG -260, JPEG quality -32..-23, compression
// -256..-247, LastRect -224, DesktopName -307, VMware cursor 0x574D5664).
//
// The wire value is an unsigned 32-bit two's-complement word, so a negative
// encoding -n is written ^uint32(n-1): -239 is ^uint32(238).
func displayOnlyEncoding(e uint32) bool {
	switch {
	case e == 0, e == 1, e == 2, e == 5, e == 7, e == 16, e == 21, e == ^uint32(259):
		return true
	case e >= ^uint32(31) && e <= ^uint32(22), e >= ^uint32(255) && e <= ^uint32(246):
		return true
	case e == ^uint32(222), e == ^uint32(223), e == ^uint32(238), e == ^uint32(306), e == 0x574D5664:
		return true
	}
	return false
}

// rewriteSetEncodings returns msg with every encoding that is not
// display-only removed (RFC 6143 §7.5.2 framing: type, padding, count, list).
func rewriteSetEncodings(msg []byte) []byte {
	kept := make([]byte, 4, len(msg))
	copy(kept, msg[:4])
	count := 0
	for i := 4; i+4 <= len(msg); i += 4 {
		if displayOnlyEncoding(binary.BigEndian.Uint32(msg[i : i+4])) {
			kept = append(kept, msg[i:i+4]...)
			count++
		}
	}
	binary.BigEndian.PutUint16(kept[2:4], uint16(count))
	return kept
}

func (f *filter) next() (int, bool, error) {
	p := f.pending
	switch f.stage {
	case 0:
		if len(p) < 12 {
			return 0, false, nil
		}
		if string(p[:12]) != "RFB 003.008\n" {
			return 0, false, errors.New("unsupported RFB version")
		}
		f.stage++
		return 12, true, nil
	case 1:
		if len(p) < 1 {
			return 0, false, nil
		}
		if p[0] != 1 {
			return 0, false, errors.New("unsupported RFB security")
		}
		f.stage++
		return 1, true, nil
	case 2:
		if len(p) < 1 {
			return 0, false, nil
		}
		f.stage++
		return 1, true, nil
	}
	switch p[0] {
	case 0:
		if len(p) < 20 {
			return 0, false, nil
		}
		return 20, true, nil
	case 2:
		if len(p) < 4 {
			return 0, false, nil
		}
		n := 4 + 4*int(binary.BigEndian.Uint16(p[2:4]))
		if n > maxFrame {
			return 0, false, errors.New("too many RFB encodings")
		}
		if len(p) < n {
			return 0, false, nil
		}
		return n, true, nil
	case 3:
		if len(p) < 10 {
			return 0, false, nil
		}
		return 10, true, nil
	case 4:
		if len(p) < 8 {
			return 0, false, nil
		}
		return 8, f.control(), nil
	case 5:
		if len(p) < 6 {
			return 0, false, nil
		}
		return 6, f.control(), nil
	case 6:
		if len(p) < 8 {
			return 0, false, nil
		}
		n := binary.BigEndian.Uint32(p[4:8])
		if n > maxCutText {
			return 0, false, errors.New("RFB cut text too large")
		}
		total := 8 + int(n)
		if len(p) < total {
			return 0, false, nil
		}
		return total, f.control() && f.clipboard, nil
	default:
		return 0, false, errors.New("unknown RFB client message")
	}
}
