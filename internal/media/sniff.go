// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package media

import (
	"bytes"
	"encoding/binary"
)

// DetectType returns a media type only when the leading bytes contain a
// structurally plausible image, audio, or video header. The longest header
// inspected is 16 bytes so streaming callers can classify one bounded prefix.
func DetectType(body []byte) string {
	if len(body) >= 3 && bytes.Equal(body[:3], []byte{0xff, 0xd8, 0xff}) {
		return "image/jpeg"
	}
	if len(body) >= 8 && bytes.Equal(body[:8], []byte("\x89PNG\r\n\x1a\n")) {
		return "image/png"
	}
	if len(body) >= 14 && (bytes.Equal(body[:6], []byte("GIF87a")) || bytes.Equal(body[:6], []byte("GIF89a"))) &&
		binary.LittleEndian.Uint16(body[6:8]) > 0 && binary.LittleEndian.Uint16(body[8:10]) > 0 &&
		(body[13] == 0x2c || body[13] == 0x21 || body[13] == 0x3b) {
		return "image/gif"
	}
	if len(body) >= 14 && bytes.Equal(body[:2], []byte("BM")) &&
		bytes.Equal(body[6:10], []byte{0, 0, 0, 0}) && binary.LittleEndian.Uint32(body[10:14]) >= 14 {
		return "image/bmp"
	}
	if len(body) >= 16 && bytes.Equal(body[:4], []byte("RIFF")) && bytes.Equal(body[8:12], []byte("WEBP")) &&
		(bytes.Equal(body[12:16], []byte("VP8 ")) || bytes.Equal(body[12:16], []byte("VP8L")) || bytes.Equal(body[12:16], []byte("VP8X"))) {
		return "image/webp"
	}
	if len(body) >= 4 && (bytes.Equal(body[:4], []byte{0, 0, 1, 0}) || bytes.Equal(body[:4], []byte{0, 0, 2, 0})) {
		return "image/x-icon"
	}
	if len(body) >= 12 && bytes.Equal(body[:4], []byte("FORM")) && bytes.Equal(body[8:12], []byte("AIFF")) {
		return "audio/aiff"
	}
	if validID3Header(body) {
		return "audio/mpeg"
	}
	if len(body) >= 8 && bytes.Equal(body[:8], []byte("MThd\x00\x00\x00\x06")) {
		return "audio/midi"
	}
	if len(body) >= 12 && bytes.Equal(body[:4], []byte("RIFF")) {
		switch string(body[8:12]) {
		case "AVI ":
			return "video/avi"
		case "WAVE":
			return "audio/wave"
		}
	}
	if len(body) >= 12 && binary.BigEndian.Uint32(body[:4]) >= 12 && bytes.Equal(body[4:8], []byte("ftyp")) {
		return "video/mp4"
	}
	if len(body) >= 4 && bytes.Equal(body[:4], []byte{0x1a, 0x45, 0xdf, 0xa3}) {
		return "video/webm"
	}
	if len(body) >= 12 && bytes.Equal(body[:4], []byte(".snd")) && binary.BigEndian.Uint32(body[4:8]) >= 24 {
		return "audio/basic"
	}
	return ""
}

func validID3Header(body []byte) bool {
	if len(body) < 10 || !bytes.Equal(body[:3], []byte("ID3")) || body[3] < 2 || body[3] > 4 ||
		body[4] == 0xff || body[5]&0x0f != 0 {
		return false
	}
	for _, b := range body[6:10] {
		if b&0x80 != 0 {
			return false
		}
	}
	return true
}
