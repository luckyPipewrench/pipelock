// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package media

import "testing"

func TestDetectType(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		body []byte
		want string
	}{
		{"jpeg", []byte{0xff, 0xd8, 0xff, 0xe0}, "image/jpeg"},
		{"png", []byte("\x89PNG\r\n\x1a\n"), "image/png"},
		{"gif", append([]byte("GIF89a"), 1, 0, 1, 0, 0, 0, 0, 0x3b), "image/gif"},
		{"bmp", []byte{'B', 'M', 0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0}, "image/bmp"},
		{"webp", []byte("RIFF\x08\x00\x00\x00WEBPVP8 "), "image/webp"},
		{"ico", []byte{0, 0, 1, 0}, "image/x-icon"},
		{"aiff", []byte("FORM\x00\x00\x00\x04AIFF"), "audio/aiff"},
		{"id3", []byte{'I', 'D', '3', 4, 0, 0, 0, 0, 0, 1}, "audio/mpeg"},
		{"midi", []byte("MThd\x00\x00\x00\x06"), "audio/midi"},
		{"avi", []byte("RIFF\x08\x00\x00\x00AVI "), "video/avi"},
		{"wave", []byte("RIFF\x08\x00\x00\x00WAVE"), "audio/wave"},
		{"mp4", []byte{0, 0, 0, 12, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'}, "video/mp4"},
		{"webm", []byte{0x1a, 0x45, 0xdf, 0xa3}, "video/webm"},
		{"au", []byte{'.', 's', 'n', 'd', 0, 0, 0, 24, 0, 0, 0, 0}, "audio/basic"},
		{"csv_bmw", []byte("BMW,model,price\n"), ""},
		{"id3_text", []byte("ID3 tagging guidance\n"), ""},
		{"id3_invalid_synchsafe_size", []byte{'I', 'D', '3', 4, 0, 0, 0x80, 0, 0, 1}, ""},
		{"gif_text", []byte("GIF89a is a file signature\n"), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := DetectType(tt.body); got != tt.want {
				t.Errorf("DetectType() = %q, want %q", got, tt.want)
			}
		})
	}
}
