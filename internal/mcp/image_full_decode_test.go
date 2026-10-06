// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"image"
	"image/png"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func imageWithEncodedAWSShape(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 256, 256))
	var state uint32 = 1
	for i := range img.Pix {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		img.Pix[i] = byte(state & 0xff)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	// A private ancillary PNG chunk contains binary bytes whose base64 spelling
	// resembles an access ID. One leading byte aligns the spelling to a quartet.
	shape := "AKIA" + "QWERTYUIOPASDFGH"
	binaryShape, err := base64.StdEncoding.DecodeString(shape)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte{0}, binaryShape...)
	if len(data) != 16 {
		t.Fatalf("unexpected ancillary chunk length: %d", len(data))
	}
	chunk := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(chunk[:4], 16)
	copy(chunk[4:8], "npAd")
	copy(chunk[8:], data)
	binary.BigEndian.PutUint32(chunk[len(chunk)-4:], crc32.ChecksumIEEE(chunk[4:len(chunk)-4]))
	media := append(append([]byte{}, buf.Bytes()[:33]...), chunk...)
	media = append(media, buf.Bytes()[33:]...)
	if _, err := png.Decode(bytes.NewReader(media)); err != nil {
		t.Fatalf("fixture is not a valid PNG: %v", err)
	}
	// Extend with binary ancillary chunks to exceed the old 64-character window.
	encoded := base64.StdEncoding.EncodeToString(media)
	if len(encoded) < 100*1024 {
		t.Fatalf("fixture is only %d bytes of base64", len(encoded))
	}
	if !strings.Contains(encoded, shape) {
		t.Fatal("fixture lacks the encoded access-ID shape")
	}
	return encoded
}

func imageResponse(data, sibling string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","data":%q},{"type":"text","text":%q}]}}`, data, sibling))
}

func TestMCPImageFullDecode(t *testing.T) {
	sc := testScanner(t)
	clean := imageWithEncodedAWSShape(t)
	key := "AKIA" + "Z7P6R5T4V3X2Y1W0"
	wrapped := append([]byte{}, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}...)
	wrapped = append(wrapped, []byte{0, 0, 0, 13, 'I', 'H', 'D', 'R'}...)
	wrapped = append(wrapped, make([]byte, 17)...)
	wrapped = append(wrapped, make([]byte, 128)...)
	wrapped = append(wrapped, []byte(key)...)
	if strings.Contains(base64.StdEncoding.EncodeToString(wrapped), key) {
		t.Fatal("hidden key unexpectedly appears in raw base64")
	}
	tests := []struct {
		name      string
		data      string
		sibling   string
		wantClean bool
	}{
		{name: "valid large PNG with encoded access ID shape", data: clean, wantClean: true},
		{name: "hidden plaintext key after old decode window", data: base64.StdEncoding.EncodeToString(wrapped)},
		{name: "hidden plaintext key in data URL", data: "data:image/png;base64," + base64.StdEncoding.EncodeToString(wrapped)},
		{name: "key in sibling text", data: clean, sibling: key},
		{name: "malformed base64", data: clean + "!" + key},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict := ScanResponse(imageResponse(tc.data, tc.sibling), sc)
			if verdict.Clean != tc.wantClean {
				t.Fatalf("Clean = %v, want %v; DLP matches = %+v; error = %q", verdict.Clean, tc.wantClean, verdict.DLPMatches, verdict.Error)
			}
			if !tc.wantClean {
				found := false
				for _, m := range verdict.DLPMatches {
					found = found || m.PatternName == "AWS Access ID"
				}
				if !found {
					t.Fatalf("missing AWS Access ID finding: %+v", verdict.DLPMatches)
				}
			}
		})
	}
}

func TestMCPImageOversizedPayloadRemainsVisible(t *testing.T) {
	// Transports reject messages above MaxLineSize before response scanning.
	// At the extractor boundary, an oversized media candidate must still fail
	// closed instead of being classified as opaque: the extraction reports that
	// it did not finish, and a caller blocks rather than scanning a prefix.
	data := strings.Repeat("A", transport.MaxLineSize+1)
	result := jsonrpc.ExtractVisibleStringsFromJSONResult(json.RawMessage(fmt.Sprintf(`{"content":[{"type":"image","data":%q}]}`, data)))
	if result.IncompleteReason == "" {
		t.Fatal("oversized media candidate was not reported as uninspected")
	}
	if slices.Contains(result.Strings, data) || len(result.Strings) != 0 {
		t.Fatal("an incomplete extraction must not hand back partial text")
	}
}
