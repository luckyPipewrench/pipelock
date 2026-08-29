// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestExciseVerifiedImageDataURLsJoinsSplitSecret(t *testing.T) {
	t.Parallel()

	pngBytes := randomPNG(t, 21)
	imageURL := dataURLForPNGBytes(t, pngBytes)
	left, right := "AKIA", "ABCDEFGHIJKLMNOP"
	got := exciseVerifiedImageDataURLs(left + imageURL + right)
	if got != left+right {
		t.Fatalf("excised = %q, want joined %q", got, left+right)
	}
	if strings.Contains(got, "data:image/") {
		t.Fatalf("verified image data URL still present: %q", got)
	}
}

func TestExciseImagesRetainingDecodedForDLP(t *testing.T) {
	t.Parallel()

	t.Run("no verified image returns original", func(t *testing.T) {
		t.Parallel()
		text := "prefix data:image/gif;base64,R0lGODlh suffix"
		if got := exciseImagesRetainingDecodedForDLP(text); got != text {
			t.Fatalf("unverified payload changed text: %q", got)
		}
	})

	t.Run("verified image appends decoded bytes", func(t *testing.T) {
		t.Parallel()
		pngBytes := randomPNG(t, 22)
		imageURL := dataURLForPNGBytes(t, pngBytes)
		got := exciseImagesRetainingDecodedForDLP("left" + imageURL + "right")
		wantPrefix := "leftright\n"
		if !strings.HasPrefix(got, wantPrefix) {
			t.Fatalf("got %q, want prefix %q", got, wantPrefix)
		}
		if !strings.Contains(got, string(pngBytes)) {
			t.Fatal("decoded PNG bytes were not retained for DLP")
		}
	})
}

func TestAsciiEqualFoldUppercaseTarget(t *testing.T) {
	t.Parallel()

	if !asciiEqualFold("data:image/png", "DATA:IMAGE/PNG") {
		t.Fatal("lowercase source did not fold onto uppercase target")
	}
	if asciiEqualFold("data:image/png", "DATA:IMAGE/JPG") {
		t.Fatal("different uppercase target matched")
	}
}

func TestPNGOrJPEGBase64HeaderRejectsParamsWithoutBase64(t *testing.T) {
	t.Parallel()

	if isPNGOrJPEGBase64DataImageHeader("data:image/png;charset=utf-8;name=fixture") {
		t.Fatal("header with params but no base64 flag was accepted")
	}
	if !isPNGOrJPEGBase64DataImageHeader("data:image/jpeg;base64") {
		t.Fatal("plain jpeg base64 header was rejected")
	}
}

func TestDecodeVerifiedPNGOrJPEGEncodings(t *testing.T) {
	t.Parallel()

	pngBytes := randomPNG(t, 23)
	if _, ok := decodeVerifiedPNGOrJPEG(base64.URLEncoding.EncodeToString(pngBytes)); !ok {
		t.Fatal("URL-encoded complete PNG was rejected")
	}
	if _, ok := decodeVerifiedPNGOrJPEG(base64.RawURLEncoding.EncodeToString(pngBytes)); !ok {
		t.Fatal("raw URL-encoded complete PNG was rejected")
	}
	if decoded, ok := decodeVerifiedPNGOrJPEG("%not-base64"); ok || decoded != nil {
		t.Fatal("invalid payload decoded as a verified image")
	}
}

func TestCompletePNGRejectsWrongIHDRAndIENDLengths(t *testing.T) {
	t.Parallel()

	ihdr := pngChunk(t, "IHDR", bytes.Repeat([]byte{0}, 12))
	idat := pngChunk(t, "IDAT", []byte{0x00})
	iend := pngChunk(t, "IEND", nil)
	if isCompletePNG(pngWithChunks(t, ihdr, idat, iend)) {
		t.Fatal("IHDR length 12 accepted")
	}

	valid := randomPNG(t, 24)
	badIEND := pngWithChunks(t,
		pngChunk(t, "IHDR", valid[16:29]),
		pngChunk(t, "IDAT", []byte{0x00}),
		pngChunk(t, "IEND", []byte{0x00}),
	)
	if isCompletePNG(badIEND) {
		t.Fatal("IEND with payload accepted")
	}
}

func TestCompleteJPEGAcceptsFillSOIAndAlternateSOF(t *testing.T) {
	t.Parallel()

	// Extra 0xFF fill plus a second SOI marker before SOF.
	data := []byte{
		0xff, 0xd8,
		0xff, 0xff, 0xd8,
		0xff, 0xc2, 0x00, 0x0b,
		0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
		0xff, 0xda, 0x00, 0x08,
		0x01, 0x01, 0x00, 0x00, 0x3f, 0x00,
		0xff, 0xd9,
	}
	if !isCompleteJPEG(data) {
		t.Fatal("JPEG with fill bytes, extra SOI, and SOF2 rejected")
	}
	if !isJPEGSOFMarker(0xc2) || isJPEGSOFMarker(0xc4) {
		t.Fatal("SOF2 must be a SOF marker and DHT (0xc4) must not")
	}
}

func TestDataURLBase64PayloadEndStopsAfterTwoPads(t *testing.T) {
	t.Parallel()

	if got := dataURLBase64PayloadEnd("QUJD===rest", 0); got != len("QUJD==") {
		t.Fatalf("third pad included: end=%d", got)
	}
	if !isBase64DataURLByte('-') || !isBase64DataURLByte('_') {
		t.Fatal("URL-safe base64 alphabet rejected")
	}
	if isBase64DataURLByte(',') || isBase64DataURLByte('%') {
		t.Fatal("non-alphabet bytes accepted")
	}
}

func TestIndexDataImagePrefixCaseAndMiss(t *testing.T) {
	t.Parallel()

	if got := indexDataImagePrefix("xxDATA:IMAGE/png;base64,"); got != 2 {
		t.Fatalf("case-insensitive prefix index = %d, want 2", got)
	}
	if got := indexDataImagePrefix("no image here at all"); got != -1 {
		t.Fatalf("unrelated text index = %d, want -1", got)
	}
}
