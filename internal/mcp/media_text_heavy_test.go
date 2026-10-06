// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// textHeavyBody builds n bytes of uncompressed text in the shape of an ordinary
// PDF content stream or a metadata box: one printable line per row, joined by
// newlines. Every line is long enough for the plain ASCII view to emit it, so
// the control-collapsed view has nothing to add.
func textHeavyBody(n int) []byte {
	var b bytes.Buffer
	b.Grow(n + 128)
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "BT /F1 12 Tf 72 %d Td (Quarterly summary row %d of the report) Tj ET\n", 700-i%600, i)
	}
	return b.Bytes()[:n]
}

// textHeavyShortLines mixes in the one and two letter operators real content
// streams carry. The plain view drops those, so the joined view must keep them
// and this payload costs about twice its size.
func textHeavyShortLines(n int) []byte {
	var b bytes.Buffer
	b.Grow(n + 128)
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "q\n0.1 0.2 0.3 rg\n72 %d m\n(Quarterly summary row %d) Tj\nQ\n", 700-i%600, i)
	}
	return b.Bytes()[:n]
}

func ftypHeader() []byte {
	return []byte{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0, 'i', 's', 'o', 'm', 'i', 's', 'o', '2'}
}

func TestTextHeavyMediaIsDeliveredNotBudgetBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("large payloads")
	}
	sc := testScanner(t)
	for _, hdr := range []struct {
		name  string
		bytes []byte
	}{{"pdf", []byte("%PDF-1.7\n")}, {"ftyp", ftypHeader()}} {
		for _, body := range []struct {
			name string
			mk   func(int) []byte
			mibs []int
		}{
			{"lines", textHeavyBody, []int{3, 4, 6, 7}},
			{"short lines", textHeavyShortLines, []int{3}},
		} {
			for _, mib := range body.mibs {
				// Under the race detector keep the largest text-heavy case and
				// the short-lines shape; the full sweep runs in normal builds.
				if raceEnabled && (hdr.name != "pdf" || (body.name == "lines" && mib != 7)) {
					continue
				}
				// ftyp shares the extraction path with pdf; two sizes bound
				// its race-detector cost.
				if hdr.name == "ftyp" && (mib == 4 || mib == 6 || body.name == "short lines") {
					continue
				}
				t.Run(fmt.Sprintf("%s %s %d MiB", hdr.name, body.name, mib), func(t *testing.T) {
					raw := append(append([]byte{}, hdr.bytes...), body.mk(mib<<20)...)
					msg := []byte(makeMediaResponse(base64.StdEncoding.EncodeToString(raw)))
					if len(msg) > transport.MaxLineSize {
						t.Fatalf("fixture is %d bytes, over the transport limit", len(msg))
					}
					start := time.Now()
					verdict := ScanResponse(msg, sc)
					elapsed := time.Since(start)
					t.Logf("%s %s decoded=%dMiB message=%.2fMiB clean=%v elapsed=%s", hdr.name, body.name, mib, float64(len(msg))/(1<<20), verdict.Clean, elapsed.Round(time.Millisecond))
					if !verdict.Clean || verdict.Error != "" {
						t.Fatalf("benign %d MiB text media was not delivered: %+v", mib, verdict)
					}
					// Generous: the race detector slows a 7 MiB scan to about a minute.
					if elapsed > 5*time.Minute {
						t.Fatalf("scan took %s", elapsed)
					}
				})
			}
		}
	}
}
