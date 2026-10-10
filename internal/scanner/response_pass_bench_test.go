// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// responsePassFixtureCap bounds how much of the local fixture is read.
const responsePassFixtureCap = 2108646

func responsePassFixture(t testing.TB) []byte {
	t.Helper()
	path := os.Getenv("PIPELOCK_RESPONSE_PASS_SAMPLE")
	if path == "" {
		t.Skip("set PIPELOCK_RESPONSE_PASS_SAMPLE to a local response fixture")
	}
	body, err := readResponsePassFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bytes=%d sha256=%x", len(body), sha256.Sum256(body))
	return body
}

// readResponsePassFixture reads at most responsePassFixtureCap bytes from a
// regular file. The file is opened without blocking and its type is checked
// on the open descriptor, so a path swapped for a FIFO or device between a
// check and the open cannot stall the test, and a huge file cannot exhaust
// memory.
func readResponsePassFixture(path string) ([]byte, error) {
	f, err := openFixtureNonblocking(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("response fixture %q is not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(f, responsePassFixtureCap))
}

func TestResponsePassCosts(t *testing.T) {
	body := responsePassFixture(t)
	cfg := config.Defaults()
	cfg.Internal = nil
	bodyScanner := MustNew(cfg)
	defer bodyScanner.Close()
	start := time.Now()
	result := bodyScanner.ScanResponseBodyWithSuppress(context.Background(), body, "", nil)
	t.Logf("body total=%s clean=%t findings=%v", time.Since(start), result.Clean, result.Matches)
	// Attribute lazy proof compilation to the first pass that needs it.
	s := MustNew(cfg)
	defer s.Close()
	raw := string(body)
	start = time.Now()
	content := normalize.ForMatching(raw)
	t.Logf("transform primary=%s same=%t", time.Since(start), content == raw)
	start = time.Now()
	spaced := normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(raw))
	t.Logf("transform spaced=%s same=%t", time.Since(start), spaced == content)
	start = time.Now()
	leeted := normalize.Leetspeak(content)
	t.Logf("transform leet=%s same=%t", time.Since(start), leeted == content)
	start = time.Now()
	folded := normalize.FoldVowels(content)
	t.Logf("transform vowels=%s same=%t", time.Since(start), folded == content)
	memo := newResponseMatchMemo(len(content))
	for _, group := range []struct {
		name                  string
		patterns, opt, vowels []*compiledPattern
		pf, optpf, vowelpf    *responsePreFilter
	}{
		{"core", s.core.responsePatterns, s.core.responseOptSpacePatterns, s.core.responseVowelFoldPatterns, s.core.responsePreFilter, s.core.responseOptSpacePreFilter, s.core.responseVowelFoldPreFilter},
		{"configured", s.responsePatterns, s.responseOptSpacePatterns, s.responseVowelFoldPatterns, s.responsePreFilter, s.responseOptSpacePreFilter, s.responseVowelFoldPreFilter},
	} {
		for _, pass := range []struct {
			name, text string
			patterns   []*compiledPattern
			pf         *responsePreFilter
		}{
			{"primary", content, group.patterns, group.pf},
			{"spaced", spaced, group.patterns, group.pf},
			{"leet", leeted, group.patterns, group.pf},
			{"opt-space", content, group.opt, group.optpf},
			{"vowels", folded, group.vowels, group.vowelpf},
		} {
			start = time.Now()
			matches := memo.match(pass.pf, pass.patterns, pass.text)
			t.Logf("%s/%s=%s matches=%d", group.name, pass.name, time.Since(start), len(matches))
		}
		start = time.Now()
		if group.name == "core" {
			s.matchDecodedCoreResponse(content, nil)
		} else {
			s.matchDecodedResponse(content)
		}
		t.Logf("%s/decode=%s", group.name, time.Since(start))
	}
	start = time.Now()
	matches := matchPatternsPreFiltered(&responsePreFilter{gates: make([]*responseGate, len(s.responsePatterns))}, s.responsePatterns, content)
	t.Logf("configured raw matching=%s matches=%d", time.Since(start), len(matches))
	for _, text := range []string{content, spaced, leeted, folded} {
		for _, p := range s.responsePatterns {
			if !hasExternalTransferCompanions(p) {
				continue
			}
			start = time.Now()
			locs := responsePatternMatchLocations(p, text)
			t.Logf("external-transfer bytes=%d elapsed=%s matches=%d", len(text), time.Since(start), len(locs))
		}
	}
}

func BenchmarkResponsePassCold(b *testing.B) {
	b.StopTimer()
	body := responsePassFixture(b)
	cfg := config.Defaults()
	cfg.Internal = nil
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		s := MustNew(cfg)
		b.StartTimer()
		result := s.ScanResponseBodyWithSuppress(context.Background(), body, "", nil)
		b.StopTimer()
		s.Close()
		if result.Failed() {
			b.Fatal(result.ScanError)
		}
		b.StartTimer()
	}
}
