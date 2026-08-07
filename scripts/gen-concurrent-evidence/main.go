// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Command gen-concurrent-evidence writes an evidence corpus from several
// recorders running at once, which is the state that exposes interleaving
// defects in the write path. It exists so the shipped structural doctor has an
// adversarial corpus to inspect in CI; a single-writer corpus cannot surface
// the defects this guards against.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func main() {
	dir := flag.String("dir", "", "evidence directory to write into")
	writers := flag.Int("writers", 6, "concurrent recorders")
	entries := flag.Int("entries", 40, "entries written by each recorder")
	payloadBytes := flag.Int("payload-bytes", 6000, "summary size, deliberately above the recorder write buffer")
	flag.Parse()

	if strings.TrimSpace(*dir) == "" {
		fmt.Fprintln(os.Stderr, "gen-concurrent-evidence: --dir is required")
		os.Exit(2)
	}
	if *writers < 2 {
		fmt.Fprintln(os.Stderr, "gen-concurrent-evidence: --writers must be at least 2; one writer cannot interleave")
		os.Exit(2)
	}

	recs := make([]*recorder.Recorder, 0, *writers)
	for range *writers {
		rec, err := recorder.New(recorder.Config{
			Enabled: true,
			Dir:     *dir,
			// High enough that automatic checkpoints do not dominate the corpus.
			CheckpointInterval: 1_000_000,
		}, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-concurrent-evidence: new recorder: %v\n", err)
			os.Exit(1)
		}
		recs = append(recs, rec)
	}

	payload := strings.Repeat("p", *payloadBytes)

	// Warm each recorder up serially. Resume happens lazily on the first write,
	// and several recorders resuming at once fail closed with "evidence file
	// changed during read". That is a startup race, not the interleaving defect
	// this corpus exists to expose, so it is taken out of the picture rather
	// than left to mask the property under test.
	for i, rec := range recs {
		if err := rec.Record(recorder.Entry{
			SessionID: "proxy",
			Type:      "action_receipt",
			Transport: "mcp-stdio",
			Summary:   fmt.Sprintf("warmup %d", i),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "gen-concurrent-evidence: warmup write: %v\n", err)
			os.Exit(1)
		}
	}

	failures := make(chan error, *writers)
	var wg sync.WaitGroup
	for _, rec := range recs {
		wg.Add(1)
		go func(rec *recorder.Recorder) {
			defer wg.Done()
			for range *entries {
				if err := rec.Record(recorder.Entry{
					SessionID: "proxy",
					Type:      "action_receipt",
					Transport: "mcp-stdio",
					Summary:   payload,
				}); err != nil {
					failures <- fmt.Errorf("record: %w", err)
					return
				}
			}
		}(rec)
	}
	wg.Wait()
	close(failures)

	for _, rec := range recs {
		if err := rec.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "gen-concurrent-evidence: close recorder: %v\n", err)
			os.Exit(1)
		}
	}
	for err := range failures {
		fmt.Fprintf(os.Stderr, "gen-concurrent-evidence: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %d entries from %d concurrent recorders into %s\n", *writers**entries, *writers, *dir)
}
