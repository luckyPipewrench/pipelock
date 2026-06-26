// Command tmp-makebundle is a throwaway tool that re-archives a sealed run dir
// (e.g. a downloaded verify kit's app/run) into the raw bundle the broker serves
// at /api/live/bundle, so the WASM verifier can be proven in a real browser.
// Not part of the product; delete after use.
package main

import (
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: tmp-makebundle <runDir> <out.tar.gz>")
		os.Exit(2)
	}
	pubHex := "539bda06995b228e55af68c05c41cee14b060041ff4d0c13fcf13544e922abcb"
	b, err := playground.ArchiveRunForDownload(os.Args[1], pubHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "archive:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", os.Args[2], len(b))
}
