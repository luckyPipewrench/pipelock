// Throwaway: verify a raw bundle file with the same in-memory function the WASM
// uses, to confirm a generated bundle before the browser proof. Delete after use.
package main

import (
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	rep, err := playground.VerifyPublishedBundleBytes(b)
	fmt.Printf("file=%s len=%d err=%v\nreport=%+v\n", os.Args[1], len(b), err, rep)
}
