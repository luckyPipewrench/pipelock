// Package main is the entry point for the Pipelock CLI.
package main

import (
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
