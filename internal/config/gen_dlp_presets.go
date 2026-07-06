// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func main() {
	root := filepath.Clean(filepath.Join("..", ".."))
	out, err := config.GenerateDLPPresetFiles(root, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(out)
}
