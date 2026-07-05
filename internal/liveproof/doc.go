// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package liveproof holds end-to-end proofs that build and drive the shipped
// pipelock binary the way a customer does. The tests live in the external
// liveproof_test package behind the `liveproof` build tag and run only via
// `make test-liveproof` (or `go test -tags liveproof ./internal/liveproof/...`),
// never in the normal `go test ./...` lane.
//
// This file gives the directory a base package so tooling that compiles the
// package without the build tag (scoped coverage runs, explicit `go test
// ./internal/liveproof/`) sees an empty package with no test files instead of
// failing with "build constraints exclude all Go files".
package liveproof
