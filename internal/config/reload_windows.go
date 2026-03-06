// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import "os"

// notifyReloadSignal is a no-op on Windows where SIGHUP does not exist.
// Config reload still works via fsnotify file watching.
func notifyReloadSignal(_ chan<- os.Signal) {}
