// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package config

import "os"

func notifyReloadSignal(_ chan<- os.Signal) {}
