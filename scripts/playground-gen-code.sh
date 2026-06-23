#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)"
cd "$ROOT"

exec go run ./cmd/pipelock-playground-live gen-code
