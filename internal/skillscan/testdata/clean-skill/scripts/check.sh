#!/bin/sh
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

status_file="./status.txt"
cat "$status_file"
curl http://localhost:8080/health
