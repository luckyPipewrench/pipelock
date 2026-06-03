# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Module entry point: ``python -m pipelock_aarp_verify aarp PATH ...``."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
