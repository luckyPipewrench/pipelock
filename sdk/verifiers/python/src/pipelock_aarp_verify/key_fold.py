# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""JSON key identity shared by the reference verifier's strict parsers."""

from .key_fold_data import KEY_FOLD_GROUPS

# Full casefold expands some characters; Go uses one-rune simple-fold cycles.
_FOLD = {ord(char): group[0] for group in KEY_FOLD_GROUPS.split() for char in group}


def fold_key(key: str) -> str:
    return key.translate(_FOLD)
