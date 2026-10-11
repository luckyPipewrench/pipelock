# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""JSON key identity shared by the reference verifier's strict parsers."""

from .key_fold_data import KEY_FOLD_GROUPS

# Full casefold expands some characters; Go uses one-rune simple-fold cycles.
_FOLD = {ord(char): group[0] for group in KEY_FOLD_GROUPS.split() for char in group}


def fold_key(key: str) -> str:
    return key.translate(_FOLD)


def field_alias(key: str, allowed: set[str]) -> str | None:
    return next(
        (name for name in allowed if key != name and fold_key(key) == fold_key(name)),
        None,
    )


def reject_folded_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    seen: dict[str, str] = {}
    for key, value in pairs:
        folded = fold_key(key)
        if folded in seen:
            raise ValueError(
                f"duplicate object key: {seen[folded]!r} and {key!r} (case-insensitive)"
            )
        seen[folded] = key
        result[key] = value
    return result
