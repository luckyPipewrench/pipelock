# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Typed interpreter for the evidence-provenance transform profile v1.

This is deliberately independent from receipt parsing: recipes are fixture-only
data and must be rejected before they can silently change provenance evidence.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

PROFILE_DIGEST = (
    "sha256:3de14968449593cae58da869cfc97855cb098e491494390a12ba742cb0b70f94"
)
UNICODE_VERSION = "15.0.0"
MAX_INPUT_BYTES = 2 << 20
MAX_OUTPUT_BYTES = 1 << 20
MAX_OPERATIONS = 32
MAX_CUMULATIVE_PROCESSED_BYTES = 16 << 20
_KINDS = (
    "identity",
    "url_component",
    "percent_decode",
    "dlp_normalize",
    "lowercase",
    "invisible_strip",
    "hex_decode",
    "base32_decode",
    "base64_decode",
    "leetspeak",
    "vowel_fold",
    "query_unescape",
    "invisible_space",
    "matching_normalize",
    "hex_decode_liberal",
    "base32_decode_liberal",
    "base64_decode_liberal",
    "encoded_token_normalize",
    "text_segment",
    "html_entity_decode",
    "whitespace_compact",
    "url_noise_strip",
    "ordered_query_concat",
    "query_subsequence",
    "hostname_dot_remove",
    "encoded_run",
    "canary_canonicalize",
)
_FIELDS = {
    "kind",
    "component",
    "selector",
    "occurrence",
    "passes",
    "profile",
    "decode_padding",
    "alphabet",
    "indices",
    "minimum_length",
}
_CONFUSABLES = {
    "А": "A",
    "В": "B",
    "С": "C",
    "Е": "E",
    "Н": "H",
    "І": "I",
    "Ј": "J",
    "К": "K",
    "М": "M",
    "О": "O",
    "Р": "P",
    "Ѕ": "S",
    "Т": "T",
    "Х": "X",
    "а": "a",
    "в": "v",
    "е": "e",
    "н": "h",
    "і": "i",
    "к": "k",
    "м": "m",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "ј": "j",
    "ѕ": "s",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "α": "a",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "Օ": "O",
    "օ": "o",
    "Ս": "S",
    "ս": "s",
    "Ռ": "L",
    "հ": "h",
    "ո": "n",
    "ռ": "n",
    "ա": "a",
    "Ꭺ": "A",
    "Ꭲ": "I",
    "Ꮢ": "P",
    "Ꮪ": "S",
    "Ꭱ": "E",
    "Ꮃ": "W",
    "Ꮤ": "T",
    "Ø": "O",
    "ø": "o",
    "Đ": "D",
    "đ": "d",
    "Ł": "L",
    "ł": "l",
    "Ħ": "H",
    "ħ": "h",
    "Ŧ": "T",
    "ŧ": "t",
    "ᴀ": "A",
    "ʙ": "B",
    "ᴄ": "C",
    "ᴅ": "D",
    "ᴇ": "E",
    "ꜰ": "F",
    "ɢ": "G",
    "ʜ": "H",
    "ɪ": "I",
    "ᴊ": "J",
    "ᴋ": "K",
    "ʟ": "L",
    "ᴍ": "M",
    "ɴ": "N",
    "ᴏ": "O",
    "ᴘ": "P",
    "ʀ": "R",
    "ꜱ": "S",
    "ᴛ": "T",
    "ᴜ": "U",
    "ᴠ": "V",
    "ᴡ": "W",
    "ʏ": "Y",
    "ᴢ": "Z",
}
_INVISIBLE_SINGLE = {0x00AD, 0x115F, 0x1160, 0x3164, 0xFEFF, *range(0xFFF9, 0xFFFC)}
_TEXT_DELIMS = set("/?&= \n\r\t\"'`{}[]()<>:,;")


class ProvenanceError(ValueError):
    """A transform recipe or application failure."""


def supported_operation_kinds() -> tuple[str, ...]:
    return _KINDS


def _unicode() -> Any:
    """Return Python 3.12's profile-pinned Unicode 15.0 database."""
    if unicodedata.unidata_version != UNICODE_VERSION:
        raise ProvenanceError(
            "evidence-provenance Unicode database = "
            f"{unicodedata.unidata_version}, want {UNICODE_VERSION}"
        )
    return unicodedata


def _control(value: str) -> bool:
    unicode = _unicode()
    return any(unicode.category(ch) == "Cc" for ch in value)


def _invisible(ch: str) -> bool:
    cp = ord(ch)
    return (
        (cp < 32 and ch not in "\t\n\r")
        or 0x7F <= cp <= 0x9F
        or cp in _INVISIBLE_SINGLE
        or 0x200B <= cp <= 0x200F
        or 0x202A <= cp <= 0x202E
        or 0x2060 <= cp <= 0x2064
        or 0x2066 <= cp <= 0x2069
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0000 <= cp <= 0xE007F
        or 0xE0100 <= cp <= 0xE01EF
    )


def _dlp(value: str) -> str:
    unicode = _unicode()
    dlp_spaces = {0x00A0, 0x1680, 0x180E, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000}
    value = "".join(
        ch
        for ch in value
        if not _control(ch)
        and not _invisible(ch)
        and ord(ch) not in dlp_spaces
        and not 0x2000 <= ord(ch) <= 0x200A
    )
    value = unicode.normalize("NFKC", value)
    value = "".join(_confusable(ch) for ch in value)
    return "".join(
        ch for ch in unicode.normalize("NFD", value) if unicode.category(ch) != "Mn"
    )


def _confusable(ch: str) -> str:
    cp = ord(ch)
    if 0x1F170 <= cp <= 0x1F189 or 0x1F1E6 <= cp <= 0x1F1FF:
        return chr(ord("A") + (cp - (0x1F170 if cp <= 0x1F189 else 0x1F1E6)))
    return _CONFUSABLES.get(ch, ch)


def _simple_lower(value: str) -> str:
    """Unicode 15 simple lowercase mapping, not Python's full mapping."""
    # This reference verifier is constrained to Python 3.12, whose built-in
    # Unicode database is exactly 15.0. U+0130 is the sole Unicode 15 simple
    # lowercase mapping whose full Python mapping expands to multiple code
    # points (``i`` + COMBINING DOT ABOVE); Go uses the one-rune mapping.
    _unicode()
    return "".join("i" if ch == "\u0130" else ch.lower() for ch in value)


def _matching_whitespace(value: str) -> str:
    return value.translate(
        str.maketrans(
            dict.fromkeys(
                (
                    0x00A0,
                    0x1680,
                    0x180E,
                    *range(0x2000, 0x200B),
                    0x2028,
                    0x2029,
                    0x202F,
                    0x205F,
                    0x3000,
                ),
                " ",
            )
        )
    )


def _strict_percent(value: str, plus: bool = False) -> str:
    # urllib accepts malformed percent sequences, unlike Go's unescapers.
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ProvenanceError("percent decode: invalid URL escape")
    if plus:
        value = value.replace("+", " ")
    try:
        return unquote_to_bytes(value).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("output: invalid UTF-8") from exc


def _query_unescape(value: str, charge: Callable[[str], None]) -> str:
    for _ in range(500):
        charge(value)
        try:
            decoded = _strict_percent(value, plus=True)
        except ProvenanceError:
            break
        if decoded == value:
            break
        value = decoded
    return value


def _decode(
    value: str,
    kind: str,
    padded: bool,
    alphabet: str = "standard",
    label: str = "",
) -> str:
    label = label or f"{kind} decode"
    try:
        if kind == "hex":
            if not re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", value):
                raise ValueError("non-hexadecimal number")
            raw = binascii.unhexlify(value)
        elif kind == "base32":
            if not padded and "=" in value:
                raise ValueError("unexpected padding")
            source = value + ("=" * (-len(value) % 8) if not padded else "")
            raw = base64.b32decode(source, casefold=False)
        else:
            if not padded and "=" in value:
                raise ValueError("unexpected padding")
            source = value + ("=" * (-len(value) % 4) if not padded else "")
            raw = (
                base64.b64decode(source, altchars=b"-_", validate=True)
                if alphabet == "url"
                else base64.b64decode(source, validate=True)
            )
    except (ValueError, binascii.Error) as exc:
        raise ProvenanceError(f"{label}: {exc}") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError(f"{label} output: invalid UTF-8") from exc


@dataclass(frozen=True)
class Recipe:
    transform_profile_digest: str
    operations: tuple[dict[str, Any], ...]

    @classmethod
    def from_json(cls, digest: Any, operations: Any) -> Recipe:
        if not isinstance(digest, str):
            raise ProvenanceError("recipe: missing transform profile digest")
        if not isinstance(operations, list) or any(
            not isinstance(op, dict) for op in operations
        ):
            raise ProvenanceError("recipe: operations must be an array")
        return cls(digest, tuple(operations))

    def validate(self) -> None:
        if not self.transform_profile_digest:
            raise ProvenanceError("recipe: missing transform profile digest")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.transform_profile_digest):
            raise ProvenanceError(
                "recipe: transform profile digest: invalid SHA-256 digest"
            )
        if self.transform_profile_digest != PROFILE_DIGEST:
            raise ProvenanceError(
                "recipe: transform profile digest: unknown profile "
                f"{self.transform_profile_digest!r}"
            )
        if len(self.operations) > MAX_OPERATIONS:
            raise ProvenanceError(f"recipe: exceeds {MAX_OPERATIONS} operations")
        for index, op in enumerate(self.operations):
            try:
                self._validate_op(op)
            except ProvenanceError as exc:
                raise ProvenanceError(
                    f"recipe operation {index} ({op.get('kind', '')}): {exc}"
                ) from exc

    def _validate_op(self, op: dict[str, Any]) -> None:
        if set(op) - _FIELDS:
            raise ProvenanceError("unknown operation field")
        kind = op.get("kind")
        if not isinstance(kind, str) or kind not in _KINDS:
            raise ProvenanceError(f"unknown operation {kind!r}")
        for field in ("selector", "profile"):
            if field in op and (not isinstance(op[field], str) or _control(op[field])):
                raise ProvenanceError(f"{field} for {kind} contains control character")
        allowed: set[str] = {"kind"}
        required: set[str] = set()
        if kind == "url_component":
            allowed |= {"component", "selector", "occurrence"}
            required.add("component")
            component = op.get("component")
            if component not in {
                "url",
                "hostname",
                "path",
                "query_key",
                "query_value",
                "raw_query",
            }:
                raise ProvenanceError(f"unknown URL component {component!r}")
            if component in {"query_key", "query_value"}:
                required.add("selector")
                # Requiring the KEY is not the same as requiring a value. An
                # empty selector satisfied this check here while the Rust and
                # TypeScript verifiers rejected it, so the same recipe was valid
                # in one implementation and invalid in two.
                if op.get("selector", "") == "":
                    raise ProvenanceError("query component: missing selector")
            elif "selector" in op or "occurrence" in op:
                raise ProvenanceError(f"unsupported selector for {kind}")
        elif kind == "percent_decode":
            allowed.add("passes")
            required.add("passes")
            if not _uint(op.get("passes"), 8) or not 1 <= op["passes"] <= 4:
                raise ProvenanceError("percent decode passes must be 1..4")
        elif kind in {"dlp_normalize", "matching_normalize"}:
            allowed.add("profile")
            required.add("profile")
            want = (
                "pipelock-dlp-v1" if kind == "dlp_normalize" else "pipelock-matching-v1"
            )
            if op.get("profile") != want:
                profile_kind = "DLP" if kind == "dlp_normalize" else "matching"
                raise ProvenanceError(
                    f"unknown {profile_kind} profile {op.get('profile')!r}"
                )
        elif kind in {"base32_decode", "base64_decode", "base32_decode_liberal"}:
            allowed.add("decode_padding")
        elif kind == "base64_decode_liberal":
            allowed |= {"decode_padding", "alphabet"}
            required.add("alphabet")
            if op.get("alphabet") not in {"standard", "url"}:
                raise ProvenanceError(f"unknown base64 alphabet {op.get('alphabet')!r}")
        elif kind == "encoded_token_normalize":
            allowed.add("alphabet")
            required.add("alphabet")
            if op.get("alphabet") not in {
                "hex",
                "base32",
                "base64_standard",
                "base64_url",
            }:
                raise ProvenanceError(
                    f"unknown encoded-token alphabet {op.get('alphabet')!r}"
                )
        elif kind == "text_segment":
            allowed.add("occurrence")
        elif kind == "query_subsequence":
            allowed.add("indices")
            required.add("indices")
            indices = op.get("indices")
            if not isinstance(indices, list) or not 2 <= len(indices) <= 4:
                raise ProvenanceError(
                    "query subsequence indices must contain 2..4 entries"
                )
            if any(not _uint(x, 8) or x >= 20 for x in indices):
                raise ProvenanceError("query subsequence index exceeds scanner limit")
            if indices != sorted(set(indices)):
                raise ProvenanceError(
                    "query subsequence indices must be strictly increasing"
                )
        elif kind == "encoded_run":
            allowed |= {"occurrence", "minimum_length"}
            required.add("minimum_length")
            if not _uint(op.get("minimum_length"), 32) or op["minimum_length"] < 1:
                raise ProvenanceError("encoded run minimum_length must be positive")
        if not required <= set(op):
            raise ProvenanceError(f"missing {next(iter(required - set(op)))}")
        if set(op) - allowed:
            raise ProvenanceError(f"unsupported {(set(op) - allowed).pop()} for {kind}")
        for field in ("occurrence", "passes", "minimum_length"):
            if field in op and not _uint(
                op[field], {"occurrence": 32, "passes": 8, "minimum_length": 32}[field]
            ):
                raise ProvenanceError(f"{field} must be an unsigned integer")
        if "decode_padding" in op and not isinstance(op["decode_padding"], bool):
            raise ProvenanceError("decode_padding must be boolean")

    def apply_bytes(
        self,
        input_bytes: bytes,
        charge_fixture_work: Callable[[int], None] | None = None,
    ) -> str:
        try:
            value = input_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProvenanceError("recipe input: invalid UTF-8") from exc
        return self.apply(value, charge_fixture_work)

    def apply(
        self, value: str, charge_fixture_work: Callable[[int], None] | None = None
    ) -> str:
        self.validate()
        if len(value.encode()) > MAX_INPUT_BYTES:
            raise ProvenanceError("recipe input: exceeds profile byte limit")
        remaining = MAX_CUMULATIVE_PROCESSED_BYTES

        def charge(processed: str) -> None:
            nonlocal remaining
            size = len(processed.encode())
            if size > remaining:
                raise ProvenanceError("recipe: exceeds cumulative processing budget")
            if charge_fixture_work is not None:
                charge_fixture_work(size)
            remaining -= size

        for index, op in enumerate(self.operations):
            try:
                charge(value)
                value = self._apply_op(value, op, charge)
            except ProvenanceError as exc:
                raise ProvenanceError(
                    f"recipe operation {index} ({op['kind']}): {exc}"
                ) from exc
            if len(value.encode()) > MAX_OUTPUT_BYTES:
                raise ProvenanceError(
                    f"recipe operation {index} ({op['kind']}): "
                    "output exceeds profile byte limit"
                )
        return value

    def _apply_op(
        self, v: str, op: dict[str, Any], charge: Callable[[str], None]
    ) -> str:
        k = op["kind"]
        if k == "identity":
            return v
        if k == "url_component":
            return _url_component(v, op)
        if k == "percent_decode":
            for _ in range(op["passes"]):
                charge(v)
                v = _strict_percent(v)
            return v
        if k == "dlp_normalize":
            return _dlp(v)
        if k == "lowercase":
            return _simple_lower(v)
        if k == "invisible_strip":
            return "".join(ch for ch in v if not _invisible(ch))
        if k in {"hex_decode", "base32_decode", "base64_decode"}:
            kind = k.removesuffix("_decode")
            padded = op.get("decode_padding", False)
            out = _decode(v, kind, padded)
            encoded = (
                out.encode().hex()
                if kind == "hex"
                else (
                    base64.b32encode(out.encode()).decode()
                    if kind == "base32"
                    else base64.b64encode(out.encode()).decode()
                )
            )
            if not padded and kind != "hex":
                encoded = encoded.rstrip("=")
            if encoded != v:
                raise ProvenanceError(f"{kind} decode: non-canonical encoding")
            return out
        if k == "leetspeak":
            return v.translate(str.maketrans("013457@$", "oieatsas"))
        if k == "vowel_fold":
            return v.translate(str.maketrans("aeiouAEIOU", "aaaaaAAAAA"))
        if k == "query_unescape":
            return _query_unescape(v, charge)
        if k == "invisible_space":
            return "".join(" " if _invisible(ch) else ch for ch in v)
        if k == "matching_normalize":
            unicode = _unicode()
            normalized = unicode.normalize(
                "NFKC", "".join(ch for ch in v if not _invisible(ch))
            )
            normalized = "".join(_confusable(ch) for ch in normalized)
            normalized = "".join(
                ch
                for ch in unicode.normalize("NFD", normalized)
                if unicode.category(ch) != "Mn"
            )
            return _matching_whitespace(normalized)
        if k.endswith("_liberal"):
            base = k.removesuffix("_decode_liberal")
            return _decode(
                v,
                base,
                op.get("decode_padding", False),
                op.get("alphabet", "standard"),
                f"liberal {base} decode",
            )
        if k == "encoded_token_normalize":
            return _encoded_token(v, op["alphabet"])
        if k == "text_segment":
            pattern = "[" + re.escape("".join(sorted(_TEXT_DELIMS))) + "]+"
            parts = [x for x in re.split(pattern, v) if x]
            return _at(parts, op.get("occurrence", 0), "text segment")
        if k == "html_entity_decode":
            for _ in range(16):
                charge(v)
                out = html.unescape(v)
                if out == v:
                    break
                v = out
            return v
        if k == "whitespace_compact":
            # Python treats U+001C..U+001F as whitespace; Go unicode.IsSpace
            # deliberately does not. Unicode White_Space is the profile rule.
            return "".join(
                ch
                for ch in v
                if not (
                    ch in "\t\n\v\f\r "
                    or ord(ch)
                    in (0x0085, 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000)
                    or 0x2000 <= ord(ch) <= 0x200A
                )
            )
        if k == "url_noise_strip":
            return v.translate(str.maketrans("", "", "./ +,;|\t\n\r"))
        if k == "ordered_query_concat":
            return "".join(
                _query_unescape(x.partition("=")[2], charge)
                for x in v.split("&")
                if x.partition("=")[2]
            )
        if k == "query_subsequence":
            values = [
                _query_unescape(x.partition("=")[2], charge)
                for x in v.split("&")
                if x.partition("=")[2]
            ][:20]
            return "".join(_at(values, x, "query subsequence") for x in op["indices"])
        if k == "hostname_dot_remove":
            return v.replace(".", "")
        if k == "encoded_run":
            runs = [
                m.group(0)
                for m in re.finditer(r"[A-Za-z0-9+/_-]+={0,2}", v)
                if len(m.group(0)) >= op["minimum_length"]
            ]
            return _at(runs, op.get("occurrence", 0), "encoded run")
        if k == "canary_canonicalize":
            return v.translate(str.maketrans("", "", ".\\/?&= \t\n\r:;,-_@%+#"))
        raise ProvenanceError(f"unknown operation {k!r}")


def _uint(value: Any, bits: int) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**bits
    )


def _encoded_token(value: str, alphabet: str) -> str:
    if len(value) < 4:
        return ""
    if alphabet == "hex":
        value = (
            value.replace(r"\x", "")
            .replace(r"\X", "")
            .replace("0x", "")
            .replace("0X", "")
        )
        value = value.translate(str.maketrans("", "", ": -,"))
        return (
            value
            if value
            and len(value) % 2 == 0
            and all(ch in "0123456789abcdefABCDEF" for ch in value)
            else ""
        )
    data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789="
    if alphabet == "base32":
        data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
    elif alphabet == "base64_standard":
        data += "+/"
    else:
        data += "-_"
    separators = " \t\n\r\f\v."
    separators += {"base32": "-_/", "base64_standard": "-_", "base64_url": "/+"}.get(
        alphabet, ""
    )
    out: list[str] = []
    changed = False
    for ch in value:
        if ch in data:
            out.append(ch)
        elif ch in separators:
            changed = True
        else:
            return ""
    normalized = "".join(out)
    return normalized if changed and len(normalized) >= 4 else ""


def _at(values: list[str], index: int, name: str) -> str:
    if index >= len(values):
        raise ProvenanceError(
            f"{name}: occurrence {index} unavailable"
            if name != "query subsequence"
            else f"query subsequence: index {index} unavailable"
        )
    return values[index]


def _url_component(value: str, op: dict[str, Any]) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        raise ProvenanceError("URL parse: invalid absolute URL")
    component = op["component"]
    if component == "url":
        return value
    if component == "hostname":
        authority = parsed.netloc.rsplit("@", 1)[-1]
        if authority.startswith("["):
            return authority[1 : authority.index("]")]
        return authority.rsplit(":", 1)[0] if ":" in authority else authority
    if component == "path":
        return parsed.path
    if component == "raw_query":
        return parsed.query
    pairs = []
    for raw in parsed.query.split("&"):
        key, _, raw_value = raw.partition("=")
        try:
            pairs.append((_strict_percent(key, True), _strict_percent(raw_value, True)))
        except ProvenanceError as exc:
            raise ProvenanceError("query parse: invalid URL escape") from exc
    values = [value for key, value in pairs if key == op["selector"]]
    if op["selector"] not in [key for key, _ in pairs] or op.get(
        "occurrence", 0
    ) >= len(values):
        raise ProvenanceError(
            f"query component: occurrence {op.get('occurrence', 0)} unavailable"
        )
    return (
        op["selector"] if component == "query_key" else values[op.get("occurrence", 0)]
    )
