# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Command-line entry point, ported from ``cmd/pipelock-verifier/aarp.go``.

Usage::

    python -m pipelock_aarp_verify aarp PATH --trust TRUST_JSON [--chain] [--json]

Exit codes mirror the Go reference and the cross-language gate:

  - 0  the envelope was appraised (single) / the stream is linked (chain)
  - 1  the envelope is fatal / the chain is not linked
  - 2  an I/O or trust-file error
  - 64 a usage error
"""

from __future__ import annotations

import argparse
import binascii
import json
import sys
from typing import IO, Any

from .appraise import (
    TrustEntry,
    VerifyOptions,
    comparable_appraisal,
    verify,
)
from .chain import comparable_chain, verify_chain
from .envelope import unmarshal
from .svid import SVIDConfigError, appraise_with_svid, load_svid_file

ED25519_PUBLIC_KEY_SIZE = 32

EXIT_OK = 0
EXIT_GENERAL = 1
EXIT_CONFIG = 2
EXIT_USAGE = 64

# Allowed keys in the trust file (Go uses DisallowUnknownFields on these).
_TRUST_KEYS = {"trusted_keys", "trust_entries"}
_TRUST_ENTRY_KEYS = {"mediator_id", "role", "trust_domain"}


class UsageError(Exception):
    """A CLI usage error (exit 64)."""


class ConfigError(Exception):
    """An I/O or trust-file error (exit 2)."""


def _load_trust_file(path: str) -> VerifyOptions:
    """Read the pinned trust JSON. A missing path yields empty trust."""
    opts = VerifyOptions()
    if path == "":
        return opts
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise ConfigError(f"read trust file: {exc}") from exc
    try:
        tf = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"parse trust file: {exc}") from exc
    if not isinstance(tf, dict):
        raise ConfigError("parse trust file: top-level value is not an object")
    for key in tf:
        if key not in _TRUST_KEYS:
            raise ConfigError(f"parse trust file: unknown field {key!r}")
    trusted_keys = tf.get("trusted_keys", {})
    if trusted_keys is None:
        trusted_keys = {}
    if not isinstance(trusted_keys, dict):
        raise ConfigError("parse trust file: trusted_keys must be an object")
    for key_id, key_hex in trusted_keys.items():
        if not isinstance(key_hex, str):
            raise ConfigError(f"trusted_keys[{key_id!r}]: not a string")
        try:
            raw = binascii.unhexlify(key_hex)
        except (binascii.Error, ValueError) as exc:
            raise ConfigError(f"trusted_keys[{key_id!r}]: not hex: {exc}") from exc
        if len(raw) != ED25519_PUBLIC_KEY_SIZE:
            raise ConfigError(
                f"trusted_keys[{key_id!r}]: {len(raw)} bytes, "
                f"want {ED25519_PUBLIC_KEY_SIZE}"
            )
        opts.trusted_keys[key_id] = raw
    trust_entries = tf.get("trust_entries", {})
    if trust_entries is None:
        trust_entries = {}
    if not isinstance(trust_entries, dict):
        raise ConfigError("parse trust file: trust_entries must be an object")
    for key_id, entry in trust_entries.items():
        if not isinstance(entry, dict):
            raise ConfigError(f"trust_entries[{key_id!r}] must be an object")
        for ekey in entry:
            if ekey not in _TRUST_ENTRY_KEYS:
                raise ConfigError(
                    f"parse trust file: unknown field {ekey!r} in trust_entries"
                )
        opts.trust[key_id] = TrustEntry(
            mediator_id=str(entry.get("mediator_id", "")),
            role=str(entry.get("role", "")),
            trust_domain=str(entry.get("trust_domain", "")),
        )
    return opts


def _emit_fatal(stdout: IO[str], stderr: IO[str], json_mode: bool, cause: str) -> int:
    """Print the envelope-fatal marker (or human text) and return exit 1."""
    if json_mode:
        body: dict[str, Any] = {"envelope_fatal": True}
        if cause:
            body["error"] = cause
        stdout.write(json.dumps(body, separators=(",", ":"), ensure_ascii=False))
        stdout.write("\n")
    else:
        stderr.write(f"ENVELOPE FATAL: {cause}\n")
    return EXIT_GENERAL


def _run_chain(stdout: IO[str], stderr: IO[str], data: bytes, json_mode: bool) -> int:
    lines = data.strip().split(b"\n")
    envs = []
    for i, line in enumerate(lines):
        if line.strip() == b"":
            continue
        try:
            envs.append(unmarshal(line))
        except Exception as exc:  # noqa: BLE001 - any parse failure is fatal
            return _emit_fatal(stdout, stderr, json_mode, f"chain line {i}: {exc}")

    try:
        comparable = comparable_chain(envs)
    except Exception as exc:  # noqa: BLE001 - render failure
        stderr.write(f"render chain: {exc}\n")
        return EXIT_GENERAL
    if json_mode:
        stdout.write(comparable.decode("utf-8"))
        stdout.write("\n")
    else:
        stdout.write(f"AARP chain: {len(envs)} envelopes\n")
    try:
        verify_chain(envs)
    except Exception:  # noqa: BLE001 - not linked
        return EXIT_GENERAL
    return EXIT_OK


def _run_aarp(
    stdout: IO[str],
    stderr: IO[str],
    target: str,
    trust_path: str,
    json_mode: bool,
    chain_mode: bool,
    svid_path: str,
) -> int:
    # --svid is single-envelope only; combining it with --chain is a usage error.
    if chain_mode and svid_path != "":
        stderr.write(
            "--svid is single-envelope only and cannot be combined with --chain\n"
        )
        return EXIT_USAGE

    try:
        verify_opts = _load_trust_file(trust_path)
    except ConfigError as exc:
        stderr.write(f"load trust: {exc}\n")
        return EXIT_CONFIG

    # Load the SVID sidecar (if any) before reading the envelope, so a malformed
    # pinned bundle is reported as a config error (exit 2) rather than entangled
    # with envelope appraisal.
    svid_evidence: dict[str, Any] | None = None
    svid_opts = None
    if svid_path != "":
        try:
            svid_evidence, svid_opts = load_svid_file(svid_path)
        except SVIDConfigError as exc:
            stderr.write(f"load svid: {exc}\n")
            return EXIT_CONFIG

    try:
        with open(target, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        stderr.write(f"read envelope: {exc}\n")
        return EXIT_CONFIG

    if chain_mode:
        return _run_chain(stdout, stderr, data, json_mode)

    try:
        env = unmarshal(data)
    except Exception as exc:  # noqa: BLE001 - any parse failure is fatal
        return _emit_fatal(stdout, stderr, json_mode, str(exc))

    try:
        if svid_evidence is not None:
            ap = appraise_with_svid(env, svid_evidence, verify_opts, svid_opts)
        else:
            ap = verify(env, verify_opts)
    except Exception as exc:  # noqa: BLE001 - envelope-fatal appraisal failure
        return _emit_fatal(stdout, stderr, json_mode, str(exc))

    try:
        comparable = comparable_appraisal(ap)
    except Exception as exc:  # noqa: BLE001 - render failure
        stderr.write(f"render appraisal: {exc}\n")
        return EXIT_GENERAL
    if json_mode:
        stdout.write(comparable.decode("utf-8"))
        stdout.write("\n")
    else:
        _emit_human(stdout, ap)
    return EXIT_OK


def _emit_human(stdout: IO[str], ap: Any) -> None:
    stdout.write(f"AARP appraisal ({ap.profile})\n")
    stdout.write(f"  assertion_signed:   {str(ap.assertion_signed).lower()}\n")
    stdout.write(f"  verified_claims:    {ap.verified_claims}\n")
    stdout.write(f"  claimed_unverified: {ap.claimed_unverified}\n")
    for s in ap.signatures:
        stdout.write(f"  signature {s.key_id}/{s.alg}: {s.status}\n")
    stdout.write(f"  does_not_assert:    {ap.does_not_assert}\n")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="pipelock_aarp_verify",
        description="Appraise an AARP v0.1 assurance envelope against a trust file.",
        add_help=True,
    )
    sub = parser.add_subparsers(dest="command")
    aarp_p = sub.add_parser("aarp", help="appraise an AARP v0.1 assurance envelope")
    aarp_p.add_argument("path", help="path to a JSON envelope (or JSONL with --chain)")
    aarp_p.add_argument("--trust", default="", help="path to the pinned trust JSON")
    aarp_p.add_argument(
        "--svid",
        default="",
        help="path to the SVID attestation JSON (evidence + pinned bundle/action-time)",
    )
    aarp_p.add_argument(
        "--json", action="store_true", help="emit the comparable appraisal JSON"
    )
    aarp_p.add_argument(
        "--chain",
        action="store_true",
        help="PATH is a JSONL stream; verify Rung-1 chain linkage",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit:
        # argparse exits 2 on usage error; the gate expects 64 for usage.
        return EXIT_USAGE

    if args.command != "aarp":
        parser.print_usage(sys.stderr)
        return EXIT_USAGE

    return _run_aarp(
        sys.stdout,
        sys.stderr,
        args.path,
        args.trust,
        args.json,
        args.chain,
        args.svid,
    )
