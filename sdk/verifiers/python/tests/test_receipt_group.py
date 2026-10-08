# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import gzip
import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path

from pipelock_aarp_verify.ael import AELVerificationError, _read_bounded_stream
from pipelock_aarp_verify.cli import main
from pipelock_aarp_verify.group import (
    GROUP_INCOMPLETE,
    GROUP_INVALID,
    GROUP_VALID,
    GroupVerificationError,
    _parse_evidence_filename,
    _session_evidence_paths,
    check_group_ael_membership,
    duplicate_signed_ael_run_error,
    verify_receipt_group,
)

FIXTURES = Path(__file__).parent / "fixtures" / "receipt-groups.zip"
ATTACK_FIXTURE_PARTS = tuple(
    Path(__file__).parents[2]
    / "fixtures"
    / f"receipt-groups-attacks.zip.part{index:02d}"
    for index in range(7)
)
ATTACK_FIXTURES = b"".join(part.read_bytes() for part in ATTACK_FIXTURE_PARTS)
MATRIX_FIXTURES = Path(__file__).parent / "fixtures" / "receipt-groups-matrix.zip.gz"
FILENAME_VECTORS = Path(__file__).parents[2] / "filename-vectors.json"
MEMBERSHIP_VECTORS = Path(__file__).parents[2] / "receipt-group-membership-vectors.json"
STREAM_VECTORS = Path(__file__).parents[2] / "receipt-group-stream-vectors.json"


def test_shared_signed_shard_ael_membership_vectors() -> None:
    cases = json.loads(MEMBERSHIP_VECTORS.read_text())
    assert len(cases) == 5
    for item in cases:
        try:
            check_group_ael_membership(
                item["signed_sessions"], item["claimed_sessions"], item["incomplete"]
            )
        except GroupVerificationError as exc:
            assert item["error"] in str(exc), item["name"]
            assert item["error"], item["name"]
        else:
            assert not item["error"], item["name"]


def test_shared_ael_stream_and_duplicate_run_vectors() -> None:
    vectors = json.loads(STREAM_VECTORS.read_text())
    for item in vectors["bounded_stream"]:
        assert item["initial_size"] <= item["limit"], item["name"]
        try:
            actual = _read_bounded_stream(
                io.BytesIO(item["data"].encode()), item["limit"]
            )
        except AELVerificationError as exc:
            assert item["error"] in str(exc), item["name"]
            assert item["error"], item["name"]
        else:
            assert not item["error"], item["name"]
            assert actual == item["data"].encode(), item["name"]
    duplicate = vectors["duplicate_run"]
    assert duplicate["error"] in str(duplicate_signed_ael_run_error(duplicate["run"]))


def test_shared_filename_vectors(tmp_path: Path) -> None:
    vectors = json.loads(FILENAME_VECTORS.read_text())
    for item in vectors["parse"]:
        parsed = _parse_evidence_filename(item["name"])
        assert parsed == (
            (item["session"], item["seq"]) if item["session"] is not None else None
        ), item["name"]
    for name in vectors["duplicate"]:
        (tmp_path / name).write_bytes(b"")
    try:
        _session_evidence_paths(tmp_path, "proxy")
    except GroupVerificationError as exc:
        assert "ambiguous evidence shard sequence start" in str(exc)
    else:
        raise AssertionError("duplicate sequence was accepted")


with zipfile.ZipFile(FIXTURES) as fixture_archive:
    GROUP_TRUST = json.loads(fixture_archive.read("group-valid/trust.json"))
GROUP_ID = GROUP_TRUST["group_id"]
TRUSTED_KEYS = GROUP_TRUST["trusted_keys"]
TRUSTED_KEY = TRUSTED_KEYS[0]
with zipfile.ZipFile(FIXTURES) as fixture_archive:
    SUCCESSOR_TRUST = json.loads(fixture_archive.read("group-successor/trust.json"))
SUCCESSOR_ID = SUCCESSOR_TRUST["group_id"]
SUCCESSOR_KEYS = SUCCESSOR_TRUST["trusted_keys"]
with zipfile.ZipFile(FIXTURES) as fixture_archive:
    RECOVERY_TRUST = json.loads(
        fixture_archive.read("group-recovery-successor/trust.json")
    )
RECOVERY_ID = RECOVERY_TRUST["group_id"]
RECOVERY_KEYS = RECOVERY_TRUST["trusted_keys"]


def test_shared_ael_matrix(tmp_path: Path, capsys) -> None:
    with zipfile.ZipFile(
        io.BytesIO(gzip.decompress(MATRIX_FIXTURES.read_bytes()))
    ) as archive:
        cases = json.loads(archive.read("matrix.json"))
        controls = json.loads(archive.read("controls.json"))
        assert len(cases) == 119
        for entry in archive.infolist():
            if not entry.filename.startswith(("cases/", "controls/")):
                continue
            destination = tmp_path / entry.filename
            if entry.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(entry))
    for prefix, entries in (("cases", cases), ("controls", controls)):
        for case in entries:
            result = verify_receipt_group(
                tmp_path / prefix / case["name"], case["group_id"], case["trusted_keys"]
            )
            assert result["verdict"] == case["expected"], (case["name"], result)
            if case["name"] == "predecessor__signed-close-head-disagrees":
                assert "close head" in result.get("error", "")
            if case["name"] == "shard__unsafe-number-line__present":
                assert "outside cross-language exact range" in result.get("error", "")
            if case["name"] == "predecessor__intact__present":
                assert "GROUP_INCOMPLETE" in result.get("error", "")
            if case["name"] in {
                "rotation__legacy__bad-middle-json__present",
                "shard__unsafe-number-line__present",
            }:
                code = main(
                    [
                        "receipt",
                        str(tmp_path / prefix / case["name"]),
                        "--group",
                        case["group_id"],
                        "--key",
                        case["trusted_keys"][0],
                        "--json",
                    ]
                )
                assert code != 0
                assert json.loads(capsys.readouterr().out)["verdict"] == GROUP_INVALID


def _extract_fixture(name: str, target: Path) -> Path:
    with zipfile.ZipFile(FIXTURES) as fixture_archive:
        prefix = name + "/"
        for entry in fixture_archive.infolist():
            if entry.filename.startswith(prefix):
                relative = Path(entry.filename).relative_to(name)
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(fixture_archive.read(entry))
    return target


def _copy_fixture(name: str, target: Path) -> Path:
    return _extract_fixture(name, target)


def _extract_attack_fixture(name: str, target: Path) -> Path:
    with zipfile.ZipFile(io.BytesIO(ATTACK_FIXTURES)) as archive:
        for entry in archive.infolist():
            if entry.filename.startswith(name + "/"):
                relative = Path(entry.filename).relative_to(name)
                destination = target / relative
                if entry.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.read(entry))
    return target


def test_shared_attack_vectors_reject_predecessor_and_successor(tmp_path: Path) -> None:
    for name in ("forged-untrusted", "flipped-signature", "lying-chain-head"):
        fixture = _extract_attack_fixture(name, tmp_path / name)
        predecessor = next(
            path.name[len("receipt-group-") : -len("-open.json")]
            for path in fixture.glob("receipt-group-*-open.json")
            if path.name != f"receipt-group-{SUCCESSOR_ID}-open.json"
        )
        for group_id in (predecessor, SUCCESSOR_ID):
            result = verify_receipt_group(fixture, group_id, SUCCESSOR_KEYS)
            assert result["verdict"] == GROUP_INVALID, (name, group_id, result)

    for name in ("extra-unowned-ael", "empty-unowned-ael"):
        fixture = _extract_attack_fixture(name, tmp_path / name)
        result = verify_receipt_group(fixture, GROUP_ID, [TRUSTED_KEY])
        assert result["verdict"] == GROUP_INVALID
        assert "no signed session owner" in result["error"]

    for name in (
        "self-signed-owner",
        "damaged-recorder-owner",
        "damaged-recorder-trusted-owner",
        "damaged-legacy-ael",
        "damaged-neighbor-ael",
        "missing-legacy-ael",
        "missing-neighbor-ael",
        "damaged-legacy-incomplete",
    ):
        fixture = _extract_attack_fixture(name, tmp_path / name)
        trust = json.loads((fixture / "trust.json").read_text())
        result = verify_receipt_group(fixture, trust["group_id"], trust["trusted_keys"])
        assert result["verdict"] == GROUP_INVALID, (name, result)

    for scenario in ("damaged-neighbor-ael", "missing-neighbor-ael"):
        neighbor = _extract_attack_fixture(scenario, tmp_path / scenario)
        trust = json.loads((neighbor / "trust.json").read_text())
        for opening in neighbor.glob("receipt-group-*-open.json"):
            group_id = opening.name[len("receipt-group-") : -len("-open.json")]
            result = verify_receipt_group(neighbor, group_id, trust["trusted_keys"])
            assert result["verdict"] == GROUP_INVALID, (scenario, group_id, result)

    legacy = _extract_attack_fixture("trusted-legacy-owner", tmp_path / "legacy")
    trust = json.loads((legacy / "trust.json").read_text())
    result = verify_receipt_group(legacy, trust["group_id"], trust["trusted_keys"])
    assert result["verdict"] == GROUP_VALID, result

    large = _extract_attack_fixture("large-legacy-ael", tmp_path / "large")
    trust = json.loads((large / "trust.json").read_text())
    result = verify_receipt_group(large, trust["group_id"], trust["trusted_keys"])
    assert result["verdict"] == GROUP_VALID, result


def test_recovery_seal_survives_shard_count_change(tmp_path: Path) -> None:
    fixture = _extract_attack_fixture(
        "recovery-count-change", tmp_path / "count-change"
    )
    trust = json.loads((fixture / "trust.json").read_text())
    result = verify_receipt_group(fixture, trust["group_id"], trust["trusted_keys"])
    assert result["verdict"] == GROUP_VALID, result.get("error")
    assert result["shard_count"] == 3


def test_shared_duplicate_successors_are_invalid(tmp_path: Path) -> None:
    fixture = _extract_attack_fixture("duplicate-successor", tmp_path / "duplicate")
    trust = json.loads((fixture / "trust.json").read_text())
    ids = [
        path.name[len("receipt-group-") : -len("-open.json")]
        for path in fixture.glob("receipt-group-*-open.json")
    ]
    assert len(ids) == 3
    for group_id in ids:
        result = verify_receipt_group(fixture, group_id, trust["trusted_keys"])
        assert result["verdict"] == GROUP_INVALID, (group_id, result)


def test_go_producer_group_fixture_verifies(tmp_path: Path) -> None:
    fixture = _extract_fixture("group-valid", tmp_path / "valid")
    result = verify_receipt_group(fixture, GROUP_ID, [TRUSTED_KEY])
    assert result["verdict"] == GROUP_VALID, result.get("error")
    assert result["shard_count"] == 2


def test_go_producer_successor_group_and_transition_verify(tmp_path: Path) -> None:
    fixture = _extract_fixture("group-successor", tmp_path / "successor")
    result = verify_receipt_group(fixture, SUCCESSOR_ID, SUCCESSOR_KEYS)
    assert result["verdict"] == GROUP_VALID, result.get("error")


def test_go_producer_recovery_successor_verifies(tmp_path: Path) -> None:
    fixture = _extract_fixture("group-recovery-successor", tmp_path / "recovery")
    result = verify_receipt_group(fixture, RECOVERY_ID, RECOVERY_KEYS)
    assert result["verdict"] == GROUP_VALID, result.get("error")


def test_tampered_recovery_seal_is_invalid(tmp_path: Path) -> None:
    copied = _extract_fixture("group-recovery-successor", tmp_path / "recovery")
    seal = next(copied.glob("chain-link-*.json"))
    raw = seal.read_bytes()
    seal.write_bytes(raw.replace(b"shard_sha256", b"shard_sha25", 1))

    result = verify_receipt_group(copied, RECOVERY_ID, RECOVERY_KEYS)
    assert result["verdict"] == GROUP_INVALID
    assert "recovery seal" in result["error"]


def test_missing_recovery_seal_is_invalid(tmp_path: Path) -> None:
    copied = _extract_fixture("group-recovery-successor", tmp_path / "recovery")
    next(copied.glob("chain-link-*.json")).unlink()

    result = verify_receipt_group(copied, RECOVERY_ID, RECOVERY_KEYS)
    assert result["verdict"] == GROUP_INVALID
    assert "recovery seal" in result["error"]


def test_tampered_recovery_predecessor_prefix_is_invalid(tmp_path: Path) -> None:
    copied = _extract_fixture("group-recovery-successor", tmp_path / "recovery")
    seal = json.loads(next(copied.glob("chain-link-*.json")).read_text())
    shard = copied / seal["shard"]
    raw = shard.read_bytes()
    shard.write_bytes(raw.replace(b"receipt_group_v1", b"receipt_group_x", 1))

    result = verify_receipt_group(copied, RECOVERY_ID, RECOVERY_KEYS)
    assert result["verdict"] == GROUP_INVALID
    assert "shard" in result["error"]


def test_group_cli_requires_complete_pinned_group(tmp_path: Path, capsys) -> None:
    fixture = _extract_fixture("group-valid", tmp_path / "valid")
    code = main(
        [
            "receipt",
            str(fixture),
            "--group",
            GROUP_ID,
            "--key",
            TRUSTED_KEY,
            "--json",
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == GROUP_VALID


def test_missing_close_is_incomplete_and_nonzero(tmp_path: Path, capsys) -> None:
    copied = tmp_path / "evidence"
    _copy_fixture("group-valid", copied)
    (copied / f"receipt-group-{GROUP_ID}-close.json").unlink()

    result = verify_receipt_group(copied, GROUP_ID, [TRUSTED_KEY])
    assert result["verdict"] == GROUP_INCOMPLETE, result.get("error")
    code = main(
        [
            "receipt",
            str(copied),
            "--group",
            GROUP_ID,
            "--key",
            TRUSTED_KEY,
            "--json",
        ]
    )
    assert code != 0
    assert json.loads(capsys.readouterr().out)["verdict"] == GROUP_INCOMPLETE


def test_deleted_listed_shard_is_invalid(tmp_path: Path) -> None:
    copied = tmp_path / "evidence"
    _copy_fixture("group-valid", copied)
    shard = next(copied.glob("evidence-*.jsonl"))
    shard.unlink()

    result = verify_receipt_group(copied, GROUP_ID, [TRUSTED_KEY])
    assert result["verdict"] == GROUP_INVALID
    assert "missing" in result["error"]


def test_tampered_native_ael_record_is_invalid(tmp_path: Path) -> None:
    copied = tmp_path / "evidence"
    _copy_fixture("group-valid", copied)
    ael = next(copied.glob("ael/*/recorders/pipelock.jsonl"))
    lines = ael.read_text().splitlines()
    lines[0] = lines[0][:-1] + ("A" if lines[0][-1] != "A" else "B")
    ael.write_text("\n".join(lines) + "\n")

    result = verify_receipt_group(copied, GROUP_ID, [TRUSTED_KEY])
    assert result["verdict"] == GROUP_INVALID
    assert "native AEL" in result["error"]


def test_missing_native_ael_stream_is_invalid(tmp_path: Path) -> None:
    copied = tmp_path / "evidence"
    _copy_fixture("group-valid", copied)
    ael = next(copied.glob("ael/*/recorders/pipelock.jsonl"))
    ael.unlink()

    result = verify_receipt_group(copied, GROUP_ID, [TRUSTED_KEY])
    assert result["verdict"] == GROUP_INVALID
    assert "native AEL" in result["error"]


def test_forged_close_signature_is_invalid(tmp_path: Path) -> None:
    copied = tmp_path / "evidence"
    _copy_fixture("group-valid", copied)
    close_path = copied / f"receipt-group-{GROUP_ID}-close.json"
    close = json.loads(close_path.read_text())
    close["signature"] = "ed25519:" + "00" * 64
    close_path.write_text(json.dumps(close, separators=(",", ":")))

    result = verify_receipt_group(copied, GROUP_ID, [TRUSTED_KEY])
    assert result["verdict"] == GROUP_INVALID
    assert "signature" in result["error"]


def test_unpinned_group_signer_is_invalid(tmp_path: Path) -> None:
    fixture = _extract_fixture("group-valid", tmp_path / "valid")
    result = verify_receipt_group(fixture, GROUP_ID, [])
    assert result["verdict"] == GROUP_INVALID
    assert "trusted signer" in result["error"]


def test_forged_successor_transition_is_invalid(tmp_path: Path) -> None:
    copied = tmp_path / "evidence"
    _copy_fixture("group-successor", copied)
    transition = next(copied.glob(f"receipt-group-{SUCCESSOR_ID}-transition.json"))
    artifact = json.loads(transition.read_text())
    artifact["signature"] = "ed25519:" + "00" * 64
    transition.write_text(json.dumps(artifact, separators=(",", ":")))

    result = verify_receipt_group(copied, SUCCESSOR_ID, SUCCESSOR_KEYS)
    assert result["verdict"] == GROUP_INVALID
    assert "signature" in result["error"]


def test_duplicate_successor_transition_is_invalid(tmp_path: Path) -> None:
    copied = tmp_path / "evidence"
    _copy_fixture("group-successor", copied)
    transition = next(copied.glob(f"receipt-group-{SUCCESSOR_ID}-transition.json"))
    duplicate = copied / f"receipt-group-{'f' * 32}-transition.json"
    duplicate.write_bytes(transition.read_bytes())

    result = verify_receipt_group(copied, SUCCESSOR_ID, SUCCESSOR_KEYS)
    assert result["verdict"] == GROUP_INVALID
    assert "file identity" in result["error"]


def test_transition_filename_must_match_signed_successor(tmp_path: Path) -> None:
    copied = tmp_path / "evidence"
    _copy_fixture("group-successor", copied)
    transition = copied / f"receipt-group-{SUCCESSOR_ID}-transition.json"
    transition.rename(copied / f"receipt-group-{'f' * 32}-transition.json")

    result = verify_receipt_group(copied, SUCCESSOR_ID, SUCCESSOR_KEYS)
    assert result["verdict"] == GROUP_INVALID
    assert "transition" in result["error"]


MUTATION_VECTORS = Path(__file__).parents[2] / "receipt-group-mutation-vectors.json"
DUPLICATE_RUN_FIXTURE = (
    Path(__file__).parents[2] / "fixtures" / "receipt-group-duplicate-ael-run.zip"
)


def _apply_mutation(directory: Path, op: dict) -> None:
    target = directory / op["file"]
    kind = op["op"]
    if kind == "create":
        target.write_text(op.get("arg", ""))
        return
    if kind == "delete":
        target.unlink()
        return
    data = target.read_bytes()
    if kind == "append":
        data += bytes.fromhex(op["arg"])
    elif kind == "bom":
        data = b"\xef\xbb\xbf" + data
    elif kind == "empty":
        data = b""
    elif kind == "strip_final_newline":
        assert data.endswith(b"\n")
        data = data[:-1]
    elif kind == "truncate_half":
        data = data[: len(data) // 2]
    elif kind == "drop_last_line":
        data = b"\n".join(data.rstrip(b"\n").split(b"\n")[:-1]) + b"\n"
    else:
        raise AssertionError(f"unknown mutation {kind}")
    target.write_bytes(data)


def test_shared_mutation_vectors_match_the_go_verdict(tmp_path: Path) -> None:
    """Every verdict was produced by the Go CLI on the same mutated directory."""
    vectors = json.loads(MUTATION_VECTORS.read_text())
    assert len(vectors) == 25
    with zipfile.ZipFile(
        io.BytesIO(gzip.decompress(MATRIX_FIXTURES.read_bytes()))
    ) as archive:
        archive.extractall(tmp_path / "matrix")
    for item in vectors:
        directory = tmp_path / "mutated" / item["name"]
        shutil.copytree(tmp_path / "matrix" / "cases" / item["case"], directory)
        for op in item["ops"]:
            _apply_mutation(directory, op)
        result = verify_receipt_group(directory, item["group_id"], item["trusted_keys"])
        assert result["verdict"] == item["expected"], (item["name"], result)
        if item.get("error_contains"):
            assert item["error_contains"] in result.get("error", ""), item["name"]


def test_unknown_receipt_group_artifact_is_invalid(tmp_path: Path) -> None:
    """Go, TS and Rust refuse a stray receipt-group-* file; so does Python."""
    with zipfile.ZipFile(FIXTURES) as archive:
        archive.extractall(tmp_path)
    directory = tmp_path / "group-valid"
    assert (
        verify_receipt_group(directory, GROUP_ID, TRUSTED_KEYS)["verdict"]
        == GROUP_VALID
    )
    (directory / "receipt-group-zz.json").write_text("{}")
    result = verify_receipt_group(directory, GROUP_ID, TRUSTED_KEYS)
    assert result["verdict"] == GROUP_INVALID
    assert "unknown receipt group artifact" in result["error"]
    (directory / "receipt-group-zz.json").unlink()
    (directory / f"receipt-group-{GROUP_ID.upper()}-open.json").write_text("{}")
    assert (
        verify_receipt_group(directory, GROUP_ID, TRUSTED_KEYS)["verdict"]
        == GROUP_INVALID
    )


def test_duplicate_signed_native_ael_run_is_rejected_end_to_end(tmp_path: Path) -> None:
    """A Go-produced closed group whose two shards sign one native AEL run.

    The message is asserted so the test fails if the guard is removed: the
    orphaned second run would then be reported as unowned instead.
    """
    with zipfile.ZipFile(DUPLICATE_RUN_FIXTURE) as archive:
        archive.extractall(tmp_path)
    directory = tmp_path / "duplicate-ael-run"
    trust = json.loads((directory / "trust.json").read_text())
    result = verify_receipt_group(directory, trust["group_id"], trust["trusted_keys"])
    assert result["verdict"] == GROUP_INVALID, result
    assert "duplicate signed native AEL run" in result["error"], result


V2_CORPUS = Path(__file__).parent / "fixtures" / "receipt-groups-v2.zip"


def test_shared_v2_group_corpus_matches_the_go_verdict(tmp_path: Path) -> None:
    """Groups from the real server emitter path, with v2 evidence receipts.

    Covers a transition from a closed, crashed or torn-and-sealed predecessor,
    and tamper cases whose recorder hash chain (and checkpoint, seal and
    transition signatures) were recomputed, so only the signed content is
    wrong. Every verdict is the Go verifier's own.
    """
    with zipfile.ZipFile(V2_CORPUS) as archive:
        archive.extractall(tmp_path)
    cases = json.loads((tmp_path / "cases.json").read_text())
    assert len(cases) == 20
    for item in cases:
        result = verify_receipt_group(
            tmp_path / "cases" / item["name"], item["group_id"], item["trusted_keys"]
        )
        assert result["verdict"] == item["expected"], (item["name"], result)


def test_unexpected_exception_from_untrusted_input_is_group_invalid(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A shape no check anticipated is an invalid group, never a traceback."""
    from pipelock_aarp_verify import group as group_module

    with zipfile.ZipFile(V2_CORPUS) as archive:
        archive.extractall(tmp_path)
    cases = {c["name"]: c for c in json.loads((tmp_path / "cases.json").read_text())}
    item = cases["v2-n2-closed"]
    directory = tmp_path / "cases" / item["name"]
    assert (
        verify_receipt_group(directory, item["group_id"], item["trusted_keys"])[
            "verdict"
        ]
        == GROUP_VALID
    )

    def explode(*_args, **_kwargs):
        raise AttributeError("'list' object has no attribute 'get'")

    monkeypatch.setattr(group_module, "_verify_ael_inventory", explode)
    result = verify_receipt_group(directory, item["group_id"], item["trusted_keys"])
    assert result["verdict"] == GROUP_INVALID
    assert "AttributeError" in result["error"]
    code = main(
        [
            "receipt",
            str(directory),
            "--group",
            item["group_id"],
            "--key",
            ",".join(item["trusted_keys"]),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert json.loads(captured.out)["verdict"] == GROUP_INVALID


def test_shared_group_fixtures_are_byte_identical_across_language_directories() -> None:
    """Go reads only the python copy; other copies must be the same bytes."""
    languages = Path(__file__).parents[2]
    for name in (
        "receipt-groups-matrix.zip.gz",
        "receipt-groups.zip",
        "receipt-groups-v2.zip",
    ):
        reference = hashlib.sha256(
            (languages / "python" / "tests" / "fixtures" / name).read_bytes()
        ).hexdigest()
        for language in ("ts", "rust", "python"):
            copy = languages / language / "tests" / "fixtures" / name
            assert hashlib.sha256(copy.read_bytes()).hexdigest() == reference, (
                language,
                name,
            )


def test_group_manifest_integers_reject_json_booleans() -> None:
    """Go decodes version and shard_index as integers; True is not 1."""
    from pipelock_aarp_verify.group import _validate_open

    with zipfile.ZipFile(FIXTURES) as archive:
        opening = json.loads(
            archive.read(f"group-valid/receipt-group-{GROUP_ID}-open.json")
        )
    _validate_open(opening, GROUP_ID)
    for mutate in (
        lambda value: value.__setitem__("version", True),
        lambda value: value.__setitem__("version", 1.0),
        lambda value: value["shards"][1].__setitem__("shard_index", True),
    ):
        forged = json.loads(json.dumps(opening))
        mutate(forged)
        try:
            _validate_open(forged, GROUP_ID)
        except GroupVerificationError:
            continue
        raise AssertionError("boolean or float integer field was accepted")
