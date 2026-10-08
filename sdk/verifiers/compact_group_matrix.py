# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Compact and copy the signed matrix after the Go writer generates it.

Run after UPDATE_ROTATION_MATRIX=1 go test ./internal/receipt
-run '^TestGenerateReceiptGroupRotationMatrix$'. Regeneration needs 7z;
verifier tests only need the committed gzip files.
"""

from __future__ import annotations

import gzip
import io
import json
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELATIVE_FIXTURE = Path("tests/fixtures/receipt-groups-matrix.zip.gz")
SOURCE = ROOT / "sdk/verifiers/python" / RELATIVE_FIXTURE
MAX_BYTES = 500 * 1024


def main() -> None:
    command = shutil.which("7z")
    if command is None:
        raise SystemExit(
            "7z is required to regenerate the compact receipt group matrix"
        )
    raw = gzip.decompress(SOURCE.read_bytes())
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if archive.testzip() is not None:
            raise SystemExit("signed receipt group matrix ZIP is corrupt")
        cases = json.loads(archive.read("matrix.json"))
        if len(cases) != 119:
            raise SystemExit(
                f"signed receipt group matrix has {len(cases)} cases, want 119"
            )
    with tempfile.TemporaryDirectory(prefix="receipt-group-matrix-") as directory:
        zip_path = Path(directory) / "receipt-groups-matrix.zip"
        packed_path = Path(directory) / "receipt-groups-matrix.zip.gz"
        zip_path.write_bytes(raw)
        subprocess.run(
            [command, "a", "-tgzip", "-mx=9", str(packed_path), str(zip_path)],
            check=True,
            capture_output=True,
        )
        packed = packed_path.read_bytes()
        if gzip.decompress(packed) != raw:
            raise SystemExit("compact matrix differs from Go-generated ZIP")
        if len(packed) > MAX_BYTES:
            raise SystemExit(
                f"compact matrix is {len(packed)} bytes, limit is {MAX_BYTES}"
            )
        for language in ("python", "rust", "ts"):
            (ROOT / "sdk/verifiers" / language / RELATIVE_FIXTURE).write_bytes(packed)
    print(f"copied {len(cases)} signed matrix cases, {len(packed)} bytes per language")


if __name__ == "__main__":
    main()
