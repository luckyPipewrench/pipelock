# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from pipelock_aarp_verify.receipt import ReceiptError, load_receipt


def test_receipt_rejects_oversized_input_before_parse(tmp_path):
    target = tmp_path / "receipt.json"
    with target.open("wb") as stream:
        stream.truncate((8 << 20) + 1)
    with pytest.raises(ReceiptError, match="exceeds"):
        load_receipt(target)
