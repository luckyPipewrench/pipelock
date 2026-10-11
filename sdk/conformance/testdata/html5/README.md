The named-character-reference source is WHATWG's [entities.json](https://html.spec.whatwg.org/entities.json), referenced by the [HTML named character references section](https://html.spec.whatwg.org/multipage/named-characters.html#named-character-references). This directory vendors the original bytes. Their SHA-256 is `d741d877ac77c4194c4ad526b5b4a19aef8dfe411ab840a466891cdbb9f362e6`; the generator checks it before using the file. The table has 2,231 entries, including 106 legacy spellings without a semicolon and 93 entries producing two code points.

From the repository root, regenerate with:

```sh
python3 sdk/conformance/generate-html5-entities.py
```

The generator uses Python's standard library and `gofmt`. It emits the Go and Rust named-reference tables used exclusively by replay v5, `parity-v5.json`, and the generated HTML5 vectors in the v5 replay corpus. TypeScript and Python use their existing decoders; every implementation is tested against the same expected UTF-8 bytes. Historical v1-v4 tables, decoders, profile documents, digests, and vectors are unchanged.

The oracle takes the longest matching WHATWG name at each ampersand in the original pass input. It uses the HTML text state, so a legacy name can match before a letter, digit, or equals sign, as in `&notit;`. Only a table key that omits the semicolon permits that spelling. The test covers every table key, every semicolon-omitted name, legacy-prefix contexts, unknown names, Unicode suffixes, and references exposed by decoding `&amp;` on a previous pass. Each recipe repeats up to the v5 limit of 16 passes.

Run the byte comparison and all historical replay corpora with:

```sh
bash sdk/conformance/replay-corpus-gate.sh
```

That gate also runs the generator with `--check`, which rejects a changed source hash or stale generated artifact. The full-table tests report every divergence as `[input, expected_base64, actual_base64]` before failing. Generated v5 replay vectors cover all multi-code-point entries, all legacy spellings, and legacy-prefix contexts, including their cumulative processed-byte charges. No network access is needed to regenerate or test the pinned snapshot.
