// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { after, before, test } = require("node:test");
const {
  isMainThread,
  parentPort,
  Worker,
  workerData,
} = require("node:worker_threads");

if (!isMainThread) {
  runWasmWorker().catch((error) => {
    parentPort.postMessage({ error: error.stack || String(error) });
  });
} else {
  const repoRoot = path.resolve(__dirname, "../..");
  const testdata = path.join(repoRoot, "sdk/conformance/testdata");
  const keyInfo = JSON.parse(
    readFileSync(path.join(testdata, "test-key.json"), "utf8"),
  );
  const primaryKey = keyInfo.public_key_hex;
  const rotatedKey = keyInfo.rotated_public_key_hex;
  const rotatedTwiceKey = keyInfo.rotated_twice_public_key_hex;
  const tempRoot = process.env.TMPDIR || tmpdir();
  let outDir;
  let worker;
  let oracleByName;
  let groupCases;
  let groupFixture;
  let nextID = 1;
  const pending = new Map();

  const cases = [
    { name: "valid-chain.jsonl", valid: true },
    { name: "g1-valid-chain.jsonl", valid: true },
    { name: "g1-restart-chain.jsonl", valid: true },
    {
      name: "broken-chain.jsonl",
      valid: false,
      reason: /chain_prev_hash mismatch/u,
    },
    {
      name: "g1-broken-genesis.jsonl",
      valid: false,
      reason: /session_open genesis hash mismatch/u,
    },
    {
      name: "g1-legacy-open-genesis.jsonl",
      valid: false,
      reason: /session_open on legacy genesis/u,
    },
    {
      name: "g1-inconsistent-heartbeat.jsonl",
      valid: false,
      reason: /heartbeat chain_head mismatch/u,
    },
    {
      name: "g1-inconsistent-close.jsonl",
      valid: false,
      reason: /session_close root_hash mismatch/u,
    },
    {
      name: "g1-ambiguous-session-control.jsonl",
      valid: false,
      reason: /session_control must carry exactly one payload/u,
    },
    {
      name: "g1-ambiguous-open-close.jsonl",
      valid: false,
      reason: /session_control must carry exactly one payload/u,
    },
    {
      name: "g1-ambiguous-heartbeat-close.jsonl",
      valid: false,
      reason: /session_control must carry exactly one payload/u,
    },
    {
      name: "g1-rotated-close-count-valid.jsonl",
      valid: true,
      keys: [primaryKey, rotatedKey],
    },
    {
      name: "g1-rotated-close-count-invalid.jsonl",
      valid: false,
      keys: [primaryKey, rotatedKey],
      reason: /session_close receipt_count mismatch/u,
    },
    {
      name: "g1-rotated-twice-valid.jsonl",
      valid: true,
      keys: [primaryKey, rotatedKey, rotatedTwiceKey],
    },
    {
      name: "g1-rotated-same-key-invalid.jsonl",
      valid: false,
      reason: /key_transition does not change signer key/u,
    },
    { name: "g1-ext-chain.jsonl", valid: true },
    {
      name: "g1-ext-tampered-invalid.jsonl",
      valid: false,
      reason: /chain_prev_hash mismatch/u,
    },
    {
      name: "g1-plain-after-close.jsonl",
      valid: false,
      reason: /record observed after session_close/u,
    },
    {
      name: "g1-empty-run-nonce-after-close.jsonl",
      valid: true,
    },
    {
      name: "g1-heartbeat-after-close.jsonl",
      valid: false,
      reason: /record observed after session_close/u,
    },
    {
      name: "g1-close-without-open.jsonl",
      valid: false,
      reason: /first receipt is not a matching session_open/u,
    },
    {
      name: "g1-new-session-after-close.jsonl",
      valid: true,
    },
    {
      name: "g1-reopen-closed-run.jsonl",
      valid: false,
      reason: /duplicate session_open for run_nonce/u,
    },
  ].map((tc) => ({
    ...tc,
    path: path.join(testdata, tc.name),
    keys: tc.keys || [primaryKey],
  }));

  before(async () => {
    outDir = mkdtempSync(path.join(tempRoot, "pipelock-wasm-verify-"));
    execFileSync("bash", ["deploy/wasm-verify/build.sh", outDir], {
      cwd: repoRoot,
      env: process.env,
      encoding: "utf8",
    });
    oracleByName = runOracle(cases, repoRoot);
    groupFixture = readFileSync(
      path.join(
        repoRoot,
        "sdk/verifiers/python/tests/fixtures/receipt-groups.zip",
      ),
    );
    groupCases = runGroupOracle(
      path.join(
        repoRoot,
        "sdk/verifiers/python/tests/fixtures/receipt-groups.zip",
      ),
      repoRoot,
    );
    worker = await startWorker(outDir);
    worker.on("message", (message) => {
      if (message.error) {
        for (const { reject } of pending.values()) {
          reject(new Error(message.error));
        }
        pending.clear();
        return;
      }
      if (!message.id) {
        return;
      }
      const waiting = pending.get(message.id);
      if (!waiting) {
        return;
      }
      pending.delete(message.id);
      if (message.callError) {
        waiting.reject(new Error(message.callError));
        return;
      }
      waiting.resolve(message.result);
    });
    // A worker that crashes or exits AFTER startup emits an error/exit event,
    // not a message, so without these handlers any in-flight verify calls would
    // hang until the after() cleanup. Reject them promptly instead.
    const failPending = (err) => {
      for (const { reject } of pending.values()) {
        reject(err);
      }
      pending.clear();
    };
    worker.on("error", (err) => {
      failPending(err instanceof Error ? err : new Error(String(err)));
    });
    worker.on("exit", (code) => {
      if (code !== 0) {
        failPending(new Error(`wasm worker exited with code ${code}`));
      }
    });
  });

  after(async () => {
    for (const { reject } of pending.values()) {
      reject(new Error("test ended before wasm call completed"));
    }
    pending.clear();
    if (worker) {
      await worker.terminate();
    }
    if (outDir) {
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  test("build emits wasm and standard Go wasm glue", () => {
    assert.ok(existsSync(path.join(outDir, "pipelock-verifier.wasm")));
    assert.ok(existsSync(path.join(outDir, "wasm_exec.js")));
  });

  test("clean g1 raw chain verifies with the trusted key", async () => {
    const result = await verifyFixture("g1-valid-chain.jsonl", "uint8array");
    assert.equal(result.valid, true, result.error);
    assert.equal(result.receiptCount, 5);
    assert.equal(result.finalSeq, 4);
    assert.deepEqual(result.signerKeys, [primaryKey]);
  });

  test("shared Go evidence-line whitespace vectors match WASM", async () => {
    const vectors = JSON.parse(
      readFileSync(
        path.join(
          repoRoot,
          "sdk/conformance/testdata/receipt-line-whitespace.json",
        ),
        "utf8",
      ),
    ).vectors;
    assert.equal(vectors.length, 93);
    const base = readFileSync(path.join(testdata, "g1-valid-chain.jsonl"));
    const firstEnd = base.indexOf(0x0a);
    assert.ok(firstEnd > 0);
    for (const vector of vectors) {
      const mark = Buffer.from(String.fromCodePoint(vector.codepoint));
      let altered;
      if (vector.placement === "whole") {
        altered = Buffer.concat([
          base.subarray(0, firstEnd + 1),
          mark,
          Buffer.from("\n"),
          base.subarray(firstEnd + 1),
        ]);
      } else if (vector.placement === "leading") {
        altered = Buffer.concat([mark, base]);
      } else {
        altered = Buffer.concat([
          base.subarray(0, firstEnd),
          mark,
          base.subarray(firstEnd),
        ]);
      }
      const result = await verifyBytes(altered, primaryKey, "uint8array");
      assert.equal(
        result.valid,
        vector.expected !== "reject",
        `${vector.name}: ${result.error}`,
      );
    }
  });

  test("rotated g1 raw chain verifies with multi-key input", async () => {
    const result = await verifyFixture(
      "g1-rotated-close-count-valid.jsonl",
      "uint8array",
    );
    assert.equal(result.valid, true, result.error);
    assert.equal(result.receiptCount, 6);
    assert.equal(result.finalSeq, 2);
    assert.deepEqual(result.signerKeys, [primaryKey, rotatedKey]);
  });

  test("raw chain input accepts ArrayBuffer and string forms", async () => {
    const arrayBufferResult = await verifyFixture(
      "g1-valid-chain.jsonl",
      "arraybuffer",
    );
    assert.equal(arrayBufferResult.valid, true, arrayBufferResult.error);

    const stringResult = await verifyFixture("g1-valid-chain.jsonl", "string");
    assert.equal(stringResult.valid, true, stringResult.error);
  });

  test("all raw JSONL golden fixtures match the Go receipt verifier", async () => {
    assertCaseListCoversTopLevelJSONLFixtures(cases, testdata);
    for (const tc of cases) {
      const result = await verifyFixture(tc.name, "uint8array");
      assertChainParity(result, oracleByName.get(tc.name), tc.name);
      assert.deepEqual(
        result.checks || [],
        [
          { name: "raw_receipts_extracted", pass: true },
          { name: "receipt_chain_verified", pass: tc.valid },
        ],
        `${tc.name}: chain checks`,
      );
      assert.equal(
        result.valid,
        tc.valid,
        `${tc.name}: ${result.error || "unexpected result"}`,
      );
      if (tc.reason) {
        assert.match(result.error || "", tc.reason, tc.name);
      }
    }
  });

  test("malformed raw chain inputs fail closed", async () => {
    const empty = await verifyBytes(Buffer.alloc(0), primaryKey, "uint8array");
    assert.equal(empty.valid, false);
    assert.match(
      empty.error || "",
      /chain string is empty|no receipts found in chain/u,
    );

    const badKey = await verifyBytes(
      readFileSync(path.join(testdata, "g1-valid-chain.jsonl")),
      [],
      "uint8array",
    );
    assert.equal(badKey.valid, false);
    assert.match(badKey.error || "", /at least one trusted key is required/u);

    const missingKey = await verifyBytes(
      readFileSync(path.join(testdata, "g1-valid-chain.jsonl")),
      undefined,
      "uint8array",
    );
    assert.equal(missingKey.valid, false);
    assert.match(missingKey.error || "", /trusted keys must be/u);

    const wrongTypedKey = await verifyBytes(
      readFileSync(path.join(testdata, "g1-valid-chain.jsonl")),
      [primaryKey, 7],
      "uint8array",
    );
    assert.equal(wrongTypedKey.valid, false);
    assert.match(wrongTypedKey.error || "", /trusted key at index 1/u);

    const wrongTypedChain = await verifyBytes(
      readFileSync(path.join(testdata, "g1-valid-chain.jsonl")),
      primaryKey,
      "plainobject",
    );
    assert.equal(wrongTypedChain.valid, false);
    assert.match(wrongTypedChain.error || "", /chain must be/u);

    // A valid chain must not verify when a non-receipt line is appended or
    // spliced in: the extractor rejects the malformed record rather than
    // silently skipping it and certifying the surrounding chain.
    const validBytes = readFileSync(
      path.join(testdata, "g1-valid-chain.jsonl"),
    );
    const garbage = Buffer.from('{"not":"a receipt","x":123}\n');
    const trailingGarbage = await verifyBytes(
      Buffer.concat([validBytes, Buffer.from("\n"), garbage]),
      primaryKey,
      "uint8array",
    );
    assert.equal(trailingGarbage.valid, false, trailingGarbage.error);

    const firstNewline = validBytes.indexOf(0x0a);
    const middleGarbage = await verifyBytes(
      Buffer.concat([
        validBytes.subarray(0, firstNewline + 1),
        garbage,
        validBytes.subarray(firstNewline + 1),
      ]),
      primaryKey,
      "uint8array",
    );
    assert.equal(middleGarbage.valid, false, middleGarbage.error);
  });

  test("closed, successor, and recovery groups match the Go verifier", async () => {
    for (const tc of groupCases.filter(
      (item) => item.verdict === "GROUP_VALID",
    )) {
      const result = await verifyGroup(groupFixture, tc.groupId, tc.keys);
      assert.equal(
        result.verdict,
        "GROUP_VALID",
        `${tc.scenario}/${tc.groupId}: ${result.error}`,
      );
      assert.equal(result.valid, true);
      assert.equal(result.groupId, tc.groupId);
      assert.ok(result.shardCount > 0);
    }
  });

  test("explicit ZIP root directory entry verifies in the browser", async () => {
    const tc = groupCases.find(
      (item) =>
        item.scenario === "group-valid" && item.verdict === "GROUP_VALID",
    );
    assert.ok(tc, "Go-produced closed group fixture missing");
    const bundle = path.join(outDir, "explicit-root-group.zip");
    execFileSync("python3", [
      "-c",
      `
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as source, zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as target:
    target.writestr("group-valid/", b"")
    for entry in source.infolist():
        target.writestr(entry, source.read(entry))
`,
      path.join(
        repoRoot,
        "sdk/verifiers/python/tests/fixtures/receipt-groups.zip",
      ),
      bundle,
    ]);
    const result = await verifyGroup(readFileSync(bundle), tc.groupId, tc.keys);
    assert.equal(result.verdict, "GROUP_VALID", result.error);
  });

  test("shared group attack vectors match the native verifier", async () => {
    const source = path.join(outDir, "receipt-groups-attacks.zip");
    writeFileSync(
      source,
      Buffer.concat(
        Array.from({ length: 7 }, (_, index) =>
          readFileSync(
            path.join(
              repoRoot,
              "sdk/verifiers/fixtures",
              `receipt-groups-attacks.zip.part${String(index).padStart(2, "0")}`,
            ),
          ),
        ),
      ),
    );
    for (const scenario of [
      "forged-untrusted",
      "flipped-signature",
      "lying-chain-head",
      "extra-unowned-ael",
      "empty-unowned-ael",
      "self-signed-owner",
      "damaged-recorder-owner",
      "damaged-recorder-trusted-owner",
      "damaged-legacy-ael",
      "damaged-neighbor-ael",
      "missing-legacy-ael",
      "missing-neighbor-ael",
      "damaged-legacy-incomplete",
      "trusted-legacy-owner",
      "large-legacy-ael",
      "duplicate-successor",
      "recovery-count-change",
    ]) {
      const bundle = path.join(outDir, `${scenario}.zip`);
      const trustFile = path.join(outDir, `${scenario}-trust.json`);
      execFileSync("python3", [
        "-c",
        `
import json, re, sys, zipfile
source, scenario, output, trust_file = sys.argv[1:]
with zipfile.ZipFile(source) as archive, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as selected:
    prefix = scenario + "/"
    ids = set()
    for entry in archive.infolist():
        if entry.filename.startswith(prefix):
            selected.writestr(entry.filename[len(prefix):], archive.read(entry))
            match = re.fullmatch(r"receipt-group-([0-9a-f]{32})-open[.]json", entry.filename[len(prefix):])
            if match:
                ids.add(match.group(1))
    trust = json.loads(archive.read(prefix + "trust.json"))
    trust["group_ids"] = sorted(ids)
    with open(trust_file, "w") as stream:
        json.dump(trust, stream)
`,
        source,
        scenario,
        bundle,
        trustFile,
      ]);
      const trust = JSON.parse(readFileSync(trustFile, "utf8"));
      const bytes = readFileSync(bundle);
      const successor = trust.group_id;
      const ids =
        scenario === "duplicate-successor" ||
        scenario === "damaged-neighbor-ael" ||
        scenario === "missing-neighbor-ael"
          ? trust.group_ids
          : scenario === "extra-unowned-ael" ||
              scenario === "empty-unowned-ael" ||
              scenario === "self-signed-owner" ||
              scenario === "damaged-recorder-owner" ||
              scenario === "damaged-recorder-trusted-owner" ||
              scenario === "damaged-legacy-ael" ||
              scenario === "missing-legacy-ael" ||
              scenario === "damaged-legacy-incomplete" ||
              scenario === "trusted-legacy-owner" ||
              scenario === "large-legacy-ael" ||
              scenario === "recovery-count-change"
            ? [successor]
            : ["a3c1883b420f1b8d42658bb680bfae4d", successor];
      for (const id of ids) {
        const result = await verifyGroup(bytes, id, trust.trusted_keys);
        const want =
          scenario === "recovery-count-change" ||
          scenario === "trusted-legacy-owner" ||
          scenario === "large-legacy-ael"
            ? "GROUP_VALID"
            : "GROUP_INVALID";
        assert.equal(
          result.verdict,
          want,
          `${scenario}/${id}: ${result.error}`,
        );
      }
    }
  });

  test("shared native AEL matrix matches every expected verdict", async () => {
    const source = path.join(
      repoRoot,
      "sdk/verifiers/python/tests/fixtures/receipt-groups-matrix.zip.gz",
    );
    const destination = path.join(outDir, "group-matrix");
    execFileSync("python3", [
      "-c",
      `
import gzip, io, json, os, sys, zipfile
source, destination = sys.argv[1:]
os.makedirs(destination, exist_ok=True)
with zipfile.ZipFile(io.BytesIO(gzip.decompress(open(source, "rb").read()))) as archive:
    cases = json.loads(archive.read("matrix.json"))
    controls = json.loads(archive.read("controls.json"))
    with open(os.path.join(destination, "matrix.json"), "w") as output:
        json.dump(cases, output)
    with open(os.path.join(destination, "controls.json"), "w") as output:
        json.dump(controls, output)
    for case in cases + controls:
        prefix = ("cases/" if case in cases else "controls/") + case["name"] + "/"
        with zipfile.ZipFile(os.path.join(destination, case["name"] + ".zip"), "w", zipfile.ZIP_DEFLATED) as selected:
            for entry in archive.infolist():
                if entry.filename.startswith(prefix):
                    selected.writestr(entry.filename[len(prefix):], archive.read(entry))
`,
      source,
      destination,
    ]);
    const cases = JSON.parse(
      readFileSync(path.join(destination, "matrix.json"), "utf8"),
    );
    const controls = JSON.parse(
      readFileSync(path.join(destination, "controls.json"), "utf8"),
    );
    assert.equal(cases.length, 119);
    assert.equal(controls.length, 1);
    for (const item of [...cases, ...controls]) {
      const bytes = readFileSync(path.join(destination, `${item.name}.zip`));
      const result = await verifyGroup(bytes, item.group_id, item.trusted_keys);
      assert.equal(
        result.verdict,
        item.expected,
        `${item.name}: ${result.error}`,
      );
      if (item.name === "predecessor__intact__present")
        assert.match(result.error || "", /GROUP_INCOMPLETE/u);
    }
  });

  test("missing predecessor close stays GROUP_INCOMPLETE", async () => {
    const tc = groupCases.find(
      (item) =>
        item.scenario === "group-recovery-successor" &&
        item.verdict === "GROUP_INCOMPLETE",
    );
    assert.ok(
      tc,
      "Go-produced recovery fixture has no incomplete predecessor group",
    );
    const result = await verifyGroup(groupFixture, tc.groupId, tc.keys);
    assert.equal(result.verdict, "GROUP_INCOMPLETE", result.error);
    assert.equal(result.valid, false);
    assert.match(result.error || "", /no signed close manifest/u);
  });

  test("tampered ZIP content and unpinned signer fail closed", async () => {
    const tc = groupCases.find(
      (item) =>
        item.scenario === "group-valid" && item.verdict === "GROUP_VALID",
    );
    assert.ok(tc, "Go-produced closed group fixture missing");
    const closePath = `group-valid/receipt-group-${tc.groupId}-close.json`;
    const tampered = corruptStoredZipEntry(groupFixture, closePath);
    const corruptResult = await verifyGroup(tampered, tc.groupId, tc.keys);
    assert.equal(corruptResult.verdict, "GROUP_INVALID", corruptResult.error);
    assert.equal(corruptResult.valid, false);

    const wrongKey = "00".repeat(32);
    const unpinnedResult = await verifyGroup(groupFixture, tc.groupId, [
      wrongKey,
    ]);
    assert.equal(unpinnedResult.verdict, "GROUP_INVALID");
    assert.equal(unpinnedResult.valid, false);
  });

  test("malformed and oversized group archives fail closed", async () => {
    const tc = groupCases.find(
      (item) =>
        item.scenario === "group-valid" && item.verdict === "GROUP_VALID",
    );
    assert.ok(tc);
    const malformed = await verifyGroup(
      Buffer.from("not a zip"),
      tc.groupId,
      tc.keys,
    );
    assert.equal(malformed.verdict, "GROUP_INVALID");
    assert.equal(malformed.valid, false);
    const oversized = await verifyGroup(
      Buffer.alloc((8 << 20) + 1),
      tc.groupId,
      tc.keys,
    );
    assert.equal(oversized.verdict, "GROUP_INCOMPLETE");
    assert.equal(oversized.valid, false);
    assert.match(oversized.error || "", /host verifier/u);
    const largeEntry = path.join(outDir, "large-entry.zip");
    execFileSync("python3", [
      "-c",
      `
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("group-valid/large.bin", b"x" * (33 << 20))
`,
      largeEntry,
    ]);
    const unsupported = await verifyGroup(
      readFileSync(largeEntry),
      tc.groupId,
      tc.keys,
    );
    assert.equal(unsupported.verdict, "GROUP_INCOMPLETE");
    assert.equal(unsupported.valid, false);
    assert.match(unsupported.error || "", /host verifier/u);
  });

  async function verifyFixture(name, mode) {
    const tc = cases.find((candidate) => candidate.name === name);
    assert.ok(tc, `missing test case ${name}`);
    return verifyBytes(
      readFileSync(tc.path),
      tc.keys.length === 1 ? tc.keys[0] : tc.keys,
      mode,
    );
  }

  async function verifyBytes(bytes, keys, mode) {
    const id = nextID++;
    const result = new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
    });
    worker.postMessage({ id, bytes: Uint8Array.from(bytes), keys, mode });
    return result;
  }

  async function verifyGroup(bytes, groupID, keys) {
    const id = nextID++;
    const result = new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
    });
    worker.postMessage({
      id,
      operation: "group",
      bytes: Uint8Array.from(bytes),
      groupID,
      keys,
    });
    return result;
  }
}

async function runWasmWorker() {
  require(workerData.wasmExec);
  const go = new globalThis.Go();
  const wasm = readFileSync(workerData.wasm);
  const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
  go.run(instance).catch((error) => {
    parentPort.postMessage({ error: error.stack || String(error) });
  });
  parentPort.on("message", (message) => {
    try {
      const bytes = new Uint8Array(message.bytes);
      const result =
        message.operation === "group"
          ? globalThis.pipelockVerifyReceiptGroup(
              bytes,
              message.groupID,
              message.keys,
            )
          : globalThis.pipelockVerifyChain(
              wasmInput(bytes, message.mode),
              message.keys,
            );
      parentPort.postMessage({
        id: message.id,
        result: JSON.parse(JSON.stringify(result)),
      });
    } catch (error) {
      parentPort.postMessage({
        id: message.id,
        callError: error.stack || String(error),
      });
    }
  });
  parentPort.postMessage({ ready: true });
}

function wasmInput(bytes, mode) {
  switch (mode) {
    case "arraybuffer":
      return bytes.buffer.slice(
        bytes.byteOffset,
        bytes.byteOffset + bytes.byteLength,
      );
    case "string":
      return Buffer.from(bytes).toString("utf8");
    case "uint8array":
      return bytes;
    case "plainobject":
      return { bytes: Array.from(bytes) };
    default:
      throw new Error(`unknown wasm input mode ${mode}`);
  }
}

function runOracle(cases, repoRoot) {
  const input = JSON.stringify(
    cases.map((tc) => ({
      name: tc.name,
      path: tc.path,
      keys: tc.keys,
    })),
  );
  const output = execFileSync(
    "go",
    ["run", "./deploy/wasm-verify/chain_oracle.go"],
    {
      cwd: repoRoot,
      env: process.env,
      input,
      encoding: "utf8",
    },
  );
  return new Map(JSON.parse(output).map((result) => [result.name, result]));
}

function runGroupOracle(fixturePath, repoRoot) {
  const output = execFileSync(
    "go",
    ["run", "./deploy/wasm-verify/group_oracle.go", fixturePath],
    {
      cwd: repoRoot,
      env: process.env,
      encoding: "utf8",
    },
  );
  return JSON.parse(output);
}

function corruptStoredZipEntry(archive, name) {
  const bytes = Buffer.from(archive);
  const nameBytes = Buffer.from(name);
  const nameAt = bytes.indexOf(nameBytes);
  assert.ok(nameAt >= 30, `ZIP entry ${name} is missing`);
  const headerAt = nameAt - 30;
  assert.equal(
    bytes.readUInt32LE(headerAt),
    0x04034b50,
    `${name} local header`,
  );
  assert.equal(
    bytes.readUInt16LE(headerAt + 8),
    0,
    `${name} must be stored for byte mutation`,
  );
  const nameLength = bytes.readUInt16LE(headerAt + 26);
  const extraLength = bytes.readUInt16LE(headerAt + 28);
  const dataAt = headerAt + 30 + nameLength + extraLength;
  assert.ok(dataAt < bytes.length, `${name} payload is missing`);
  bytes[dataAt + Math.min(8, bytes.length - dataAt - 1)] ^= 0x01;
  return bytes;
}

function startWorker(outDir) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, {
      workerData: {
        wasm: path.join(outDir, "pipelock-verifier.wasm"),
        wasmExec: path.join(outDir, "wasm_exec.js"),
      },
    });
    worker.once("error", reject);
    worker.once("message", (message) => {
      if (message.error) {
        reject(new Error(message.error));
        return;
      }
      assert.equal(message.ready, true);
      resolve(worker);
    });
  });
}

function assertChainParity(actual, expected, name) {
  assert.ok(expected, `${name}: missing Go oracle result`);
  assert.deepEqual(
    comparableChainResult(actual),
    comparableChainResult(expected),
    name,
  );
}

function assertCaseListCoversTopLevelJSONLFixtures(cases, testdata) {
  const expected = readdirSync(testdata)
    .filter((name) => name.endsWith(".jsonl"))
    .sort();
  const actual = cases.map((tc) => tc.name).sort();
  assert.deepEqual(actual, expected, "raw JSONL fixture case list drifted");
}

function comparableChainResult(result) {
  // Default ONLY missing (null/undefined) fields with `??`, never `||`: a
  // present-but-falsey value (e.g. a drifted `receiptCount: false` or an
  // `integrityVerified: 0`) must survive into the comparison so deepEqual
  // catches wasm/Go schema or type drift instead of masking it to the default.
  return {
    valid: result.valid,
    observed: result.observed ?? 0,
    error: result.error ?? "",
    reason: result.reason ?? "",
    integrityVerified: result.integrityVerified ?? false,
    receiptCount: result.receiptCount ?? 0,
    finalSeq: result.finalSeq ?? 0,
    rootHash: result.rootHash ?? "",
    startTime: result.startTime ?? "",
    endTime: result.endTime ?? "",
    failureKind: result.failureKind ?? "",
    brokenAtSeq: result.brokenAtSeq ?? null,
    brokenAtIndex: result.brokenAtIndex ?? null,
    signerKeys: result.signerKeys ?? [],
    segments: result.segments ?? [],
    untrustedSignerKey: result.untrustedSignerKey ?? "",
  };
}
