// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { after, before, test } = require("node:test");
const { isMainThread, parentPort, Worker, workerData } = require("node:worker_threads");

if (!isMainThread) {
  runWasmWorker().catch((error) => {
    parentPort.postMessage({ error: error.stack || String(error) });
  });
} else {
  const repoRoot = path.resolve(__dirname, "../..");
  const testdata = path.join(repoRoot, "sdk/conformance/testdata");
  const keyInfo = JSON.parse(readFileSync(path.join(testdata, "test-key.json"), "utf8"));
  const primaryKey = keyInfo.public_key_hex;
  const rotatedKey = keyInfo.rotated_public_key_hex;
  const tempRoot = process.env.TMPDIR || tmpdir();
  let outDir;
  let worker;
  let oracleByName;
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

  test("rotated g1 raw chain verifies with multi-key input", async () => {
    const result = await verifyFixture("g1-rotated-close-count-valid.jsonl", "uint8array");
    assert.equal(result.valid, true, result.error);
    assert.equal(result.receiptCount, 6);
    assert.equal(result.finalSeq, 2);
    assert.deepEqual(result.signerKeys, [primaryKey, rotatedKey]);
  });

  test("raw chain input accepts ArrayBuffer and string forms", async () => {
    const arrayBufferResult = await verifyFixture("g1-valid-chain.jsonl", "arraybuffer");
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
      assert.equal(result.valid, tc.valid, `${tc.name}: ${result.error || "unexpected result"}`);
      if (tc.reason) {
        assert.match(result.error || "", tc.reason, tc.name);
      }
    }
  });

  test("malformed raw chain inputs fail closed", async () => {
    const empty = await verifyBytes(Buffer.alloc(0), primaryKey, "uint8array");
    assert.equal(empty.valid, false);
    assert.match(empty.error || "", /chain string is empty|no receipts found in chain/u);

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
    const validBytes = readFileSync(path.join(testdata, "g1-valid-chain.jsonl"));
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
      const input = wasmInput(bytes, message.mode);
      const result = globalThis.pipelockVerifyChain(input, message.keys);
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
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
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
  const output = execFileSync("go", ["run", "./deploy/wasm-verify/chain_oracle.go"], {
    cwd: repoRoot,
    env: process.env,
    input,
    encoding: "utf8",
  });
  return new Map(JSON.parse(output).map((result) => [result.name, result]));
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
  assert.deepEqual(comparableChainResult(actual), comparableChainResult(expected), name);
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
