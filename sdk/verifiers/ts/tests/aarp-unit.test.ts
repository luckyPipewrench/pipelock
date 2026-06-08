// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the AARP TS modules: canonicalization, strict parsing, number
// safety, typed-string grammars, suite checks, envelope decode/validate, chain
// linkage, appraisal, and trust-file loading. These cover the error branches the
// corpus-driven test does not exercise directly.

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import {
  CanonicalizeError,
  canonicalize,
  canonicalizeBytes,
  compareCodePointStrings,
} from "../src/aarp/canonical.js";
import { FatalParseError, RawNumber, parseJSONStrict } from "../src/aarp/strictjson.js";
import {
  FatalNumberError,
  GrammarError,
  enforceSafeNumbers,
  validateHex256,
  validateTimestamp,
  validateUint64String,
} from "../src/aarp/numbers.js";
import {
  MalformedCritError,
  UnknownCritError,
  checkCriticalExtensions,
} from "../src/aarp/suite.js";
import {
  SchemaError,
  canonicalPayload,
  decodeEnvelope,
  payloadDigest,
  signingInput,
  validateStructure,
} from "../src/aarp/envelope.js";
import { verifyChain } from "../src/aarp/chain.js";
import { comparableAppraisal, verify } from "../src/aarp/appraise.js";
import { TrustFileError, emptyTrust, loadTrustFile, unmarshal } from "../src/aarp/index.js";

// Shared corpus path for the few tests that exercise the real crypto-verify path.
const corpus = "../../conformance/testdata/aarp-corpus";

// ---- canonical ----

test("canonical: sorts keys by code point and emits compact bytes", () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalizeBytes({ a: 1 }).toString("utf8"), '{"a":1}');
});

test("canonical: HTML-escapes < > & like Go encoding/json", () => {
  assert.equal(
    canonicalize({ k: "<a> & </b>" }),
    '{"k":"\\u003ca\\u003e \\u0026 \\u003c/b\\u003e"}',
  );
});

test("canonical: escapes U+2028 and U+2029", () => {
  assert.equal(canonicalize("  "), '"\\u2028\\u2029"');
});

test("canonical: NFC-normalizes strings", () => {
  // U+00E9 (é) vs U+0065 U+0301 (e + combining acute) normalize to the same NFC.
  assert.equal(canonicalize("é"), canonicalize("é"));
});

test("canonical: rejects floats and unsupported types", () => {
  assert.throws(() => canonicalize(1.5), CanonicalizeError);
  assert.throws(() => canonicalize(() => 0), CanonicalizeError);
});

test("canonical: emits bigint, bool, null, arrays", () => {
  assert.equal(
    canonicalize({ n: 10n, b: true, z: null, a: [1, 2] }),
    '{"a":[1,2],"b":true,"n":10,"z":null}',
  );
});

test("canonical: rejects NFC key collision", () => {
  assert.throws(() => canonicalize({ é: 1, é: 2 }), CanonicalizeError);
});

test("canonical: compareCodePointStrings orders by code point and length", () => {
  assert.ok(compareCodePointStrings("a", "b") < 0);
  assert.ok(compareCodePointStrings("ab", "a") > 0);
  assert.equal(compareCodePointStrings("a", "a"), 0);
});

// ---- strictjson ----

test("strictjson: parses primitives and preserves number literals", () => {
  const tree = parseJSONStrict('{"a":"x","b":true,"c":null,"d":[1,2],"e":12.5}') as Record<
    string,
    unknown
  >;
  assert.equal(tree.a, "x");
  assert.equal(tree.b, true);
  assert.equal(tree.c, null);
  assert.ok(tree.e instanceof RawNumber);
  assert.equal((tree.e as RawNumber).literal, "12.5");
});

test("strictjson: rejects duplicate keys at any depth", () => {
  assert.throws(() => parseJSONStrict('{"a":1,"a":2}'), FatalParseError);
  assert.throws(() => parseJSONStrict('{"x":{"a":1,"a":2}}'), FatalParseError);
});

test("strictjson: rejects trailing tokens", () => {
  assert.throws(() => parseJSONStrict('{"a":1} extra'), FatalParseError);
  assert.doesNotThrow(() => parseJSONStrict('{"a":1}  \n '));
});

test("strictjson: handles escapes and surrogate pairs in strings", () => {
  assert.equal(parseJSONStrict('"\\u0061\\n\\t\\"\\\\\\/"'), 'a\n\t"\\/');
  assert.equal(parseJSONStrict('"\\uD83D\\uDE00"'), "\u{1F600}");
});

test("strictjson/canonical: unpaired surrogates match Go replacement character", () => {
  assert.equal(canonicalize(parseJSONStrict('"\\uD800.example"')), '"�.example"');
  assert.equal(canonicalize(parseJSONStrict('"\\uD800\\u0041"')), '"�A"');
  assert.equal(canonicalize(parseJSONStrict('"\\uDC00"')), '"�"');
});

test("strictjson: rejects malformed input", () => {
  assert.throws(() => parseJSONStrict(""), FatalParseError);
  assert.throws(() => parseJSONStrict("{"), FatalParseError);
  assert.throws(() => parseJSONStrict('{"a" 1}'), FatalParseError);
  assert.throws(() => parseJSONStrict('{"a":1,}'), FatalParseError);
  assert.throws(() => parseJSONStrict("[1,]"), FatalParseError);
  assert.throws(() => parseJSONStrict("nul"), FatalParseError);
  assert.throws(() => parseJSONStrict("01"), FatalParseError);
  assert.throws(() => parseJSONStrict("1.e5"), FatalParseError);
  assert.throws(() => parseJSONStrict('"\\x"'), FatalParseError);
  assert.throws(() => parseJSONStrict('"\\u00zz"'), FatalParseError);
  assert.throws(() => parseJSONStrict('""'), FatalParseError);
  assert.throws(() => parseJSONStrict("{1:2}"), FatalParseError);
});

test("strictjson: parses empty object and array", () => {
  assert.deepEqual(parseJSONStrict("{}"), {});
  assert.deepEqual(parseJSONStrict("[]"), []);
});

test("strictjson: additional malformed branches", () => {
  assert.throws(() => parseJSONStrict("tru"), FatalParseError); // bad literal
  assert.throws(() => parseJSONStrict('"unterminated'), FatalParseError);
  assert.throws(() => parseJSONStrict("[1 2]"), FatalParseError); // array missing comma
  assert.throws(() => parseJSONStrict("1e+"), FatalParseError); // exponent no digits
  assert.throws(() => parseJSONStrict("-"), FatalParseError); // sign no digits
  assert.throws(() => parseJSONStrict('"\\u00"'), FatalParseError); // short \\u
  assert.throws(() => parseJSONStrict('{"a":1 "b":2}'), FatalParseError); // missing comma in obj
  // Raw control char (U+0001) inside a string is rejected.
  assert.throws(() => parseJSONStrict(`"${String.fromCharCode(1)}"`), FatalParseError);
  // Unpaired high surrogate is kept lenient (no throw): decodes to two units.
  assert.doesNotThrow(() => parseJSONStrict('"\\uD83Dx"'));
  // Exponent and bare integer parse to RawNumber.
  assert.ok(parseJSONStrict("1E5") instanceof RawNumber);
  assert.ok(parseJSONStrict("-0") instanceof RawNumber);
});

// ---- numbers ----

test("numbers: enforceSafeNumbers accepts safe integers and walks nested objects", () => {
  assert.doesNotThrow(() => enforceSafeNumbers(parseJSONStrict('{"a":1,"b":[0,-5]}')));
  // Nested object + string + bool + null all walked without error.
  assert.doesNotThrow(() =>
    enforceSafeNumbers(parseJSONStrict('{"o":{"n":7,"s":"x","t":true,"z":null}}')),
  );
  // A nested-object number out of range is still caught.
  assert.throws(
    () => enforceSafeNumbers(parseJSONStrict('{"o":{"big":99999999999999999}}')),
    FatalNumberError,
  );
});

test("numbers: enforceSafeNumbers rejects float, exponent, neg-zero, out-of-range", () => {
  assert.throws(() => enforceSafeNumbers(parseJSONStrict("1.5")), FatalNumberError);
  assert.throws(() => enforceSafeNumbers(parseJSONStrict("1e3")), FatalNumberError);
  assert.throws(() => enforceSafeNumbers(parseJSONStrict("-0")), FatalNumberError);
  assert.throws(() => enforceSafeNumbers(parseJSONStrict("9999999999999999")), FatalNumberError);
});

test("numbers: validateHex256 grammar", () => {
  assert.doesNotThrow(() => validateHex256("a".repeat(64)));
  assert.throws(() => validateHex256("a".repeat(63)), GrammarError);
  assert.throws(() => validateHex256("A".repeat(64)), GrammarError); // uppercase
  assert.throws(() => validateHex256("g".repeat(64)), GrammarError);
});

test("numbers: validateUint64String grammar", () => {
  assert.doesNotThrow(() => validateUint64String("0"));
  assert.doesNotThrow(() => validateUint64String("18446744073709551615"));
  assert.throws(() => validateUint64String(""), GrammarError);
  assert.throws(() => validateUint64String("01"), GrammarError);
  assert.throws(() => validateUint64String("1a"), GrammarError);
  assert.throws(() => validateUint64String("18446744073709551616"), GrammarError);
});

test("numbers: validateTimestamp grammar", () => {
  assert.doesNotThrow(() => validateTimestamp("2026-04-15T12:00:00.000000000Z"));
  assert.doesNotThrow(() => validateTimestamp("2026-04-15T12:00:00+05:30"));
  assert.throws(() => validateTimestamp(""), GrammarError);
  assert.throws(() => validateTimestamp("2026-04-15 12:00:00Z"), GrammarError);
  assert.throws(() => validateTimestamp("2026-13-15T12:00:00Z"), GrammarError);
  assert.throws(() => validateTimestamp("2026-04-32T12:00:00Z"), GrammarError);
  assert.throws(() => validateTimestamp("2026-04-15T25:00:00Z"), GrammarError);
  assert.throws(() => validateTimestamp("2026-04-15T12:00:00+30:00"), GrammarError);
});

// ---- suite ----

test("suite: checkCriticalExtensions rejects empty/dup/unknown, accepts undefined", () => {
  assert.doesNotThrow(() => checkCriticalExtensions(undefined));
  assert.throws(() => checkCriticalExtensions([""]), MalformedCritError);
  assert.throws(() => checkCriticalExtensions(["a", "a"]), MalformedCritError);
  assert.throws(() => checkCriticalExtensions(["unknown"]), UnknownCritError);
});

// ---- envelope ----

function baseEnvelopeObject(): Record<string, unknown> {
  return {
    profile: "aarp/v0.1",
    subject: {
      action_record_sha256: "5".repeat(64),
      receipt_envelope_sha256: "0".repeat(64),
      receipt_signer_key: "8".repeat(64),
      receipt_type: "action_receipt_v1",
    },
    assertion: {
      claimed: ["mediated"],
      mediator_id: "mediator.example",
      complete_mediation: false,
      issued_at: "2026-04-15T12:00:00.000000000Z",
    },
    signatures: [
      {
        protected: {
          profile: "aarp/v0.1",
          canon: "jcs-rfc8785-nfc",
          alg: "ed25519",
          key_type: "ed25519",
          key_id: "k-signer",
          signer_role: "mediator",
        },
        sig: "ed25519:AAAA",
      },
    ],
  };
}

test("envelope: decodeEnvelope rejects unknown fields", () => {
  const obj = baseEnvelopeObject();
  obj.bogus = 1;
  assert.throws(() => decodeEnvelope(obj), SchemaError);
});

test("envelope: decodeEnvelope rejects wrong types and missing required", () => {
  assert.throws(() => decodeEnvelope("nope"), SchemaError);
  const noSubject = baseEnvelopeObject();
  delete noSubject.subject;
  assert.throws(() => decodeEnvelope(noSubject), SchemaError);
  const badSigs = baseEnvelopeObject();
  badSigs.signatures = {};
  assert.throws(() => decodeEnvelope(badSigs), SchemaError);
});

test("envelope: ext field is allowed and ignored", () => {
  const obj = baseEnvelopeObject();
  obj.ext = { anything: { nested: true } };
  assert.doesNotThrow(() => decodeEnvelope(obj));
});

test("envelope: validateStructure enforces profile, receipt type, empty sigs", () => {
  const env = decodeEnvelope(baseEnvelopeObject());
  assert.doesNotThrow(() => validateStructure(env));

  const badProfile = decodeEnvelope({ ...baseEnvelopeObject(), profile: "aarp/v9" });
  assert.throws(() => validateStructure(badProfile), SchemaError);

  const noSigsObj = baseEnvelopeObject();
  noSigsObj.signatures = [];
  const noSigs = decodeEnvelope(noSigsObj);
  assert.throws(() => validateStructure(noSigs), SchemaError);
});

test("envelope: validateStructure rejects bad receipt type and grammar", () => {
  const badType = baseEnvelopeObject();
  (badType.subject as Record<string, unknown>).receipt_type = "nope";
  assert.throws(() => validateStructure(decodeEnvelope(badType)), SchemaError);

  const badDigest = baseEnvelopeObject();
  (badDigest.subject as Record<string, unknown>).action_record_sha256 = "xyz";
  assert.throws(() => validateStructure(decodeEnvelope(badDigest)), SchemaError);

  const noMediator = baseEnvelopeObject();
  (noMediator.assertion as Record<string, unknown>).mediator_id = "";
  assert.throws(() => validateStructure(decodeEnvelope(noMediator)), SchemaError);
});

test("envelope: signature-level profile/canon mismatch is per-signature, not fatal", () => {
  // A signature's protected profile/canon mismatch no longer rejects the
  // envelope; validateStructure passes and verify reports unknown_suite for the
  // offending signature (never verifies, no fallback).
  const o1 = baseEnvelopeObject();
  ((o1.signatures as Record<string, unknown>[])[0]!.protected as Record<string, unknown>).profile =
    "aarp/v9";
  const e1 = decodeEnvelope(o1);
  assert.doesNotThrow(() => validateStructure(e1));
  const ap1 = verify(e1, emptyTrust());
  assert.equal(ap1.signatures[0]!.status, "unknown_suite");
  assert.equal(ap1.assertion_signed, false);

  const o2 = baseEnvelopeObject();
  ((o2.signatures as Record<string, unknown>[])[0]!.protected as Record<string, unknown>).canon =
    "other";
  const e2 = decodeEnvelope(o2);
  assert.doesNotThrow(() => validateStructure(e2));
  const ap2 = verify(e2, emptyTrust());
  assert.equal(ap2.signatures[0]!.status, "unknown_suite");
  assert.equal(ap2.assertion_signed, false);
});

test("envelope: signature-level unknown/malformed crit is per-signature, not fatal", () => {
  // An unknown critical extension in a signature's protected header -> per-sig
  // unknown_suite. An empty-string or duplicate crit name -> per-sig malformed.
  const oUnknown = baseEnvelopeObject();
  (
    (oUnknown.signatures as Record<string, unknown>[])[0]!.protected as Record<string, unknown>
  ).crit = ["unknown-ext"];
  const eUnknown = decodeEnvelope(oUnknown);
  assert.doesNotThrow(() => validateStructure(eUnknown));
  assert.equal(verify(eUnknown, emptyTrust()).signatures[0]!.status, "unknown_suite");

  const oEmpty = baseEnvelopeObject();
  ((oEmpty.signatures as Record<string, unknown>[])[0]!.protected as Record<string, unknown>).crit =
    [""];
  const eEmpty = decodeEnvelope(oEmpty);
  assert.doesNotThrow(() => validateStructure(eEmpty));
  assert.equal(verify(eEmpty, emptyTrust()).signatures[0]!.status, "malformed");

  const oDup = baseEnvelopeObject();
  ((oDup.signatures as Record<string, unknown>[])[0]!.protected as Record<string, unknown>).crit = [
    "dup",
    "dup",
  ];
  const eDup = decodeEnvelope(oDup);
  assert.doesNotThrow(() => validateStructure(eDup));
  assert.equal(verify(eDup, emptyTrust()).signatures[0]!.status, "malformed");
});

test("envelope: payload digest and signing input are stable", () => {
  const env = decodeEnvelope(baseEnvelopeObject());
  const d1 = payloadDigest(env);
  const d2 = payloadDigest(env);
  assert.equal(d1, d2);
  assert.match(d1, /^[0-9a-f]{64}$/u);
  const input = signingInput(d1, env.signatures[0]!.protected);
  assert.ok(input.length > 0);
  assert.ok(canonicalPayload(env).length > 0);
});

test("envelope: payload includes optional fields and signing input includes crit", () => {
  const obj = baseEnvelopeObject();
  (obj.assertion as Record<string, unknown>).trust_domain = "example.org";
  (obj.assertion as Record<string, unknown>).evidence_refs = ["spiffe_svid"];
  obj.chain = { issuer_id: "iss", seq: "0", prior_hash: "0".repeat(64) };
  const env = decodeEnvelope(obj);
  const payload = canonicalPayload(env).toString("utf8");
  assert.match(payload, /"trust_domain":"example.org"/u);
  assert.match(payload, /"evidence_refs":\["spiffe_svid"\]/u);
  assert.match(payload, /"chain":/u);

  // A protected header carrying a (known-empty here, so use undefined) crit list:
  // exercise the non-empty crit branch in signingInput via a crafted header.
  const header = { ...env.signatures[0]!.protected, crit: ["x"] };
  const input = signingInput(payloadDigest(env), header);
  assert.match(input.toString("utf8"), /"crit":\["x"\]/u);
});

test("envelope: chain seq/prior_hash grammar errors are schema-fatal", () => {
  const badSeq = baseEnvelopeObject();
  badSeq.chain = { issuer_id: "iss", seq: "01", prior_hash: "a".repeat(64) };
  assert.throws(() => validateStructure(decodeEnvelope(badSeq)), SchemaError);

  const badPrior = baseEnvelopeObject();
  badPrior.chain = { issuer_id: "iss", seq: "1", prior_hash: "zz" };
  assert.throws(() => validateStructure(decodeEnvelope(badPrior)), SchemaError);
});

test("envelope: chain link grammar is validated", () => {
  const withGenesis = baseEnvelopeObject();
  withGenesis.chain = { issuer_id: "iss", seq: "0", prior_hash: "0".repeat(64) };
  assert.doesNotThrow(() => validateStructure(decodeEnvelope(withGenesis)));

  const badGenesis = baseEnvelopeObject();
  badGenesis.chain = { issuer_id: "iss", seq: "0", prior_hash: "a".repeat(64) };
  assert.throws(() => validateStructure(decodeEnvelope(badGenesis)), SchemaError);

  const badNonGenesis = baseEnvelopeObject();
  badNonGenesis.chain = { issuer_id: "iss", seq: "1", prior_hash: "0".repeat(64) };
  assert.throws(() => validateStructure(decodeEnvelope(badNonGenesis)), SchemaError);

  const noIssuer = baseEnvelopeObject();
  noIssuer.chain = { issuer_id: "", seq: "1", prior_hash: "a".repeat(64) };
  assert.throws(() => validateStructure(decodeEnvelope(noIssuer)), SchemaError);
});

// ---- chain ----

test("chain: verifyChain rejects empty and broken streams", () => {
  assert.equal(verifyChain([]), false);
  const e = decodeEnvelope(baseEnvelopeObject());
  assert.equal(verifyChain([e]), false); // no chain link on a single envelope
});

// ---- appraise ----

test("appraise: unknown claim is reported claim-only", () => {
  const obj = baseEnvelopeObject();
  (obj.assertion as Record<string, unknown>).claimed = ["totally_unknown_claim"];
  const env = decodeEnvelope(obj);
  const ap = verify(env, emptyTrust());
  assert.equal(ap.assertion_signed, false);
  assert.deepEqual(ap.claimed_unverified, ["totally_unknown_claim"]);
});

test("appraise: per-signature statuses for unknown suite, unimplemented, unknown key", () => {
  const obj = baseEnvelopeObject();
  obj.signatures = [
    {
      protected: {
        profile: "aarp/v0.1",
        canon: "jcs-rfc8785-nfc",
        alg: "rsa-2048",
        key_type: "rsa",
        key_id: "k-rsa",
        signer_role: "countersig",
      },
      sig: "rsa-2048:AAAA",
    },
    {
      protected: {
        profile: "aarp/v0.1",
        canon: "jcs-rfc8785-nfc",
        alg: "ml-dsa-65",
        key_type: "ml-dsa",
        key_id: "k-pq",
        signer_role: "countersig",
      },
      sig: "ml-dsa-65:AAAA",
    },
    {
      protected: {
        profile: "aarp/v0.1",
        canon: "jcs-rfc8785-nfc",
        alg: "ed25519",
        key_type: "ed25519",
        key_id: "k-untrusted",
        signer_role: "mediator",
      },
      sig: "ed25519:AAAA",
    },
  ];
  const ap = verify(decodeEnvelope(obj), emptyTrust());
  assert.equal(ap.signatures[0]!.status, "unknown_suite");
  assert.equal(ap.signatures[1]!.status, "unimplemented");
  assert.equal(ap.signatures[2]!.status, "unknown_key");
  assert.equal(ap.assertion_signed, false);
});

test("appraise: malformed signature on key-type mismatch and bad role", () => {
  const obj = baseEnvelopeObject();
  (
    (obj.signatures as Record<string, unknown>[])[0]!.protected as Record<string, unknown>
  ).key_type = "rsa";
  const ap = verify(decodeEnvelope(obj), emptyTrust());
  assert.equal(ap.signatures[0]!.status, "malformed");
});

test("appraise: comparableAppraisal omits warnings and reason", () => {
  const ap = verify(decodeEnvelope(baseEnvelopeObject()), emptyTrust());
  const bytes = comparableAppraisal(ap);
  assert.ok(!bytes.includes("warnings"));
  assert.ok(!bytes.includes("reason"));
  assert.ok(!bytes.includes("assurance_claimed"));
});

// ---- index / trust ----

test("index: unmarshal rejects fatal inputs", () => {
  assert.throws(() => unmarshal('{"a":1} junk'), FatalParseError);
  assert.throws(() => unmarshal('{"a":1.5}'), FatalNumberError);
});

test("index: loadTrustFile empty path yields empty trust", () => {
  const opts = loadTrustFile("");
  assert.equal(opts.trustedKeys.size, 0);
  assert.equal(opts.trust.size, 0);
});

test("index: loadTrustFile loads keys and entries", () => {
  const dir = mkdtempSync(join(tmpdir(), "aarp-trust-"));
  try {
    const path = join(dir, "trust.json");
    writeFileSync(
      path,
      JSON.stringify({
        trusted_keys: { "k-signer": "c".repeat(64) },
        trust_entries: { "k-signer": { mediator_id: "m", role: "mediator", trust_domain: "d" } },
      }),
    );
    const opts = loadTrustFile(path);
    assert.equal(opts.trustedKeys.size, 1);
    assert.equal(opts.trust.get("k-signer")?.mediator_id, "m");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("appraise: full crypto-verify success path confirms claims", () => {
  // Load the real corpus envelope + trust so the Ed25519 verify branch and
  // mediatorKeyPinned both execute the success path.
  const env = unmarshal(
    readFileSync(`${corpus}/golden/g01-single-ed25519-mediated.aarp.json`, "utf8"),
  );
  const opts = loadTrustFile(`${corpus}/trust.json`);
  const ap = verify(env, opts);
  assert.equal(ap.assertion_signed, true);
  assert.ok(ap.verified_claims.includes("receipt_signature_valid"));
  assert.ok(ap.verified_claims.includes("mediator_key_pinned"));
  assert.equal(ap.signatures[0]!.status, "verified");
});

test("appraise: verified but unpinned (no trust entry) omits mediator_key_pinned", () => {
  const env = unmarshal(readFileSync(`${corpus}/golden/g04-signed-but-unpinned.aarp.json`, "utf8"));
  const opts = loadTrustFile(`${corpus}/trust.json`);
  const ap = verify(env, opts);
  assert.equal(ap.assertion_signed, true);
  assert.ok(!ap.verified_claims.includes("mediator_key_pinned"));
});

test("appraise: signature-wire failures with a trusted key", () => {
  const opts = loadTrustFile(`${corpus}/trust.json`);

  // Wrong wire prefix -> malformed.
  const wrongPrefix = baseEnvelopeObject();
  (wrongPrefix.signatures as Record<string, unknown>[])[0]!.sig = "rsa-2048:AAAA";
  let ap = verify(decodeEnvelope(wrongPrefix), opts);
  assert.equal(ap.signatures[0]!.status, "malformed");

  // Non-base64 body -> malformed (round-trip mismatch).
  const badB64 = baseEnvelopeObject();
  (badB64.signatures as Record<string, unknown>[])[0]!.sig = "ed25519:not*base64*";
  ap = verify(decodeEnvelope(badB64), opts);
  assert.equal(ap.signatures[0]!.status, "malformed");

  // Valid base64 but wrong signature length -> failed (not 64 bytes).
  const shortSig = baseEnvelopeObject();
  (shortSig.signatures as Record<string, unknown>[])[0]!.sig = "ed25519:AAAA";
  ap = verify(decodeEnvelope(shortSig), opts);
  assert.equal(ap.signatures[0]!.status, "failed");

  // Correct length, wrong bytes -> failed (crypto verify false).
  const wrongBytes = baseEnvelopeObject();
  (wrongBytes.signatures as Record<string, unknown>[])[0]!.sig =
    `ed25519:${Buffer.alloc(64).toString("base64")}`;
  ap = verify(decodeEnvelope(wrongBytes), opts);
  assert.equal(ap.signatures[0]!.status, "failed");
});

test("appraise: empty key_id signature is malformed", () => {
  const obj = baseEnvelopeObject();
  ((obj.signatures as Record<string, unknown>[])[0]!.protected as Record<string, unknown>).key_id =
    "";
  // validateStructure passes (key_id empty is a per-signature problem), so verify
  // reports malformed rather than throwing.
  const ap = verify(decodeEnvelope(obj), emptyTrust());
  assert.equal(ap.signatures[0]!.status, "malformed");
});

test("appraise: bad signer_role is malformed", () => {
  const obj = baseEnvelopeObject();
  (
    (obj.signatures as Record<string, unknown>[])[0]!.protected as Record<string, unknown>
  ).signer_role = "bogus";
  const ap = verify(decodeEnvelope(obj), emptyTrust());
  assert.equal(ap.signatures[0]!.status, "malformed");
});

test("appraise: mediatorKeyPinned rejects role and domain mismatch", () => {
  const env = unmarshal(
    readFileSync(`${corpus}/golden/g01-single-ed25519-mediated.aarp.json`, "utf8"),
  );
  const base = loadTrustFile(`${corpus}/trust.json`);
  // Same key, but the trust entry now requires a different role.
  const roleMismatch = {
    trustedKeys: base.trustedKeys,
    trust: new Map([["k-signer", { mediator_id: "mediator.example", role: "issuer" }]]),
  };
  const ap = verify(env, roleMismatch);
  assert.ok(!ap.verified_claims.includes("mediator_key_pinned"));

  // Same key, but the trust entry requires a trust_domain the assertion lacks.
  const domainMismatch = {
    trustedKeys: base.trustedKeys,
    trust: new Map([["k-signer", { mediator_id: "mediator.example", trust_domain: "other" }]]),
  };
  const ap2 = verify(env, domainMismatch);
  assert.ok(!ap2.verified_claims.includes("mediator_key_pinned"));
});

test("envelope: optional fields (trust_domain, evidence_refs, crit_ext) decode", () => {
  const obj = baseEnvelopeObject();
  (obj.assertion as Record<string, unknown>).trust_domain = "example.org";
  (obj.assertion as Record<string, unknown>).evidence_refs = ["spiffe_svid"];
  const env = decodeEnvelope(obj);
  assert.equal(env.assertion.trust_domain, "example.org");
  assert.deepEqual(env.assertion.evidence_refs, ["spiffe_svid"]);
  // crit_ext present but empty is allowed (checkCriticalExtensions on []).
  const withCrit = baseEnvelopeObject();
  withCrit.crit_ext = [];
  assert.doesNotThrow(() => validateStructure(decodeEnvelope(withCrit)));
});

test("envelope: wrong field types are schema-fatal", () => {
  const badClaimed = baseEnvelopeObject();
  (badClaimed.assertion as Record<string, unknown>).claimed = "not-an-array";
  assert.throws(() => decodeEnvelope(badClaimed), SchemaError);

  const badBool = baseEnvelopeObject();
  (badBool.assertion as Record<string, unknown>).complete_mediation = "yes";
  assert.throws(() => decodeEnvelope(badBool), SchemaError);

  const badSubjectType = baseEnvelopeObject();
  badSubjectType.subject = "string";
  assert.throws(() => decodeEnvelope(badSubjectType), SchemaError);

  const sigMissingProtected = baseEnvelopeObject();
  sigMissingProtected.signatures = [{ sig: "ed25519:AAAA" }];
  assert.throws(() => decodeEnvelope(sigMissingProtected), SchemaError);

  const arrayItemBadType = baseEnvelopeObject();
  (arrayItemBadType.assertion as Record<string, unknown>).claimed = [1];
  assert.throws(() => decodeEnvelope(arrayItemBadType), SchemaError);
});

test("envelope: bad timestamp grammar is schema-fatal via wrapSchema", () => {
  const obj = baseEnvelopeObject();
  (obj.assertion as Record<string, unknown>).issued_at = "not-a-time";
  assert.throws(() => validateStructure(decodeEnvelope(obj)), SchemaError);
});

test("chain: verifyChain accepts a genuine two-link stream", () => {
  // Build link 0 (genesis) then link 1 whose prior_hash is link0's payload digest.
  const o0 = baseEnvelopeObject();
  o0.chain = { issuer_id: "iss", seq: "0", prior_hash: "0".repeat(64) };
  const e0 = decodeEnvelope(o0);
  const d0 = payloadDigest(e0);
  const o1 = baseEnvelopeObject();
  o1.chain = { issuer_id: "iss", seq: "1", prior_hash: d0 };
  const e1 = decodeEnvelope(o1);
  assert.equal(verifyChain([e0, e1]), true);

  // Wrong prior hash breaks it.
  const oBad = baseEnvelopeObject();
  oBad.chain = { issuer_id: "iss", seq: "1", prior_hash: "a".repeat(64) };
  assert.equal(verifyChain([e0, decodeEnvelope(oBad)]), false);

  // Mixed issuer breaks it.
  const oMixed = baseEnvelopeObject();
  oMixed.chain = { issuer_id: "other", seq: "1", prior_hash: d0 };
  assert.equal(verifyChain([e0, decodeEnvelope(oMixed)]), false);
});

test("index: loadTrustFile reports errors as TrustFileError", () => {
  assert.throws(() => loadTrustFile("/nonexistent/trust.json"), TrustFileError);
  const dir = mkdtempSync(join(tmpdir(), "aarp-trust-"));
  try {
    const badJSON = join(dir, "bad.json");
    writeFileSync(badJSON, "{not json");
    assert.throws(() => loadTrustFile(badJSON), TrustFileError);

    const badShape = join(dir, "arr.json");
    writeFileSync(badShape, "[]");
    assert.throws(() => loadTrustFile(badShape), TrustFileError);

    const unknownField = join(dir, "uf.json");
    writeFileSync(unknownField, JSON.stringify({ bogus: 1 }));
    assert.throws(() => loadTrustFile(unknownField), TrustFileError);

    const badKey = join(dir, "bk.json");
    writeFileSync(badKey, JSON.stringify({ trusted_keys: { k: "zz" } }));
    assert.throws(() => loadTrustFile(badKey), TrustFileError);

    const shortKey = join(dir, "sk.json");
    writeFileSync(shortKey, JSON.stringify({ trusted_keys: { k: "ab" } }));
    assert.throws(() => loadTrustFile(shortKey), TrustFileError);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Regression: a high,high,low surrogate-escape run must re-pair the 2nd and 3rd
// escapes into the valid astral char (non-greedy), matching Go encoding/json and
// Python json. A greedy decoder consumes the 2nd escape and emits three U+FFFD,
// producing different canonical bytes than Go -- a cross-language differential
// that would break chain prior_hash linkage in some languages only.
test("canonical: high-high-low surrogate re-pairs like Go (non-greedy)", () => {
  const got = canonicalizeBytes(parseJSONStrict('{"x":"\\ud800\\udbff\\udc00"}'));
  // Decoded reference form: U+FFFD followed by the astral pair U+10FC00.
  const want = canonicalizeBytes(parseJSONStrict('{"x":"\uFFFD\u{10FC00}"}'));
  assert.deepEqual(got, want);
  const threeFffd = canonicalizeBytes(parseJSONStrict('{"x":"\uFFFD\uFFFD\uFFFD"}'));
  assert.notDeepEqual(got, threeFffd);
});

test("canonical: lone high surrogate then non-low is non-greedy", () => {
  const got = canonicalizeBytes(parseJSONStrict('{"x":"\\ud800A"}'));
  const want = canonicalizeBytes(parseJSONStrict('{"x":"\uFFFDA"}'));
  assert.deepEqual(got, want);
});
