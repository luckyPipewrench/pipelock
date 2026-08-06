// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import he from "he";
import unicode15Assigned from "@unicode/unicode-15.0.0/Binary_Property/Assigned/regex.js";
import unicode15NonspacingMark from "@unicode/unicode-15.0.0/General_Category/Nonspacing_Mark/regex.js";
import unicode15Whitespace from "@unicode/unicode-15.0.0/Binary_Property/White_Space/regex.js";
import unicode15LowercaseMap from "@unicode/unicode-15.0.0/Simple_Case_Mapping/Lowercase/code-points.js";

/** The pinned, fixture-only evidence-provenance transform profile. */
export const EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST =
  "sha256:3de14968449593cae58da869cfc97855cb098e491494390a12ba742cb0b70f94";

const MAX_INPUT_BYTES = 2 << 20;
const MAX_OUTPUT_BYTES = 1 << 20;
const MAX_OPERATIONS = 32;
const MAX_CUMULATIVE_PROCESSED_BYTES = 16 << 20;
const utf8 = new TextDecoder("utf-8", { fatal: true });
const encoder = new TextEncoder();
const kinds = new Set([
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
]);

export function supportedOperationKinds(): string[] {
  return [...kinds];
}

/** Unicode 15.0.0's Simple_Lowercase_Mapping table, pinned by dependency. */
const unicode15SimpleLowercase = unicode15LowercaseMap as Map<number, number>;

function unicode15Normalize(value: string, form: "NFD" | "NFKC"): string {
  // ICU in Node 24 uses Unicode 17. Normalizing an assigned Unicode-15 run is
  // compatible with Go/x/text's Unicode-15 tables; newer code points are kept
  // as opaque scalars, so Node cannot introduce a post-profile mapping.
  let result = "";
  let assigned = "";
  for (const char of value) {
    if (unicode15Assigned.test(char)) {
      assigned += char;
      continue;
    }
    result += assigned.normalize(form) + char;
    assigned = "";
  }
  return result + assigned.normalize(form);
}
function isUnicode15NonspacingMark(char: string): boolean {
  return unicode15NonspacingMark.test(char);
}
function isUnicode15Whitespace(char: string): boolean {
  return unicode15Whitespace.test(char);
}
function unicode15Lowercase(value: string): string {
  return [...value]
    .map((char) =>
      String.fromCodePoint(
        unicode15SimpleLowercase.get(char.codePointAt(0)!) ?? char.codePointAt(0)!,
      ),
    )
    .join("");
}
function removeUnicode15NonspacingMarks(value: string): string {
  return [...value].filter((char) => !isUnicode15NonspacingMark(char)).join("");
}
function compactUnicode15Whitespace(value: string): string {
  // Deliberately the plain White_Space property test. Unicode does NOT mark
  // U+001C..U+001F as White_Space, so this already matches Go's unicode.IsSpace,
  // which also excludes them. A review suggested excluding them explicitly;
  // measured against @unicode/unicode-15.0.0 the property is already false for
  // all four, so such a guard would be dead code. See the retention test in
  // tests/evidence-provenance.test.ts, which pins the agreement.
  return [...value].filter((char) => !isUnicode15Whitespace(char)).join("");
}

function mapUnicode15ExoticWhitespace(value: string): string {
  return [...value]
    .map((char) =>
      /[\u00a0\u1680\u180e\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u.test(char) ? " " : char,
    )
    .join("");
}

export type ProvenanceOperation = Record<string, unknown>;
export interface EvidenceProvenanceRecipe {
  transform_profile_digest: string;
  operations: ProvenanceOperation[];
}

function fail(message: string): never {
  throw new Error(message);
}
function text(bytes: Uint8Array, context: string): string {
  try {
    return utf8.decode(bytes);
  } catch {
    return fail(`${context}: invalid UTF-8`);
  }
}
function byteLength(value: string): number {
  return encoder.encode(value).length;
}
function assertOutput(value: string, index: number): void {
  // A JavaScript string cannot hold malformed UTF-8, but checking the encoding
  // keeps the profile boundary explicit and catches output expansion.
  if (byteLength(value) > MAX_OUTPUT_BYTES)
    fail(`recipe operation ${index}: output exceeds profile byte limit`);
}
function isControl(value: string): boolean {
  return /[\p{Cc}]/u.test(value);
}
function opString(
  op: Record<string, unknown>,
  field: string,
  required = false,
): string | undefined {
  const value = op[field];
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string") fail(`${field} must be a string`);
  return value;
}
function opBool(op: Record<string, unknown>, field: string): boolean {
  const value = op[field];
  if (value === undefined) return false;
  if (typeof value !== "boolean") fail(`${field} must be a boolean`);
  return value;
}
function opUint(
  op: Record<string, unknown>,
  field: string,
  required = false,
  max = 0xffffffff,
): number {
  const value = op[field];
  if (value === undefined && !required) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > max)
    fail(`${field} must be an unsigned integer`);
  return value;
}
function assertFields(op: Record<string, unknown>, kind: string, allowed: readonly string[]): void {
  for (const field of Object.keys(op))
    if (!allowed.includes(field)) fail(`unsupported ${field} for ${kind}`);
  for (const field of ["selector", "profile"]) {
    const value = op[field];
    if (typeof value === "string" && isControl(value))
      fail(`${field} for ${kind} contains control character`);
  }
}

/** Validates an untrusted JSON recipe before any source bytes are transformed. */
export function validateEvidenceProvenanceRecipe(
  recipe: unknown,
): asserts recipe is EvidenceProvenanceRecipe {
  if (recipe === null || typeof recipe !== "object" || Array.isArray(recipe))
    fail("recipe must be an object");
  const r = recipe as Record<string, unknown>;
  if (r.transform_profile_digest === undefined || r.transform_profile_digest === "")
    fail("recipe: missing transform profile digest");
  if (
    typeof r.transform_profile_digest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/u.test(r.transform_profile_digest)
  )
    fail("recipe: transform profile digest: invalid SHA-256 digest");
  if (r.transform_profile_digest !== EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST)
    fail("recipe: transform profile digest: unknown profile");
  if (!Array.isArray(r.operations)) fail("recipe: operations must be an array");
  if (r.operations.length > MAX_OPERATIONS) fail(`recipe: exceeds ${MAX_OPERATIONS} operations`);
  for (const [index, raw] of r.operations.entries()) {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw))
      fail(`recipe operation ${index}: must be an object`);
    const op = raw as Record<string, unknown>;
    const kind = opString(op, "kind", true)!;
    if (!kinds.has(kind)) fail(`recipe operation ${index} (${kind}): unknown operation`);
    validateOperation(op, kind);
  }
}

function validateOperation(op: Record<string, unknown>, kind: string): void {
  const none = ["kind"];
  switch (kind) {
    case "identity":
    case "lowercase":
    case "invisible_strip":
    case "hex_decode":
    case "leetspeak":
    case "vowel_fold":
    case "query_unescape":
    case "invisible_space":
    case "hex_decode_liberal":
    case "html_entity_decode":
    case "whitespace_compact":
    case "url_noise_strip":
    case "ordered_query_concat":
    case "hostname_dot_remove":
    case "canary_canonicalize":
      assertFields(op, kind, none);
      return;
    case "url_component": {
      assertFields(op, kind, ["kind", "component", "selector", "occurrence"]);
      const component = opString(op, "component", true)!;
      if (!["url", "hostname", "path", "query_key", "query_value", "raw_query"].includes(component))
        fail(`unknown URL component ${JSON.stringify(component)}`);
      if (["query_key", "query_value"].includes(component)) {
        if (opString(op, "selector") === undefined || opString(op, "selector") === "")
          fail("query component: missing selector");
      } else if (op.selector !== undefined || op.occurrence !== undefined)
        fail(`unsupported ${op.selector !== undefined ? "selector" : "occurrence"} for ${kind}`);
      opUint(op, "occurrence");
      return;
    }
    case "percent_decode":
      assertFields(op, kind, ["kind", "passes"]);
      {
        const p = opUint(op, "passes", true, 255);
        if (p < 1 || p > 4) fail("percent decode passes must be 1..4");
      }
      return;
    case "dlp_normalize":
      assertFields(op, kind, ["kind", "profile"]);
      if (opString(op, "profile", true) !== "pipelock-dlp-v1") fail("unknown DLP profile");
      return;
    case "matching_normalize":
      assertFields(op, kind, ["kind", "profile"]);
      if (opString(op, "profile", true) !== "pipelock-matching-v1")
        fail("unknown matching profile");
      return;
    case "base32_decode":
    case "base64_decode":
    case "base32_decode_liberal":
      assertFields(op, kind, ["kind", "decode_padding"]);
      opBool(op, "decode_padding");
      return;
    case "base64_decode_liberal": {
      assertFields(op, kind, ["kind", "alphabet", "decode_padding"]);
      const a = opString(op, "alphabet", true)!;
      if (a !== "standard" && a !== "url") fail(`unknown base64 alphabet ${JSON.stringify(a)}`);
      opBool(op, "decode_padding");
      return;
    }
    case "encoded_token_normalize": {
      assertFields(op, kind, ["kind", "alphabet"]);
      if (
        !["hex", "base32", "base64_standard", "base64_url"].includes(
          opString(op, "alphabet", true)!,
        )
      )
        fail("unknown encoded-token alphabet");
      return;
    }
    case "text_segment":
      assertFields(op, kind, ["kind", "occurrence"]);
      opUint(op, "occurrence");
      return;
    case "query_subsequence": {
      assertFields(op, kind, ["kind", "indices"]);
      const indices = op.indices;
      if (!Array.isArray(indices) || indices.length < 2 || indices.length > 4)
        fail("query subsequence indices must contain 2..4 entries");
      let previous = -1;
      for (const value of indices) {
        if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value >= 20)
          fail("query subsequence index exceeds scanner limit");
        if (value <= previous) fail("query subsequence indices must be strictly increasing");
        previous = value;
      }
      return;
    }
    case "encoded_run":
      assertFields(op, kind, ["kind", "occurrence", "minimum_length"]);
      opUint(op, "occurrence");
      if (opUint(op, "minimum_length", true) < 1)
        fail("encoded run minimum_length must be positive");
      return;
    default:
      fail(`unknown operation ${JSON.stringify(kind)}`);
  }
}

export function applyEvidenceProvenanceRecipe(
  input: Uint8Array,
  recipe: unknown,
  chargeFixtureWork: (bytes: number) => void = () => {},
): Uint8Array {
  const source = text(input, "recipe input");
  if (input.length > MAX_INPUT_BYTES) fail("recipe input: exceeds profile byte limit");
  validateEvidenceProvenanceRecipe(recipe);
  let value = source;
  let remaining = MAX_CUMULATIVE_PROCESSED_BYTES;
  const charge = (processed: string): void => {
    const size = byteLength(processed);
    if (size > remaining) fail("recipe: exceeds cumulative processing budget");
    chargeFixtureWork(size);
    remaining -= size;
  };
  for (const [index, raw] of recipe.operations.entries()) {
    const op = raw as Record<string, unknown>;
    try {
      charge(value);
      value = apply(value, op, charge);
    } catch (error) {
      if (error instanceof Error && error.name === "FixtureWorkLimit") throw error;
      throw new Error(
        `recipe operation ${index} (${String(op.kind)}): ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    assertOutput(value, index);
  }
  return encoder.encode(value);
}

function percentDecode(value: string): string {
  const bytes: number[] = [];
  const chars = [...value];
  for (let i = 0; i < chars.length; i++) {
    if (chars[i] === "%") {
      const h = chars.slice(i + 1, i + 3).join("");
      if (!/^[0-9a-f]{2}$/iu.test(h)) fail("percent decode: malformed escape");
      bytes.push(Number.parseInt(h, 16));
      i += 2;
    } else bytes.push(...encoder.encode(chars[i]!));
  }
  return text(Uint8Array.from(bytes), "output");
}
function queryUnescapeOnce(value: string): string {
  return percentDecode(value.replaceAll("+", " "));
}
function queryUnescape(value: string, charge: (value: string) => void): string {
  for (let i = 0; i < 500; i++) {
    charge(value);
    try {
      const next = queryUnescapeOnce(value);
      if (next === value) break;
      value = next;
    } catch {
      break;
    }
  }
  return value;
}
function base64Decode(
  value: string,
  alphabet: "standard" | "url",
  padded: boolean,
  canonical: boolean,
): string {
  const chars = alphabet === "standard" ? "A-Za-z0-9+/" : "A-Za-z0-9_-";
  const pattern = padded ? new RegExp(`^[${chars}]*={0,2}$`) : new RegExp(`^[${chars}]*$`);
  if (
    !pattern.test(value) ||
    (padded && (value.length % 4 !== 0 || /=[^=]/u.test(value))) ||
    (!padded && value.length % 4 === 1)
  )
    fail(`${canonical ? "base64" : "liberal base64"} decode: invalid encoding`);
  const paddedValue = padded ? value : value + "=".repeat((4 - (value.length % 4)) % 4);
  let bytes: Uint8Array;
  try {
    bytes = Buffer.from(
      alphabet === "url" ? paddedValue.replaceAll("-", "+").replaceAll("_", "/") : paddedValue,
      "base64",
    );
  } catch {
    fail(`${canonical ? "base64" : "liberal base64"} decode: invalid encoding`);
  }
  const encoded = Buffer.from(bytes).toString("base64");
  const selected = alphabet === "url" ? encoded.replaceAll("+", "-").replaceAll("/", "_") : encoded;
  if (canonical && (padded ? selected : selected.replace(/=+$/u, "")) !== value)
    fail("base64 decode: non-canonical encoding");
  return text(bytes, `${canonical ? "base64 decode" : "liberal base64 decode"} output`);
}
function base32Decode(value: string, padded: boolean, canonical: boolean): string {
  if (
    !/^[A-Z2-7]*={0,6}$/u.test(value) ||
    (padded && (value.length % 8 !== 0 || /=[^=]/u.test(value))) ||
    (!padded &&
      (value.includes("=") ||
        value.length % 8 === 1 ||
        value.length % 8 === 3 ||
        value.length % 8 === 6))
  )
    fail(`${canonical ? "base32" : "liberal base32"} decode: invalid encoding`);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    count = 0;
  const out: number[] = [];
  for (const char of value.replace(/=+$/u, "")) {
    bits = (bits << 5) | alphabet.indexOf(char);
    count += 5;
    if (count >= 8) {
      out.push((bits >>> (count - 8)) & 255);
      count -= 8;
    }
  }
  const bytes = Uint8Array.from(out);
  let encoded = "";
  bits = 0;
  count = 0;
  for (const b of bytes) {
    bits = (bits << 8) | b;
    count += 8;
    while (count >= 5) {
      encoded += alphabet[(bits >>> (count - 5)) & 31];
      count -= 5;
    }
  }
  if (count) encoded += alphabet[(bits << (5 - count)) & 31];
  if (padded) encoded += "=".repeat((8 - (encoded.length % 8)) % 8);
  if (canonical && encoded !== value) fail("base32 decode: non-canonical encoding");
  return text(bytes, `${canonical ? "base32 decode" : "liberal base32 decode"} output`);
}
function hexDecode(value: string, canonical: boolean): string {
  if (!/^[0-9a-fA-F]*$/u.test(value) || value.length % 2)
    fail(`${canonical ? "hex" : "liberal hex"} decode: invalid encoding`);
  const bytes = Uint8Array.from(value.match(/../gu)?.map((x) => Number.parseInt(x, 16)) ?? []);
  if (canonical && Buffer.from(bytes).toString("hex") !== value)
    fail("hex decode: non-canonical encoding");
  return text(bytes, `${canonical ? "hex decode" : "liberal hex decode"} output`);
}

const confusablePairs =
  "0410:A 0412:B 0421:C 0415:E 041D:H 0406:I 0408:J 041A:K 041C:M 041E:O 0420:P 0405:S 0422:T 0425:X 0430:a 0432:v 0435:e 043D:h 0456:i 043A:k 043C:m 043E:o 0440:p 0441:c 0442:t 0443:y 0445:x 0458:j 0455:s 0391:A 0392:B 0395:E 0396:Z 0397:H 0399:I 039A:K 039C:M 039D:N 039F:O 03A1:P 03A4:T 03A5:Y 03A7:X 03B1:a 03B5:e 03B9:i 03BA:k 03BD:v 03BF:o 0555:O 0585:o 054D:S 057D:s 054C:L 0570:h 0578:n 057C:n 0561:a 13AA:A 13A2:I 13D2:P 13DA:S 13A1:E 13B3:W 13D4:T 00D8:O 00F8:o 0110:D 0111:d 0141:L 0142:l 0126:H 0127:h 0166:T 0167:t 1D00:A 0299:B 1D04:C 1D05:D 1D07:E A730:F 0262:G 029C:H 026A:I 1D0A:J 1D0B:K 029F:L 1D0D:M 0274:N 1D0F:O 1D18:P 0280:R A731:S 1D1B:T 1D1C:U 1D20:V 1D21:W 028F:Y 1D22:Z";
const confusable = new Map(
  confusablePairs.split(" ").map((x) => {
    const [key, value] = x.split(":");
    return [String.fromCodePoint(Number.parseInt(key!, 16)), value!];
  }),
);
function invisible(char: string): boolean {
  const cp = char.codePointAt(0)!;
  return (
    (cp <= 0x1f && char !== "\t" && char !== "\n" && char !== "\r") ||
    cp === 0x7f ||
    (cp >= 0x80 && cp <= 0x9f) ||
    cp === 0xad ||
    (cp >= 0x115f && cp <= 0x1160) ||
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x2064) ||
    (cp >= 0x2066 && cp <= 0x2069) ||
    cp === 0x3164 ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    cp === 0xfeff ||
    (cp >= 0xfff9 && cp <= 0xfffb) ||
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    (cp >= 0xe0100 && cp <= 0xe01ef)
  );
}
function stripInvisible(value: string, replacement = ""): string {
  return [...value].map((c) => (invisible(c) ? replacement : c)).join("");
}
function confusableAscii(value: string): string {
  return [...value]
    .map(
      (c) =>
        confusable.get(c) ??
        (() => {
          const cp = c.codePointAt(0)!;
          return cp >= 0x1f170 && cp <= 0x1f189
            ? String.fromCharCode(65 + cp - 0x1f170)
            : cp >= 0x1f1e6 && cp <= 0x1f1ff
              ? String.fromCharCode(65 + cp - 0x1f1e6)
              : c;
        })(),
    )
    .join("");
}
function dlp(value: string): string {
  const withoutControls = [...value]
    .filter(
      (c) =>
        !invisible(c) &&
        c.codePointAt(0)! > 0x1f &&
        c.codePointAt(0)! !== 0x7f &&
        !/[\u00a0\u1680\u180e\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u.test(c),
    )
    .join("");
  return removeUnicode15NonspacingMarks(
    unicode15Normalize(confusableAscii(unicode15Normalize(withoutControls, "NFKC")), "NFD"),
  );
}
function matching(value: string): string {
  return mapUnicode15ExoticWhitespace(
    removeUnicode15NonspacingMarks(
      unicode15Normalize(confusableAscii(unicode15Normalize(stripInvisible(value), "NFKC")), "NFD"),
    ),
  );
}
function encodedToken(value: string, alphabet: string): string {
  if (value.length < 4) return "";
  if (alphabet === "hex") {
    const v = value
      .replaceAll("\\x", "")
      .replaceAll("\\X", "")
      .replaceAll("0x", "")
      .replaceAll("0X", "")
      .replace(/[: ,\-]/gu, "");
    return v.length && v.length % 2 === 0 && /^[0-9a-f]+$/iu.test(v) ? v : "";
  }
  const data =
    alphabet === "base32"
      ? /^[A-Z2-7=]$/u
      : alphabet === "base64_standard"
        ? /^[A-Za-z0-9+/=]$/u
        : /^[A-Za-z0-9_\-=]$/u;
  const separator =
    alphabet === "base32"
      ? /^[ \t\n\r\f\v._\-/]$/u
      : alphabet === "base64_standard"
        ? /^[ \t\n\r\f\v._-]$/u
        : /^[ \t\n\r\f\v._/+]$/u;
  let changed = false,
    result = "";
  for (const c of value) {
    if (data.test(c)) result += c;
    else if (separator.test(c)) changed = true;
    else return "";
  }
  return changed && result.length >= 4 ? result : "";
}
function htmlDecode(value: string, charge: (value: string) => void): string {
  // `he` ships the full WHATWG/HTML5 named-character-reference table. Its
  // non-strict text-mode decoding matches Go html.UnescapeString's liberal
  // treatment of malformed and semicolon-less references.
  for (let i = 0; i < 16 && value.includes("&"); i++) {
    charge(value);
    const next = he.decode(value, { isAttributeValue: false, strict: false });
    if (next === value) break;
    value = next;
  }
  return value;
}
function parseQuery(value: string): [string, string][] {
  return value.split("&").map((pair) => {
    const p = pair.indexOf("=");
    try {
      return [
        queryUnescapeOnce(p < 0 ? pair : pair.slice(0, p)),
        queryUnescapeOnce(p < 0 ? "" : pair.slice(p + 1)),
      ];
    } catch {
      fail("query parse: malformed escape");
    }
  });
}
function rawHostname(value: string): string {
  // Callers reject a missing "://" before dispatch, so indexOf cannot return
  // -1 here. Kept as a named constant rather than an inline expression so the
  // dependency on that precondition is visible.
  const authorityStart = value.indexOf("://");
  const authority = value
    .slice(authorityStart + 3)
    .split(/[/?#]/u, 1)[0]!
    .split("@")
    .at(-1)!;
  if (authority.startsWith("[")) return authority.slice(1, authority.indexOf("]"));
  const colon = authority.lastIndexOf(":");
  return colon < 0 ? authority : authority.slice(0, colon);
}
function apply(
  value: string,
  op: Record<string, unknown>,
  charge: (value: string) => void,
): string {
  const kind = op.kind as string;
  switch (kind) {
    case "identity":
      return value;
    case "url_component": {
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        fail("URL parse: invalid absolute URL");
      }
      if (!url.protocol || !url.host) fail("URL parse: invalid absolute URL");
      // A value such as "https:api.vendor.example" has a scheme but no literal
      // "://" authority. Go rejects it outright. Guarding only the hostname
      // branch left path, raw_query and the query components deriving views
      // from a URL the reference implementation refuses, so the rejection
      // belongs here, before any component dispatch.
      if (!/^[A-Za-z][A-Za-z0-9+.-]*:\/\//u.test(value)) fail("URL parse: invalid absolute URL");
      const c = op.component as string;
      if (c === "url") return value;
      if (c === "hostname") return rawHostname(value);
      if (c === "path") return url.pathname;
      const queryStart = value.indexOf("?");
      const rawQuery = queryStart < 0 ? "" : value.slice(queryStart + 1).split("#", 1)[0]!;
      if (c === "raw_query") return rawQuery;
      const selector = op.selector as string,
        matches = parseQuery(rawQuery).filter(([key]) => key === selector);
      const occurrence = (op.occurrence as number | undefined) ?? 0;
      if (!matches[occurrence]) fail(`query component: occurrence ${occurrence} unavailable`);
      return c === "query_key" ? selector : matches[occurrence]![1];
    }
    case "percent_decode": {
      for (let i = 0; i < (op.passes as number); i++) {
        charge(value);
        value = percentDecode(value);
      }
      return value;
    }
    case "dlp_normalize":
      return dlp(value);
    case "lowercase":
      return unicode15Lowercase(value);
    case "invisible_strip":
      return stripInvisible(value);
    case "hex_decode":
      return hexDecode(value, true);
    case "base32_decode":
      return base32Decode(value, opBool(op, "decode_padding"), true);
    case "base64_decode":
      return base64Decode(value, "standard", opBool(op, "decode_padding"), true);
    case "leetspeak":
      return value.replace(
        /[013457@$]/gu,
        (c) =>
          ({ "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s" })[c]!,
      );
    case "vowel_fold":
      return value.replace(/[aeiouAEIOU]/gu, (c) => (c >= "A" && c <= "Z" ? "A" : "a"));
    case "query_unescape":
      return queryUnescape(value, charge);
    case "invisible_space":
      return stripInvisible(value, " ");
    case "matching_normalize":
      return matching(value);
    case "hex_decode_liberal":
      return hexDecode(value, false);
    case "base32_decode_liberal":
      return base32Decode(value, opBool(op, "decode_padding"), false);
    case "base64_decode_liberal":
      return base64Decode(
        value,
        op.alphabet as "standard" | "url",
        opBool(op, "decode_padding"),
        false,
      );
    case "encoded_token_normalize":
      return encodedToken(value, op.alphabet as string);
    case "text_segment": {
      const segments = value.split(/[/?&= \n\r\t"'`{}\[\]()<>:,;]/u).filter(Boolean);
      const occurrence = (op.occurrence as number | undefined) ?? 0;
      if (!segments[occurrence]) fail(`text segment: occurrence ${occurrence} unavailable`);
      return segments[occurrence]!;
    }
    case "html_entity_decode":
      return htmlDecode(value, charge);
    case "whitespace_compact":
      return compactUnicode15Whitespace(value);
    case "url_noise_strip":
      return value.replace(/[./ \t\n\r+,;|]/gu, "");
    case "ordered_query_concat":
      return value
        .split("&")
        .map((x) => (x.includes("=") ? x.slice(x.indexOf("=") + 1) : ""))
        .filter(Boolean)
        .map((item) => queryUnescape(item, charge))
        .join("");
    case "query_subsequence": {
      const values = value
        .split("&")
        .map((x) => (x.includes("=") ? x.slice(x.indexOf("=") + 1) : ""))
        .filter(Boolean)
        .slice(0, 20)
        .map((item) => queryUnescape(item, charge));
      return (op.indices as number[])
        .map((i) => values[i] ?? fail(`query subsequence: index ${i} unavailable`))
        .join("");
    }
    case "hostname_dot_remove":
      return value.replaceAll(".", "");
    case "encoded_run": {
      const runs: string[] = [];
      const re = /[A-Za-z0-9+/_-]+={0,2}/gu;
      for (const match of value.matchAll(re))
        if (match[0].length >= (op.minimum_length as number)) runs.push(match[0]);
      const occurrence = (op.occurrence as number | undefined) ?? 0;
      return runs[occurrence] ?? fail(`encoded run: occurrence ${occurrence} unavailable`);
    }
    case "canary_canonicalize":
      return value.replace(/[./\\?&= \t\n\r:;,\-_@%+#]/gu, "");
    default:
      return fail(`unknown operation ${JSON.stringify(kind)}`);
  }
}
