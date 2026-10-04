// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Fixture-only port of internal/egressevidence. Validation authenticates no
// registry membership, policy authority, producer coverage, or durability.
import { isIP } from "node:net";
import { objectMemberSpan } from "./rawjson.js";

export const secretEgressDecisionKind = "secret_egress_decision_v1";

const envelopeRequired = [
  "record_type",
  "receipt_version",
  "payload_kind",
  "canonicalization",
  "crit",
  "event_id",
  "timestamp",
  "signature",
  "chain_seq",
  "chain_prev_hash",
  "policy_hash",
  "payload",
];
const envelopeOptionalStrings = [
  "principal",
  "actor",
  "active_manifest_hash",
  "contract_hash",
  "selector_id",
];
const canonicalizationFields = [
  "jcs_profile",
  "jcs_version",
  "hash_alg",
  "sig_alg",
  "redaction_ruleset_id",
  "redaction_ruleset_version",
  "redaction_ruleset_hash",
];
const signatureFields = ["signer_key_id", "key_purpose", "algorithm", "signature"];

function nonemptyString(value: unknown, label: string): void {
  if (typeof value !== "string" || value === "") throw new Error(`invalid secret-egress ${label}`);
}

function canonicalTimestamp(value: string): boolean {
  const match =
    /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{0,8}[1-9])?Z$/u.exec(
      value,
    );
  if (match === null || match[0] !== value || value === "0001-01-01T00:00:00Z") return false;
  const [, y, m, d, h, min, sec] = match;
  const year = Number(y),
    month = Number(m),
    day = Number(d);
  const days = [
    31,
    year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= days[month - 1] &&
    Number(h) < 24 &&
    Number(min) < 60 &&
    Number(sec) < 60
  );
}

function integer(value: unknown, minimum: number, label: string): void {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    Object.is(value, -0)
  ) {
    throw new Error(`invalid secret-egress ${label}`);
  }
}

// This stricter wire profile belongs only to the fixture-only new kind. It
// does not alter required/default/omitempty behavior for existing receipt kinds.
export function validateSecretEgressEnvelope(value: unknown): void {
  const envelope = object(value, envelopeRequired, [
    ...envelopeOptionalStrings,
    "delegation_chain",
    "contract_generation",
  ]);
  if (
    envelope["record_type"] !== "evidence_receipt_v2" ||
    envelope["receipt_version"] !== 2 ||
    envelope["payload_kind"] !== secretEgressDecisionKind
  ) {
    throw new Error("invalid secret-egress envelope identity");
  }
  for (const name of ["event_id", "timestamp", "chain_prev_hash", "policy_hash"])
    nonemptyString(envelope[name], name);
  if (!canonicalTimestamp(envelope["timestamp"] as string))
    throw new Error("invalid secret-egress canonical UTC timestamp");
  const policyHash = envelope["policy_hash"] as string;
  if (policyHash.length !== 71 || !/^sha256:[0-9a-f]{64}$/u.test(policyHash))
    throw new Error("invalid secret-egress policy hash");
  for (const name of envelopeOptionalStrings)
    if (Object.hasOwn(envelope, name)) nonemptyString(envelope[name], name);
  integer(envelope["chain_seq"], 0, "chain_seq");
  if (Object.hasOwn(envelope, "contract_generation"))
    integer(envelope["contract_generation"], 1, "contract_generation");
  if (Object.hasOwn(envelope, "delegation_chain")) {
    const chain = envelope["delegation_chain"];
    if (!Array.isArray(chain) || chain.length === 0)
      throw new Error("invalid secret-egress delegation_chain");
    for (const item of chain) nonemptyString(item, "delegation_chain entry");
  }
  const crit = envelope["crit"];
  if (
    !Array.isArray(crit) ||
    crit.length !== 2 ||
    !crit.includes("canonicalization") ||
    !crit.includes(secretEgressDecisionKind)
  ) {
    throw new Error("invalid secret-egress critical features");
  }
  const canonicalization = object(envelope["canonicalization"], canonicalizationFields);
  for (const name of canonicalizationFields)
    nonemptyString(canonicalization[name], `canonicalization.${name}`);
  const signature = object(envelope["signature"], signatureFields);
  for (const name of signatureFields) nonemptyString(signature[name], `signature.${name}`);
  const proof = signature["signature"] as string;
  if (proof.length !== 136 || !/^ed25519:[0-9a-f]{128}$/u.test(proof)) {
    throw new Error("invalid secret-egress lowercase signature encoding");
  }
}

const decisionFields = [
  "version",
  "action_id",
  "decision_id",
  "site_id",
  "plane",
  "transport",
  "location",
  "view",
  "boundary",
  "phase",
  "destination_kind",
  "pattern_class",
  "rule_id",
  "finding_disposition",
  "planned_byte_form",
  "authorization",
  "persistence_policy",
];

const transportBoundaries: Record<string, readonly string[]> = {
  fetch: ["upstream_request"],
  forward: ["upstream_request"],
  connect: ["tunnel_admission"],
  intercept: ["upstream_request"],
  reverse: ["upstream_request"],
  websocket: ["upstream_request", "upstream_frame"],
  mcp_stdio: ["upstream_request", "tool_dispatch"],
  mcp_http_upstream: ["upstream_request", "tool_dispatch"],
  mcp_ws: ["upstream_request", "tool_dispatch"],
  mcp_http_listener: ["upstream_request", "tool_dispatch"],
};

function object(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("secret-egress fields must be an object");
  }
  const fields = value as Record<string, unknown>;
  for (const key of Object.keys(fields)) {
    if (!required.includes(key) && !optional.includes(key)) {
      throw new Error(`unknown secret-egress field ${key}`);
    }
    if (fields[key] === null) throw new Error(`null secret-egress field ${key}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(fields, key)) throw new Error(`missing secret-egress field ${key}`);
  }
  return fields;
}

function member(value: unknown, allowed: readonly string[], label: string): string {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new Error(`invalid secret-egress ${label}`);
  }
  return value;
}

function identifier(value: unknown): boolean {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    !/[^a-zA-Z0-9._:-]/u.test(value)
  );
}

function uuid(value: unknown): boolean {
  return (
    typeof value === "string" &&
    value.length === 36 &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
  );
}

export function validateSecretEgressPayload(value: unknown, eventID?: unknown): void {
  const payload = object(value, ["registry_hash", "decision"]);
  const hash = payload["registry_hash"];
  if (typeof hash !== "string" || hash.length !== 71 || !/^sha256:[0-9a-f]{64}$/u.test(hash)) {
    throw new Error("registry_hash must be sha256:<64 lowercase hex>");
  }
  validateSecretEgressDecision(payload["decision"]);
  const decision = payload["decision"] as Record<string, unknown>;
  if (
    eventID !== undefined &&
    (eventID === decision["action_id"] || eventID === decision["decision_id"])
  ) {
    throw new Error("event ID aliases action or decision ID");
  }
}

// Preserve the new contract's raw nested size and integer spelling checks,
// which cannot be recovered after JSON.parse. Existing receipt kinds retain
// their existing parser and canonicalization behavior.
export function validateSecretEgressSource(receipt: unknown, text: string, start = 0): void {
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) return;
  const fields = receipt as Record<string, unknown>;
  if (
    !Object.entries(fields).some(
      ([key, value]) =>
        (key.toLowerCase() === "payload_kind" && value === secretEgressDecisionKind) ||
        (key.toLowerCase() === "crit" &&
          Array.isArray(value) &&
          value.every((item) => typeof item === "string") &&
          value.includes(secretEgressDecisionKind)),
    )
  )
    return;
  validateSecretEgressEnvelope(receipt);
  // Candidate wire profile: producer timestamps are unescaped ASCII tokens.
  // Go's time.Time JSON decoder does not unescape the timestamp string value.
  const timestamp = objectMemberSpan(text, start, "timestamp");
  if (
    timestamp === undefined ||
    text.slice(timestamp.start, timestamp.end) !== JSON.stringify(fields["timestamp"])
  ) {
    throw new Error("invalid secret-egress raw timestamp spelling");
  }
  for (const name of ["receipt_version", "chain_seq", "contract_generation"]) {
    const span = objectMemberSpan(text, start, name);
    if (span === undefined) continue; // Required fields were checked above.
    const literal = text.slice(span.start, span.end);
    if (name === "receipt_version" ? literal !== "2" : !/^(?:0|[1-9][0-9]*)$/u.test(literal)) {
      throw new Error(`invalid secret-egress ${name} spelling`);
    }
  }
  const payload = objectMemberSpan(text, start, "payload");
  if (payload === undefined) return;
  const decision = objectMemberSpan(text, payload.start, "decision");
  if (decision === undefined) return;
  if (Buffer.byteLength(text.slice(decision.start, decision.end), "utf8") > 16 * 1024) {
    throw new Error("invalid evidence decision size");
  }
  const version = objectMemberSpan(text, decision.start, "version");
  if (version !== undefined && text.slice(version.start, version.end) !== "1") {
    throw new Error("unsupported evidence decision version spelling");
  }
}

export function validateSecretEgressDecision(value: unknown): void {
  const d = object(value, decisionFields, [
    "destination_ref",
    "destination_redaction",
    "outcome",
    "rewrite_fallback",
  ]);
  if (d["version"] !== 1) throw new Error("unsupported evidence decision version");
  if (!uuid(d["action_id"]) || !uuid(d["decision_id"]) || d["action_id"] === d["decision_id"]) {
    throw new Error("invalid or aliased action and decision IDs");
  }
  if (!identifier(d["site_id"]) || !identifier(d["rule_id"])) {
    throw new Error("invalid secret-egress site or rule reference");
  }
  member(d["plane"], ["proxy"], "plane");
  const transport = member(d["transport"], Object.keys(transportBoundaries), "transport");
  member(d["boundary"], transportBoundaries[transport], "transport/boundary pairing");
  member(
    d["location"],
    ["url", "header", "body", "tool_arguments", "envelope", "frame"],
    "location",
  );
  member(
    d["view"],
    ["original", "normalized", "post_transform", "reassembled", "authorization"],
    "view",
  );
  member(d["pattern_class"], ["core_floor", "configured"], "pattern class");
  const destination = member(
    d["destination_kind"],
    ["network", "local_process"],
    "destination kind",
  );
  const retained = Object.hasOwn(d, "destination_ref");
  const redacted = Object.hasOwn(d, "destination_redaction");
  if (retained === redacted)
    throw new Error("destination requires exactly one reference or redaction");
  if ((destination === "local_process") !== (transport === "mcp_stdio")) {
    throw new Error("destination kind and transport disagree");
  }
  if (retained) {
    if (
      destination === "network"
        ? !canonicalHost(d["destination_ref"])
        : !identifier(d["destination_ref"])
    ) {
      throw new Error("invalid retained destination reference");
    }
  } else {
    const redaction = object(d["destination_redaction"], ["reason"]);
    member(redaction["reason"], ["classified_sensitive"], "destination redaction reason");
  }
  // Redaction withholds identity; it does not establish a shared destination,
  // complete attribution, or a collection-coverage gap.
  const planned = member(
    d["planned_byte_form"],
    ["none", "original", "transformed"],
    "planned byte form",
  );
  const disposition = member(
    d["finding_disposition"],
    ["block", "redact", "observe", "authorize", "exempt"],
    "finding disposition",
  );
  if (disposition === "block" && planned !== "none")
    throw new Error("block intent cannot plan byte release");
  if (disposition === "redact" && planned === "original")
    throw new Error("redact intent cannot plan original byte release");
  const authorization = object(d["authorization"], ["kind"], ["ref", "origin"]);
  const expected =
    disposition === "authorize" ? "authorization" : disposition === "exempt" ? "exemption" : "none";
  if (authorization["kind"] !== expected)
    throw new Error("finding and authorization kind disagree");
  if (expected === "none") {
    if (Object.hasOwn(authorization, "ref") || Object.hasOwn(authorization, "origin")) {
      throw new Error("non-authorized finding has an authority reference or origin");
    }
  } else {
    if (!identifier(authorization["ref"])) throw new Error("invalid named authority reference");
    member(authorization["origin"], ["builtin", "operator"], "authority origin");
  }
  if (Object.hasOwn(d, "rewrite_fallback")) {
    const fallback = object(d["rewrite_fallback"], ["reason", "policy_ref", "policy_origin"]);
    member(
      fallback["reason"],
      [
        "unparseable_body",
        "no_safe_raw_span",
        "unsupported_encoding",
        "unsupported_shape",
        "opaque_arguments",
      ],
      "rewrite fallback reason",
    );
    if (!identifier(fallback["policy_ref"]))
      throw new Error("invalid rewrite fallback policy reference");
    member(fallback["policy_origin"], ["builtin", "operator"], "rewrite fallback policy origin");
  }
  member(d["persistence_policy"], ["required_before_action", "best_effort"], "persistence policy");
  const phase = member(d["phase"], ["intent", "outcome"], "phase");
  if (phase === "intent") {
    if (Object.hasOwn(d, "outcome")) throw new Error("intent cannot contain observed byte outcome");
  } else {
    const outcome = object(d["outcome"], ["release", "byte_form"]);
    const release = member(
      outcome["release"],
      ["none", "partial", "complete", "unknown"],
      "observed release",
    );
    const form = member(
      outcome["byte_form"],
      ["none", "original", "transformed", "unknown"],
      "observed byte form",
    );
    if ((release === "none") !== (form === "none"))
      throw new Error("observed release and byte form disagree");
  }
  // A mismatch between planned and observed release remains valid evidence of
  // an enforcement failure. Finding class alone never establishes eligibility.
}

function canonicalHost(value: unknown): boolean {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 253 ||
    value.toLowerCase() !== value
  )
    return false;
  if (isIP(value) === 4) return true;
  if (isIP(value) === 6) return canonicalIPv6(value) === value;
  // Numeric aliases accepted by Go destination.ParseIPLiteral must not become
  // distinct DNS identities. Then reject numeric-looking final labels rather
  // than treating malformed or overflowing IP spellings as DNS identities.
  // No DNS lookup is performed.
  const alternative = alternativeIPv4(value);
  if (alternative !== undefined) return alternative === value;
  const lastLabel = value.slice(value.lastIndexOf(".") + 1);
  if (/^(?:[0-9]+|0x[0-9a-f]*)$/u.test(lastLabel)) return false;
  return value
    .split(".")
    .every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        !label.startsWith("-") &&
        !label.endsWith("-") &&
        !/[^a-z0-9-]/u.test(label),
    );
}

function component(value: string, bits: number): bigint | undefined {
  let digits = value;
  let radix = 10;
  if (value.startsWith("0x") || value.startsWith("0X")) {
    digits = value.slice(2);
    radix = 16;
  } else if (value.length > 1 && value.startsWith("0")) {
    digits = value.slice(1);
    radix = 8;
  }
  if (
    digits === "" ||
    (radix === 16 ? /[^0-9a-fA-F]/u : radix === 8 ? /[^0-7]/u : /[^0-9]/u).test(digits)
  )
    return undefined;
  const number = BigInt((radix === 16 ? "0x" : radix === 8 ? "0o" : "") + digits);
  return number < 1n << BigInt(bits) ? number : undefined;
}

function alternativeIPv4(value: string): string | undefined {
  const parts = value.split(".");
  if (parts.length > 4) return undefined;
  const widths =
    parts.length === 1
      ? [32]
      : parts.length === 2
        ? [8, 24]
        : parts.length === 3
          ? [8, 8, 16]
          : [8, 8, 8, 8];
  let packed = 0n;
  for (let i = 0; i < parts.length; i++) {
    const part = component(parts[i], widths[i]);
    if (part === undefined) return undefined;
    packed = (packed << BigInt(widths[i])) | part;
  }
  return [24n, 16n, 8n, 0n].map((shift) => String((packed >> shift) & 255n)).join(".");
}

function canonicalIPv6(value: string): string {
  // isIP has already validated the literal. A zone is never a canonical host.
  if (value.includes("%")) return "";
  let expanded = value;
  if (value.includes(".")) {
    const colon = value.lastIndexOf(":");
    const octets = value
      .slice(colon + 1)
      .split(".")
      .map(Number);
    expanded =
      value.slice(0, colon + 1) +
      ((octets[0] << 8) | octets[1]).toString(16) +
      ":" +
      ((octets[2] << 8) | octets[3]).toString(16);
  }
  const halves = expanded.split("::");
  const left = halves[0] === "" ? [] : halves[0].split(":").map((s) => Number.parseInt(s, 16));
  const right =
    halves.length === 1 || halves[1] === ""
      ? []
      : halves[1].split(":").map((s) => Number.parseInt(s, 16));
  const words =
    halves.length === 1
      ? left
      : [...left, ...Array<number>(8 - left.length - right.length).fill(0), ...right];
  if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff) {
    return [words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255].join(".");
  }
  let bestStart = -1;
  let bestLength = 1;
  for (let i = 0; i < words.length; i++) {
    if (words[i] !== 0) continue;
    const start = i;
    while (i < words.length && words[i] === 0) i++;
    if (i - start > bestLength) {
      bestStart = start;
      bestLength = i - start;
    }
  }
  const text = words.map((word) => word.toString(16));
  if (bestStart === -1) return text.join(":");
  return text.slice(0, bestStart).join(":") + "::" + text.slice(bestStart + bestLength).join(":");
}
