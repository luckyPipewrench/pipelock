import type { ActionRecord, Receipt, JSONValue } from "./types.js";

type FieldSpec = readonly [name: string, omitempty: boolean, nested?: NestedKind];
type NestedKind = "action_record" | "redaction" | "shield" | "taint_source";

const actionRecordFields: readonly FieldSpec[] = [
  ["version", false],
  ["action_id", false],
  ["parent_action_id", true],
  ["action_type", false],
  ["timestamp", false],
  ["principal", false],
  ["actor", false],
  ["delegation_chain", false],
  ["target", false],
  ["intent", true],
  ["data_classes_in", true],
  ["data_classes_out", true],
  ["side_effect_class", false],
  ["reversibility", false],
  ["policy_hash", false],
  ["verdict", false],
  ["session_taint_level", true],
  ["session_contaminated", true],
  ["recent_taint_sources", true, "taint_source"],
  ["session_task_id", true],
  ["session_task_label", true],
  ["authority_kind", true],
  ["taint_decision", true],
  ["taint_decision_reason", true],
  ["task_override_applied", true],
  ["contract_winning_source", true],
  ["contract_live_verdict", true],
  ["contract_policy_sources", true],
  ["contract_rule_id", true],
  ["active_manifest_hash", true],
  ["contract_hash", true],
  ["contract_selector_id", true],
  ["contract_generation", true],
  ["transport", false],
  ["method", true],
  ["layer", true],
  ["pattern", true],
  ["severity", true],
  ["redaction", true, "redaction"],
  ["shield", true, "shield"],
  ["request_id", true],
  ["chain_prev_hash", false],
  ["chain_seq", false],
  ["venue", true],
  ["jurisdiction", true],
  ["rulebook_id", true],
  ["remedy_class", true],
  ["contestation_window", true],
  ["precedent_refs", true],
];

const receiptFields: readonly FieldSpec[] = [
  ["version", false],
  ["action_record", false, "action_record"],
  ["signature", false],
  ["signer_key", false],
];

const redactionFields: readonly FieldSpec[] = [
  ["profile", true],
  ["provider", true],
  ["parser", true],
  ["total_redactions", true],
  ["by_class", true],
  ["cache_boundary_kept", true],
];

// shieldFields mirrors receipt.ShieldSummary in Go struct-declaration order.
// The nested shield object MUST be reordered to this exact order before
// serialization or a shield-bearing receipt recomputes a different signing
// hash than the Go signer produced.
const shieldFields: readonly FieldSpec[] = [
  ["pipeline", true],
  ["total_rewrites", true],
  ["extension_probes", true],
  ["tracking_beacons", true],
  ["agent_traps", true],
  ["fingerprint_shim_injected", true],
  ["svg_foreign_objects", true],
  ["svg_event_handlers", true],
  ["svg_external_references", true],
  ["svg_hidden_text", true],
  ["svg_animation_injections", true],
  ["body_bytes", true],
  ["scanned_bytes", true],
  ["partial", true],
  ["adaptive_signals_recorded", true],
  ["adaptive_signal_max_per_body", true],
];

const taintSourceFields: readonly FieldSpec[] = [
  ["url", false],
  ["kind", false],
  ["level", false],
  ["timestamp", false],
  ["receipt_id", true],
  ["match_reason", true],
];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isGoZero(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === "boolean") return !value;
  if (typeof value === "number") return value === 0;
  if (typeof value === "string") return value === "";
  if (Array.isArray(value)) return value.length === 0;
  if (isPlainObject(value)) return Object.keys(value).length === 0;
  return false;
}

function orderStruct(
  value: Record<string, unknown>,
  fields: readonly FieldSpec[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, omitempty, nested] of fields) {
    let fieldValue = value[name];
    if (!Object.prototype.hasOwnProperty.call(value, name)) {
      if (omitempty) continue;
      fieldValue = zeroValue(name, nested);
    }
    if (omitempty && isGoZero(fieldValue)) continue;
    if (nested === "action_record" && isPlainObject(fieldValue)) {
      fieldValue = orderStruct(fieldValue, actionRecordFields);
    } else if (nested === "redaction" && isPlainObject(fieldValue)) {
      fieldValue = orderStruct(fieldValue, redactionFields);
    } else if (nested === "shield" && isPlainObject(fieldValue)) {
      fieldValue = orderStruct(fieldValue, shieldFields);
    } else if (nested === "taint_source" && Array.isArray(fieldValue)) {
      fieldValue = fieldValue.map((item) =>
        isPlainObject(item) ? orderStruct(item, taintSourceFields) : item,
      );
    } else {
      fieldValue = normalizeMaps(fieldValue);
    }
    out[name] = fieldValue;
  }
  return out;
}

function zeroValue(name: string, nested?: NestedKind): unknown {
  if (nested === "action_record") return {};
  if (name === "version" || name === "chain_seq" || name === "level") return 0;
  if (name === "delegation_chain") return null;
  if (name === "timestamp") return "0001-01-01T00:00:00Z";
  return "";
}

function normalizeMaps(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => normalizeMaps(item));
  if (!isPlainObject(value)) return value;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort(compareCodePointStrings)) {
    const item = value[key];
    if (item === undefined) continue;
    out[key] = normalizeMaps(item);
  }
  return out;
}

function compareCodePointStrings(a: string, b: string): number {
  const left = Array.from(a);
  const right = Array.from(b);
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i++) {
    const leftCodePoint = left[i]?.codePointAt(0) ?? 0;
    const rightCodePoint = right[i]?.codePointAt(0) ?? 0;
    if (leftCodePoint !== rightCodePoint) return leftCodePoint - rightCodePoint;
  }
  return left.length - right.length;
}

function stringifyCompact(value: unknown): string {
  return JSON.stringify(value);
}

function goHTMLEscape(serialized: string): string {
  return serialized
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

export function canonicalizeActionRecord(actionRecord: ActionRecord): Buffer {
  return Buffer.from(
    goHTMLEscape(stringifyCompact(orderStruct(actionRecord, actionRecordFields))),
    "utf8",
  );
}

export function canonicalizeReceipt(receipt: Receipt): Buffer {
  return Buffer.from(goHTMLEscape(stringifyCompact(orderStruct(receipt, receiptFields))), "utf8");
}

export function canonicalJSONString(value: JSONValue): string {
  return goHTMLEscape(stringifyCompact(value));
}
