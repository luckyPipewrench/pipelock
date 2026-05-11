import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { ErrorObject } from "ajv";
import type { AuditPacket } from "./types.js";

const schemaURL = new URL("./v0.schema.json", import.meta.url);
const require = createRequire(import.meta.url);
const addFormats = require("ajv-formats") as (ajv: Ajv2020) => void;
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const schema = JSON.parse(readFileSync(fileURLToPath(schemaURL), "utf8")) as object;
const cachedValidator = ajv.compile(schema);

function formatAjvError(error: ErrorObject): string {
  const location = error.instancePath === "" ? "/" : error.instancePath;
  return `${location} ${error.message ?? "failed validation"}`;
}

export function validateSchema(packet: unknown): string[] {
  if (cachedValidator(packet)) return [];
  return (cachedValidator.errors ?? []).map(formatAjvError);
}

const totalsKeys = ["allow", "block", "warn", "ask", "strip", "forward", "redirect", "other"] as const;
const verifierVerdicts = new Set(["valid", "invalid", "error", "not_run", "self_consistent_only"]);
const providers = new Set(["github_actions", "self_hosted", "local"]);
const rawSocketStatuses = new Set(["denied", "allowed", "unknown"]);
const dockerSocketStatuses = new Set(["denied", "masked", "allowed", "absent", "unknown"]);
const dnsUDPStatuses = new Set(["denied", "proxied", "allowed", "unknown"]);
const browserProxyStatuses = new Set(["forced", "advisory", "absent", "unknown"]);
const websocketFrameScanning = new Set(["explicit_ws_proxy_path_required", "always_on", "off"]);

function enumCheck(name: string, value: unknown, values: Set<string>, errors: string[]): void {
  if (typeof value !== "string" || !values.has(value)) {
    errors.push(`${name} ${JSON.stringify(value)} is not a valid v0 value`);
  }
}

function nonNegativeMap(name: string, value: unknown, errors: string[]): void {
  if (value === undefined) return;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return;
  for (const [key, count] of Object.entries(value)) {
    if (typeof count !== "number" || !Number.isInteger(count) || count < 0) {
      errors.push(`${name}[${JSON.stringify(key)}] must be non-negative`);
    }
  }
}

export function validateStructural(packet: AuditPacket): string[] {
  const errors: string[] = [];
  if (packet.schema_version !== "pipelock.audit_packet.v0") {
    errors.push(`schema_version ${JSON.stringify(packet.schema_version)} is not "pipelock.audit_packet.v0"`);
  }
  if (!packet.run) {
    errors.push("run is required");
  } else {
    enumCheck("provider", packet.run.provider, providers, errors);
    if (!packet.run.agent_identity) errors.push("agent_identity is required");
    if (!packet.run.started_at) errors.push("started_at is required");
  }
  if (!packet.policy || !Array.isArray(packet.policy.policy_hashes)) {
    errors.push("policy_hashes is required (use empty array, not null)");
  }
  if (!packet.summary || !packet.summary.totals) {
    errors.push("summary.totals is required");
  } else {
    const receiptCount = packet.summary.receipt_count ?? -1;
    if (!Number.isInteger(receiptCount) || receiptCount < 0) {
      errors.push("receipt_count must be non-negative");
    }
    let sum = 0;
    for (const key of totalsKeys) {
      const value = packet.summary.totals[key];
      if (!Number.isInteger(value) || value < 0) errors.push(`totals.${key} must be non-negative`);
      sum += Number.isFinite(value) ? value : 0;
    }
    if (sum !== receiptCount) {
      errors.push(`totals sum ${sum} does not match receipt_count ${receiptCount}`);
    }
    nonNegativeMap("transports", packet.summary.transports, errors);
    nonNegativeMap("layers", packet.summary.layers, errors);
    const domains = packet.summary.domains_touched ?? [];
    for (let i = 1; i < domains.length; i++) {
      if ((domains[i - 1] as string) > (domains[i] as string)) {
        errors.push("domains_touched must be sorted");
        break;
      }
      if (domains[i - 1] === domains[i]) {
        errors.push(`domains_touched contains duplicate ${JSON.stringify(domains[i])}`);
        break;
      }
    }
  }
  if (!packet.verifier) {
    errors.push("verifier is required");
  } else {
    const verdict = packet.verifier.verdict;
    if (typeof verdict !== "string" || !verifierVerdicts.has(verdict)) {
      errors.push(`verdict ${JSON.stringify(verdict)} not in {valid, invalid, error, not_run, self_consistent_only}`);
    }
    if (packet.verifier.trusted === true && verdict !== "valid") {
      errors.push(`trusted=true requires verdict=valid, got ${JSON.stringify(verdict)}`);
    }
    if (verdict === "valid" && packet.verifier.trusted !== true) {
      errors.push("verdict=valid requires trusted=true");
    }
    if (packet.verifier.trusted === true && !packet.verifier.signer_key) {
      errors.push("trusted=true requires signer_key");
    }
    if ((packet.verifier.receipt_count ?? 0) < 0) errors.push("receipt_count must be non-negative");
    if ((packet.verifier.final_seq ?? 0) < 0) errors.push("final_seq must be non-negative");
  }
  if (!packet.posture) {
    errors.push("posture is required");
  } else {
    if (!packet.posture.enforcement_mode) errors.push("enforcement_mode is required");
    if (!packet.posture.runner_os) errors.push("runner_os is required");
    enumCheck("raw_socket_status", packet.posture.raw_socket_status, rawSocketStatuses, errors);
    enumCheck("docker_socket_status", packet.posture.docker_socket_status, dockerSocketStatuses, errors);
    enumCheck("dns_udp_status", packet.posture.dns_udp_status, dnsUDPStatuses, errors);
    enumCheck("browser_proxy_status", packet.posture.browser_proxy_status, browserProxyStatuses, errors);
    enumCheck("websocket_frame_scanning", packet.posture.websocket_frame_scanning, websocketFrameScanning, errors);
    if (!Array.isArray(packet.posture.unsupported_paths)) {
      errors.push("unsupported_paths is required (use empty array, not null)");
    }
  }
  if (!packet.artifacts?.packet) errors.push("packet path is required");
  if (!packet.artifacts?.evidence) errors.push("evidence path is required");
  if (!packet.artifacts?.verifier) errors.push("verifier path is required");
  return errors;
}

export function validateAuditPacket(packet: AuditPacket): string[] {
  return [...validateSchema(packet), ...validateStructural(packet)];
}
