export type JSONValue =
  | null
  | boolean
  | number
  | string
  | JSONValue[]
  | { [key: string]: JSONValue };

export type JSONObject = { [key: string]: JSONValue };

export interface Receipt {
  version?: number;
  action_record?: ActionRecord;
  signature?: string;
  signer_key?: string;
  [key: string]: unknown;
}

export interface ActionRecord {
  version?: number;
  action_id?: string;
  action_type?: string;
  timestamp?: string;
  principal?: string;
  actor?: string;
  delegation_chain?: string[];
  target?: string;
  intent?: string;
  data_classes_in?: string[];
  data_classes_out?: string[];
  side_effect_class?: string;
  reversibility?: string;
  policy_hash?: string;
  verdict?: string;
  session_taint_level?: string;
  session_contaminated?: boolean;
  recent_taint_sources?: TaintSourceRef[];
  session_task_id?: string;
  session_task_label?: string;
  authority_kind?: string;
  taint_decision?: string;
  taint_decision_reason?: string;
  task_override_applied?: boolean;
  contract_winning_source?: string;
  contract_live_verdict?: string;
  contract_policy_sources?: string[];
  contract_rule_id?: string;
  active_manifest_hash?: string;
  contract_hash?: string;
  contract_selector_id?: string;
  contract_generation?: number;
  transport?: string;
  method?: string;
  layer?: string;
  pattern?: string;
  severity?: string;
  redaction?: RedactionSummary;
  request_id?: string;
  chain_prev_hash?: string;
  chain_seq?: number;
  venue?: string;
  jurisdiction?: string;
  rulebook_id?: string;
  remedy_class?: string;
  contestation_window?: string;
  precedent_refs?: string[];
  [key: string]: unknown;
}

export interface TaintSourceRef {
  url?: string;
  kind?: string;
  level?: string | number;
  timestamp?: string;
  receipt_id?: string;
  match_reason?: string;
  [key: string]: unknown;
}

export interface RedactionSummary {
  profile?: string;
  provider?: string;
  parser?: string;
  total_redactions?: number;
  by_class?: Record<string, number>;
  cache_boundary_kept?: boolean;
  [key: string]: unknown;
}

export interface RecorderEntry {
  v?: number;
  seq?: number;
  ts?: string;
  session_id?: string;
  type?: string;
  detail?: unknown;
}

export interface Totals {
  allow: number;
  block: number;
  warn: number;
  ask: number;
  strip: number;
  forward: number;
  redirect: number;
  other: number;
}

export interface AuditPacket {
  schema_version?: string;
  generated_at?: string;
  run?: {
    provider?: string;
    repository?: string;
    sha?: string;
    agent_identity?: string;
    started_at?: string;
    [key: string]: unknown;
  };
  policy?: {
    policy_hashes?: unknown;
    [key: string]: unknown;
  };
  summary?: {
    receipt_count?: number;
    totals?: Totals;
    transports?: Record<string, number>;
    layers?: Record<string, number>;
    domains_touched?: string[];
    [key: string]: unknown;
  };
  verifier?: {
    verdict?: string;
    trusted?: boolean;
    receipt_count?: number;
    root_hash?: string;
    final_seq?: number;
    signer_key?: string;
    [key: string]: unknown;
  };
  posture?: {
    enforcement_mode?: string;
    unsupported_paths?: string[];
    [key: string]: unknown;
  };
  artifacts?: {
    packet?: string;
    evidence?: string;
    verifier?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface ChainResult {
  valid: boolean;
  receipt_count: number;
  final_seq: number;
  root_hash: string;
  error?: string;
  broken_at_seq?: number;
}

export interface AuditPacketReport {
  path: string;
  verdict: string;
  trusted: boolean;
  valid: boolean;
  summary: {
    receipt_count: number;
    totals: Totals;
  };
  posture: {
    enforcement_mode: string;
    unsupported_paths: string[];
  };
  run: {
    provider: string;
    repository?: string;
    sha?: string;
    agent_identity: string;
  };
  errors?: string[];
  warnings?: string[];
  schema_check: "pass" | "fail" | "skipped";
  chain_check: "pass" | "fail" | "skipped";
  cross_check: "pass" | "fail" | "skipped";
}
