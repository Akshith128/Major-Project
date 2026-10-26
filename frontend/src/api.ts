/** Typed client for the AEGIS FastAPI service (aegis/api.py). */

import { readSession } from './lib/operator';

const BASE = import.meta.env.VITE_AEGIS_API_URL || 'http://127.0.0.1:8000';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type GovernanceDecision = 'NO_ACTION' | 'AUTO_APPROVED' | 'PENDING_REVIEW';
export type RunStatus = 'RUNNING' | 'COMPLETED' | 'FAILED' | 'STOPPED';
export type RunMode = 'auto' | 'gemini' | 'rules' | 'hybrid';
export type Role = 'analyst' | 'responder' | 'manager' | 'researcher';
export type Permission = 'run' | 'review' | 'control';

export interface Account {
  username: string;
  name: string;
  role: Role;
  role_label: string;
  permissions?: Permission[];
}

export interface Session {
  token: string;
  expires_at: number;
  user: Account;
}

export interface Health {
  status: string;
  project: string;
  gemini: { configured: boolean; model: string };
  datasets: number;
  accounts: boolean;
  paused: boolean;
}

export interface ControlState {
  paused: boolean;
  by: string | null;
  at: string | null;
  reason: string | null;
}

export interface Dataset {
  dataset_id: string;
  rows: number;
  attack_share: number;
  excluded_by_default: boolean;
  caution: string | null;
}

/** What is needed to reproduce one LLM decision. */
export interface Provenance {
  prompt_template: string;
  prompt_sha256: string;
  input_sha256: string;
  model: string | null;
  model_version?: string;
  temperature?: number;
  latency_ms?: number;
  tokens_in?: number | null;
  tokens_out?: number | null;
  schema_valid?: boolean;
  error?: string;
}

/** Benign-trained anomaly detector's verdict and evidence for one window (hybrid mode). */
export interface DetectorEvidence {
  method: string;
  anomalous: boolean;
  anomaly_score: number;
  threshold: number;
  score: number;
  confidence: number;
  deviations: string[];
  similar_incidents: { family: string; day: string; distance: number }[];
}

export interface WindowResult {
  index: number;
  row_start: number;
  row_end: number;
  features: Record<string, number>;
  monitoring: { score: number; suspicious: boolean; threshold: number; signals: string[]; method?: string; homogeneity_score?: number };
  detector?: DetectorEvidence;
  detection?: {
    threat: boolean;
    attack_type: string | null;
    confidence: number;
    reasoning: string;
    source: string;
    note?: string;
    provenance?: Provenance;
    severity_hint?: Severity | null;
    attack_techniques?: string[];
    decided_by?: string;
  };
  risk?: { score: number; severity: Severity; factors: string[] };
  response?: { actions: string[]; rationale: string; source: string; execution: string; note?: string; provenance?: Provenance };
  governance: { decision: GovernanceDecision; reasons: string[]; policy: string };
  trace: string[];
  review: { decision: 'APPROVED' | 'REJECTED'; operator: string; username?: string; role?: Role; note: string; at: string } | null;
  truth: { label_counts: Record<string, number>; dominant_label: string; attack_share: number; is_attack: boolean };
  baselines?: {
    random_forest?: { attack: boolean; attack_share: number };
    tcp_window_rule?: { attack: boolean };
  } | null;
}

type Interval = [number, number] | null;

export interface Metrics {
  n: number;
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  prevalence: number | null;
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  specificity: number | null;
  f1: number | null;
  false_positive_rate: number | null;
  balanced_accuracy: number | null;
  mcc: number | null;
  ci95: Record<'accuracy' | 'precision' | 'recall' | 'false_positive_rate' | 'f1' | 'mcc', Interval>;
}

export interface Evaluation {
  monitoring: Metrics;
  pipeline: Metrics;
  baselines: Partial<Record<'random_forest' | 'tcp_window_rule', Metrics>>;
  comparisons: { a: string; b: string; a_only_correct: number; b_only_correct: number; p_value: number }[];
  monitoring_auc: { roc_auc: number | null; pr_auc: number | null; note?: string };
  calibration: {
    n: number;
    ece?: number;
    brier?: number;
    accuracy_conf_ge_80?: number | null;
    accuracy_conf_lt_80?: number | null;
    note?: string;
  };
  governance: {
    responses: number;
    review_load: number | null;
    auto_approved: number;
    auto_approval_precision: number | null;
    auto_approved_benign: number;
    escalation_recall: number | null;
    reviewed: number;
    override_rate: number | null;
  };
  operations: {
    llm_calls: number;
    escalation_rate: number | null;
    detection_fallback_rate: number | null;
    schema_invalid: number;
    latency_ms_median: number | null;
    latency_ms_p95: number | null;
    tokens_total: number | null;
    tokens_per_window: number | null;
    model_versions: string[];
  };
}

export interface AuditRecord {
  seq: number;
  at: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
  prev_hash: string;
  hash: string;
  mac?: string;
}

export interface AuditCheck {
  valid: boolean;
  records: number;
  broken_at: number | null;
  reason: string | null;
  signed?: boolean;
  unsigned_records?: number;
  checkpoint_seq?: number | null;
}

export interface RunSummary {
  windows: number;
  suspicious: number;
  threats: number;
  severity: Partial<Record<Severity, number>>;
  attack_types: Record<string, number>;
  pending_review: number;
  decisions: Partial<Record<GovernanceDecision, number>>;
  agent_sources: Record<string, number>;
}

export interface RunConfig {
  dataset_id: string;
  windows: number;
  window_size: number;
  sampling: 'spread' | 'sequential';
  start_row: number;
  mode: RunMode;
  seed?: number | null;
  detector_baseline?: 'same-network' | 'cross-day';
}

export interface RunListItem {
  id: string;
  created_at: string;
  operator: string;
  status: RunStatus;
  config: RunConfig & { label_threshold?: number };
  llm: { provider: string; model: string | null };
  progress: { done: number; total: number };
  summary: RunSummary | null;
}

export interface Run extends RunListItem {
  windows: WindowResult[];
  evaluation: Evaluation | null;
  baselines: Record<string, { available: boolean; reason?: string; trained_on?: string[]; training_flows?: number }> | null;
  dataset_caution?: string | null;
  detector?: {
    method: string;
    baseline: string;
    normal_windows: number;
    sources: string[];
    known_incidents: number;
    threshold: number;
    false_alarm_budget: number;
  } | null;
  audit: AuditRecord[];
  error: string | null;
}

/** Raised when the session is missing or expired; the console signs out. */
export class SessionExpired extends Error {}

const listeners = new Set<() => void>();
export const onSessionExpired = (fn: () => void) => {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {};
  if (init?.body) headers['Content-Type'] = 'application/json';
  const token = readSession()?.token;
  if (token) headers.Authorization = `Bearer ${token}`;
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, { ...init, headers });
  } catch {
    throw new Error(`AEGIS API is not reachable at ${BASE}. Start it with: uvicorn aegis.api:app --port 8000`);
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = (payload as { detail?: unknown }).detail;
    const message = typeof detail === 'string' ? detail : `Request failed (HTTP ${response.status})`;
    if (response.status === 401 && path !== '/api/auth/login') {
      listeners.forEach((fn) => fn());
      throw new SessionExpired(message);
    }
    throw new Error(message);
  }
  return payload as T;
}

export const api = {
  health: () => request<Health>('/api/health'),
  login: (username: string, password: string) =>
    request<Session>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  me: () => request<Account>('/api/auth/me'),
  control: () => request<ControlState>('/api/control'),
  setPaused: (paused: boolean, reason: string) =>
    request<ControlState>('/api/control', { method: 'POST', body: JSON.stringify({ paused, reason }) }),
  datasets: () => request<Dataset[]>('/api/datasets'),
  runs: () => request<RunListItem[]>('/api/runs'),
  run: (id: string) => request<Run>(`/api/runs/${encodeURIComponent(id)}`),
  startRun: (body: RunConfig) =>
    request<{ id: string; status: RunStatus }>('/api/runs', { method: 'POST', body: JSON.stringify(body) }),
  review: (id: string, index: number, decision: 'APPROVED' | 'REJECTED', note: string) =>
    request<WindowResult>(`/api/runs/${encodeURIComponent(id)}/windows/${index}/review`, {
      method: 'POST',
      body: JSON.stringify({ decision, note }),
    }),
  verifyAudit: (id: string) => request<AuditCheck>(`/api/runs/${encodeURIComponent(id)}/audit/verify`),
};

export function datasetLabel(id: string): string {
  return id.replace('_TrafficForML_CICFlowMeter.parquet', '').replace(/-/g, ' ');
}
