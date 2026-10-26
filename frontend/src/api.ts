/** Typed client for the AEGIS FastAPI service (aegis/api.py). */

const BASE = import.meta.env.VITE_AEGIS_API_URL || 'http://127.0.0.1:8000';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type GovernanceDecision = 'NO_ACTION' | 'AUTO_APPROVED' | 'PENDING_REVIEW';
export type RunStatus = 'RUNNING' | 'COMPLETED' | 'FAILED';
export type RunMode = 'auto' | 'gemini' | 'rules';

export interface Health {
  status: string;
  project: string;
  gemini: { configured: boolean; model: string };
  datasets: number;
}

export interface Dataset {
  dataset_id: string;
  rows: number;
}

export interface WindowResult {
  index: number;
  row_start: number;
  row_end: number;
  features: Record<string, number>;
  monitoring: { score: number; suspicious: boolean; threshold: number; signals: string[] };
  detection?: {
    threat: boolean;
    attack_type: string | null;
    confidence: number;
    reasoning: string;
    source: string;
    note?: string;
  };
  risk?: { score: number; severity: Severity; factors: string[] };
  response?: { actions: string[]; rationale: string; source: string; execution: string; note?: string };
  governance: { decision: GovernanceDecision; reasons: string[]; policy: string };
  trace: string[];
  review: { decision: 'APPROVED' | 'REJECTED'; operator: string; note: string; at: string } | null;
  truth: { label_counts: Record<string, number>; dominant_label: string; attack_share: number; is_attack: boolean };
}

export interface Metrics {
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  false_positive_rate: number | null;
}

export interface AuditRecord {
  seq: number;
  at: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
  prev_hash: string;
  hash: string;
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
}

export interface RunListItem {
  id: string;
  created_at: string;
  operator: string;
  status: RunStatus;
  config: RunConfig;
  llm: { provider: string; model: string | null };
  progress: { done: number; total: number };
  summary: RunSummary | null;
}

export interface Run extends RunListItem {
  windows: WindowResult[];
  evaluation: { monitoring: Metrics; pipeline: Metrics } | null;
  audit: AuditRecord[];
  error: string | null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      ...init,
      headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
    });
  } catch {
    throw new Error(`AEGIS API is not reachable at ${BASE}. Start it with: uvicorn aegis.api:app --port 8000`);
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = (payload as { detail?: unknown }).detail;
    throw new Error(typeof detail === 'string' ? detail : `Request failed (HTTP ${response.status})`);
  }
  return payload as T;
}

export const api = {
  health: () => request<Health>('/api/health'),
  datasets: () => request<Dataset[]>('/api/datasets'),
  runs: () => request<RunListItem[]>('/api/runs'),
  run: (id: string) => request<Run>(`/api/runs/${encodeURIComponent(id)}`),
  startRun: (body: RunConfig & { operator: string }) =>
    request<{ id: string; status: RunStatus }>('/api/runs', { method: 'POST', body: JSON.stringify(body) }),
  review: (id: string, index: number, decision: 'APPROVED' | 'REJECTED', operator: string, note: string) =>
    request<WindowResult>(`/api/runs/${encodeURIComponent(id)}/windows/${index}/review`, {
      method: 'POST',
      body: JSON.stringify({ decision, operator, note }),
    }),
  verifyAudit: (id: string) =>
    request<{ valid: boolean; records: number; broken_at: number | null }>(
      `/api/runs/${encodeURIComponent(id)}/audit/verify`
    ),
};

export function datasetLabel(id: string): string {
  return id.replace('_TrafficForML_CICFlowMeter.parquet', '').replace(/-/g, ' ');
}
