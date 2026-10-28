/**
 * Operator personalization. Who is at the console now comes from a signed-in
 * account (the server decides the role); this module keeps the session token
 * and maps each role to its label and focus line. Every role opens on Overview.
 */

import type { Account, Permission, Role, Session } from '../api';

export type OperatorRole = Role;

export type ConsolePage = 'overview' | 'walkthrough' | 'incidents' | 'governance' | 'agents';

export interface RoleSpec {
  id: OperatorRole;
  label: string;
  blurb: string;
  focus: string;
}

export const ROLES: RoleSpec[] = [
  {
    id: 'analyst',
    label: 'SOC Analyst',
    blurb: 'Launch runs, triage detections',
    focus: 'Start a monitoring run and triage what the agents detect.',
  },
  {
    id: 'responder',
    label: 'Incident Responder',
    blurb: 'Review and approve responses',
    focus: 'Responses waiting for your approval are at the top of the incident list.',
  },
  {
    id: 'manager',
    label: 'Security Manager',
    blurb: 'Governance and digital trust',
    focus: 'The review queue, the signed audit trail and evaluation evidence. Halt AEGIS is at the top of every page.',
  },
  {
    id: 'researcher',
    label: 'Researcher',
    blurb: 'Agents and evaluation (read-only)',
    focus: 'How the five LangGraph agents route each traffic window, and how they compare with the baselines.',
  },
];

export const PAGES: { id: ConsolePage; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'walkthrough', label: 'How it works' },
  { id: 'incidents', label: 'Incidents' },
  { id: 'governance', label: 'Governance' },
  { id: 'agents', label: 'Agents' },
];

/** Mirrors PERMISSIONS in aegis/auth.py; the server enforces it, the console only hides buttons. */
const PERMISSIONS: Record<Permission, OperatorRole[]> = {
  run: ['analyst', 'manager'],
  review: ['analyst', 'responder', 'manager'],
  stop: ['analyst', 'responder', 'manager', 'researcher'],
  control: ['manager'],
};

export function can(account: Account | null | undefined, permission: Permission): boolean {
  return !!account && PERMISSIONS[permission].includes(account.role);
}

const STORAGE_KEY = 'aegis.session.v2';

export function roleSpec(role: OperatorRole): RoleSpec {
  return ROLES.find((r) => r.id === role) ?? ROLES[0];
}

/** "Remember me" keeps the session in localStorage; otherwise it ends with the tab. */
export function saveSession(session: Session, remember: boolean): void {
  try {
    clearSession();
    (remember ? window.localStorage : window.sessionStorage).setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    // Storage can be blocked (private mode); the in-memory session still works.
    memory = session;
  }
}

let memory: Session | null = null;

export function readSession(): Session | null {
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY) ?? window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return memory;
    const session = JSON.parse(raw) as Session;
    if (!session.token || session.expires_at * 1000 < Date.now()) return null;
    return session;
  } catch {
    return memory;
  }
}

export function clearSession(): void {
  memory = null;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
    window.sessionStorage.removeItem(STORAGE_KEY);
    window.localStorage.removeItem('aegis.operator.v1'); // pre-account profile
  } catch {
    // Nothing stored to clear.
  }
}

export function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return 'OP';
  return parts
    .slice(0, 2)
    .map((p) => p[0])
    .join('')
    .toUpperCase();
}

export function greetingFor(date: Date = new Date()): string {
  const h = date.getHours();
  if (h < 12) return 'Good morning';
  if (h < 17) return 'Good afternoon';
  return 'Good evening';
}
