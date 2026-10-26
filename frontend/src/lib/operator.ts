/**
 * Operator personalization: who is at the console, what role they hold, and
 * which view they land on. Stored only in this browser when the operator
 * opts in with "Remember me".
 */

export type OperatorRole = 'analyst' | 'responder' | 'manager' | 'researcher';

export type ConsolePage = 'overview' | 'events' | 'workflow' | 'evaluation' | 'runs';

export interface OperatorProfile {
  name: string;
  role: OperatorRole;
  remember: boolean;
}

export interface RoleSpec {
  id: OperatorRole;
  label: string;
  blurb: string;
  focus: string;
  landing: ConsolePage;
}

export const ROLES: RoleSpec[] = [
  {
    id: 'analyst',
    label: 'SOC Analyst',
    blurb: 'Triage live threat events',
    focus: 'Your queue opens on the command center, highest-severity windows first.',
    landing: 'overview',
  },
  {
    id: 'responder',
    label: 'Incident Responder',
    blurb: 'Contain and verify',
    focus: 'Containment proposals awaiting backend confirmation are pinned for you.',
    landing: 'events',
  },
  {
    id: 'manager',
    label: 'Security Manager',
    blurb: 'Governance and digital trust',
    focus: 'Evaluation evidence and trust guarantees are your starting view.',
    landing: 'evaluation',
  },
  {
    id: 'researcher',
    label: 'Researcher',
    blurb: 'Agents and evaluation',
    focus: 'The LangGraph agent workflow and its contracts are front and centre.',
    landing: 'workflow',
  },
];

export const PAGES: { id: ConsolePage; label: string }[] = [
  { id: 'overview', label: 'Command Center' },
  { id: 'events', label: 'Threat Events' },
  { id: 'workflow', label: 'Agent Workflow' },
  { id: 'evaluation', label: 'Evaluation' },
  { id: 'runs', label: 'Run Results' },
];

const STORAGE_KEY = 'aegis.operator.v1';

export function roleSpec(role: OperatorRole): RoleSpec {
  return ROLES.find((r) => r.id === role) ?? ROLES[0];
}

export function loadOperator(): OperatorProfile | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<OperatorProfile>;
    if (typeof parsed.name !== 'string' || !ROLES.some((r) => r.id === parsed.role)) {
      return null;
    }
    return { name: parsed.name, role: parsed.role as OperatorRole, remember: true };
  } catch {
    return null;
  }
}

export function saveOperator(profile: OperatorProfile): void {
  try {
    if (profile.remember) {
      window.localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ name: profile.name, role: profile.role })
      );
    } else {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Storage can be blocked (private mode); personalization still works for this session.
  }
}

export function clearOperator(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
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
