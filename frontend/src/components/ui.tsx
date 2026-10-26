import type { ReactNode } from 'react';
import type { GovernanceDecision, Severity, WindowResult } from '../api';

export function ShieldMark({ size = 28, className = 'text-signal' }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      <path d="M12 2.5l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10v-6l8-3z" />
      <path d="M8.5 12l2.5 2.5 4.5-5" />
    </svg>
  );
}

export function Kicker({ children, className = 'text-muted' }: { children: ReactNode; className?: string }) {
  return <p className={`m-0 font-mono text-xs uppercase tracking-[0.14em] ${className}`}>{children}</p>;
}

export function Panel({
  title,
  meta,
  children,
  className = '',
  bodyClassName = 'p-5',
}: {
  title?: ReactNode;
  meta?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`min-w-0 rounded-xl border border-line bg-panel ${className}`}>
      {(title || meta) && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-5 py-4">
          {title && <h2 className="m-0 text-base font-semibold">{title}</h2>}
          {meta && <span className="font-mono text-xs text-muted">{meta}</span>}
        </div>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

const BADGE = 'inline-block rounded-full border px-2.5 py-0.5 font-mono text-xs font-bold whitespace-nowrap';

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: 'bg-[#3A1418] text-crit border-[#6B2A30]',
  HIGH: 'bg-[#3A2A0C] text-warn border-[#6B4F1A]',
  MEDIUM: 'bg-[#13283A] text-[#7CCBFF] border-[#24496B]',
  LOW: 'bg-panel-2 text-soft border-line-strong',
};

export function SeverityBadge({ severity }: { severity?: Severity }) {
  if (!severity) return <span className="font-mono text-xs text-muted">—</span>;
  return <span className={`${BADGE} ${SEVERITY_STYLES[severity]}`}>{severity}</span>;
}

/** Governance outcome, including the analyst's review once made. */
export function DecisionBadge({ window: w }: { window: WindowResult }) {
  const decision: GovernanceDecision | 'APPROVED' | 'REJECTED' = w.review?.decision ?? w.governance.decision;
  const styles: Record<typeof decision, [string, string]> = {
    NO_ACTION: ['No action', 'bg-panel-2 text-soft border-line-strong'],
    AUTO_APPROVED: ['Auto-approved', 'bg-[#0F2E22] text-ok border-[#1E5A41]'],
    PENDING_REVIEW: ['Needs review', 'bg-[#3A2A0C] text-warn border-[#6B4F1A]'],
    APPROVED: ['Approved', 'bg-[#0F2E22] text-ok border-[#1E5A41]'],
    REJECTED: ['Rejected', 'bg-[#3A1418] text-crit border-[#6B2A30]'],
  };
  const [label, style] = styles[decision];
  return <span className={`${BADGE} ${style}`}>{label}</span>;
}

export function Stat({
  label,
  value,
  note,
  tone = 'text-fg',
}: {
  label: string;
  value: ReactNode;
  note?: ReactNode;
  tone?: string;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5 rounded-xl border border-line bg-panel px-5 py-4">
      <span className="font-mono text-xs uppercase tracking-[0.1em] text-muted">{label}</span>
      <span className={`font-mono text-3xl font-bold tabular-nums ${tone}`}>{value}</span>
      {note && <span className="text-sm text-muted">{note}</span>}
    </div>
  );
}

export function SourceTag({ source }: { source?: string }) {
  if (!source) return null;
  const ai = source === 'gemini';
  return (
    <span className={`font-mono text-[11px] uppercase tracking-wider ${ai ? 'text-signal' : 'text-muted'}`}>
      {ai ? 'Gemini' : source === 'playbook' ? 'Playbook' : 'Rules'}
    </span>
  );
}

export function formatRatio(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : value.toFixed(3);
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="m-0 rounded-xl border border-dashed border-line-strong p-8 text-center text-sm text-muted">{children}</p>;
}
