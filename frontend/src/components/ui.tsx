import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Moon, Sun } from 'lucide-react';
import { applyTheme, storedTheme, type Theme } from '../lib/theme';
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
    <section className={`aegis-glass min-w-0 rounded-2xl border border-line ${className}`}>
      {(title || meta) && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-5 py-4">
          {title && (
            <h2 className="m-0 flex items-center gap-2.5 text-base font-semibold">
              <span className="aegis-accent-bar h-4 w-1 rounded-full" aria-hidden="true" />
              {title}
            </h2>
          )}
          {meta && <span className="font-mono text-xs text-muted">{meta}</span>}
        </div>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

const BADGE = 'inline-block rounded-full border px-2.5 py-0.5 font-mono text-xs font-bold whitespace-nowrap';

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: 'bg-crit-soft text-crit border-crit-line',
  HIGH: 'bg-warn-soft text-warn border-warn-line',
  MEDIUM: 'bg-info-soft text-info border-info-line',
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
    AUTO_APPROVED: ['Auto-approved', 'bg-ok-soft text-ok border-ok-line'],
    PENDING_REVIEW: ['Needs review', 'bg-warn-soft text-warn border-warn-line'],
    APPROVED: ['Approved', 'bg-ok-soft text-ok border-ok-line'],
    REJECTED: ['Rejected', 'bg-crit-soft text-crit border-crit-line'],
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
    <div className="aegis-glass aegis-lift relative flex min-w-0 flex-col gap-1.5 overflow-hidden rounded-2xl border border-line px-5 py-4">
      <span className="font-mono text-xs uppercase tracking-[0.1em] text-muted">{label}</span>
      <span className={`font-mono text-3xl font-bold tabular-nums ${tone}`}>
        {typeof value === 'number' ? <CountUp value={value} /> : value}
      </span>
      {note && <span className="text-sm text-muted">{note}</span>}
    </div>
  );
}

/** Counts up to `value` once when it first appears or changes (instant if the user prefers reduced motion). */
export function CountUp({ value, duration = 700 }: { value: number; duration?: number }) {
  const [shown, setShown] = useState(value);
  const from = useRef(0);
  useEffect(() => {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      setShown(value);
      return;
    }
    const start = performance.now();
    const origin = from.current;
    let frame = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - (1 - t) ** 3;
      setShown(Math.round(origin + (value - origin) * eased));
      if (t < 1) frame = requestAnimationFrame(tick);
      else from.current = value;
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value, duration]);
  return <>{shown}</>;
}

/** Midnight / Daylight switch. */
export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => storedTheme());
  const next: Theme = theme === 'dark' ? 'light' : 'dark';
  return (
    <button
      type="button"
      onClick={() => {
        applyTheme(next);
        setTheme(next);
      }}
      aria-label={`Switch to ${next === 'light' ? 'Daylight' : 'Midnight'} theme`}
      title={`Switch to ${next === 'light' ? 'Daylight' : 'Midnight'} theme`}
      className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg border border-line-strong text-soft transition-colors hover:border-signal hover:text-fg"
    >
      {theme === 'dark' ? <Sun className="h-4 w-4" aria-hidden="true" /> : <Moon className="h-4 w-4" aria-hidden="true" />}
    </button>
  );
}

export function SourceTag({ source }: { source?: string }) {
  if (!source) return null;
  const ai = ['ollama', 'groq', 'gemini', 'hybrid'].includes(source);
  const labels: Record<string, string> = {
    ollama: 'Ollama',
    groq: 'Groq',
    gemini: 'Gemini',
    hybrid: 'Detector + LLM',
    anomaly: 'Detector only',
    playbook: 'Playbook',
  };
  return <span className={`font-mono text-[11px] uppercase tracking-wider ${ai ? 'text-signal' : 'text-muted'}`}>{labels[source] ?? 'Rules'}</span>;
}

export function formatRatio(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : value.toFixed(3);
}

/** Placeholder layout while a run loads; it fades into the real page when data arrives. */
export function SkeletonPage() {
  return (
    <div className="flex flex-col gap-5" aria-busy="true" aria-label="Loading run">
      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="aegis-glass flex flex-col gap-3 rounded-2xl border border-line px-5 py-4">
            <span className="aegis-skeleton h-3 w-24" />
            <span className="aegis-skeleton h-8 w-16" />
            <span className="aegis-skeleton h-3 w-32" />
          </div>
        ))}
      </div>
      <div className="aegis-glass flex flex-col gap-4 rounded-2xl border border-line p-5">
        <span className="aegis-skeleton h-4 w-48" />
        <span className="aegis-skeleton h-40 w-full" />
      </div>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="aegis-glass m-0 rounded-2xl border border-dashed border-line-strong p-8 text-center text-sm text-muted">{children}</p>;
}
