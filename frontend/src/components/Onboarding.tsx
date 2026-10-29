import { lazy, Suspense, useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, BrainCircuit, Check, EyeOff, FileLock2, Gauge, KeyRound, ListChecks, Minus, Radar, ShieldCheck, Siren, X } from 'lucide-react';
import { api, type Health, type Session } from '../api';
import { ROLES } from '../lib/operator';
import { ShieldMark, ThemeToggle } from './ui';
import { useTheme } from '../lib/theme';

// Three.js is loaded only for the landing page.
const OrbitScene = lazy(() => import('./OrbitScene').then((m) => ({ default: m.OrbitScene })));

/* Measured on fresh, never-tuned-on CIC-IDS2018 windows (reports/detector-tuning-results.md). */
const RESULTS = {
  mcc: '0.78',
  falseAlarms: '7.7%',
  recall: '93%',
  family: '100%',
};

type Stage = { icon: typeof Radar; name: string; result: string; tone: 'ok' | 'warn' | 'crit' | 'muted' };

/* Illustrative scenarios for the hero preview; the console shows real runs. */
const SCENARIOS: { window: string; label: string; stages: Stage[] }[] = [
  {
    window: 'W14 · 100 flows',
    label: 'Volumetric flood',
    stages: [
      { icon: Radar, name: 'Anomaly detector', result: 'abnormal · less normal than 99% of baseline', tone: 'crit' },
      { icon: BrainCircuit, name: 'Incident memory', result: 'DDoS · 3 of 3 nearest incidents agree', tone: 'crit' },
      { icon: Gauge, name: 'Risk', result: 'CRITICAL · 94 / 100', tone: 'crit' },
      { icon: ListChecks, name: 'Response', result: 'rate-limit · SYN cookies · scrubbing', tone: 'warn' },
      { icon: ShieldCheck, name: 'Governance', result: 'awaiting analyst approval', tone: 'warn' },
    ],
  },
  {
    window: 'W15 · 100 flows',
    label: 'Normal traffic',
    stages: [
      { icon: Radar, name: 'Anomaly detector', result: 'within normal traffic', tone: 'ok' },
      { icon: BrainCircuit, name: 'Incident memory', result: 'not needed', tone: 'muted' },
      { icon: Gauge, name: 'Risk', result: 'not scored', tone: 'muted' },
      { icon: ListChecks, name: 'Response', result: 'nothing to contain', tone: 'muted' },
      { icon: ShieldCheck, name: 'Governance', result: 'no action · logged', tone: 'ok' },
    ],
  },
  {
    window: 'W16 · 100 flows',
    label: 'Login attack',
    stages: [
      { icon: Radar, name: 'Anomaly detector', result: 'abnormal · less normal than 97% of baseline', tone: 'crit' },
      { icon: BrainCircuit, name: 'Incident memory', result: 'Brute Force · matches a confirmed incident', tone: 'crit' },
      { icon: Gauge, name: 'Risk', result: 'HIGH · 78 / 100', tone: 'warn' },
      { icon: ListChecks, name: 'Response', result: 'lock accounts · enforce MFA', tone: 'warn' },
      { icon: ShieldCheck, name: 'Governance', result: 'awaiting analyst approval', tone: 'warn' },
    ],
  },
];

const TONE = { ok: 'text-ok', warn: 'text-warn', crit: 'text-crit', muted: 'text-muted' };

/** The hero artwork is the product: a looping preview of a window moving through the agents. */
function LivePreview() {
  const reduce = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const [scenario, setScenario] = useState(0);
  const [stage, setStage] = useState(reduce ? 5 : 0);
  const [hashes, setHashes] = useState<string[]>(['9f2c…', '41ab…']);

  useEffect(() => {
    if (reduce) return;
    const id = setTimeout(() => {
      if (stage < 5) setStage(stage + 1);
      else {
        setHashes((h) => [...h.slice(-2), Math.random().toString(16).slice(2, 6) + '…']);
        setScenario((s) => (s + 1) % SCENARIOS.length);
        setStage(0);
      }
    }, stage < 5 ? 900 : 2200);
    return () => clearTimeout(id);
  }, [stage, reduce]);

  const current = SCENARIOS[scenario];
  return (
    <div className="aegis-glass rounded-2xl border border-line p-6 sm:p-7" aria-label="Illustrative preview of the AEGIS pipeline" role="img">
      <div className="flex items-center justify-between gap-3">
        <span className="font-mono text-xs tracking-[0.14em] text-muted uppercase">aegis · live pipeline</span>
        <span className="rounded-full border border-line px-2.5 py-1 font-mono text-[11px] text-muted">illustrative preview</span>
      </div>

      <div key={scenario} className="aegis-fade-up mt-6 flex items-center justify-between gap-3 rounded-xl border border-line bg-panel-2 px-4 py-3">
        <span className="flex items-center gap-2.5">
          <span className="h-2 w-2 rounded-full bg-signal aegis-pulse" aria-hidden="true" />
          <span className="font-mono text-sm">{current.window}</span>
        </span>
        <span className="text-sm text-soft">{current.label}</span>
      </div>

      <ol className="m-0 mt-4 flex list-none flex-col gap-1 p-0">
        {current.stages.map((s, i) => {
          const done = i < stage;
          const active = i === stage;
          const Icon = s.icon;
          return (
            <li
              key={`${scenario}-${s.name}`}
              className={`flex items-center gap-3 rounded-xl px-3 py-2.5 transition-colors duration-300 ${active ? 'bg-signal-soft' : ''}`}
            >
              <span
                className={`flex h-8 w-8 flex-none items-center justify-center rounded-lg border transition-colors duration-300 ${
                  done ? 'border-signal text-signal' : active ? 'border-signal bg-signal text-signal-ink' : 'border-line text-muted'
                }`}
              >
                {done ? <Check className="h-4 w-4" aria-hidden="true" /> : <Icon className="h-4 w-4" aria-hidden="true" />}
              </span>
              <span className="w-36 flex-none text-sm font-semibold">{s.name}</span>
              <span className="min-w-0 truncate font-mono text-xs">
                {done ? (
                  <span className={`aegis-fade-up inline-block ${TONE[s.tone]}`}>{s.result}</span>
                ) : active ? (
                  <span className="aegis-shimmer-text">analysing…</span>
                ) : (
                  <span className="aegis-skeleton inline-block h-3 w-40 align-middle" />
                )}
              </span>
            </li>
          );
        })}
      </ol>

      <div className="mt-5 flex items-center gap-2 border-t border-line pt-4 font-mono text-[11px] text-muted">
        <FileLock2 className="h-3.5 w-3.5 flex-none text-signal" aria-hidden="true" />
        <span className="flex-none">audit chain</span>
        {hashes.map((h, i) => (
          <span key={h + i} className={`flex items-center gap-2 ${i === hashes.length - 1 ? 'aegis-pop text-fg' : ''}`}>
            <span className="text-line-strong">→</span>
            <span className="rounded-md border border-line px-1.5 py-0.5">{h}</span>
          </span>
        ))}
        <span className="ml-auto flex-none">signed</span>
      </div>
    </div>
  );
}

const STEPS = [
  { icon: Radar, title: 'Detect', text: 'A one-class model learns what normal traffic looks like on your network and flags windows that do not fit — no attack examples needed.' },
  { icon: BrainCircuit, title: 'Recognise', text: 'An incident memory names the attack family from the closest known and analyst-confirmed incidents, and maps it to MITRE ATT&CK.' },
  { icon: Gauge, title: 'Assess', text: 'A fixed, auditable formula turns confidence, homogeneity and attack impact into a risk score. The model may raise severity, never lower it.' },
  { icon: Siren, title: 'Respond', text: 'A local language model explains the evidence and drafts containment steps. Nothing is executed automatically.' },
  { icon: ShieldCheck, title: 'Govern', text: 'Policy AEGIS-GOV-1 decides what needs a human. Every decision and approval is hash-chained and signed.' },
];

/* The kill chain, and what AEGIS can see of it from network flows (CIC-IDS2018 families). */
const KILL_CHAIN: { stage: string; seen: boolean; what: string; family?: string }[] = [
  { stage: 'Reconnaissance', seen: true, what: 'Hosts and ports are probed from inside the network.', family: 'Infiltration scans' },
  { stage: 'Weaponization', seen: false, what: 'The exploit is built on the attacker’s side. No traffic reaches you yet.' },
  { stage: 'Delivery', seen: true, what: 'Repeated logins hammer FTP, SSH and web forms.', family: 'Brute Force' },
  { stage: 'Exploitation', seen: true, what: 'Crafted requests try to break the web application.', family: 'SQL injection · XSS' },
  { stage: 'Installation', seen: false, what: 'Malware settles on a host. That happens on the endpoint, not the wire.' },
  { stage: 'Command & control', seen: true, what: 'Infected machines check in with the attacker on a schedule.', family: 'Botnet' },
  { stage: 'Actions on objectives', seen: true, what: 'Floods take services down.', family: 'DoS · DDoS' },
];

type Cell = 'yes' | 'no' | 'part' | string;
const COMPARE: { row: string; cells: [Cell, Cell, Cell] }[] = [
  { row: 'Learns from normal traffic, no attack examples', cells: ['yes', 'no', 'no'] },
  { row: 'Names the attack family', cells: ['yes', 'part', 'part'] },
  { row: 'Explains each decision in plain language', cells: ['yes', 'part', 'no'] },
  { row: 'Human approval before any response', cells: ['yes', 'no', 'no'] },
  { row: 'Signed, tamper-evident audit trail', cells: ['yes', 'no', 'no'] },
  { row: 'Detection quality on unseen traffic (MCC)', cells: ['0.78', '0.66', '0.21'] },
];

function CompareCell({ value, strong }: { value: Cell; strong?: boolean }) {
  if (value === 'yes')
    return (
      <span className="inline-flex items-center gap-2 text-signal">
        <Check className="h-4 w-4" aria-hidden="true" />
        <span className="text-sm text-fg">Yes</span>
      </span>
    );
  if (value === 'no')
    return (
      <span className="inline-flex items-center gap-2 text-muted">
        <X className="h-4 w-4" aria-hidden="true" />
        <span className="text-sm">No</span>
      </span>
    );
  if (value === 'part')
    return (
      <span className="inline-flex items-center gap-2 text-muted">
        <Minus className="h-4 w-4" aria-hidden="true" />
        <span className="text-sm">Partly</span>
      </span>
    );
  return <span className={`font-mono text-lg font-bold ${strong ? 'text-signal' : 'text-soft'}`}>{value}</span>;
}

export function Onboarding({ onSignedIn }: { onSignedIn: (session: Session, remember: boolean) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    api.health().then(setHealth).catch((err) => setError(err instanceof Error ? err.message : 'API unavailable'));
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSignedIn(await api.login(username.trim(), password), remember);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed.');
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  const theme = useTheme();
  const noAccounts = health && !health.accounts;
  const section = 'mx-auto w-full max-w-[1280px] px-5 py-24 sm:px-8 lg:py-32';

  return (
    <div className="flex min-h-screen flex-col">
      <Suspense fallback={null}>
        <OrbitScene theme={theme} />
      </Suspense>
      <header className="aegis-header sticky top-0 z-20 border-b border-line">
        <nav className="mx-auto flex max-w-[1280px] items-center gap-6 px-5 py-3 sm:px-8" aria-label="Site">
          <a href="#top" className="flex items-center gap-2.5 text-fg no-underline">
            <ShieldMark />
            <span className="font-mono text-sm font-bold tracking-[0.3em]">AEGIS</span>
          </a>
          {/* What the name stands for, in the wordmark's mono face; needs the wide header's room. */}
          <span className="hidden border-l border-line-strong pl-6 font-mono text-xs tracking-[0.04em] whitespace-nowrap text-muted xl:inline">
            Autonomous Engine for Governance, Intelligence and Security
          </span>
          <div className="ml-auto hidden items-center gap-6 text-sm text-soft md:flex">
            <a href="#how" className="text-soft no-underline transition-colors hover:text-fg">How it works</a>
            <a href="#killchain" className="text-soft no-underline transition-colors hover:text-fg">Kill chain</a>
            <a href="#results" className="text-soft no-underline transition-colors hover:text-fg">Results</a>
            <a href="#compare" className="text-soft no-underline transition-colors hover:text-fg">Compare</a>
            <a href="#trust" className="text-soft no-underline transition-colors hover:text-fg">Trust</a>
          </div>
          <div className="ml-auto flex items-center gap-3 md:ml-0">
            <ThemeToggle />
            <a href="#signin" className="flex h-11 items-center rounded-lg border border-line-strong px-4 text-sm font-semibold text-fg no-underline transition-colors hover:border-signal">
              Sign in
            </a>
          </div>
        </nav>
      </header>

      <main id="top">
        {/* Hero: the black hole is the centrepiece; the pitch sits centred beneath it. */}
        <section className="mx-auto flex min-h-[calc(100svh-68px)] w-full max-w-[1280px] flex-col items-center justify-center px-5 pt-6 pb-20 text-center sm:px-8">
          {/* Stage for the 3D black hole (OrbitScene centres and sizes itself here); CSS rings stand in without WebGL. */}
          <div data-orbit-anchor className="aegis-orbit h-[48svh] min-h-[280px] w-full max-w-[1100px]" aria-hidden="true" />
          <p className="aegis-fade-up m-0 mb-8 flex items-center gap-4 font-mono text-xs tracking-[0.24em] text-signal uppercase">
            <span className="h-px w-10 bg-current opacity-50" aria-hidden="true" />
            Nothing escapes the event horizon
            <span className="h-px w-10 bg-current opacity-50" aria-hidden="true" />
          </p>
          <div className="flex max-w-3xl flex-col items-center gap-6">
            <p className="aegis-fade-up m-0 font-mono text-xs tracking-[0.24em] text-muted uppercase">Agentic SOC</p>
            <h1 className="aegis-fade-up m-0 text-[clamp(38px,5.6vw,72px)] leading-[1.02] font-extrabold tracking-[-0.03em] text-balance" style={{ animationDelay: '80ms' }}>
              Threat detection that <span className="aegis-accent-text">shows its work.</span>
            </h1>
            <p className="aegis-fade-up m-0 max-w-2xl text-lg leading-relaxed text-soft" style={{ animationDelay: '160ms' }}>
              Agentic AI for autonomous threat detection and response. Five agents detect, recognise, assess and explain every
              suspicious window — and a human signs off before anything happens.
            </p>
            <div className="aegis-fade-up flex flex-col items-center gap-4" style={{ animationDelay: '240ms' }}>
              <a href="#signin" className="flex h-12 items-center gap-2.5 rounded-lg bg-signal px-6 text-base font-bold text-signal-ink no-underline transition-shadow duration-200 hover:shadow-[0_0_0_4px_var(--spot-fill),0_0_32px_-4px_var(--spot)]">
                Sign in to the console <ArrowRight className="h-[18px] w-[18px]" aria-hidden="true" />
              </a>
              <span className="font-mono text-xs text-muted">
                MCC {RESULTS.mcc} · false alarms {RESULTS.falseAlarms} · fresh CIC-IDS2018 windows
              </span>
            </div>
          </div>
        </section>

        {/* How it works: asymmetric — a sticky statement left, the five agents right. */}
        <section id="how" className={`${section} grid gap-14 border-t border-line lg:grid-cols-[1fr_1.4fr]`}>
          <div className="flex flex-col gap-5 lg:sticky lg:top-28 lg:self-start">
            <p className="m-0 font-mono text-xs tracking-[0.24em] text-signal uppercase">How it works</p>
            <h2 className="m-0 text-[clamp(30px,3.6vw,46px)] leading-[1.08] font-extrabold tracking-[-0.02em] text-balance">
              Five agents. One decision chain you can read end to end.
            </h2>
            <p className="m-0 max-w-md text-soft">
              AEGIS works like an event horizon: every window of 100 network flows is pulled through the same LangGraph pipeline,
              and nothing comes back out without a governance decision on record. Every step leaves evidence behind, so an analyst can
              see exactly why the system acted.
            </p>
            <LivePreview />
          </div>
          <ol className="m-0 flex list-none flex-col gap-4 p-0">
            {STEPS.map((s, i) => (
              <li key={s.title} className="aegis-glass aegis-lift flex gap-5 rounded-xl border border-line p-6">
                <span className="font-mono text-sm text-muted">0{i + 1}</span>
                <span className="flex flex-col gap-2">
                  <span className="flex items-center gap-2.5 text-lg font-bold">
                    <s.icon className="h-5 w-5 text-signal" aria-hidden="true" />
                    {s.title}
                  </span>
                  <span className="text-soft">{s.text}</span>
                </span>
              </li>
            ))}
          </ol>
        </section>

        {/* Kill chain: where each attack stage meets AEGIS, including the two it cannot see. */}
        <section id="killchain" className={`${section} border-t border-line`}>
          <div className="flex max-w-3xl flex-col gap-5">
            <p className="m-0 font-mono text-xs tracking-[0.24em] text-signal uppercase">The kill chain</p>
            <h2 className="m-0 text-[clamp(30px,3.6vw,46px)] leading-[1.08] font-extrabold tracking-[-0.02em] text-balance">
              Attacks move in seven steps. AEGIS breaks the five that touch the network.
            </h2>
            <p className="m-0 max-w-2xl text-soft">
              AEGIS reads traffic, so it sees every stage that leaves flows behind. The two it cannot see are marked as such: pair
              AEGIS with endpoint protection for those.
            </p>
          </div>
          <ol className="relative m-0 mt-14 grid list-none gap-3 p-0 lg:grid-cols-7 lg:gap-0">
            <span className="absolute top-[19px] right-[7%] left-[7%] hidden h-px bg-line-strong lg:block" aria-hidden="true" />
            {KILL_CHAIN.map((k, i) => (
              <li key={k.stage} className={`relative flex gap-4 lg:flex-col lg:items-center lg:gap-4 lg:px-2 lg:text-center`}>
                <span
                  className={`relative z-10 flex h-10 w-10 flex-none items-center justify-center rounded-full border font-mono text-sm font-bold ${
                    k.seen ? 'border-signal bg-ink text-signal shadow-[0_0_0_6px_var(--spot-fill)]' : 'border-dashed border-line-strong bg-ink text-muted'
                  }`}
                >
                  {i + 1}
                </span>
                <span className="flex min-w-0 flex-col gap-2 pb-4 lg:items-center">
                  <span className="font-semibold">{k.stage}</span>
                  <span className="text-sm text-soft">{k.what}</span>
                  {k.seen ? (
                    <span className="mt-1 inline-flex w-fit items-center gap-1.5 rounded-full border border-signal/40 bg-signal-soft px-2.5 py-1 font-mono text-[11px] text-signal">
                      <Radar className="h-3 w-3" aria-hidden="true" /> {k.family}
                    </span>
                  ) : (
                    <span className="mt-1 inline-flex w-fit items-center gap-1.5 rounded-full border border-line px-2.5 py-1 font-mono text-[11px] text-muted">
                      <EyeOff className="h-3 w-3" aria-hidden="true" /> Not visible in traffic
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ol>
        </section>

        {/* Results: the headline number is the largest thing on the page. */}
        <section id="results" className={`${section} border-t border-line`}>
          <div className="grid items-end gap-12 lg:grid-cols-[1.5fr_1fr]">
            <div className="flex flex-col gap-4">
              <p className="m-0 font-mono text-xs tracking-[0.24em] text-signal uppercase">Measured, not claimed</p>
              <p className="m-0 font-mono text-[clamp(96px,16vw,200px)] leading-[0.9] font-bold tracking-[-0.05em] text-fg">{RESULTS.mcc}</p>
              <p className="m-0 max-w-lg text-lg text-soft">
                Detection quality (Matthews correlation) on 800 CIC-IDS2018 windows the system never saw while it was being built,
                once analysts have confirmed similar incidents (0.74 without). The rule-based baseline scored 0.66 on comparable unseen
                windows and leans on a testbed shortcut.
              </p>
            </div>
            <dl className="m-0 grid grid-cols-1 gap-3">
              {[
                ['False alarm rate', RESULTS.falseAlarms, 'down from 19% in the first design'],
                ['Attacks caught', RESULTS.recall, 'recall on the same windows'],
                ['Attack family named', RESULTS.family, 'once analysts confirm similar incidents'],
              ].map(([k, v, note]) => (
                <div key={k} className="aegis-glass aegis-lift flex items-baseline justify-between gap-4 rounded-xl border border-line px-5 py-4">
                  <dt className="flex flex-col">
                    <span className="text-sm font-semibold">{k}</span>
                    <span className="text-xs text-muted">{note}</span>
                  </dt>
                  <dd className="m-0 font-mono text-2xl font-bold text-signal">{v}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        {/* Comparison: the same questions asked of AEGIS and the two usual alternatives. */}
        <section id="compare" className={`${section} border-t border-line`}>
          <div className="flex max-w-3xl flex-col gap-5">
            <p className="m-0 font-mono text-xs tracking-[0.24em] text-signal uppercase">The comparison</p>
            <h2 className="m-0 text-[clamp(30px,3.6vw,46px)] leading-[1.08] font-extrabold tracking-[-0.02em] text-balance">
              Why agents, and not just rules or a classifier.
            </h2>
          </div>
          <div className="aegis-glass mt-12 overflow-x-auto rounded-2xl border border-line">
            <table className="w-full min-w-[640px] border-collapse text-left">
              <caption className="sr-only">AEGIS compared with signature rules and a supervised classifier</caption>
              <thead>
                <tr className="border-b border-line">
                  <th scope="col" className="px-6 py-5 text-sm font-medium text-muted">What you get</th>
                  <th scope="col" className="bg-signal-soft px-6 py-5">
                    <span className="flex items-center gap-2 font-bold text-fg">
                      <ShieldMark size={20} /> AEGIS
                    </span>
                  </th>
                  <th scope="col" className="px-6 py-5 font-semibold text-soft">Signature rules</th>
                  <th scope="col" className="px-6 py-5 font-semibold text-soft">Supervised classifier</th>
                </tr>
              </thead>
              <tbody>
                {COMPARE.map(({ row, cells }) => (
                  <tr key={row} className="border-b border-line last:border-b-0">
                    <th scope="row" className="px-6 py-4 text-sm font-medium text-fg">{row}</th>
                    <td className="bg-signal-soft px-6 py-4"><CompareCell value={cells[0]} strong /></td>
                    <td className="px-6 py-4"><CompareCell value={cells[1]} /></td>
                    <td className="px-6 py-4"><CompareCell value={cells[2]} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="m-0 mt-4 max-w-3xl text-xs text-muted">
            MCC on CIC-IDS2018 windows that were not used to build or tune each method. Rules and classifier come from the multi-day
            benchmark; the classifier is a Random Forest trained on the other day-files.
          </p>
        </section>

        {/* Trust: statement left, the audit chain right. */}
        <section id="trust" className={`${section} grid items-center gap-14 border-t border-line lg:grid-cols-[1.2fr_1fr]`}>
          <div className="flex flex-col gap-6">
            <p className="m-0 font-mono text-xs tracking-[0.24em] text-signal uppercase">Digital trust</p>
            <h2 className="m-0 text-[clamp(30px,3.6vw,46px)] leading-[1.08] font-extrabold tracking-[-0.02em] text-balance">
              Autonomy with a human hand on the switch.
            </h2>
            <ul className="m-0 flex list-none flex-col gap-3 p-0 text-soft">
              {[
                'Responses are recommendations — high-risk ones wait for a signed-in analyst.',
                'Agents only ever see label-free traffic statistics; no payloads, no addresses.',
                'A local model runs on the machine: no quota, and no data leaves it.',
                'A manager can pause the whole system in one click.',
              ].map((t) => (
                <li key={t} className="flex gap-3">
                  <Check className="mt-1 h-4 w-4 flex-none text-signal" aria-hidden="true" />
                  {t}
                </li>
              ))}
            </ul>
          </div>
          <div className="aegis-glass rounded-2xl border border-line p-6 font-mono text-xs">
            <p className="m-0 mb-4 tracking-[0.14em] text-muted uppercase">Signed audit trail</p>
            <ol className="m-0 flex list-none flex-col gap-2 p-0">
              {[
                ['#41', 'RUN_STARTED', 'user:analyst'],
                ['#42', 'WINDOW_DECIDED', 'aegis:governance'],
                ['#43', 'RESPONSE_APPROVED', 'user:responder'],
              ].map(([seq, action, actor], i) => (
                <li key={seq} className="flex flex-col gap-1">
                  <span className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-panel-2 px-3.5 py-2.5">
                    <span className="text-fg">{seq} {action}</span>
                    <span className="text-muted">{actor} · HMAC ✓</span>
                  </span>
                  {i < 2 && <span className="pl-4 text-line-strong">│ prev-hash links the next record</span>}
                </li>
              ))}
            </ol>
            <p className="m-0 mt-4 text-muted">Edit, delete or reorder a record and verification fails.</p>
          </div>
        </section>

        {/* Sign in */}
        <section id="signin" className={`${section} grid items-start gap-14 border-t border-line lg:grid-cols-[1fr_1fr]`}>
          <div className="flex flex-col gap-5">
            <p className="m-0 font-mono text-xs tracking-[0.24em] text-signal uppercase">Operator console</p>
            <h2 className="m-0 text-[clamp(30px,3.6vw,46px)] leading-[1.08] font-extrabold tracking-[-0.02em]">Sign in</h2>
            <p className="m-0 text-soft">Everyone opens on the overview; your account’s role sets what you may do.</p>
            <ul className="m-0 flex list-none flex-col gap-2.5 p-0 text-sm text-soft">
              {ROLES.map((r) => (
                <li key={r.id} className="flex flex-wrap gap-x-2">
                  <span className="font-semibold text-fg">{r.label}</span>
                  <span>· {r.blurb}</span>
                </li>
              ))}
            </ul>
          </div>

          <form onSubmit={submit} className="aegis-glass flex w-full flex-col gap-5 rounded-2xl border border-line p-7">
            {noAccounts && (
              <div role="status" className="flex flex-col gap-2 rounded-xl border border-warn-line bg-warn-soft p-4 text-sm text-warn">
                <span className="flex items-center gap-2 font-semibold">
                  <KeyRound className="h-4 w-4" aria-hidden="true" /> No operator accounts yet
                </span>
                <span className="text-soft">Create one on the server, then sign in:</span>
                <code className="rounded bg-ink px-2 py-1.5 font-mono text-xs text-fg">python -m aegis.users add yourname --role analyst</code>
              </div>
            )}
            <label className="flex flex-col gap-2 font-mono text-xs tracking-[0.12em] text-muted uppercase">
              Username
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
                className="h-12 rounded-xl border border-line-strong bg-ink px-3.5 font-sans text-base tracking-normal text-fg normal-case transition-colors focus:border-signal"
              />
            </label>
            <label className="flex flex-col gap-2 font-mono text-xs tracking-[0.12em] text-muted uppercase">
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                className="h-12 rounded-xl border border-line-strong bg-ink px-3.5 font-sans text-base tracking-normal text-fg normal-case transition-colors focus:border-signal"
              />
            </label>
            <label className="flex cursor-pointer items-center gap-2.5 text-sm text-soft">
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} className="h-4 w-4 accent-signal" />
              Keep me signed in on this device
            </label>
            {error && (
              <p role="alert" className="m-0 text-sm text-warn">
                {error}
              </p>
            )}
            <button
              type="submit"
              disabled={busy || !username.trim() || !password}
              className="flex h-12 cursor-pointer items-center justify-center gap-2.5 rounded-lg bg-signal text-base font-bold text-signal-ink transition-shadow duration-200 hover:shadow-[0_0_0_4px_var(--spot-fill),0_0_32px_-4px_var(--spot)] disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:shadow-none"
            >
              {busy ? <span className="aegis-shimmer-text">Signing in…</span> : 'Sign in'}
              <ArrowRight className="h-[18px] w-[18px]" aria-hidden="true" />
            </button>
          </form>
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-[1280px] flex-wrap justify-between gap-3 px-5 py-8 font-mono text-xs text-muted sm:px-8">
          <span>AEGIS · Nothing escapes the event horizon · Enhancing Cybersecurity Governance and Digital Trust</span>
          <span>LangGraph · Ollama · Backend server · CIC-IDS2018</span>
        </div>
      </footer>
    </div>
  );
}
