import { useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, KeyRound } from 'lucide-react';
import { api, type Health, type Session } from '../api';
import { PAGES, ROLES } from '../lib/operator';
import { ShieldMark } from './ui';

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

  const noAccounts = health && !health.accounts;

  return (
    <div className="aegis-grid flex min-h-screen flex-col items-center justify-center gap-8 px-4 py-12">
      <div className="flex max-w-3xl flex-col items-center gap-3.5 text-center">
        <div className="flex items-center gap-3">
          <ShieldMark size={40} />
          <span className="font-mono text-[22px] font-bold tracking-[0.32em]">AEGIS</span>
        </div>
        <p className="m-0 font-mono text-xs uppercase tracking-[0.18em] text-muted">
          B.Tech Major Project · Secure operator sign-in
        </p>
        <h1 className="m-0 text-[clamp(30px,4.4vw,48px)] font-bold leading-[1.08] tracking-tight text-balance">
          Agentic AI for Autonomous Threat Detection and Response
        </h1>
        <p className="m-0 text-lg text-soft">Enhancing Cybersecurity Governance and Digital Trust</p>
      </div>

      <form onSubmit={submit} className="flex w-full max-w-[560px] flex-col gap-5 rounded-2xl border border-line-strong bg-panel p-7">
        {noAccounts && (
          <div role="status" className="flex flex-col gap-2 rounded-lg border border-[#6B4F1A] bg-[#2A1F0A] p-4 text-sm text-warn">
            <span className="flex items-center gap-2 font-semibold">
              <KeyRound className="h-4 w-4" aria-hidden="true" /> No operator accounts yet
            </span>
            <span className="text-soft">Create one on the server, then sign in:</span>
            <code className="rounded bg-ink px-2 py-1.5 font-mono text-xs text-fg">python -m aegis.users add yourname --role analyst</code>
          </div>
        )}
        <label className="flex flex-col gap-2 font-mono text-xs uppercase tracking-[0.12em] text-muted">
          Username
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
            className="h-12 rounded-lg border border-line-strong bg-ink px-3.5 font-sans text-base normal-case tracking-normal text-fg"
          />
        </label>
        <label className="flex flex-col gap-2 font-mono text-xs uppercase tracking-[0.12em] text-muted">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            className="h-12 rounded-lg border border-line-strong bg-ink px-3.5 font-sans text-base normal-case tracking-normal text-fg"
          />
        </label>

        <label className="flex cursor-pointer items-center gap-2.5 text-sm text-soft">
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} className="h-4 w-4 accent-[#38D6F5]" />
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
          className="flex h-[52px] cursor-pointer items-center justify-center gap-2.5 rounded-lg bg-signal text-base font-bold text-signal-ink hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? 'Signing in…' : 'Sign in'}
          <ArrowRight className="h-[18px] w-[18px]" aria-hidden="true" />
        </button>

        <div className="flex flex-col gap-2 border-t border-line pt-4">
          <span className="font-mono text-xs uppercase tracking-[0.12em] text-muted">Your account's role sets where you land and what you may do</span>
          <ul className="m-0 grid list-none grid-cols-1 gap-1.5 p-0 text-sm text-soft sm:grid-cols-2">
            {ROLES.map((r) => (
              <li key={r.id}>
                <span className="font-semibold text-fg">{r.label}</span> · {r.blurb} · opens {PAGES.find((p) => p.id === r.landing)?.label}
              </li>
            ))}
          </ul>
        </div>
      </form>
    </div>
  );
}
