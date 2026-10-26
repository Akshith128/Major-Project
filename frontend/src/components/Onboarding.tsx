import { useState, type FormEvent } from 'react';
import { ArrowRight } from 'lucide-react';
import { ROLES, type OperatorProfile, type OperatorRole } from '../lib/operator';
import { ShieldMark } from './ui';

export function Onboarding({
  initial,
  onEnter,
}: {
  initial: OperatorProfile | null;
  onEnter: (profile: OperatorProfile) => void;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [role, setRole] = useState<OperatorRole>(initial?.role ?? 'analyst');
  const [remember, setRemember] = useState(initial?.remember ?? true);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onEnter({ name: name.trim(), role, remember });
  };

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

      <form
        onSubmit={submit}
        className="flex w-full max-w-[560px] flex-col gap-5 rounded-2xl border border-line-strong bg-panel p-7"
      >
        <div className="flex flex-col gap-2">
          <label htmlFor="op-name" className="font-mono text-xs uppercase tracking-[0.12em] text-muted">
            Operator name
          </label>
          <input
            id="op-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Akshith"
            autoComplete="name"
            autoFocus
            className="h-12 rounded-lg border border-line-strong bg-ink px-3.5 text-base text-fg placeholder:text-muted"
          />
        </div>

        <fieldset className="m-0 flex flex-col gap-2.5 border-0 p-0">
          <legend className="mb-2.5 p-0 font-mono text-xs uppercase tracking-[0.12em] text-muted">
            Your role — the console adapts to it
          </legend>
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            {ROLES.map((r) => {
              const on = r.id === role;
              return (
                <button
                  key={r.id}
                  type="button"
                  aria-pressed={on}
                  onClick={() => setRole(r.id)}
                  className={`min-h-16 cursor-pointer rounded-lg border px-3.5 py-3 text-left transition-colors ${
                    on ? 'border-signal bg-[#122631]' : 'border-line-strong bg-ink hover:border-muted'
                  }`}
                >
                  <span className="block text-[15px] font-semibold">{r.label}</span>
                  <span className="mt-1 block text-sm text-soft">{r.blurb}</span>
                </button>
              );
            })}
          </div>
        </fieldset>

        <label className="flex cursor-pointer items-center gap-2.5 text-sm text-soft">
          <input
            type="checkbox"
            checked={remember}
            onChange={(e) => setRemember(e.target.checked)}
            className="h-4 w-4 accent-[#38D6F5]"
          />
          Remember me on this device
        </label>

        <button
          type="submit"
          className="flex h-[52px] cursor-pointer items-center justify-center gap-2.5 rounded-lg bg-signal text-base font-bold text-signal-ink hover:brightness-110"
        >
          Enter command center
          <ArrowRight className="h-[18px] w-[18px]" aria-hidden="true" />
        </button>
        <p className="m-0 text-center text-sm text-muted">
          Your name and role decide what the console shows you first.
        </p>
      </form>
    </div>
  );
}
