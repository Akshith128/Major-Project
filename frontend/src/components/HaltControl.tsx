import { useRef, useState, type FormEvent } from 'react';
import { OctagonPause, Play } from 'lucide-react';
import type { ControlState } from '../api';

/**
 * EU AI Act Art. 14(4)(e): a stop control that halts the system in a safe state.
 * It sits in the console header on every page. Halting blocks new runs and stops a
 * running one after its current window; one confirmation step guards against a
 * stray click. Anyone signed in may halt AEGIS; only a security manager may resume
 * it (the server enforces both).
 */
export function HaltControl({
  control,
  canHalt,
  canResume,
  onPause,
}: {
  control: ControlState | null;
  canHalt: boolean;
  canResume: boolean;
  onPause: (paused: boolean, reason: string) => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const paused = !!control?.paused;
  const allowed = paused ? canResume : canHalt;

  const open = () => {
    setError(null);
    dialog.current?.showModal();
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onPause(!paused, reason);
      setReason('');
      dialog.current?.close();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change the halt control.');
    } finally {
      setBusy(false);
    }
  };

  const title = !allowed
    ? 'AEGIS is halted. Only a security manager can resume it.'
    : paused
      ? 'Resume AEGIS'
      : 'Halt AEGIS: block new runs and stop the current one';

  return (
    <>
      <button
        type="button"
        onClick={open}
        disabled={!allowed}
        title={title}
        className={`flex h-11 shrink-0 cursor-pointer items-center gap-2 rounded-lg border px-3.5 text-sm font-bold whitespace-nowrap transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${
          paused ? 'border-ok bg-ok text-on-ok hover:brightness-110' : 'border-crit bg-crit text-on-crit hover:brightness-110'
        }`}
      >
        {paused ? <Play className="h-4 w-4" aria-hidden="true" /> : <OctagonPause className="h-4 w-4" aria-hidden="true" />}
        <span className="hidden sm:inline">{paused ? 'Resume AEGIS' : 'Halt AEGIS'}</span>
        <span className="sm:hidden">{paused ? 'Resume' : 'Halt'}</span>
      </button>

      <dialog
        ref={dialog}
        aria-labelledby="halt-title"
        className="m-auto w-[min(92vw,460px)] rounded-2xl border border-line-strong bg-panel p-0 text-fg backdrop:bg-black/60 backdrop:backdrop-blur-sm"
      >
        <form onSubmit={submit} className="flex flex-col gap-4 p-6">
          <h2 id="halt-title" className="m-0 flex items-center gap-2.5 text-lg font-bold">
            {paused ? <Play className="h-5 w-5 text-ok" aria-hidden="true" /> : <OctagonPause className="h-5 w-5 text-crit" aria-hidden="true" />}
            {paused ? 'Resume AEGIS?' : 'Halt AEGIS?'}
          </h2>
          <p className="m-0 text-sm text-soft">
            {paused
              ? 'New runs will be allowed again. Nothing that was pending changes on its own.'
              : 'New runs are blocked and a running one stops after its current window. Nothing is ever executed automatically, so the network is left as it is and pending recommendations stay pending. A security manager must resume AEGIS afterwards.'}
          </p>
          {!paused && (
            <label className="flex flex-col gap-1.5 text-sm text-soft">
              Reason (recorded in the audit trail)
              <input
                autoFocus
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={300}
                placeholder="e.g. Suspected model misbehaviour"
                className="h-11 rounded-lg border border-line-strong bg-ink px-3 text-sm text-fg"
              />
            </label>
          )}
          {error && (
            <p role="alert" className="m-0 text-sm text-warn">
              {error}
            </p>
          )}
          <div className="flex flex-wrap justify-end gap-3">
            <button
              type="button"
              onClick={() => dialog.current?.close()}
              className="h-11 cursor-pointer rounded-lg border border-line-strong px-4 text-sm font-semibold text-soft hover:text-fg"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className={`flex h-11 cursor-pointer items-center gap-2 rounded-lg px-4 text-sm font-bold disabled:opacity-50 ${paused ? 'bg-ok text-on-ok' : 'bg-crit text-on-crit'}`}
            >
              {paused ? <Play className="h-4 w-4" aria-hidden="true" /> : <OctagonPause className="h-4 w-4" aria-hidden="true" />}
              {busy ? (paused ? 'Resuming…' : 'Halting…') : paused ? 'Resume AEGIS' : 'Halt AEGIS'}
            </button>
          </div>
        </form>
      </dialog>
    </>
  );
}
