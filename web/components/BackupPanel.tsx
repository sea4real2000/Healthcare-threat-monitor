'use client';

import { useEffect, useRef, useState } from 'react';

// Making, downloading and restoring backups in the browser. The work is done by the installation's backup service;
// this sends the request and follows the job until it is done, including through the console starting again
// after a restore.

type Status = { state: 'working' | 'done' | 'failed'; step?: string; code?: string; message?: string; bytes?: number; madeAt?: string };
type Text = Record<string, string>;

const POLL_MS = 2000;

function size(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

async function follow(id: string, text: Text, onStep: (s: string) => void, stopped: () => boolean, limitMinutes: number): Promise<Status> {
  const end = Date.now() + limitMinutes * 60_000;
  while (Date.now() < end && !stopped()) {
    try {
      const r = await fetch(`/api/backups/${id}/status`, { cache: 'no-store' });
      if (r.ok) {
        const s = (await r.json()) as Status;
        if (s.state !== 'working') return s;
        onStep(text[`backups.step.${s.step ?? 'waiting'}`] ?? s.step ?? '');
      }
    } catch {
      // The console may be starting again with the restored keys. Keep asking.
      onStep(text['backups.step.restarting']);
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
  return { state: 'failed', message: text['backups.error.timeout'] };
}

async function errorText(r: Response, text: Text): Promise<string> {
  const body = (await r.json().catch(() => ({}))) as { error?: string };
  return text[`backups.error.${body.error ?? 'failed'}`] ?? text['backups.error.failed'];
}

/** Make a backup and download it. Administrators only. */
export function MakeBackup({ text, minLength, limitMinutes }: { text: Text; minLength: number; limitMinutes: number }) {
  const [phase, setPhase] = useState<'idle' | 'working' | 'done' | 'failed'>('idle');
  const [note, setNote] = useState('');
  const [ready, setReady] = useState<{ id: string; bytes: number } | null>(null);
  const gone = useRef(false);
  useEffect(() => () => { gone.current = true; }, []);

  async function start(form: HTMLFormElement) {
    const data = new FormData(form);
    const passphrase = String(data.get('passphrase') ?? '');
    if (passphrase.length < minLength) return (setPhase('failed'), setNote(text['backups.error.passphrase_too_short']));
    if (passphrase !== String(data.get('confirm') ?? '')) return (setPhase('failed'), setNote(text['backups.error.passphrases_differ']));
    setPhase('working');
    setNote(text['backups.step.waiting']);
    const r = await fetch('/api/backups', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase }) });
    if (!r.ok) return (setPhase('failed'), setNote(await errorText(r, text)));
    const { id } = (await r.json()) as { id: string };
    form.reset();
    const s = await follow(id, text, setNote, () => gone.current, limitMinutes);
    if (s.state === 'done') {
      setReady({ id, bytes: s.bytes ?? 0 });
      setPhase('done');
      setNote(text['backups.made']);
    } else {
      setPhase('failed');
      setNote((s.code && text[`backups.error.${s.code}`]) || s.message || text['backups.error.failed']);
    }
  }

  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); void start(e.currentTarget); }}>
      <label>
        {text['backups.passphrase']}
        <input type="password" name="passphrase" required minLength={minLength} maxLength={500} autoComplete="new-password" />
        <span className="sub">{text['backups.passphrase_hint']}</span>
      </label>
      <label>
        {text['backups.passphrase_again']}
        <input type="password" name="confirm" required minLength={minLength} maxLength={500} autoComplete="new-password" />
      </label>
      <div>
        <button className="button button-primary" type="submit" disabled={phase === 'working'}>{text['backups.make']}</button>
      </div>
      {note ? <p className={phase === 'failed' ? 'flash flash-error' : 'flash flash-ok'} role="status" data-backup-state={phase}>{note}</p> : null}
      {ready ? (
        <p>
          <a className="button" href={`/api/backups/${ready.id}/file`} data-backup-download={ready.id}>
            {text['backups.download']} ({size(ready.bytes)})
          </a>
        </p>
      ) : null}
    </form>
  );
}

/**
 * Restore a backup onto this installation. Signed in administrators use it from Settings; on a new installation
 * nobody has set up, whoever has the setup code from its screen uses it from the first visit page.
 */
export function RestoreBackup({ text, confirmWord, withCode, limitMinutes }: { text: Text; confirmWord: string; withCode: boolean; limitMinutes: number }) {
  const [phase, setPhase] = useState<'idle' | 'working' | 'done' | 'failed'>('idle');
  const [note, setNote] = useState('');
  const gone = useRef(false);
  useEffect(() => () => { gone.current = true; }, []);

  async function start(form: HTMLFormElement) {
    const data = new FormData(form);
    const file = data.get('file');
    if (!(file instanceof File) || file.size === 0) return (setPhase('failed'), setNote(text['backups.error.no_file']));
    const headers: Record<string, string> = {};
    if (withCode) headers['X-Setup-Code'] = String(data.get('code') ?? '');
    setPhase('working');
    setNote(text['backups.step.uploading']);
    const up = await fetch('/api/backups/upload', { method: 'POST', headers: { ...headers, 'Content-Type': 'application/octet-stream' }, body: file });
    if (!up.ok) return (setPhase('failed'), setNote(await errorText(up, text)));
    const { upload } = (await up.json()) as { upload: string };
    const r = await fetch('/api/backups/restore', {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ upload, passphrase: String(data.get('passphrase') ?? ''), confirm: String(data.get('confirm') ?? '') }),
    });
    if (!r.ok) return (setPhase('failed'), setNote(await errorText(r, text)));
    const { id } = (await r.json()) as { id: string };
    const s = await follow(id, text, setNote, () => gone.current, limitMinutes);
    if (s.state === 'done') {
      setPhase('done');
      setNote(text['backups.restored']);
    } else {
      setPhase('failed');
      setNote((s.code && text[`backups.error.${s.code}`]) || s.message || text['backups.error.failed']);
    }
  }

  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); void start(e.currentTarget); }}>
      {withCode ? (
        <label>
          {text['backups.code']}
          <input name="code" required maxLength={40} autoComplete="off" autoCapitalize="characters" spellCheck={false} placeholder="ABCDE FGHJK" />
        </label>
      ) : null}
      <label>
        {text['backups.file']}
        <input type="file" name="file" required accept=".htmbackup" />
      </label>
      <label>
        {text['backups.passphrase']}
        <input type="password" name="passphrase" required maxLength={500} autoComplete="off" />
      </label>
      <label>
        {text['backups.confirm'].replace('{word}', confirmWord)}
        <input name="confirm" required maxLength={40} autoComplete="off" spellCheck={false} />
        <span className="sub">{text['backups.confirm_hint']}</span>
      </label>
      <div>
        <button className="button button-danger" type="submit" disabled={phase === 'working' || phase === 'done'}>{text['backups.restore']}</button>
      </div>
      {note ? <p className={phase === 'failed' ? 'flash flash-error' : 'flash flash-ok'} role="status" data-backup-state={phase}>{note}</p> : null}
      {phase === 'done' ? <p><a className="button button-primary" href="/signin">{text['backups.sign_in']}</a></p> : null}
    </form>
  );
}
