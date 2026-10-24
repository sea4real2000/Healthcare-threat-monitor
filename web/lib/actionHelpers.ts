import { redirect } from 'next/navigation';
import { db } from './db';

// Small helpers shared by the console's server actions.

export function field(form: FormData, name: string, max = 500): string {
  const v = form.get(name);
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

export function back(path: string, params: Record<string, string>): never {
  const query = new URLSearchParams(params).toString();
  redirect(query ? `${path}?${query}` : path);
}

export async function audit(user: { id: string; name: string }, action: string, subjectType: string, subjectId: string, detail: object) {
  await db()`select audit_append('user', ${user.id}, ${user.name}, ${action}, ${subjectType}, ${subjectId}, ${db().json(detail as never)}::jsonb)`;
}
