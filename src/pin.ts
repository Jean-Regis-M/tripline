import { sha256 } from './util.ts';
import type { Manifest, ToolDef } from './types.ts';

export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object')
    return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
export const hashTool = (t: ToolDef) =>
  sha256(canonical({ n: t.name, d: t.description, s: t.inputSchema ?? null }));

export interface Lock { version: 1; tools: Record<string, string> }
export function createLock(m: Manifest): Lock {
  const tools: Record<string, string> = {};
  for (const s of m.servers) for (const t of s.tools) tools[`${s.name}/${t.name}`] = hashTool(t);
  return { version: 1, tools };
}
export interface Drift { ok: boolean; changed: string[]; added: string[]; removed: string[] }
export function verifyLock(m: Manifest, lock: Lock): Drift {
  const now = createLock(m).tools;
  const changed = Object.keys(now).filter((k) => k in lock.tools && lock.tools[k] !== now[k]);
  const added = Object.keys(now).filter((k) => !(k in lock.tools));
  const removed = Object.keys(lock.tools).filter((k) => !(k in now));
  return { ok: !changed.length && !added.length && !removed.length, changed, added, removed };
}
