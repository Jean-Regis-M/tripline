// Tamper evident audit trail ("flight recorder"). Each record carries the hash of the one before it, so editing,
// deleting or reordering any entry breaks the chain from that point on. Pure functions: they run in Node and in the browser.
import { canonical } from './pin.ts';
import { sha256 } from './util.ts';

export const GENESIS = '0'.repeat(64);

export interface AuditRecord {
  seq: number;
  ts: string;
  event: string;
  tool?: string;
  decision?: string;
  rules?: string[];
  detail?: string;
  /** SHA-256 of the canonical arguments. The arguments themselves are never stored, so the log cannot leak a secret. */
  argsSha256?: string;
  prev: string;
  hash: string;
}

export const chainHash = (prev: string, rec: Omit<AuditRecord, 'hash'>): string => sha256(prev + canonical(rec));
export const digestArgs = (args: unknown): string => sha256(canonical(args));

export interface ChainReport { ok: boolean; entries: number; head: string; brokenAt?: number; reason?: string }

/** Verify a log given as JSON lines. Optionally check that the chain ends at a head hash you stored elsewhere. */
export function verifyChain(lines: string[], anchor?: string): ChainReport {
  const rows = lines.map((l) => l.trim()).filter(Boolean);
  let prev = GENESIS;
  for (let i = 0; i < rows.length; i++) {
    let rec: AuditRecord;
    try { rec = JSON.parse(rows[i]); } catch { return { ok: false, entries: i, head: prev, brokenAt: i, reason: 'entry is not valid JSON' }; }
    if (rec.seq !== i) return { ok: false, entries: i, head: prev, brokenAt: i, reason: 'sequence number out of order: an entry was deleted, inserted or reordered' };
    if (rec.prev !== prev) return { ok: false, entries: i, head: prev, brokenAt: i, reason: 'previous hash does not match: an entry before this one was changed or removed' };
    const { hash, ...body } = rec;
    if (chainHash(prev, body) !== hash) return { ok: false, entries: i, head: prev, brokenAt: i, reason: 'hash does not match the content: this entry was edited' };
    prev = hash;
  }
  if (anchor && anchor !== prev) return { ok: false, entries: rows.length, head: prev, reason: 'the log ends at a different point than the anchor you stored: entries were cut off the end' };
  return { ok: true, entries: rows.length, head: prev };
}
