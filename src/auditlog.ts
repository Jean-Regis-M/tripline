// Node side of the audit trail: append records to a JSON lines file, continuing an existing chain.
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { GENESIS, chainHash, digestArgs, verifyChain, type AuditRecord } from './audit.ts';

export interface AuditFields { tool?: string; decision?: string; rules?: string[]; detail?: string; args?: unknown }

export class AuditLog {
  private prev = GENESIS;
  private seq = 0;
  readonly path: string;
  constructor(path: string) {
    this.path = path;
    if (existsSync(path)) {
      const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
      const report = verifyChain(lines);
      if (!report.ok) throw new Error(`audit log ${path} failed verification (${report.reason}); refusing to extend a broken chain`);
      this.prev = report.head; this.seq = report.entries;
    }
  }
  append(event: string, f: AuditFields = {}): AuditRecord {
    const body: Omit<AuditRecord, 'hash'> = {
      seq: this.seq, ts: new Date().toISOString(), event,
      ...(f.tool !== undefined ? { tool: f.tool } : {}), ...(f.decision !== undefined ? { decision: f.decision } : {}),
      ...(f.rules?.length ? { rules: f.rules } : {}), ...(f.detail !== undefined ? { detail: f.detail.slice(0, 200) } : {}),
      ...(f.args !== undefined ? { argsSha256: digestArgs(f.args) } : {}), prev: this.prev,
    };
    const rec: AuditRecord = { ...body, hash: chainHash(this.prev, body) };
    appendFileSync(this.path, JSON.stringify(rec) + '\n');
    this.prev = rec.hash; this.seq++;
    return rec;
  }
}
