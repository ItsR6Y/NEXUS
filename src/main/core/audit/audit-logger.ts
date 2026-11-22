import { createHash } from 'node:crypto'
import { EventEmitter } from 'node:events'
import type { Db } from '../db/database'
import type { AuditDTO, AuditVerifyResult, SecurityEventDTO } from '../../../shared/types'
import { redactValue } from '../security/redaction'

export const GENESIS = '0'.repeat(64)
const canon = (o: unknown): string => JSON.stringify(o)

export function entryHash(prev: string, ts: number, kind: string, actor: string, data: string): string {
  return createHash('sha256').update(canon([prev, ts, kind, actor, data])).digest('hex')
}

/** Append-only, hash-chained audit log plus a separate security-event table. Data is redacted before storage. */
interface AuditRow {
  id: number; ts: number; kind: string; actor: string; data: string; prev_hash: string; hash: string
}

export class AuditLogger extends EventEmitter {
  private cachedVerify: AuditVerifyResult = { ok: true, entries: 0, brokenAt: null }
  private cachedThroughId = 0
  private cachedPrevHash = GENESIS

  constructor(
    private db: Db,
    private secrets: () => Iterable<string> = () => [],
    private now: () => number = Date.now
  ) {
    super()
  }

  log(kind: string, actor: string, data: Record<string, unknown> = {}): AuditDTO {
    const clean = redactValue(data, this.secrets())
    const ts = this.now()
    const json = canon(clean)
    const row = this.db.transaction(() => {
      const last = this.db.prepare('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1').get() as { hash: string } | undefined
      const prev = last?.hash ?? GENESIS
      const hash = entryHash(prev, ts, kind, actor, json)
      const r = this.db.prepare('INSERT INTO audit_log (ts,kind,actor,data,prev_hash,hash) VALUES (?,?,?,?,?,?)').run(ts, kind, actor, json, prev, hash)
      return { id: r.lastInsertRowid, hash }
    })()
    return { id: row.id, ts, kind, actor, data: clean, hash: row.hash }
  }

  securityEvent(type: string, severity: 'info' | 'warning' | 'critical', details: Record<string, unknown> = {}, serverId: string | null = null): void {
    const clean = redactValue(details, this.secrets())
    this.db.prepare('INSERT INTO security_events (ts,type,severity,server_id,details) VALUES (?,?,?,?,?)').run(this.now(), type, severity, serverId, canon(clean))
    this.log(`security:${type}`, 'system', { severity, serverId, ...clean })
    this.emit('security')
  }

  list(limit = 100): AuditDTO[] {
    const rows = this.db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit) as {
      id: number; ts: number; kind: string; actor: string; data: string; hash: string
    }[]
    return rows.map((r) => ({ id: r.id, ts: r.ts, kind: r.kind, actor: r.actor, data: JSON.parse(r.data) as Record<string, unknown>, hash: r.hash }))
  }

  listSecurityEvents(limit = 200): SecurityEventDTO[] {
    const rows = this.db.prepare('SELECT * FROM security_events ORDER BY id DESC LIMIT ?').all(limit) as {
      id: number; ts: number; type: string; severity: SecurityEventDTO['severity']; server_id: string | null; details: string
    }[]
    return rows.map((r) => ({ id: r.id, ts: r.ts, type: r.type, severity: r.severity, serverId: r.server_id, details: JSON.parse(r.details) as Record<string, unknown> }))
  }

  countSecurityEventsSince(ts: number): number {
    return (this.db.prepare("SELECT COUNT(*) c FROM security_events WHERE ts>=? AND severity<>'info'").get(ts) as { c: number }).c
  }

  /** Full O(n) chain verification. Seeds the cache used by `lastVerify()`; run on startup and on demand. */
  verify(): AuditVerifyResult {
    return this.scan(null)
  }

  /**
   * Hot-path integrity result: returns the cached chain result, extending it only over rows
   * appended since the last verification. This keeps `dashboard:get` off a full table walk.
   * LIMIT: tampering with an already-verified row is detected only by an explicit `verify()`.
   */
  lastVerify(): AuditVerifyResult {
    if (!this.cachedVerify.ok) return this.cachedVerify
    return this.scan(this.cachedThroughId)
  }

  private scan(afterId: number | null): AuditVerifyResult {
    let prev = afterId === null ? GENESIS : this.cachedPrevHash
    let n = afterId === null ? 0 : this.cachedVerify.entries
    let lastId = afterId ?? 0
    const stmt = this.db.prepare(
      afterId === null
        ? 'SELECT * FROM audit_log ORDER BY id ASC'
        : 'SELECT * FROM audit_log WHERE id > ? ORDER BY id ASC'
    )
    const it = (afterId === null ? stmt.iterate() : stmt.iterate(afterId)) as IterableIterator<AuditRow>
    for (const r of it) {
      n++
      if (r.prev_hash !== prev || entryHash(prev, r.ts, r.kind, r.actor, r.data) !== r.hash) {
        this.cachedVerify = { ok: false, entries: n, brokenAt: r.id }
        return this.cachedVerify
      }
      prev = r.hash
      lastId = r.id
    }
    this.cachedVerify = { ok: true, entries: n, brokenAt: null }
    this.cachedThroughId = lastId
    this.cachedPrevHash = prev
    return this.cachedVerify
  }
}
