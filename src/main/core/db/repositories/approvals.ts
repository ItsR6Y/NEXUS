import { randomUUID } from 'node:crypto'
import type { Db } from '../database'
import type { ApprovalStatus, CommandSource } from '../../../../shared/types'
import type { RiskLevel } from '../../../../shared/policy-types'

export interface ApprovalRow {
  id: string
  bindingHash: string
  /** Redacted command text only — raw inline secrets are never persisted. */
  commandSanitized: string
  serverId: string
  sessionId: string
  epoch: number
  timeoutMs: number
  maxOutputBytes: number
  source: CommandSource
  requester: string
  level: RiskLevel
  reasons: string[]
  flags: string[]
  policyVersion: string
  status: ApprovalStatus
  createdAt: number
  expiresAt: number
  decidedAt: number | null
  consumedAt: number | null
  invalidationReason: string | null
}

interface RawApproval {
  id: string
  binding_hash: string
  command_sanitized: string
  server_id: string
  session_id: string
  epoch: number
  timeout_ms: number
  max_output_bytes: number
  source: CommandSource
  requester: string
  level: RiskLevel
  reasons: string
  flags: string
  policy_version: string
  status: ApprovalStatus
  created_at: number
  expires_at: number
  decided_at: number | null
  consumed_at: number | null
  invalidation_reason: string | null
}

const mapApproval = (r: RawApproval): ApprovalRow => ({
  id: r.id,
  bindingHash: r.binding_hash,
  commandSanitized: r.command_sanitized,
  serverId: r.server_id,
  sessionId: r.session_id,
  epoch: r.epoch,
  timeoutMs: r.timeout_ms,
  maxOutputBytes: r.max_output_bytes,
  source: r.source,
  requester: r.requester,
  level: r.level,
  reasons: JSON.parse(r.reasons) as string[],
  flags: JSON.parse(r.flags) as string[],
  policyVersion: r.policy_version,
  status: r.status,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  decidedAt: r.decided_at,
  consumedAt: r.consumed_at,
  invalidationReason: r.invalidation_reason
})

export type NewApproval = Omit<ApprovalRow, 'id' | 'status' | 'decidedAt' | 'consumedAt' | 'invalidationReason'>

export class ApprovalRepo {
  constructor(private db: Db) {}

  create(a: NewApproval): ApprovalRow {
    const id = randomUUID()
    this.db
      .prepare(
        `INSERT INTO approvals (id,binding_hash,command_sanitized,server_id,session_id,epoch,timeout_ms,max_output_bytes,source,requester,level,reasons,flags,policy_version,status,created_at,expires_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)`
      )
      .run(
        id,
        a.bindingHash,
        a.commandSanitized,
        a.serverId,
        a.sessionId,
        a.epoch,
        a.timeoutMs,
        a.maxOutputBytes,
        a.source,
        a.requester,
        a.level,
        JSON.stringify(a.reasons),
        JSON.stringify(a.flags),
        a.policyVersion,
        a.createdAt,
        a.expiresAt
      )
    const row = this.get(id)
    if (!row) throw new Error('failed to load created approval')
    return row
  }

  get(id: string): ApprovalRow | null {
    const r = this.db.prepare('SELECT * FROM approvals WHERE id=?').get(id) as RawApproval | undefined
    return r ? mapApproval(r) : null
  }

  list(limit = 200): ApprovalRow[] {
    return (this.db.prepare('SELECT * FROM approvals ORDER BY created_at DESC, rowid DESC LIMIT ?').all(limit) as RawApproval[]).map(mapApproval)
  }

  decide(id: string, status: 'approved' | 'rejected' | 'cancelled', now: number): boolean {
    return this.db.prepare("UPDATE approvals SET status=?, decided_at=? WHERE id=? AND status='pending' AND expires_at>?").run(status, now, id, now).changes === 1
  }

  /** Atomic single-use consumption: exactly one caller can succeed. */
  consume(id: string, now: number): boolean {
    return (
      this.db
        .prepare("UPDATE approvals SET status='consumed', consumed_at=? WHERE id=? AND status='approved' AND consumed_at IS NULL AND expires_at>?")
        .run(now, id, now).changes === 1
    )
  }

  markExpired(now: number): number {
    return this.db.prepare("UPDATE approvals SET status='expired' WHERE status IN ('pending','approved') AND expires_at<=?").run(now).changes
  }

  invalidate(id: string, reason: string): boolean {
    return this.db.prepare("UPDATE approvals SET status='invalidated', invalidation_reason=? WHERE id=? AND status IN ('pending','approved')").run(reason, id).changes === 1
  }

  invalidateBySession(sessionId: string, reason: string): number {
    return this.db.prepare("UPDATE approvals SET status='invalidated', invalidation_reason=? WHERE session_id=? AND status IN ('pending','approved')").run(reason, sessionId).changes
  }

  invalidateByServer(serverId: string, reason: string): number {
    return this.db.prepare("UPDATE approvals SET status='invalidated', invalidation_reason=? WHERE server_id=? AND status IN ('pending','approved')").run(reason, serverId).changes
  }

  invalidateAllActive(reason: string): number {
    return this.db.prepare("UPDATE approvals SET status='invalidated', invalidation_reason=? WHERE status IN ('pending','approved')").run(reason).changes
  }

  /** Delete decided approvals older than the history retention cutoff. Pending approvals are never pruned. */
  pruneDecidedBefore(cutoff: number): number {
    return this.db.prepare("DELETE FROM approvals WHERE status<>'pending' AND created_at < ?").run(cutoff).changes
  }

  invalidateOtherPolicyVersions(current: string): number {
    return this.db
      .prepare("UPDATE approvals SET status='invalidated', invalidation_reason='policy version changed' WHERE status IN ('pending','approved') AND policy_version<>?")
      .run(current).changes
  }
}
