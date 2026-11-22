import { randomUUID } from 'node:crypto'
import type { SQLInputValue } from 'node:sqlite'
import type { Db } from '../database'
import type { CommandSource, ExecutionFilter, ExecutionStatus, SessionState } from '../../../../shared/types'
import type { RiskLevel } from '../../../../shared/policy-types'

export interface SessionRow {
  id: string
  serverId: string
  title: string
  epoch: number
  state: SessionState
  openedAt: number
  closedAt: number | null
  error: string | null
}

interface RawSession {
  id: string
  server_id: string
  title: string
  connection_epoch: number
  state: SessionState
  opened_at: number
  closed_at: number | null
  error: string | null
}

const mapSession = (r: RawSession): SessionRow => ({
  id: r.id,
  serverId: r.server_id,
  title: r.title,
  epoch: r.connection_epoch,
  state: r.state,
  openedAt: r.opened_at,
  closedAt: r.closed_at,
  error: r.error
})

export class SessionRepo {
  constructor(private db: Db) {}

  create(serverId: string, title: string, now = Date.now()): SessionRow {
    const id = randomUUID()
    this.db
      .prepare("INSERT INTO sessions (id,server_id,title,connection_epoch,state,opened_at) VALUES (?,?,?,0,'connecting',?)")
      .run(id, serverId, title, now)
    const row = this.get(id)
    if (!row) throw new Error('failed to load created session')
    return row
  }

  get(id: string): SessionRow | null {
    const r = this.db.prepare('SELECT * FROM sessions WHERE id=?').get(id) as RawSession | undefined
    return r ? mapSession(r) : null
  }

  list(serverId?: string): SessionRow[] {
    const rows = serverId
      ? this.db.prepare('SELECT * FROM sessions WHERE server_id=? ORDER BY opened_at DESC').all(serverId)
      : this.db.prepare('SELECT * FROM sessions ORDER BY opened_at DESC LIMIT 500').all()
    return (rows as RawSession[]).map(mapSession)
  }

  setState(id: string, state: SessionState, error: string | null = null, now = Date.now()): void {
    const closed = state === 'disconnected' || state === 'error' ? now : null
    this.db.prepare('UPDATE sessions SET state=?, error=?, closed_at=? WHERE id=?').run(state, error, closed, id)
  }

  /** Remove a session row outright (used for attempts that never established a connection). */
  remove(id: string): boolean {
    return this.db.prepare('DELETE FROM sessions WHERE id=?').run(id).changes > 0
  }

  /** Per-server high-water mark for titles, so a deleted/failed attempt never reuses a visible `#n`. */
  nextSequence(serverId: string): number {
    const rows = this.db.prepare('SELECT title FROM sessions WHERE server_id=?').all(serverId) as { title: string }[]
    let max = 0
    for (const r of rows) {
      const m = /#(\d+)\s*$/.exec(r.title)
      if (m) max = Math.max(max, Number(m[1]))
    }
    return max + 1
  }

  bumpEpoch(id: string): number {
    this.db.prepare('UPDATE sessions SET connection_epoch = connection_epoch + 1 WHERE id=?').run(id)
    const row = this.get(id)
    if (!row) throw new Error('session vanished')
    return row.epoch
  }

  markAllDisconnected(now = Date.now()): number {
    return this.db.prepare("UPDATE sessions SET state='disconnected', closed_at=? WHERE state IN ('connecting','connected')").run(now).changes
  }
}

export interface ExecutionRow {
  id: string
  serverId: string
  sessionId: string
  source: CommandSource
  requester: string
  commandSanitized: string
  level: RiskLevel
  flags: string[]
  status: ExecutionStatus
  exitCode: number | null
  signal: string | null
  startedAt: number
  finishedAt: number | null
  truncated: boolean
  /** Present for `get()`; list() omits the blob and reports size only. */
  output: string
  outputBytes: number
  denialReason: string | null
  approvalId: string | null
}

interface RawExec {
  id: string
  server_id: string
  session_id: string
  source: CommandSource
  requester: string
  command_sanitized: string
  level: RiskLevel
  flags: string
  status: ExecutionStatus
  exit_code: number | null
  signal: string | null
  started_at: number
  finished_at: number | null
  truncated: number
  output?: string
  output_bytes?: number | null
  denial_reason: string | null
  approval_id: string | null
}

const mapExec = (r: RawExec): ExecutionRow => ({
  id: r.id,
  serverId: r.server_id,
  sessionId: r.session_id,
  source: r.source,
  requester: r.requester,
  commandSanitized: r.command_sanitized,
  level: r.level,
  flags: JSON.parse(r.flags) as string[],
  status: r.status,
  exitCode: r.exit_code,
  signal: r.signal,
  startedAt: r.started_at,
  finishedAt: r.finished_at,
  truncated: r.truncated === 1,
  output: r.output ?? '',
  outputBytes: r.output_bytes ?? Buffer.byteLength(r.output ?? '', 'utf8'),
  denialReason: r.denial_reason,
  approvalId: r.approval_id
})

export class ExecutionRepo {
  constructor(private db: Db) {}

  create(
    e: {
      id?: string
      serverId: string
      sessionId: string
      source: CommandSource
      requester: string
      commandSanitized: string
      level: RiskLevel
      flags: string[]
      status?: ExecutionStatus
      denialReason?: string | null
      approvalId: string | null
    },
    now = Date.now()
  ): ExecutionRow {
    const id = e.id ?? randomUUID()
    const status = e.status ?? 'running'
    const finishedAt = status === 'denied' ? now : null
    this.db
      .prepare(
        'INSERT INTO executions (id,server_id,session_id,source,requester,command_sanitized,level,flags,status,started_at,finished_at,denial_reason,approval_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
      )
      .run(
        id,
        e.serverId,
        e.sessionId,
        e.source,
        e.requester,
        e.commandSanitized,
        e.level,
        JSON.stringify(e.flags),
        status,
        now,
        finishedAt,
        e.denialReason ?? null,
        e.approvalId
      )
    const row = this.get(id)
    if (!row) throw new Error('failed to load created execution')
    return row
  }

  finish(
    id: string,
    f: { status: ExecutionStatus; exitCode: number | null; signal: string | null; truncated: boolean; output: string; denialReason?: string | null },
    now = Date.now()
  ): void {
    this.db
      .prepare('UPDATE executions SET status=?, exit_code=?, signal=?, truncated=?, output=?, denial_reason=?, finished_at=? WHERE id=?')
      .run(f.status, f.exitCode, f.signal, f.truncated ? 1 : 0, f.output, f.denialReason ?? null, now, id)
  }

  get(id: string): ExecutionRow | null {
    const r = this.db.prepare('SELECT *, LENGTH(CAST(output AS BLOB)) AS output_bytes FROM executions WHERE id=?').get(id) as RawExec | undefined
    return r ? mapExec(r) : null
  }

  list(f: ExecutionFilter = {}): ExecutionRow[] {
    const where: string[] = []
    const args: SQLInputValue[] = []
    for (const [col, v] of [
      ['server_id', f.serverId],
      ['session_id', f.sessionId],
      ['source', f.source],
      ['level', f.level],
      ['status', f.status]
    ] as const) {
      if (v !== undefined) {
        where.push(`${col}=?`)
        args.push(v)
      }
    }
    // Never ship the (up to 4 MB) output blob in a list payload: only its byte size.
    const sql = `SELECT id,server_id,session_id,source,requester,command_sanitized,level,flags,status,exit_code,signal,started_at,finished_at,truncated,denial_reason,approval_id,LENGTH(CAST(output AS BLOB)) AS output_bytes FROM executions ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY started_at DESC, rowid DESC LIMIT ? OFFSET ?`
    return (this.db.prepare(sql).all(...args, f.limit ?? 100, f.offset ?? 0) as RawExec[]).map(mapExec)
  }

  pruneOlderThan(cutoffMs: number): number {
    return this.db.prepare('DELETE FROM executions WHERE started_at < ?').run(cutoffMs).changes
  }

  clearAll(): number {
    return this.db.prepare('DELETE FROM executions').run().changes
  }

  failRunning(now = Date.now()): number {
    return this.db
      .prepare("UPDATE executions SET status='failed', finished_at=?, output=output||char(10)||'[interrupted: application restarted]' WHERE status='running'")
      .run(now).changes
  }
}
