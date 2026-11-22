import { afterEach, describe, expect, it } from 'vitest'
import { appliedVersions, openDatabase, type Db } from '../../src/main/core/db/database'
import { KeyringCredentialStore } from '../../src/main/core/credentials/credential-store'
import { makeHarness, type Harness } from '../fixtures/harness'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

class LockedEntry {
  static calls = 0
  constructor(_service: string, _account: string) { LockedEntry.calls++ }
  setPassword(): void { throw new Error('keyring locked') }
  getPassword(): string | null { throw new Error('keyring locked') }
  deletePassword(): boolean { return false }
}

class HealthyEntry {
  constructor(_service: string, _account: string) {}
  setPassword(): void {}
  getPassword(): string | null { return null }
  deletePassword(): boolean { return true }
}

describe('credential and persistence hardening', () => {
  it('reports an unusable keyring as unavailable instead of a constant true', () => {
    const locked = new KeyringCredentialStore(LockedEntry as never, () => 1_000)
    expect(locked.available()).toBe(false)

    const healthy = new KeyringCredentialStore(HealthyEntry as never, () => 1_000)
    expect(healthy.available()).toBe(true)
  })

  it('adds indexes for hot-path queries in a version 2 migration', () => {
    const db: Db = openDatabase(':memory:')
    try {
      expect(appliedVersions(db)).toEqual([1, 2])
      const plan = (sql: string): string =>
        (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as { detail: string }[])
          .map((r) => r.detail)
          .join(' | ')
      expect(plan("SELECT id FROM executions WHERE status='running'")).toContain('idx_executions_status')
      expect(plan("SELECT id FROM approvals WHERE session_id='s' AND status='pending'")).toContain('idx_approvals_session')
      expect(plan("SELECT id FROM approvals WHERE server_id='s' AND status='pending'")).toContain('idx_approvals_server')
      expect(plan('SELECT COUNT(*) FROM security_events WHERE ts>=1')).toContain('idx_security_events_ts')
      expect(plan('SELECT id FROM audit_log WHERE ts>=1')).toContain('idx_audit_log_ts')
    } finally {
      db.close()
    }
  })

  it('keeps the live execution store bounded when commands run concurrently', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()
    const results = await Promise.all(
      Array.from({ length: 60 }, () =>
        h!.svc.exec.execute({ serverId: h!.serverId, sessionId: sid, command: 'pwd' }, 'user')
      )
    )
    const failed = results.filter((r) => r.status !== 'completed')
    expect(failed, JSON.stringify(failed.slice(0, 2))).toEqual([])
    const stores = (h.svc.exec as unknown as { stores: Map<string, unknown> }).stores
    expect(stores.size).toBeLessThanOrEqual(50)
  }, 60_000)
})
