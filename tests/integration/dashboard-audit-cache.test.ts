import { afterEach, describe, expect, it } from 'vitest'
import { buildHandlers, type IpcEventLike } from '../../src/main/ipc/registry'
import { APP_ORIGIN } from '../../src/main/protocol'
import type { DashboardDTO } from '../../src/shared/types'
import { makeHarness, type Harness } from '../fixtures/harness'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

const rendererEvent = (): IpcEventLike => ({
  sender: { id: 1 },
  senderFrame: { url: `${APP_ORIGIN}/index.html`, parent: null }
})

describe('audit-chain caching', () => {
  it('dashboard:get never re-scans the whole audit_log table', async () => {
    h = await makeHarness()
    for (let i = 0; i < 5; i++) h.svc.audit.log('test.entry', 'system', { i })

    const db = h.svc.o.db
    const prepare = db.prepare.bind(db)
    const prepared: string[] = []
    db.prepare = (sql: string) => {
      prepared.push(sql)
      return prepare(sql)
    }

    const handlers = buildHandlers({
      services: h.svc,
      trustedOrigin: APP_ORIGIN,
      send: () => {},
      pickKeyPath: async () => null,
      openLogsFolder: async () => {},
      confirmClearHistory: async () => true,
      appInfo: { version: 'test', platform: 'linux' }
    })
    const dto = (await handlers['dashboard:get'](undefined as never, rendererEvent())) as DashboardDTO

    const auditSql = prepared.filter((q) => /from audit_log/i.test(q))
    // The full chain walk is forbidden here; only an incremental `id > last` range scan is allowed.
    const fullScans = auditSql.filter((q) => /order by id asc/i.test(q) && !/where id >/i.test(q))
    expect(fullScans).toEqual([])
    expect(dto.auditChain.ok).toBe(true)
    expect(dto.auditChain.entries).toBeGreaterThanOrEqual(5)
  })

  it('extends the cached result over appended rows instead of re-verifying everything', async () => {
    h = await makeHarness()
    const before = h.svc.audit.lastVerify().entries
    h.svc.audit.log('test.entry', 'system', { a: 1 })
    h.svc.audit.log('test.entry', 'system', { a: 2 })
    expect(h.svc.audit.lastVerify().entries).toBe(before + 2)
  })

  it('reports in-place tampering only through the explicit full verify', async () => {
    h = await makeHarness()
    expect(h.svc.audit.lastVerify().ok).toBe(true)

    // The append-only trigger normally blocks this; drop it to exercise the cache's documented limit.
    expect(() => h!.svc.o.db.prepare("UPDATE audit_log SET data='{}' WHERE id=1").run()).toThrow(/append-only/)
    h.svc.o.db.exec('DROP TRIGGER audit_log_no_update')
    h.svc.o.db.prepare("UPDATE audit_log SET data='{}' WHERE id=1").run()

    // Cached/incremental verification covers appended rows only — its limits are explicit.
    expect(h.svc.audit.lastVerify().ok).toBe(true)

    const full = h.svc.audit.verify()
    expect(full.ok).toBe(false)
    expect(full.brokenAt).toBe(1)
    // A broken result is sticky until the next explicit verify.
    expect(h.svc.audit.lastVerify().ok).toBe(false)
  })
})
