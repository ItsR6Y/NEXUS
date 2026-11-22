import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { appliedVersions, openDatabase } from '../../src/main/core/db/database'
import { makeHarness, type Harness } from '../fixtures/harness'
import { TEST_PASSWORD } from '../fixtures/ssh-server'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

describe('node:sqlite persistence, retention, audit hash chain, and credential storage', () => {
  it('applies migrations idempotently, verifies audit chain, prunes old history, and keeps secrets out of raw DB bytes', async () => {
    h = await makeHarness()
    const dbFile = join(h.dir, 'nexus.db')
    const reopened = openDatabase(dbFile)
    expect(appliedVersions(reopened)).toEqual([1, 2])
    reopened.close()

    // Audit chain intact
    expect(h.svc.audit.verify().ok).toBe(true)

    // Store a canary password and verify it is NOT stored in plaintext in SQLite file
    const canary = 'super-unique-db-canary-987654321'
    h.svc.servers.setSecret(h.serverId, 'password', canary)
    const rawDb = readFileSync(dbFile)
    expect(rawDb.includes(Buffer.from(canary, 'utf8'))).toBe(false)

    // Fail closed when encryption becomes unavailable
    h.cipher.available = false
    expect(() => h!.svc.servers.setSecret(h!.serverId, 'password', 'another-secret')).toThrow(/unavailable/i)
    h.cipher.available = true
    // Restore the harness credential after the canary-at-rest assertion before SSH auth.
    h.svc.servers.setSecret(h.serverId, 'password', TEST_PASSWORD)
    const sid = await h.connect()

    // Retention pruning removes expired rows
    h.svc.executionRepo.create(
      {
        serverId: h.serverId,
        sessionId: sid,
        source: 'user',
        requester: 'user',
        commandSanitized: 'pwd',
        level: 'LOW',
        flags: [],
        status: 'completed',
        approvalId: null
      },
      h.clock.t - 40 * 86_400_000
    )
    const pruned = h.svc.exec.pruneRetention(30, h.clock.t)
    expect(pruned).toBe(1)
  })
})
