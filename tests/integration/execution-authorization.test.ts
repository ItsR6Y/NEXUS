import { afterEach, describe, expect, it } from 'vitest'
import { DEFAULT_LIMITS } from '../../src/main/core/mcp-bridge/bridge-server'
import { buildHandlers, type IpcDeps } from '../../src/main/ipc/registry'
import { DEFAULT_SETTINGS, SettingsSchema, type Channel } from '../../src/shared/ipc'
import { POLICY_VERSION, type ApprovalPolicy, type PolicyDecision, type RiskLevel } from '../../src/shared/policy-types'
import type { ExecutionDTO, OutputPage } from '../../src/shared/types'
import { makeHarness, type Harness } from '../fixtures/harness'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

const decision = (level: RiskLevel, requiresApproval = false): PolicyDecision => ({
  level,
  reasons: [],
  flags: [],
  requiresApproval,
  parseConfidence: 1,
  policyVersion: POLICY_VERSION
})

const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

describe('execution, authorization, and MCP timing', () => {
  it('an already-aborted AbortSignal never reaches SSH', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()

    const res = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'pwd' }, 'user', AbortSignal.abort())

    expect(res.status).toBe('cancelled')
    expect(h.ssh.commands).toEqual([])
    expect(h.svc.exec.get(res.commandId)?.status).toBe('cancelled')
  })

  it('a client-generated command id can cancel while the approval dialog is still open', async () => {
    h = await makeHarness({ approvalPolicy: 'always' })
    const sid = await h.connect()
    h.approvals.handler = async () => { await wait(300); return 'approve' }

    const id = 'client-cmd-pending-approval'
    const pending = h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'pwd', clientCommandId: id }, 'user')
    await wait(50)
    expect(h.svc.exec.cancel(id)).toBe(true)

    const res = await pending
    expect(res.status).toBe('cancelled')
    expect(res.commandId).toBe(id)
    expect(h.ssh.commands).toEqual([])
  })

  it('a running command is cancellable by its client-generated command id', async () => {
    h = await makeHarness({ approvalPolicy: 'always' })
    const sid = await h.connect()
    h.approvals.handler = async () => 'approve'

    const id = 'client-cmd-running'
    const running = h.svc.exec.execute({
      serverId: h.serverId,
      sessionId: sid,
      command: 'sleep 5',
      timeoutMs: 10_000,
      clientCommandId: id
    }, 'user')
    await wait(300)
    expect(h.svc.exec.cancel(id)).toBe(true)

    const res = await running
    expect(res.status).toBe('cancelled')
    expect(res.commandId).toBe(id)
    expect(h.svc.exec.get(id)?.status).toBe('cancelled')
  })

  it('approval TTL is capped below the MCP bridge idle timeout', async () => {
    const capped = 480
    expect(capped * 1000).toBeLessThan(DEFAULT_LIMITS.idleMs)
    expect(DEFAULT_SETTINGS.approvalTtlSeconds * 1000).toBeLessThan(DEFAULT_LIMITS.idleMs)
    expect(SettingsSchema.safeParse({ ...DEFAULT_SETTINGS, approvalTtlSeconds: 900 }).success).toBe(false)
    expect(SettingsSchema.safeParse({ ...DEFAULT_SETTINGS, approvalTtlSeconds: DEFAULT_LIMITS.idleMs / 1000 }).success).toBe(false)
    expect(SettingsSchema.safeParse({ ...DEFAULT_SETTINGS, approvalTtlSeconds: capped }).success).toBe(true)

    h = await makeHarness({ approvalPolicy: 'always', settings: { approvalTtlSeconds: capped } })
    const sid = await h.connect()
    h.approvals.handler = async () => 'deny'

    await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'pwd' }, 'user')
    const row = h.svc.approvalRepo.list()[0]
    expect(row.expiresAt - row.createdAt).toBe(capped * 1000)
    expect(row.expiresAt - row.createdAt).toBeLessThan(DEFAULT_LIMITS.idleMs)
  })

  it('executions:list carries metadata only while executions:output still pages the text', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()
    h.approvals.handler = async () => 'approve'

    const res = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'echo wave3-output' }, 'user')
    expect(res.status).toBe('completed')

    const deps: IpcDeps = {
      services: h.svc,
      trustedOrigin: 'nexus-app://app',
      send: () => undefined,
      pickKeyPath: async () => null,
      openLogsFolder: async () => undefined,
      confirmClearHistory: async () => false,
      appInfo: { version: '1.0.0', platform: 'linux' }
    }
    const handlers = buildHandlers(deps)
    type Call = (payload: unknown) => Promise<unknown>
    const call = (ch: Channel, payload: unknown): Promise<unknown> => (handlers[ch] as unknown as Call)(payload)

    const rows = (await call('executions:list', {})) as ExecutionDTO[]
    const row = rows.find((r) => r.id === res.commandId)
    expect(row).toBeDefined()
    expect(row).not.toHaveProperty('output')
    expect(row?.outputBytes).toBeGreaterThan(0)

    const page = (await call('executions:output', { id: res.commandId, afterSeq: 0, maxBytes: 262_144 })) as OutputPage
    expect(page.text).toContain('wave3-output')
  })

  it('retention prunes decided approvals while pending ones survive', async () => {
    h = await makeHarness({ approvalPolicy: 'ask' })
    const sid = await h.connect()
    const repo = h.svc.approvalRepo
    const old = h.clock.t - 40 * 86_400_000

    const mk = (createdAt: number, expiresAt: number): string =>
      repo.create({
        bindingHash: `hash-${createdAt}-${Math.random()}`,
        commandSanitized: 'pwd',
        serverId: h!.serverId,
        sessionId: sid,
        epoch: 1,
        timeoutMs: 30_000,
        maxOutputBytes: 262_144,
        source: 'user',
        requester: 'user',
        level: 'LOW',
        reasons: [],
        flags: [],
        policyVersion: POLICY_VERSION,
        createdAt,
        expiresAt
      }).id

    const oldDecided = mk(old, old + 960_000)
    repo.decide(oldDecided, 'approved', old + 1_000)
    const oldPending = mk(old, h.clock.t + 960_000)
    const recentDecided = mk(h.clock.t, h.clock.t + 960_000)
    repo.decide(recentDecided, 'rejected', h.clock.t + 1_000)

    const pruned = h.svc.pruneRetention(h.clock.t)
    expect(pruned.approvals).toBe(1)
    expect(repo.get(oldDecided)).toBeNull()
    expect(repo.get(oldPending)).not.toBeNull()
    expect(repo.get(recentDecided)).not.toBeNull()
  })

  it('the (policy × source × level) approval truth table is explicit and parameterized', async () => {
    h = await makeHarness({ approvalPolicy: 'ask' })
    const cases: {
      policy: ApprovalPolicy
      source: 'user' | 'claude'
      level: RiskLevel
      requires?: boolean
      autoLow?: boolean
      expected: boolean
    }[] = [
      { policy: 'sensitive', source: 'user', level: 'LOW', expected: false },
      { policy: 'sensitive', source: 'user', level: 'MEDIUM', expected: false },
      { policy: 'sensitive', source: 'user', level: 'HIGH', expected: true },
      { policy: 'sensitive', source: 'user', level: 'CRITICAL', expected: true },
      { policy: 'sensitive', source: 'user', level: 'DESTRUCTIVE', expected: true },
      { policy: 'sensitive', source: 'user', level: 'LOW', requires: true, expected: true },
      { policy: 'ask', source: 'user', level: 'LOW', expected: false },
      { policy: 'ask', source: 'user', level: 'MEDIUM', expected: true },
      { policy: 'always', source: 'user', level: 'LOW', expected: true },
      { policy: 'sensitive', source: 'claude', level: 'LOW', autoLow: false, expected: true },
      { policy: 'sensitive', source: 'claude', level: 'LOW', autoLow: true, expected: false },
      { policy: 'sensitive', source: 'claude', level: 'MEDIUM', autoLow: true, expected: true },
      { policy: 'ask', source: 'claude', level: 'LOW', autoLow: true, expected: true },
      { policy: 'always', source: 'claude', level: 'LOW', autoLow: true, expected: true }
    ]

    for (const c of cases) {
      h.svc.settingsRepo.patch({ mcpAutoRunLow: !!c.autoLow })
      expect(
        h.svc.authz.needsApproval(decision(c.level, c.requires), c.policy, c.source),
        `${c.policy}/${c.source}/${c.level} requires=${!!c.requires} autoLow=${!!c.autoLow}`
      ).toBe(c.expected)
    }
  })
})
