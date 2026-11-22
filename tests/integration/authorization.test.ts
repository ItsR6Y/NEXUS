import { afterEach, describe, expect, it } from 'vitest'
import { POLICY_VERSION } from '../../src/shared/policy-types'
import { bindingHash } from '../../src/main/core/security/authorization'
import { makeHarness, type Harness } from '../fixtures/harness'
import { TEST_USER } from '../fixtures/ssh-server'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

describe('CommandAuthorizer & approval lifecycle', () => {
  it('defaults mcpAutoRunLow to false and requires native approval for MCP even on LOW commands', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    expect(h.svc.settings().mcpAutoRunLow).toBe(false)
    const sid = await h.connect()

    h.approvals.handler = async () => 'deny'
    const denied = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'pwd' }, 'claude')
    expect(denied.status).toBe('denied')
    expect(h.approvals.calls.length).toBe(1)
    expect(h.ssh.commands).toEqual([]) // ZERO remote SSH exec calls on deny!
  })

  it('enforces per-server approval policy (always vs ask vs sensitive) and never stores raw inline secrets in approvals DB', async () => {
    h = await makeHarness({ approvalPolicy: 'always' })
    const sid = await h.connect()

    h.approvals.handler = async () => 'approve'
    const cmdWithSecret = 'echo --password=inline-secret-canary-42'
    const res = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: cmdWithSecret }, 'user')
    expect(res.status).toBe('completed')

    // Verify SQLite approvals table NEVER stored raw secret
    const allApprovals = h.svc.approvalRepo.list()
    expect(allApprovals.length).toBe(1)
    expect(allApprovals[0].status).toBe('consumed')
    expect(allApprovals[0].commandSanitized).not.toContain('inline-secret-canary-42')
    expect(h.approvals.calls[0].commandRedacted).not.toContain('inline-secret-canary-42')
  })

  it('rejects replayed, expired, binding-mismatched, and stale-epoch approvals', async () => {
    h = await makeHarness({ approvalPolicy: 'ask' })
    const sid = await h.connect()
    const ctx = h.svc.sessions.resolveExecutionContext(h.serverId, sid)!

    const baseArgs = {
      command: 'echo hello',
      serverId: h.serverId,
      sessionId: sid,
      epoch: ctx.epoch,
      timeoutMs: 30_000,
      maxOutputBytes: 262_144,
      source: 'claude' as const,
      requester: 'mcp:test',
      policyVersion: POLICY_VERSION
    }
    const row = h.svc.approvalRepo.create({
      bindingHash: bindingHash(baseArgs),
      commandSanitized: 'echo hello',
      serverId: h.serverId,
      sessionId: sid,
      epoch: ctx.epoch,
      timeoutMs: 30_000,
      maxOutputBytes: 262_144,
      source: 'claude',
      requester: 'mcp:test',
      level: 'MEDIUM',
      reasons: ['test'],
      flags: [],
      policyVersion: POLICY_VERSION,
      createdAt: h.clock.t,
      expiresAt: h.clock.t + 60_000
    })
    h.svc.approvalRepo.decide(row.id, 'approved', h.clock.t)

    // Mismatched command fails
    const badBind = h.svc.authz.consumeApproved(row.id, { ...baseArgs, command: 'echo tampered' })
    expect(badBind.ok).toBe(false)
    if (!badBind.ok) expect(badBind.code).toBe('approval_binding_mismatch')

    // Valid consumption succeeds once
    const first = h.svc.authz.consumeApproved(row.id, baseArgs)
    expect(first.ok).toBe(true)

    // Replay of consumed approval fails
    const replay = h.svc.authz.consumeApproved(row.id, baseArgs)
    expect(replay.ok).toBe(false)
    if (!replay.ok) expect(replay.code).toBe('approval_consumed')

    // Expired approval fails
    const row2 = h.svc.approvalRepo.create({
      bindingHash: bindingHash(baseArgs),
      commandSanitized: 'echo hello',
      serverId: h.serverId,
      sessionId: sid,
      epoch: ctx.epoch,
      timeoutMs: 30_000,
      maxOutputBytes: 262_144,
      source: 'claude',
      requester: 'mcp:test',
      level: 'MEDIUM',
      reasons: ['test'],
      flags: [],
      policyVersion: POLICY_VERSION,
      createdAt: h.clock.t,
      expiresAt: h.clock.t + 10_000
    })
    h.svc.approvalRepo.decide(row2.id, 'approved', h.clock.t)
    h.clock.t += 20_000
    const exp = h.svc.authz.consumeApproved(row2.id, baseArgs)
    expect(exp.ok).toBe(false)
    if (!exp.ok) expect(exp.code).toBe('approval_expired')
  })

  it('does not execute denied or timed-out approval requests and binds approval to command, server, and session', async () => {
    h = await makeHarness({ approvalPolicy: 'always' })
    const sid = await h.connect()
    h.approvals.handler = async () => 'deny'

    const denied = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'echo denied' }, 'user')
    expect(denied.status).toBe('denied')
    expect(h.ssh.commands).toEqual([])

    h.approvals.handler = async () => {
      h!.clock.t += 20_000
      return new Promise<'approve' | 'deny'>(() => undefined)
    }
    h.svc.settingsRepo.patch({ approvalTtlSeconds: 15 })
    const timedOut = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'echo timeout' }, 'user')
    expect(timedOut.status).toBe('denied')
    expect(h.ssh.commands).toEqual([])
    expect(h.svc.approvalRepo.list().some((a) => a.commandSanitized === 'echo timeout' && a.status === 'expired')).toBe(true)

    h.clock.t += 20_000
    const ctx = h.svc.sessions.resolveExecutionContext(h.serverId, sid)
    expect(ctx).not.toBeNull()
    if (!ctx) throw new Error('expected connected test session')
    const input = {
      command: 'echo bound', serverId: h.serverId, sessionId: sid, epoch: ctx.epoch,
      timeoutMs: 30_000, maxOutputBytes: 262_144, source: 'user' as const,
      requester: 'user', policyVersion: POLICY_VERSION
    }
    const row = h.svc.approvalRepo.create({
      bindingHash: bindingHash(input), commandSanitized: input.command,
      serverId: input.serverId, sessionId: input.sessionId, epoch: input.epoch,
      timeoutMs: input.timeoutMs, maxOutputBytes: input.maxOutputBytes,
      source: input.source, requester: input.requester, level: 'MEDIUM', reasons: ['test'], flags: [],
      policyVersion: input.policyVersion, createdAt: h.clock.t, expiresAt: h.clock.t + 60_000
    })
    h.svc.approvalRepo.decide(row.id, 'approved', h.clock.t)
    const otherServer = h.svc.servers.create({
      name: 'other-server', host: '127.0.0.1', port: h.ssh.port, username: TEST_USER,
      authType: 'password', approvalPolicy: 'always', mcpAccessEnabled: true
    })
    h.svc.servers.setSecret(otherServer.id, 'password', 'test-only-password-canary-99')
    const otherSession = await h.svc.sessions.open(otherServer.id)
    expect(otherSession.status).toBe('connected')
    if (otherSession.status !== 'connected') throw new Error('expected second test session')
    const wrongServer = h.svc.authz.consumeApproved(row.id, { ...input, serverId: otherServer.id })
    expect(wrongServer.ok).toBe(false)
    const wrongSession = h.svc.authz.consumeApproved(row.id, { ...input, sessionId: otherSession.session.id })
    expect(wrongSession.ok).toBe(false)
    const wrongCommand = h.svc.authz.consumeApproved(row.id, { ...input, command: 'echo changed' })
    expect(wrongCommand.ok).toBe(false)
    expect(h.ssh.commands).toEqual([])
  }, 25_000)

  it('forbids bypassing CommandAuthorizer with a forged AuthorizedExecution object', async () => {
    h = await makeHarness()
    const sid = await h.connect()
    const fakeAuth = {
      serverId: h.serverId,
      sessionId: sid,
      epoch: 1,
      command: 'whoami',
      commandSanitized: 'whoami',
      timeoutMs: 5000,
      maxOutputBytes: 4096,
      source: 'claude',
      requester: 'mcp:forged',
      level: 'LOW',
      flags: [],
      approvalId: null
    } as never
    expect(() => h!.svc.exec.runAuthorized(fakeAuth)).toThrow(/AuthorizedExecution/)
  })
})
