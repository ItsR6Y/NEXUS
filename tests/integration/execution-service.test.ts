import { afterEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_EXEC_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  MAX_EXEC_TIMEOUT_MS,
  MAX_MAX_OUTPUT_BYTES
} from '../../src/shared/ipc'
import { makeHarness, type Harness } from '../fixtures/harness'
import { TEST_PASSWORD } from '../fixtures/ssh-server'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

describe('real ExecutionService outcomes, bounds, history, and redaction', () => {
  it('executes a real fixture command, redacts output, and persists sanitized history and output pages', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()
    h.approvals.handler = async () => 'approve'

    const result = await h.svc.exec.execute({
      serverId: h.serverId,
      sessionId: sid,
      command: `echo ${TEST_PASSWORD}`
    }, 'user')

    expect(result.status).toBe('completed')
    if (result.status !== 'completed') throw new Error('expected completed fixture execution')
    expect(result.stdout).not.toContain(TEST_PASSWORD)
    expect(result.stdout).toContain('[REDACTED]')
    expect(h.ssh.commands).toEqual([`echo ${TEST_PASSWORD}`])

    const row = h.svc.exec.get(result.commandId)
    expect(row).not.toBeNull()
    expect(row?.status).toBe('completed')
    expect(row?.commandSanitized).toBe('echo [REDACTED]')
    expect(row?.output).not.toContain(TEST_PASSWORD)
    expect(row?.finishedAt).not.toBeNull()

    const page = h.svc.exec.getOutput(result.commandId, 0, 4096)
    expect(page?.done).toBe(true)
    expect(page?.status).toBe('completed')
    expect(page?.text).not.toContain(TEST_PASSWORD)
    expect(page?.text).toContain('[REDACTED]')
    expect(h.svc.exec.list({ serverId: h.serverId, sessionId: sid, status: 'completed' }))
      .toEqual(expect.arrayContaining([expect.objectContaining({ id: result.commandId, commandSanitized: 'echo [REDACTED]' })]))
  })

  it('uses configured defaults and enforces the default output cap on the real SSH exec channel', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()
    expect(h.svc.settings().defaultExecTimeoutMs).toBe(DEFAULT_EXEC_TIMEOUT_MS)
    expect(h.svc.settings().defaultMaxOutputBytes).toBe(DEFAULT_MAX_OUTPUT_BYTES)

    h.approvals.handler = async () => 'approve'
    const result = await h.svc.exec.execute({
      serverId: h.serverId,
      sessionId: sid,
      command: 'flood 512'
    }, 'user')

    expect(result.status).toBe('completed')
    if (result.status !== 'completed') throw new Error('expected completed output-limited execution')
    expect(result.truncated).toBe(true)
    expect(Buffer.byteLength(result.stdout, 'utf8')).toBeLessThanOrEqual(DEFAULT_MAX_OUTPUT_BYTES)
    expect(h.svc.exec.get(result.commandId)?.truncated).toBe(true)
    expect(h.ssh.commands).toEqual(['flood 512'])
  })

  it('accepts and enforces the minimum and maximum output limits; records remote nonzero exit status', async () => {
    h = await makeHarness({ approvalPolicy: 'always' })
    const sid = await h.connect()
    h.approvals.handler = async () => 'approve'

    const minimum = await h.svc.exec.execute({
      serverId: h.serverId,
      sessionId: sid,
      command: 'flood 64',
      timeoutMs: 1_000,
      maxOutputBytes: 1_024
    }, 'user')
    expect(minimum.status).toBe('completed')
    if (minimum.status !== 'completed') throw new Error('expected minimum-cap command to complete')
    expect(minimum.truncated).toBe(true)
    expect(Buffer.byteLength(minimum.stdout, 'utf8')).toBeLessThanOrEqual(1_024)

    const maximum = await h.svc.exec.execute({
      serverId: h.serverId,
      sessionId: sid,
      command: 'flood 2048',
      timeoutMs: MAX_EXEC_TIMEOUT_MS,
      maxOutputBytes: MAX_MAX_OUTPUT_BYTES
    }, 'user')
    expect(maximum.status).toBe('completed')
    if (maximum.status !== 'completed') throw new Error('expected maximum-cap command to complete')
    expect(maximum.truncated).toBe(false)
    expect(Buffer.byteLength(maximum.stdout, 'utf8')).toBeGreaterThan(DEFAULT_MAX_OUTPUT_BYTES)
    expect(Buffer.byteLength(maximum.stdout, 'utf8')).toBeLessThanOrEqual(MAX_MAX_OUTPUT_BYTES)
    expect(h.svc.exec.get(maximum.commandId)?.truncated).toBe(false)

    const nonzero = await h.svc.exec.execute({
      serverId: h.serverId,
      sessionId: sid,
      command: 'exit 7'
    }, 'user')
    expect(nonzero.status).toBe('completed')
    if (nonzero.status !== 'completed') throw new Error('expected remote nonzero exit to be a completed SSH operation')
    expect(nonzero.exitCode).toBe(7)
    expect(nonzero.stderr).toContain('failed cleanly')
    expect(h.svc.exec.get(nonzero.commandId)).toMatchObject({ status: 'completed', exitCode: 7, signal: null })
    expect(h.ssh.commands).toEqual(['flood 64', 'flood 2048', 'exit 7'])
  }, 30_000)

  it('records timeout and cancellation outcomes in persistent execution history', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()
    h.approvals.handler = async () => 'approve'

    const timedOut = await h.svc.exec.execute({
      serverId: h.serverId,
      sessionId: sid,
      command: 'sleep 5',
      timeoutMs: 1_000
    }, 'user')
    expect(timedOut.status).toBe('timeout')
    expect(h.svc.exec.get(timedOut.commandId)?.status).toBe('timeout')

    const abort = new AbortController()
    setTimeout(() => abort.abort(), 100)
    const cancelled = await h.svc.exec.execute({
      serverId: h.serverId,
      sessionId: sid,
      command: 'sleep 5',
      timeoutMs: 5_000
    }, 'user', abort.signal)
    expect(cancelled.status).toBe('cancelled')
    expect(h.svc.exec.get(cancelled.commandId)?.status).toBe('cancelled')
    expect(h.svc.exec.list({ serverId: h.serverId, sessionId: sid, status: 'timeout' })).toHaveLength(1)
    expect(h.svc.exec.list({ serverId: h.serverId, sessionId: sid, status: 'cancelled' })).toHaveLength(1)
  })
})
