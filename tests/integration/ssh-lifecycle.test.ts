import { afterEach, describe, expect, it } from 'vitest'
import { buildHandlers, type IpcEventLike } from '../../src/main/ipc/registry'
import { APP_ORIGIN } from '../../src/main/protocol'
import { TerminalTailBuffer } from '../../src/main/core/ssh/terminal-tail'
import { makeHarness, type Harness } from '../fixtures/harness'
import { startSshServer, TEST_PASSWORD, TEST_USER } from '../fixtures/ssh-server'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

async function waitFor(cond: () => boolean, ms = 5_000): Promise<void> {
  const start = Date.now()
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error('timed out waiting for condition')
    await new Promise((r) => setTimeout(r, 10))
  }
}

describe('SSH lifecycle regressions', () => {
  it('disconnect during the SSH handshake aborts the attempt and never promotes it to connected', async () => {
    h = await makeHarness()
    const slow = await startSshServer({ password: TEST_PASSWORD, authenticationDelayMs: 1_200 })
    try {
      const srv = h.svc.servers.create({
        name: 'slow-box',
        host: '127.0.0.1',
        port: slow.port,
        username: TEST_USER,
        authType: 'password',
        approvalPolicy: 'ask',
        mcpAccessEnabled: false
      })
      h.svc.servers.setSecret(srv.id, 'password', TEST_PASSWORD)

      const pending = h.svc.sessions.open(srv.id)
      await waitFor(() => h!.svc.sessions.list(srv.id).some((s) => s.state === 'connecting'))
      const sessionId = h.svc.sessions.list(srv.id).find((s) => s.state === 'connecting')!.id

      h.svc.sessions.disconnect(sessionId, 'user')
      const result = await pending

      expect(result.status).not.toBe('connected')
      expect(h.svc.sessions.activeCount()).toBe(0)

      // The late authentication must not resurrect the cancelled attempt.
      await new Promise((r) => setTimeout(r, 1_400))
      expect(slow.commands).toEqual([])
      expect(h.svc.sessions.list(srv.id).every((s) => s.state !== 'connected')).toBe(true)
      expect(h.hostKeys.mismatchCalls).toHaveLength(0)
    } finally {
      await slow.close()
    }
  })

  it('a different key type for an already-pinned endpoint gets a distinct warning and a security event', async () => {
    h = await makeHarness()
    // The fixture serves an ssh-ed25519 host key; pin an unrelated key type for the same endpoint.
    h.svc.knownHostRepo.insert('127.0.0.1', h.ssh.port, 'ssh-rsa', 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', h.clock.t)

    const result = await h.svc.sessions.open(h.serverId)

    expect(result.status).not.toBe('connected')
    expect(h.hostKeys.typeMismatchCalls).toHaveLength(1)
    expect(h.hostKeys.typeMismatchCalls[0].pinnedKeyType).toBe('ssh-rsa')
    expect(h.hostKeys.typeMismatchCalls[0].presentedKeyType).toBe('ssh-ed25519')
    // A pinned endpoint must NOT be treated as a first-use host.
    expect(h.hostKeys.unknownCalls).toHaveLength(0)
    expect(h.svc.audit.listSecurityEvents().map((e) => e.type)).toContain('host_key_type_mismatch')
    // Nothing was trusted and no session survived.
    expect(h.svc.hostKeys.list().map((k) => k.keyType)).toEqual(['ssh-rsa'])
    expect(h.svc.sessions.activeCount()).toBe(0)
  })

  it('failed connections leave no session rows and titles come from a per-server high-water mark', async () => {
    h = await makeHarness()
    h.hostKeys.acceptUnknown = false
    const rejected = await h.svc.sessions.open(h.serverId)
    expect(rejected.status).toBe('host_key_rejected')
    expect(h.svc.sessions.list()).toHaveLength(0)

    h.hostKeys.acceptUnknown = true
    const sil = await h.connect()
    expect(h.svc.sessions.list().find((s) => s.id === sil)?.title).toBe('test-box #1')
    h.svc.sessions.disconnect(sil, 'test')

    const second = await h.connect()
    expect(h.svc.sessions.list().find((s) => s.id === second)?.title).toBe('test-box #2')
    h.svc.sessions.disconnect(second, 'test')

    // A failed attempt between two successful ones must not reuse a visible title.
    h.svc.servers.setSecret(h.serverId, 'password', 'wrong-password')
    const failed = await h.svc.sessions.open(h.serverId)
    expect(failed.status).not.toBe('connected')
    h.svc.servers.setSecret(h.serverId, 'password', TEST_PASSWORD)

    const third = await h.connect()
    expect(h.svc.sessions.list().find((s) => s.id === third)?.title).toBe('test-box #3')
    expect(h.svc.sessions.list()).toHaveLength(3)
  })

  it('deleting a server keeps its host-key pins and records that retention in the audit log', async () => {
    h = await makeHarness()
    const sil = await h.connect()
    h.svc.sessions.disconnect(sil, 'test')
    const before = h.svc.hostKeys.list()
    expect(before).toHaveLength(1)

    h.svc.servers.delete(h.serverId)

    expect(h.svc.servers.listPrivate()).toHaveLength(0)
    expect(h.svc.hostKeys.list()).toEqual(before)
    const entry = h.svc.audit.list(50).find((e) => e.kind === 'server.deleted')
    expect(entry).toBeTruthy()
    expect(entry!.data['retainedKnownHostPins']).toBe(1)
    expect(entry!.data['host']).toBe('127.0.0.1')
    expect(entry!.data['port']).toBe(h.ssh.port)
  })

  it('tail truncation never emits U+FFFD when the cut lands inside a multibyte character', () => {
    const ring = new TerminalTailBuffer(4096)
    // 2000 * 3 bytes = 6000 bytes; trimming to the last 4096 bytes lands mid-character.
    ring.append('\u20ac'.repeat(2000))
    const tail = ring.readTail(200)
    expect(tail).not.toContain('\ufffd')
    expect(Buffer.byteLength(tail, 'utf8')).toBeLessThanOrEqual(4096)
    expect(tail.startsWith('\u20ac')).toBe(true)

    const ring2 = new TerminalTailBuffer(4096)
    ring2.append('a' + '\u{1f512}'.repeat(1500) + 'b')
    expect(ring2.readTail(200)).not.toContain('\ufffd')
  })

  it('terminal:open records the originating webContents id on the shell.opened audit event', async () => {
    h = await makeHarness()
    const sid = await h.connect()

    const handlers = buildHandlers({
      services: h.svc,
      trustedOrigin: APP_ORIGIN,
      send: () => undefined,
      pickKeyPath: async () => null,
      openLogsFolder: async () => undefined,
      confirmClearHistory: async () => false,
      appInfo: { version: '1.0.0', platform: 'linux' }
    })
    const open = handlers['terminal:open'] as unknown as (p: unknown, ev: IpcEventLike) => Promise<unknown>
    const ev: IpcEventLike = { sender: { id: 4242 }, senderFrame: { url: `${APP_ORIGIN}/index.html`, parent: null } }
    await open({ sessionId: sid, cols: 80, rows: 24 }, ev)

    const opened = h.svc.audit.list(100).filter((e) => e.kind === 'shell.opened')
    expect(opened.length).toBeGreaterThanOrEqual(1)
    expect(opened[0].data['sessionId']).toBe(sid)
    expect(opened[0].data['webContentsId']).toBe(4242)
  })
})
