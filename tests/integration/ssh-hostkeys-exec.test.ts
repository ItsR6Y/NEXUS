import { writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { join } from 'node:path'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { generateClientKeypair, startSshServer, TEST_PASSWORD, TEST_USER } from '../fixtures/ssh-server'
import { makeHarness, type Harness } from '../fixtures/harness'
import { TerminalTailBuffer } from '../../src/main/core/ssh/terminal-tail'
import { DEFAULT_TAIL_BYTES } from '../../src/shared/ipc'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

/** Shell-channel input -> output round-trip is not instantaneous; poll instead of assuming a fixed delay. */
async function waitFor(cond: () => boolean, ms = 5_000): Promise<void> {
  const start = Date.now()
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error('timed out waiting for shell output')
    await new Promise((r) => setTimeout(r, 10))
  }
}

describe('SSH host-key verification, key-path auth, exec limits, cancellation, and terminal tail', () => {
  it('prompts on unknown host key, rejects when user rejects, accepts when user trusts, and hard-blocks mismatches', async () => {
    h = await makeHarness()
    // 1. Reject first use
    h.hostKeys.acceptUnknown = false
    const r1 = await h.svc.sessions.open(h.serverId)
    expect(r1.status).toBe('host_key_rejected')
    expect(h.svc.hostKeys.list().length).toBe(0)

    // 2. Accept first use
    h.hostKeys.acceptUnknown = true
    const r2 = await h.svc.sessions.open(h.serverId)
    expect(r2.status).toBe('connected')
    expect(h.svc.hostKeys.list().length).toBe(1)

    // 3. Reconnect with matching key -> no unknown prompt
    const beforePrompts = h.hostKeys.unknownCalls.length
    const r3 = await h.svc.sessions.open(h.serverId)
    expect(r3.status).toBe('connected')
    expect(h.hostKeys.unknownCalls.length).toBe(beforePrompts)

    // 4. Tamper stored fingerprint -> hard mismatch block (no bypass)
    const kh = h.svc.hostKeys.list()[0]
    h.svc.knownHostRepo.insert(kh.host, kh.port, kh.keyType, 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    const r4 = await h.svc.sessions.open(h.serverId)
    expect(r4.status).toBe('host_key_mismatch')
    expect(h.hostKeys.mismatchCalls.length).toBe(1)
  })

  it('rejects unknown host key on prompt timeout', async () => {
    h = await makeHarness({ hostKeyPromptTimeoutMs: 100 })
    h.hostKeys.acceptUnknown = true
    h.hostKeys.unknownDelayMs = 400
    const r = await h.svc.sessions.open(h.serverId)
    expect(r.status).toBe('host_key_rejected')
    if (r.status === 'host_key_rejected') expect(r.reason).toContain('timed out')
  })

  it('authenticates with valid and rejects invalid passwords and generated public keys', async () => {
    h = await makeHarness()

    const invalidPassword = h.svc.servers.create({
      name: 'invalid-password', host: '127.0.0.1', port: h.ssh.port, username: TEST_USER,
      authType: 'password', approvalPolicy: 'ask', mcpAccessEnabled: true
    })
    h.svc.servers.setSecret(invalidPassword.id, 'password', 'wrong-password')
    const rejectedPassword = await h.svc.sessions.open(invalidPassword.id)
    expect(rejectedPassword.status).toBe('error')
    // an attempt that never established a connection leaves no permanent session row.
    expect(h.svc.sessions.list(invalidPassword.id)).toHaveLength(0)

    const validPassword = await h.svc.sessions.open(h.serverId)
    expect(validPassword.status).toBe('connected')

    const authorizedKey = generateClientKeypair()
    const deniedKey = generateClientKeypair()
    const keyServer = await startSshServer({ authorizedPublicKey: authorizedKey.publicSsh })
    try {
      const deniedPath = join(h.dir, 'unauthorized_ed25519')
      writeFileSync(deniedPath, deniedKey.privatePem, { mode: 0o600 })
      const denied = h.svc.servers.create({
        name: 'invalid-key', host: '127.0.0.1', port: keyServer.port, username: TEST_USER,
        authType: 'key', keyPath: deniedPath, approvalPolicy: 'ask', mcpAccessEnabled: true
      })
      const rejectedKey = await h.svc.sessions.open(denied.id)
      expect(rejectedKey.status).toBe('error')

      const acceptedPath = join(h.dir, 'authorized_ed25519')
      writeFileSync(acceptedPath, authorizedKey.privatePem, { mode: 0o600 })
      const accepted = h.svc.servers.create({
        name: 'valid-key', host: '127.0.0.1', port: keyServer.port, username: TEST_USER,
        authType: 'key', keyPath: acceptedPath, approvalPolicy: 'ask', mcpAccessEnabled: true
      })
      const connectedKey = await h.svc.sessions.open(accepted.id)
      expect(connectedKey.status).toBe('connected')
    } finally {
      await keyServer.close()
    }
  })

  it('fails closed when SSH authentication does not complete before the client handshake timeout', async () => {
    h = await makeHarness()
    const slow = await startSshServer({ password: TEST_PASSWORD, authenticationDelayMs: 21_000 })
    try {
      const server = h.svc.servers.create({
        name: 'slow-auth', host: '127.0.0.1', port: slow.port, username: TEST_USER,
        authType: 'password', approvalPolicy: 'ask', mcpAccessEnabled: true
      })
      h.svc.servers.setSecret(server.id, 'password', TEST_PASSWORD)
      const result = await h.svc.sessions.open(server.id)
      expect(result.status).toBe('error')
      expect(slow.commands).toEqual([])
    } finally {
      await slow.close()
    }
  }, 30_000)

  it('returns an error on connection failure without leaking transport details', async () => {
    h = await makeHarness()
    const probe = createServer()
    const unusedPort = await new Promise<number>((resolve) => {
      probe.listen(0, '127.0.0.1', () => {
        const port = (probe.address() as AddressInfo).port
        probe.close(() => resolve(port))
      })
    })
    const server = h.svc.servers.create({
      name: 'unavailable', host: '127.0.0.1', port: unusedPort, username: TEST_USER,
      authType: 'password', approvalPolicy: 'ask', mcpAccessEnabled: true
    })
    h.svc.servers.setSecret(server.id, 'password', TEST_PASSWORD)
    const result = await h.svc.sessions.open(server.id)
    expect(result.status).toBe('error')
    if (result.status === 'error') {
      expect(result.message).toBe('SSH connection failed')
      expect(result.message).not.toContain('127.0.0.1')
      expect(result.message).not.toContain(String(unusedPort))
    }
  })

  it('reconnects with a pinned key and hard-rejects a changed key without replacing trust', async () => {
    h = await makeHarness()
    const initial = await h.svc.sessions.open(h.serverId)
    expect(initial.status).toBe('connected')
    const pinned = h.svc.hostKeys.list()[0]
    expect(pinned).toBeDefined()
    if (initial.status === 'connected') h.svc.sessions.disconnect(initial.session.id)

    const originalPort = h.ssh.port
    await h.ssh.close()
    const changedServer = await startSshServer({ password: TEST_PASSWORD, port: originalPort })
    try {
      const changed = await h.svc.sessions.open(h.serverId)
      expect(changed.status).toBe('host_key_mismatch')
      expect(h.hostKeys.unknownCalls).toHaveLength(1)
      expect(h.hostKeys.mismatchCalls).toHaveLength(1)
      expect(h.svc.hostKeys.list()).toEqual([pinned])
    } finally {
      await changedServer.close()
    }
  })

  it('authenticates with key_path read on disk without exposing keyPath in ServerPublicInfo', async () => {
    h = await makeHarness()
    const kp = generateClientKeypair()
    const keySsh = await startSshServer({ authorizedPublicKey: kp.publicSsh })
    try {
      const keyFile = join(h.dir, 'client_ed25519')
      writeFileSync(keyFile, kp.privatePem, { mode: 0o600 })
      const srv = h.svc.servers.create({
        name: 'key-box',
        host: '127.0.0.1',
        port: keySsh.port,
        username: TEST_USER,
        authType: 'key',
        keyPath: keyFile,
        approvalPolicy: 'ask',
        mcpAccessEnabled: true
      })
      expect(srv.keyPath).toBe(keyFile)
      const pubJson = JSON.stringify(h.svc.servers.listPublicForMcp())
      expect(pubJson).not.toContain('keyPath')
      expect(pubJson).not.toContain('client_ed25519')

      const res = await h.svc.sessions.open(srv.id)
      expect(res.status).toBe('connected')
    } finally {
      await keySsh.close()
    }
  })

  it('opens an interactive shell, batches multi-chunk output, closes cleanly, and bounds/redacts the terminal ring buffer', async () => {
    h = await makeHarness()
    const sid = await h.connect()
    const output: string[] = []
    const closed: string[] = []
    h.svc.sessions.on('shell-data', (id: string, data: string) => { if (id === sid) output.push(data) })
    h.svc.sessions.on('shell-closed', (id: string, reason: string) => { if (id === sid) closed.push(reason) })
    h.ssh.setShellBehavior((_command, channel) => {
      channel.write('first chunk\n')
      setTimeout(() => channel.write('second chunk\n'), 5)
      setTimeout(() => channel.write(`secret ${TEST_PASSWORD}\n`), 10)
    })

    await h.svc.sessions.openShell(sid, 100, 40)
    h.svc.sessions.shellInput(sid, 'multi-chunk\r')
    await waitFor(() => output.join('').includes('second chunk'))
    expect(output.join('')).toContain('first chunk')
    expect(output.join('')).toContain('second chunk')
    expect(output.length).toBeLessThan(4)

    const tail = h.svc.sessions.readTerminalTail(sid, 20)
    expect(tail).not.toContain(TEST_PASSWORD)
    expect(tail).toContain('[REDACTED]')
    h.svc.sessions.shellResize(sid, 120, 50)
    h.svc.sessions.closeShell(sid)
    await waitFor(() => closed.includes('shell exited'))
    expect(closed).toContain('shell exited')

    const ring = new TerminalTailBuffer(DEFAULT_TAIL_BYTES)
    ring.append('x'.repeat(DEFAULT_TAIL_BYTES + 20_000))
    expect(Buffer.byteLength(ring.readTail(1), 'utf8')).toBeLessThanOrEqual(DEFAULT_TAIL_BYTES)
    ring.append('\n' + '\u001b[31m' + TEST_PASSWORD + '\u001b[0m')
    expect(ring.readTail(1, [TEST_PASSWORD])).not.toContain(TEST_PASSWORD)
  })

  it('closes the shell and emits session closure when the SSH connection disconnects', async () => {
    h = await makeHarness()
    const sid = await h.connect()
    const closed: string[] = []
    h.svc.sessions.on('shell-closed', (id: string, reason: string) => { if (id === sid) closed.push(reason) })
    await h.svc.sessions.openShell(sid, 80, 24)
    h.svc.sessions.disconnect(sid, 'test disconnect')
    await new Promise((resolve) => setTimeout(resolve, 30))
    expect(closed).toContain('test disconnect')
    expect(h.svc.sessions.get(sid)?.state).toBe('disconnected')
  })

  it('enforces session ownership, output truncation, timeout, cancellation, and ANSI-stripped redacted terminal tail', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()
    const otherServer = h.svc.servers.create({
      name: 'other',
      host: '127.0.0.1',
      port: 2222,
      username: 'bob',
      authType: 'password',
      approvalPolicy: 'ask',
      mcpAccessEnabled: true
    })

    // Session ownership mismatch rejected with ZERO SSH calls
    const cross = await h.svc.exec.execute({ serverId: otherServer.id, sessionId: sid, command: 'pwd' }, 'user')
    expect(cross.status).toBe('denied')
    expect(h.ssh.commands).toEqual([])

    h.approvals.handler = async () => 'approve'

    // Output limit truncation
    const flooded = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'flood 64', maxOutputBytes: 4096 }, 'user')
    expect(flooded.status).toBe('completed')
    if (flooded.status === 'completed') {
      expect(flooded.truncated).toBe(true)
      expect(Buffer.byteLength(flooded.stdout, 'utf8')).toBeLessThanOrEqual(4096)
    }

    // Timeout
    const timedOut = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'sleep 5', timeoutMs: 150 }, 'user')
    expect(timedOut.status).toBe('timeout')

    // Cancellation via AbortSignal
    const ac = new AbortController()
    setTimeout(() => ac.abort(), 120)
    const cancelled = await h.svc.exec.execute({ serverId: h.serverId, sessionId: sid, command: 'sleep 5', timeoutMs: 5000 }, 'user', ac.signal)
    expect(cancelled.status).toBe('cancelled')

    // Interactive shell + ANSI-stripped & redacted terminal tail
    await h.svc.sessions.openShell(sid, 80, 24)
    h.svc.sessions.shellInput(sid, 'echo AKIAIOSFODNN7EXAMPLE\r')
    await new Promise((r) => setTimeout(r, 150))
    const tail = h.svc.sessions.readTerminalTail(sid, 20)
    expect(tail).not.toBeNull()
    expect(tail!).not.toContain('\x1b[')
    expect(tail!).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(tail!).toContain('[REDACTED]')
  })
})
