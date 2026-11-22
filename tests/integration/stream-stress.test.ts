import { rmSync } from 'node:fs'
import { afterEach, describe, expect, it } from 'vitest'
import { DEFAULT_TAIL_BYTES } from '../../src/shared/ipc'
import { makeHarness, type Harness } from '../fixtures/harness'
import { TEST_PASSWORD } from '../fixtures/ssh-server'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

interface ShellLike {
  pause(): void
  resume(): void
  isPaused(): boolean
  emit(event: 'data', chunk: Buffer): boolean
}

function liveShell(harness: Harness, sid: string): ShellLike {
  const live = (harness.svc.sessions as unknown as { live: Map<string, { shell: ShellLike | null }> }).live
  const shell = live.get(sid)?.shell
  if (!shell) throw new Error('expected an open shell')
  return shell
}

async function waitFor(cond: () => boolean, ms = 25_000): Promise<void> {
  const start = Date.now()
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error('timed out waiting for stress condition')
    await new Promise((r) => setTimeout(r, 10))
  }
}

describe('terminal and stream stress validation', () => {
  it('batches 8 MB of shell output, keeps the 256 KB tail bounded, redacts, and stays memory-bounded', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()
    await h.svc.sessions.openShell(sid, 120, 40)

    const chunkCount = 2048
    const chunk = 'x'.repeat(4095) + '\n'
    h.ssh.setShellBehavior((command, channel) => {
      if (command !== 'stress') return
      let sent = 0
      const pump = (): void => {
        if (sent >= chunkCount) { channel.write(`\x1b[31mSTRESS-DONE ${TEST_PASSWORD}\x1b[0m\r\n`); return }
        channel.write(chunk)
        sent++
        setImmediate(pump)
      }
      setImmediate(pump)
    })

    let receivedTail = ''
    let bytes = 0
    let events = 0
    const onData = (id: string, text: string): void => {
      if (id !== sid) return
      bytes += Buffer.byteLength(text, 'utf8')
      events++
      receivedTail = (receivedTail + text).slice(-16_384)
    }
    h.svc.bus.on('shell-data', onData)
    const before = process.memoryUsage()
    try {
      h.svc.sessions.shellInput(sid, 'stress\r')
      await waitFor(() => receivedTail.includes('STRESS-DONE'))
    } finally {
      h.svc.bus.off('shell-data', onData)
    }
    await new Promise((r) => setTimeout(r, 250))
    const after = process.memoryUsage()

    expect(bytes).toBeGreaterThanOrEqual(chunkCount * 4096)
    expect(events).toBeLessThan(chunkCount / 2)
    const tail = h.svc.sessions.readTerminalTail(sid, 200)
    expect(tail).not.toBeNull()
    expect(tail).toContain('STRESS-DONE')
    expect(tail).toContain('[REDACTED]')
    expect(tail).not.toContain(TEST_PASSWORD)
    expect(tail).not.toContain('\x1b[')
    expect(Buffer.byteLength(tail ?? '', 'utf8')).toBeLessThanOrEqual(DEFAULT_TAIL_BYTES + 4096)

    const heapDelta = after.heapUsed - before.heapUsed
    const rssDelta = after.rss - before.rss
    console.log('[stage-e] 8MB shell stream', JSON.stringify({ bytes, events, heapDelta, rssDelta, tailBytes: Buffer.byteLength(tail ?? '', 'utf8') }))
    expect(heapDelta).toBeLessThan(96 * 1024 * 1024)
  }, 45_000)

  it('exercises the high-watermark pause/resume pair with a single 512 KB data event and continues afterward', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sid = await h.connect()
    await h.svc.sessions.openShell(sid, 120, 40)
    const shell = liveShell(h, sid)

    let pauses = 0
    let resumes = 0
    const originalPause = shell.pause.bind(shell)
    const originalResume = shell.resume.bind(shell)
    shell.pause = () => { pauses++; originalPause() }
    shell.resume = () => { resumes++; originalResume() }

    let received = ''
    const onData = (id: string, text: string): void => {
      if (id === sid) received = (received + text).slice(-1_048_576)
    }
    h.svc.bus.on('shell-data', onData)
    try {
      shell.emit('data', Buffer.from('D'.repeat(512 * 1024), 'utf8'))
      await waitFor(() => received.length >= 512 * 1024)
      await new Promise((r) => setTimeout(r, 50))
      expect(pauses).toBeGreaterThanOrEqual(1)
      expect(resumes).toBeGreaterThanOrEqual(1)
      expect(shell.isPaused()).toBe(false)

      // Normal traffic still flows after the pause/resume pair.
      shell.emit('data', Buffer.from('AFTER-OK\r\n', 'utf8'))
      await waitFor(() => received.includes('AFTER-OK'))
    } finally {
      h.svc.bus.off('shell-data', onData)
    }
    console.log('[stage-e] pause/resume', JSON.stringify({ pauses, resumes, bytes: received.length }))
  }, 30_000)

  it('handles five concurrent flooded sessions and a session closed mid-output', async () => {
    h = await makeHarness({ approvalPolicy: 'sensitive' })
    const sessions: string[] = []
    for (let i = 0; i < 5; i++) {
      const sid = await h.connect()
      await h.svc.sessions.openShell(sid, 100, 30)
      sessions.push(sid)
    }

    h.ssh.setShellBehavior((command, channel) => {
      const wave = /^wave-(\d+)$/.exec(command)
      if (wave) {
        const block = 'W'.repeat(65_535) + '\n'
        for (let i = 0; i < 4; i++) channel.write(block)
        channel.write(`WAVE-${wave[1]}-DONE\r\n`)
        return
      }
      if (command.startsWith('echo ')) {
        channel.write(command.slice(5) + '\r\n')
        return
      }
      if (command === 'endless') {
        let n = 0
        const pump = (): void => {
          if (n++ > 4000) return
          try { channel.write('E'.repeat(4095) + '\n') } catch { return }
          setImmediate(pump)
        }
        setImmediate(pump)
      }
    })
    const tails = new Map<string, string>()
    const onData = (id: string, text: string): void => {
      tails.set(id, ((tails.get(id) ?? '') + text).slice(-8192))
    }
    h.svc.bus.on('shell-data', onData)
    // Narrow once: `h` is a mutable module-level binding, so its non-null narrowing does not
    // survive into the forEach callback below.
    const sessionsSvc = h.svc.sessions
    try {
      sessions.forEach((sid, i) => sessionsSvc.shellInput(sid, `wave-${i}\r`))
      await waitFor(() => sessions.every((sid) => /WAVE-\d-DONE/.test(tails.get(sid) ?? '')))
      expect([...tails.keys()].filter((sid) => /WAVE-\d-DONE/.test(tails.get(sid) ?? '')).length).toBe(5)
    } finally {
      h.svc.bus.off('shell-data', onData)
    }

    const closing = sessions[0]
    let shellClosedReason: string | null = null
    const onClosed = (id: string, reason: string): void => {
      if (id === closing && shellClosedReason === null) shellClosedReason = reason
    }
    h.svc.bus.on('shell-closed', onClosed)
    try {
      h.svc.sessions.shellInput(closing, 'endless\r')
      await new Promise((r) => setTimeout(r, 20))
      h.svc.sessions.closeShell(closing)
      await waitFor(() => shellClosedReason !== null, 10_000)
    } finally {
      h.svc.bus.off('shell-closed', onClosed)
    }
    expect(shellClosedReason).toBeTruthy()

    // Remaining sessions stay usable.
    const survivor = sessions[1]
    let survivorData = ''
    const onSurvivor = (id: string, text: string): void => { if (id === survivor) survivorData += text }
    h.svc.bus.on('shell-data', onSurvivor)
    try {
      h.svc.sessions.shellInput(survivor, 'echo still-alive\r')
      await waitFor(() => survivorData.includes('still-alive'))
    } finally {
      h.svc.bus.off('shell-data', onSurvivor)
    }
  }, 45_000)

  it('shuts down within a bounded time while a shell is actively flooding', async () => {
    const local = await makeHarness({ approvalPolicy: 'sensitive' })
    let stopped = false
    try {
      const sid = await local.connect()
      await local.svc.sessions.openShell(sid, 100, 30)
      local.ssh.setShellBehavior((command, channel) => {
        if (command !== 'endless') return
        let n = 0
        const pump = (): void => {
          if (n++ > 4000) return
          try { channel.write('F'.repeat(4095) + '\n') } catch { return }
          setImmediate(pump)
        }
        setImmediate(pump)
      })
      local.svc.sessions.shellInput(sid, 'endless\r')
      await new Promise((r) => setTimeout(r, 30))

      const started = Date.now()
      await local.svc.shutdown()
      stopped = true
      const elapsed = Date.now() - started
      console.log('[stage-e] shutdown-during-flood ms', elapsed)
      expect(elapsed).toBeLessThan(5_000)
    } finally {
      if (!stopped) await local.svc.shutdown().catch(() => undefined)
      await local.ssh.close()
      rmSync(local.dir, { recursive: true, force: true })
    }
  }, 30_000)
})
