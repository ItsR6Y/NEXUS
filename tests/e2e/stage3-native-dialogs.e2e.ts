import { _electron as electron, expect, test } from '@playwright/test'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { utils } from 'ssh2'
import type { NexusApi } from '../../src/shared/api'
import { openDatabase } from '../../src/main/core/db/database'
import { KnownHostRepo, ServerRepo } from '../../src/main/core/db/repositories'
import { startSshServer, TEST_PASSWORD, type TestSshServer } from '../fixtures/ssh-server'

/**
 * real native Windows dialogs.
 *
 * Launches the actual Electron app against a disposable local SSH server and locates the
 * real Windows message boxes with UI Automation (scripts/stage3-uia-dialog.ps1), asserting
 * their displayed content. Dismissal is performed by closing the dialog (cancel path),
 * which must fail closed: Reject for host keys, Deny for commands.
 *
 * Explicit "Trust & Save Host Key" / "Approve once" button activation is covered by the
 * manual procedure in the "Manual Windows-host checks" section of docs/TESTING.md because the custom
 * Chromium task-dialog buttons expose no invokable automation pattern.
 */

const execFileP = promisify(execFile)
const PS = 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
const UIA = join(process.cwd(), 'scripts', 'stage3-uia-dialog.ps1')

async function dialog(title: string, action: 'close' | string, timeoutSec = 60): Promise<string> {
  const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', UIA, '-Title', title, '-TimeoutSec', String(timeoutSec)]
  if (action === 'close') args.push('-Close')
  else args.push('-Button', action)
  const { stdout } = await execFileP(PS, args, { maxBuffer: 4 * 1024 * 1024 })
  return stdout
}

function fingerprintOf(key: Buffer): string {
  return 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '')
}

function keyTypeOf(key: Buffer): string {
  const parsed = utils.parseKey(key)
  const k = Array.isArray(parsed) ? parsed[0] : parsed
  return (k as unknown as { type: string }).type
}

type Envelope<T> = { ok: boolean; data?: T; error?: { code: string; message: string } }

test('native host-key and command-approval dialogs show real context and fail closed when closed', async () => {
  test.setTimeout(240_000)
  const userData = process.env['NEXUS_STAGE3_USERDATA'] ?? mkdtempSync(join(tmpdir(), 'nexus-stage3-native-'))
  let sshA: TestSshServer = await startSshServer({ password: TEST_PASSWORD })
  let sshB: TestSshServer | null = null
  const fingerprintA = fingerprintOf(sshA.hostKeyPublic)
  const keyTypeA = keyTypeOf(sshA.hostKeyPublic)

  // Pre-seed the disposable profile: one server with its host key already pinned.
  let serverId: string
  {
    mkdirSync(userData, { recursive: true })
    const db = openDatabase(join(userData, 'nexus.db'))
    const row = new ServerRepo(db).create({
      name: 'stage3-native',
      host: '127.0.0.1',
      port: sshA.port,
      username: 'tester',
      authType: 'password',
      approvalPolicy: 'always',
      mcpAccessEnabled: true
    })
    new KnownHostRepo(db).insert('127.0.0.1', sshA.port, keyTypeA, fingerprintA)
    serverId = row.id
    db.close()
  }

  const app = await electron.launch({
    args: ['.', '--e2e'],
    env: { ...process.env, NEXUS_E2E: '1', NEXUS_E2E_USERDATA: userData }
  })

  try {
    const page = await app.firstWindow()
    await page.waitForSelector('[data-testid="nav-dashboard"]')

    const secretRes = await page.evaluate(async ({ id }) => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.servers.setSecret(id, 'password', 'test-only-password-canary-99')
    }, { id: serverId })
    console.log('[stage3] setSecret', JSON.stringify(secretRes))

    // Connection with the pinned key needs no prompt.
    const connected = await page.evaluate((id) => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.sessions.connect(id)
    }, serverId) as Envelope<{ status: string; session: { id: string } }>
    console.log('[stage3] connect', JSON.stringify(connected))
    expect(connected.data!.status).toBe('connected')
    const sessionId = connected.data!.session.id

    // 1. Command approval dialog: real context is displayed; closing = Deny, no SSH execution.
    const pwdRun = page.evaluate(({ sid, id }) => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.commands.execute({ serverId: id, sessionId: sid, command: 'pwd' })
    }, { sid: sessionId, id: serverId })
    const pwdText = await dialog('NEXUS Approval Required [LOW]', 'close')
    const pwdResult = (await pwdRun) as Envelope<{ status: string; reason: string }>
    expect(pwdText).toContain('stage3-native')
    expect(pwdText).toContain('GUI Programmatic Command')
    expect(pwdText).toContain('pwd')
    expect(pwdText).toContain('Session:')
    expect(pwdText).toContain('Risk:')
    expect(pwdResult.data!.status).toBe('denied')
    expect(pwdResult.data!.reason).toContain('approval_denied')
    expect(sshA.commands).not.toContain('pwd')

    // 2. Expired approval after leaving the native dialog open; nothing executes.
    await page.evaluate(() => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.settings.set({ approvalTtlSeconds: 15 })
    })
    const hostnameRun = page.evaluate(({ sid, id }) => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.commands.execute({ serverId: id, sessionId: sid, command: 'hostname' })
    }, { sid: sessionId, id: serverId })
    await new Promise((r) => setTimeout(r, 17_000))
    const hostnameResult = (await hostnameRun) as Envelope<{ status: string; reason: string }>
    expect(hostnameResult.data!.status).toBe('denied')
    expect(hostnameResult.data!.reason).toContain('approval_expired')
    expect(sshA.commands).not.toContain('hostname')
    // Dismiss the stale dialog and confirm it cannot execute late.
    await dialog('NEXUS Approval Required [LOW]', 'close')
    expect(sshA.commands).not.toContain('hostname')

    // 3. Unknown host key: the real dialog shows the server and fingerprint; closing rejects.
    sshB = await startSshServer({ password: TEST_PASSWORD })
    const fingerprintB = fingerprintOf(sshB.hostKeyPublic)
    const createdB = await page.evaluate(async ({ p }) => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      const s = await n.servers.create({
        name: 'stage3-unknown',
        host: '127.0.0.1',
        port: p,
        username: 'tester',
        authType: 'password',
        approvalPolicy: 'always',
        mcpAccessEnabled: false
      })
      if (!s.ok) return s as unknown
      return (await n.servers.setSecret(s.data.id, 'password', 'test-only-password-canary-99')) as unknown
    }, { p: sshB.port }) as Envelope<{ id: string }>
    expect(createdB.ok).toBe(true)

    const unknownConnect = page.evaluate((id) => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.sessions.connect(id)
    }, createdB.data!.id)
    const unknownText = await dialog('Unknown SSH Host Key', 'close')
    const unknownResult = (await unknownConnect) as Envelope<{ status: string }>
    expect(unknownText).toContain(fingerprintB)
    expect(unknownText).toContain('stage3-unknown')
    expect(unknownText).toContain('Default is Reject')
    expect(unknownResult.data!.status).not.toBe('connected')

    const pinsAfterReject = await page.evaluate(() => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.knownHosts.list()
    }) as Envelope<{ fingerprintSha256: string }[]>
    expect(pinsAfterReject.data).toHaveLength(1)
    expect(pinsAfterReject.data![0].fingerprintSha256).toBe(fingerprintA)

    // 4. Changed host key is hard-blocked; the original pin is preserved.
    await page.evaluate((sid) => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.sessions.disconnect(sid)
    }, sessionId)
    const portA = sshA.port
    await sshA.close()
    sshA = await startSshServer({ password: TEST_PASSWORD, port: portA })
    const changedConnect = page.evaluate((id) => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.sessions.connect(id)
    }, serverId)
    const changedText = await dialog('SSH HOST KEY CHANGED — CONNECTION BLOCKED', 'close')
    const changedResult = (await changedConnect) as Envelope<{ status: string }>
    expect(changedText).toContain('stage3-native')
    expect(changedText).toContain('does NOT match the stored fingerprint')
    expect(changedResult.data!.status).not.toBe('connected')

    const pinsAfterChange = await page.evaluate(() => {
      const n = (globalThis as unknown as { nexus: NexusApi }).nexus
      return n.knownHosts.list()
    }) as Envelope<{ fingerprintSha256: string }[]>
    expect(pinsAfterChange.data).toHaveLength(1)
    expect(pinsAfterChange.data![0].fingerprintSha256).toBe(fingerprintA)
  } finally {
    await app.close()
    await sshA.close()
    if (sshB) await sshB.close()
    if (!process.env['NEXUS_STAGE3_USERDATA']) rmSync(userData, { recursive: true, force: true })
  }
})
