import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Entry } from '@napi-rs/keyring'
import { afterEach, describe, expect, it } from 'vitest'
import { KEYRING_SERVICE, KeyringCredentialStore } from '../../src/main/core/credentials/credential-store'
import { openDatabase } from '../../src/main/core/db/database'
import { resolveAppPaths } from '../../src/main/paths'
import { Services } from '../../src/main/services'
import { StubApprovalPresenter, StubHostKeyPresenter } from '../fixtures/harness'

let dir: string | null = null
let svc: Services | null = null
let account: string | null = null
afterEach(async () => {
  try { if (account) new Entry(KEYRING_SERVICE, account).deletePassword() } catch { /* already gone */ }
  if (svc) { await svc.shutdown(); svc = null }
  if (dir) { rmSync(dir, { recursive: true, force: true }); dir = null }
  account = null
})

const realKeyringEnabled = process.env['NEXUS_REAL_KEYRING'] === '1'

/** Target names currently present in Windows Credential Manager (values are never printed). */
function credentialManagerTargets(): string {
  return execFileSync('cmdkey.exe', ['/list'], { encoding: 'utf8', windowsHide: true })
}

describe.skipIf(!realKeyringEnabled)('real Windows Credential Manager through KeyringCredentialStore', () => {
  it('round-trips a disposable secret, survives a fresh store instance, and keeps it out of DB/logs/DTO/MCP', async () => {
    dir = mkdtempSync(join(tmpdir(), 'nexus-stage3-cred-'))
    const db = openDatabase(join(dir, 'nexus.db'))
    svc = new Services({
      db,
      credentialStore: new KeyringCredentialStore(Entry),
      approvalPresenter: new StubApprovalPresenter(),
      hostKeyPresenter: new StubHostKeyPresenter(),
      userDataDir: dir,
      mcpServerPath: join(dir, 'missing-mcp.mjs'),
      platform: 'win32'
    })
    await svc.init()

    const secret = randomBytes(24).toString('base64url')
    const server = svc.servers.create({
      name: 'stage3-disposable', host: '127.0.0.1', port: 1, username: 'stage3',
      authType: 'password', approvalPolicy: 'always', mcpAccessEnabled: true
    })
    account = `${server.id}:password`
    svc.servers.setSecret(server.id, 'password', secret)

    // Exact in-memory equality through the app store.
    expect(svc.creds.backendName()).toMatch(/keyring/i)
    expect(svc.creds.has(server.id, 'password')).toBe(true)
    expect(svc.creds.useSecret(server.id, 'password', (p) => p)).toBe(secret)

    // The entry is visible in the real Windows Credential Manager store (not an in-memory mock).
    expect(credentialManagerTargets()).toContain(account)

    // A fresh store instance reads the persisted OS entry (restart behavior at the store boundary).
    const restarted = new KeyringCredentialStore(Entry)
    expect(restarted.useSecret(server.id, 'password', (p) => p)).toBe(secret)

    // GUI DTO carries only booleans; MCP listing is public-only.
    const guiJson = JSON.stringify(svc.servers.getPrivate(server.id))
    expect(guiJson).not.toContain(secret)
    expect(guiJson).toContain('"password":true')
    const mcpJson = JSON.stringify(await svc.router.call({ name: 'stage3' }, 'nexus_list_servers', {}))
    expect(mcpJson).not.toContain(secret)

    // Log file and SQLite bytes (including WAL if present) contain no plaintext secret.
    svc.logger.info('stage3.log_probe', { note: 'no-secret' })
    const pathsForApp = resolveAppPaths(dir)
    const files = [pathsForApp.dbFile, `${pathsForApp.dbFile}-wal`, `${pathsForApp.dbFile}-shm`, pathsForApp.logFile]
    for (const file of files) {
      let bytes: Buffer
      try { bytes = readFileSync(file) } catch { continue }
      expect(bytes.includes(Buffer.from(secret, 'utf8')), file).toBe(false)
    }

    // Removal is confirmed at the OS entry level; a missing credential yields a sanitized result.
    svc.servers.clearSecret(server.id, 'password')
    expect(svc.creds.has(server.id, 'password')).toBe(false)
    expect(new Entry(KEYRING_SERVICE, account).getPassword()).toBeNull()
    expect(credentialManagerTargets()).not.toContain(account)
    const open = await svc.sessions.open(server.id)
    expect(open.status).toBe('needs_user_input')
    expect(JSON.stringify(open)).not.toContain(secret)
  }, 30_000)
})
