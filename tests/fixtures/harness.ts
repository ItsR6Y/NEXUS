import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ApprovalPolicy } from '../../src/shared/policy-types'
import type { SecretCipher } from '../../src/main/core/credentials/credential-store'
import { openDatabase } from '../../src/main/core/db/database'
import type { ApprovalPresentation, ApprovalPresenter } from '../../src/main/security/approvals-ui'
import { Services } from '../../src/main/services'
import type { HostKeyMismatchInfo, HostKeyPresenter, HostKeyTypeMismatchInfo, UnknownHostKeyInfo } from '../../src/main/ssh/hostkey-prompt'
import { startSshServer, TEST_PASSWORD, TEST_USER, type TestSshServer } from './ssh-server'

export class FakeCipher implements SecretCipher {
  available = true
  isAvailable(): boolean { return this.available }
  encrypt(p: string): Buffer { return Buffer.from('ENC1:' + Buffer.from(p, 'utf8').reverse().toString('base64')) }
  decrypt(b: Buffer): string {
    const s = b.toString()
    if (!s.startsWith('ENC1:')) throw new Error('bad blob')
    return Buffer.from(s.slice(5), 'base64').reverse().toString('utf8')
  }
}

export class StubApprovalPresenter implements ApprovalPresenter {
  calls: ApprovalPresentation[] = []
  handler: (req: ApprovalPresentation, signal?: AbortSignal) => Promise<'approve' | 'deny'> = async () => 'deny'
  async present(req: ApprovalPresentation, signal?: AbortSignal): Promise<'approve' | 'deny'> {
    this.calls.push(req)
    return this.handler(req, signal)
  }
}

export class StubHostKeyPresenter implements HostKeyPresenter {
  unknownCalls: UnknownHostKeyInfo[] = []
  mismatchCalls: HostKeyMismatchInfo[] = []
  typeMismatchCalls: HostKeyTypeMismatchInfo[] = []
  acceptTypeMismatch = false
  acceptUnknown = true
  confirmResult = true
  unknownDelayMs = 0
  unknownHandler?: (info: UnknownHostKeyInfo, signal?: AbortSignal) => Promise<boolean>

  async presentUnknown(info: UnknownHostKeyInfo, signal?: AbortSignal): Promise<boolean> {
    this.unknownCalls.push(info)
    if (this.unknownHandler) return this.unknownHandler(info, signal)
    if (this.unknownDelayMs > 0) {
      await new Promise<void>((r) => {
        const t = setTimeout(r, this.unknownDelayMs)
        signal?.addEventListener('abort', () => { clearTimeout(t); r() }, { once: true })
      })
    }
    return !signal?.aborted && this.acceptUnknown
  }

  async presentMismatch(info: HostKeyMismatchInfo): Promise<void> {
    this.mismatchCalls.push(info)
  }

  async presentTypeMismatch(info: HostKeyTypeMismatchInfo): Promise<boolean> {
    this.typeMismatchCalls.push(info)
    return this.acceptTypeMismatch
  }

  async confirmAction(): Promise<boolean> {
    return this.confirmResult
  }
}

export interface Harness {
  dir: string
  svc: Services
  ssh: TestSshServer
  cipher: FakeCipher
  approvals: StubApprovalPresenter
  hostKeys: StubHostKeyPresenter
  clock: { t: number }
  serverId: string
  cleanup(): Promise<void>
  connect(): Promise<string>
}

export async function makeHarness(opts: {
  mcpAccess?: boolean
  approvalPolicy?: ApprovalPolicy
  settings?: Record<string, unknown>
  hostKeyPromptTimeoutMs?: number
} = {}): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), 'nexus-test-'))
  const db = openDatabase(join(dir, 'nexus.db'))
  const cipher = new FakeCipher()
  const approvals = new StubApprovalPresenter()
  const hostKeys = new StubHostKeyPresenter()
  const clock = { t: 1_750_000_000_000 }

  const svc = new Services({
    db,
    cipher,
    approvalPresenter: approvals,
    hostKeyPresenter: hostKeys,
    userDataDir: dir,
    mcpServerPath: '/opt/nexus/out/mcp/nexus-mcp.mjs',
    platform: process.platform === 'win32' ? 'win32' : 'linux',
    now: () => clock.t,
    hostKeyPromptTimeoutMs: opts.hostKeyPromptTimeoutMs ?? 5_000
  })
  await svc.init()
  const ssh = await startSshServer({ password: TEST_PASSWORD })
  if (opts.settings) svc.settingsRepo.patch(opts.settings)

  const server = svc.servers.create({
    name: 'test-box',
    host: '127.0.0.1',
    port: ssh.port,
    username: TEST_USER,
    authType: 'password',
    approvalPolicy: opts.approvalPolicy ?? 'ask',
    mcpAccessEnabled: opts.mcpAccess ?? true
  })
  svc.servers.setSecret(server.id, 'password', TEST_PASSWORD)

  return {
    dir,
    svc,
    ssh,
    cipher,
    approvals,
    hostKeys,
    clock,
    serverId: server.id,
    async connect() {
      const r = await svc.sessions.open(server.id)
      if (r.status !== 'connected') throw new Error('harness connect failed: ' + JSON.stringify(r))
      return r.session.id
    },
    async cleanup() {
      await svc.shutdown()
      await ssh.close()
      rmSync(dir, { recursive: true, force: true })
    }
  }
}
