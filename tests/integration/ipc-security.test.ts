import { afterEach, describe, expect, it } from 'vitest'
import { CHANNELS } from '../../src/shared/ipc'
import { APP_ORIGIN } from '../../src/main/protocol'
import { isTrustedOrigin, registerIpc, type IpcEventLike } from '../../src/main/ipc/registry'
import { makeHarness, type Harness } from '../fixtures/harness'

let h: Harness | null = null
afterEach(async () => { if (h) { await h.cleanup(); h = null } })

describe('IPC boundary security', () => {
  it('rejects untrusted origins, wrong sender IDs, extra Zod fields, and never registers approval/hostkey decision channels', async () => {
    h = await makeHarness()
    const handlers = new Map<string, (ev: IpcEventLike, ...args: unknown[]) => Promise<unknown>>()
    registerIpc(
      { handle: (ch, fn) => { handlers.set(ch, fn as (ev: IpcEventLike, ...args: unknown[]) => Promise<unknown>) } },
      {
        services: h.svc,
        trustedOrigin: APP_ORIGIN,
        getExpectedWebContentsId: () => 42,
        send: () => undefined,
        pickKeyPath: async () => null,
        openLogsFolder: async () => undefined,
        confirmClearHistory: async () => false,
        appInfo: { version: '1.0.0', platform: 'win32' }
      }
    )

    // Authority decision channels MUST NOT exist
    for (const forbidden of ['approvals:approve', 'approvals:reject', 'approvals:cancel', 'hostkeys:trust', 'hostkeys:replace', 'terminal:guard']) {
      expect(CHANNELS.includes(forbidden as never)).toBe(false)
      expect(handlers.has(forbidden)).toBe(false)
    }

    const trustedEv: IpcEventLike = { sender: { id: 42 }, senderFrame: { url: `${APP_ORIGIN}/index.html`, parent: null } }
    const wrongOriginEvents: IpcEventLike[] = [
      { sender: { id: 42 }, senderFrame: { url: 'file:///C:/evil.html', parent: null } },
      { sender: { id: 42 }, senderFrame: { url: 'nexus-app://evil/index.html', parent: null } },
      { sender: { id: 42 }, senderFrame: { url: 'nexus-app://app:444/index.html', parent: null } },
      { sender: { id: 42 }, senderFrame: { url: 'https://example.com/index.html', parent: null } },
      { sender: { id: 42 }, senderFrame: { url: `${APP_ORIGIN}/frame.html`, parent: { url: `${APP_ORIGIN}/index.html` } } },
      { sender: { id: 42 }, senderFrame: null }
    ]
    const wrongSenderEv: IpcEventLike = { sender: { id: 99 }, senderFrame: { url: `${APP_ORIGIN}/index.html`, parent: null } }

    const listServers = handlers.get('servers:list')!
    expect(isTrustedOrigin(trustedEv.senderFrame?.url, APP_ORIGIN)).toBe(true)
    expect((await listServers(trustedEv) as { ok: boolean }).ok).toBe(true)
    for (const event of wrongOriginEvents) {
      expect((await listServers(event) as { ok: boolean; error: { code: string } }).error.code).toBe('forbidden')
    }
    expect((await listServers(wrongSenderEv) as { ok: boolean; error: { code: string } }).error.code).toBe('forbidden')

    // Strict Zod rejects extra fields (e.g. spoofed source or approved flag)
    const execCmd = handlers.get('commands:execute')!
    const extra = await execCmd(trustedEv, { serverId: h.serverId, sessionId: 'abc', command: 'pwd', source: 'user', approved: true }) as { ok: boolean; error: { code: string } }
    expect(extra.ok).toBe(false)
    expect(extra.error.code).toBe('invalid_input')
  })
})
