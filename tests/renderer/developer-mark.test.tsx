/**
 * @vitest-environment jsdom
 */
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { App } from '../../src/renderer/src/App'
import type { DashboardDTO } from '../../src/shared/types'
import { installApi, ok, settings } from './harness'

vi.mock('@xterm/xterm', async () => ({ Terminal: (await import('./xterm')).FakeTerminal }))
vi.mock('@xterm/addon-fit', async () => ({ FitAddon: (await import('./xterm')).FakeFitAddon }))
vi.mock('@xterm/addon-search', async () => ({ SearchAddon: (await import('./xterm')).FakeSearchAddon }))

const dashboard: DashboardDTO = {
  serverCount: 0,
  activeSessions: 0,
  pendingApprovals: 0,
  mcpListening: true,
  mcpClients: 0,
  recentExecutions: [],
  securityEvents24h: 0,
  auditChain: { ok: true, entries: 0, brokenAt: null },
  credentialBackend: 'keyring',
  credentialsAvailable: true
}

const install = (): void => {
  installApi({
    settings: { get: async () => ok(settings()) },
    approvals: { list: async () => ok([]) },
    dashboard: { get: async () => ok(dashboard) },
    sessions: { list: async () => ok([]), disconnect: async () => ok(true) },
    terminal: {
      open: async () => ok(true),
      input: async () => ok(true),
      resize: async () => ok(true),
      close: async () => ok(true)
    },
    commands: {
      execute: async () => ok({ status: 'denied', commandId: 'x', reason: 'test', level: 'LOW' }),
      cancel: async () => ok({ cancelled: false })
    }
  })
}

beforeEach(() => install())
afterEach(cleanup)

describe('Developer mark', () => {
  it('renders the author credit in the sidebar footer without disturbing the status bar', async () => {
    render(<App />)
    const mark = await screen.findByTestId('developer-mark')
    expect(mark.textContent).toBe('NEXUS · by Ray')
    expect(await screen.findByTestId('claude-status')).toBeTruthy()
  })
})
