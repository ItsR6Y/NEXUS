import { DEFAULT_SETTINGS, type Settings } from '../../src/shared/ipc'
import type {
  Envelope, ExecutionDTO, McpStatusDTO, ServerPrivateInfo, SessionDTO
} from '../../src/shared/types'

export const ok = <T,>(data: T): Envelope<T> => ({ ok: true, data })

/** Install a partial `window.nexus` stub; `on` channels default to no-op subscriptions. */
export function installApi(stub: Record<string, unknown>): Window['nexus'] {
  const api = { on: noEvents(), ...stub } as unknown as Window['nexus']
  Object.defineProperty(window, 'nexus', { value: api, configurable: true, writable: true })
  return api
}

export function noEvents(): Window['nexus']['on'] {
  const unsub = (): void => {}
  return {
    terminalData: () => unsub,
    terminalClosed: () => unsub,
    sessionsChanged: () => unsub,
    approvalsChanged: () => unsub,
    knownHostsChanged: () => unsub,
    mcpChanged: () => unsub,
    executionsChanged: () => unsub,
    securityChanged: () => unsub
  }
}

export const session = (over: Partial<SessionDTO> = {}): SessionDTO => ({
  id: 's-1',
  serverId: 'srv-1',
  serverName: 'prod',
  title: 'prod',
  epoch: 3,
  state: 'connected',
  openedAt: 1_700_000_000_000,
  closedAt: null,
  hasShell: true,
  error: null,
  ...over
})

export const server = (over: Partial<ServerPrivateInfo> = {}): ServerPrivateInfo => ({
  id: 'srv-1',
  name: 'prod',
  host: '10.0.0.1',
  port: 22,
  username: 'deploy',
  authType: 'password',
  approvalPolicy: 'ask',
  mcpAccessEnabled: false,
  connected: false,
  keyPath: null,
  credentials: { password: false, passphrase: false },
  knownHost: null,
  createdAt: 1_700_000_000_000,
  updatedAt: 1_700_000_000_000,
  ...over
})

export const settings = (over: Partial<Settings> = {}): Settings => ({ ...DEFAULT_SETTINGS, ...over })

export const execution = (over: Partial<ExecutionDTO> = {}): ExecutionDTO => ({
  id: 'exec-1',
  serverId: 'srv-1',
  sessionId: 's-1',
  source: 'user',
  requester: 'gui',
  commandSanitized: 'uptime',
  level: 'LOW',
  flags: [],
  status: 'completed',
  exitCode: 0,
  signal: null,
  startedAt: 1_700_000_000_000,
  finishedAt: 1_700_000_001_000,
  truncated: false,
  outputBytes: 12,
  denialReason: null,
  approvalId: null,
  ...over
})

export const mcpStatus = (over: Partial<McpStatusDTO> = {}): McpStatusDTO => ({
  enabled: true,
  listening: true,
  pipeName: null,
  endpointFile: null,
  clients: [],
  recentCalls: [],
  registrationCommand: 'claude mcp add nexus -- node nexus-mcp.mjs',
  jsonConfig: '{}',
  ...over
})
