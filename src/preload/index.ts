import { contextBridge, ipcRenderer } from 'electron'
import type { NexusApi } from '../shared/api'
import { EVENTS } from '../shared/events'

function deepFreeze<T>(obj: T): T {
  if (obj && typeof obj === 'object') {
    Object.freeze(obj)
    for (const v of Object.values(obj as Record<string, unknown>)) deepFreeze(v)
  }
  return obj
}

/** Pure factory exported for unit-testing the exact allowlisted preload surface. */
export function buildPreloadApi(ipc: {
  invoke: (channel: string, payload?: unknown) => Promise<unknown>
  on: (channel: string, listener: (_e: unknown, payload: unknown) => void) => void
  removeListener: (channel: string, listener: (_e: unknown, payload: unknown) => void) => void
}): NexusApi {
  const call = <T>(channel: string, payload?: unknown): Promise<T> => ipc.invoke(channel, payload) as Promise<T>
  const on = <T>(evt: string, cb: (p: T) => void): (() => void) => {
    // Strip the raw IpcRendererEvent before forwarding to renderer listeners.
    const listener = (_e: unknown, p: unknown): void => cb(p as T)
    ipc.on(evt, listener)
    return () => { ipc.removeListener(evt, listener) }
  }

  const api: NexusApi = {
    app: {
      info: () => call('app:info'),
      openLogsFolder: () => call('app:openLogsFolder')
    },
    dashboard: { get: () => call('dashboard:get') },
    servers: {
      list: () => call('servers:list'),
      create: (input) => call('servers:create', input),
      update: (id, patch) => call('servers:update', { id, patch }),
      delete: (id) => call('servers:delete', { id }),
      setSecret: (id, kind, secret) => call('servers:setSecret', { id, kind, secret }),
      clearSecret: (id, kind) => call('servers:clearSecret', { id, kind }),
      pickKeyPath: () => call('servers:pickKeyPath')
    },
    sessions: {
      list: () => call('sessions:list'),
      connect: (serverId) => call('sessions:connect', { serverId }),
      disconnect: (sessionId) => call('sessions:disconnect', { sessionId })
    },
    knownHosts: {
      list: () => call('knownHosts:list'),
      remove: (host, port, keyType) => call('knownHosts:remove', { host, port, keyType })
    },
    terminal: {
      open: (sessionId, cols, rows) => call('terminal:open', { sessionId, cols, rows }),
      input: (sessionId, data) => call('terminal:input', { sessionId, data }),
      resize: (sessionId, cols, rows) => call('terminal:resize', { sessionId, cols, rows }),
      close: (sessionId) => call('terminal:close', { sessionId })
    },
    commands: {
      execute: (input) => call('commands:execute', input),
      cancel: (commandId) => call('commands:cancel', { commandId })
    },
    approvals: {
      list: () => call('approvals:list')
    },
    executions: {
      list: (filter) => call('executions:list', filter),
      get: (id) => call('executions:get', { id }),
      output: (id, afterSeq, maxBytes) => call('executions:output', { id, afterSeq, maxBytes }),
      clear: () => call('executions:clear')
    },
    security: { events: () => call('security:events') },
    audit: {
      verify: () => call('audit:verify'),
      list: (limit) => call('audit:list', { limit })
    },
    mcp: {
      status: () => call('mcp:status'),
      setEnabled: (enabled) => call('mcp:setEnabled', { enabled }),
      disconnectClient: (clientId) => call('mcp:disconnectClient', { clientId })
    },
    settings: {
      get: () => call('settings:get'),
      set: (patch) => call('settings:set', patch)
    },
    on: {
      terminalData: (cb) => on(EVENTS.terminalData, cb),
      terminalClosed: (cb) => on(EVENTS.terminalClosed, cb),
      sessionsChanged: (cb) => on(EVENTS.sessionsChanged, cb),
      approvalsChanged: (cb) => on(EVENTS.approvalsChanged, cb),
      knownHostsChanged: (cb) => on(EVENTS.knownHostsChanged, cb),
      mcpChanged: (cb) => on(EVENTS.mcpChanged, cb),
      executionsChanged: (cb) => on(EVENTS.executionsChanged, cb),
      securityChanged: (cb) => on(EVENTS.securityChanged, cb)
    }
  }
  return deepFreeze(api)
}

if (typeof contextBridge !== 'undefined' && typeof ipcRenderer !== 'undefined') {
  contextBridge.exposeInMainWorld('nexus', buildPreloadApi(ipcRenderer))
}
