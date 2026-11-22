import { ZodError } from 'zod'
import { isTrustedRendererUrl } from '../protocol'
import { CHANNELS, EVENTS, channelSchemas, type Channel, type Settings } from '../../shared/ipc'
import type { ApprovalDTO, DashboardDTO, Envelope, ExecutionDTO } from '../../shared/types'
import type { ApprovalRow, ExecutionRow } from '../core/db/repositories'
import { CredentialError } from '../core/credentials/credential-store'
import { AuthorizationError } from '../core/security/authorization'
import { redactText } from '../core/security/redaction'
import type { Services } from '../services'

export interface IpcEventLike {
  sender?: { id?: number }
  senderFrame: { url: string; parent?: { url: string } | null } | null
}

export interface IpcMainLike {
  handle(channel: string, listener: (event: IpcEventLike, ...args: unknown[]) => unknown): void
}

export interface IpcDeps {
  services: Services
  trustedOrigin: string
  getExpectedWebContentsId?: () => number | null
  send: (event: string, payload: unknown) => void
  pickKeyPath: () => Promise<string | null>
  openLogsFolder: () => Promise<void>
  confirmClearHistory: () => Promise<boolean>
  appInfo: { version: string; platform: string }
}

export function isTrustedOrigin(url: string | undefined | null, trustedOrigin: string): boolean {
  if (!url) return false
  return isTrustedRendererUrl(url, trustedOrigin)
}

export function isTrustedEvent(event: IpcEventLike, trustedOrigin: string, expectedWebContentsId?: number | null): boolean {
  const frame = event.senderFrame
  if (!frame || ('parent' in frame && frame.parent !== null) || !isTrustedOrigin(frame.url, trustedOrigin)) return false
  if (expectedWebContentsId != null && event.sender?.id !== expectedWebContentsId) return false
  return true
}

export function sanitizeError(e: unknown, secrets: Iterable<string> = []): { code: string; message: string } {
  if (e instanceof ZodError) return { code: 'invalid_input', message: 'invalid request payload' }
  if (e instanceof AuthorizationError) return { code: e.code, message: redactText(e.message, secrets) }
  if (e instanceof CredentialError) return { code: e.code, message: redactText(e.message, secrets) }
  const msg = (e as Error)?.message ?? ''
  if (/UNIQUE|constraint|CHECK/i.test(msg)) return { code: 'conflict', message: 'that value conflicts with existing data' }
  if (/not found|no open shell|not connected|unknown/i.test(msg) && msg.length < 120) {
    return { code: 'not_found', message: redactText(msg, secrets) }
  }
  return { code: 'internal_error', message: 'operation failed' }
}

export function approvalToDTO(a: ApprovalRow, serverName: string): ApprovalDTO {
  return {
    id: a.id,
    commandSanitized: a.commandSanitized,
    serverId: a.serverId,
    serverName,
    sessionId: a.sessionId,
    epoch: a.epoch,
    level: a.level,
    reasons: a.reasons,
    flags: a.flags,
    source: a.source,
    requester: a.requester,
    status: a.status,
    createdAt: a.createdAt,
    expiresAt: a.expiresAt,
    timeoutMs: a.timeoutMs,
    maxOutputBytes: a.maxOutputBytes,
    invalidationReason: a.invalidationReason
  }
}

export function executionToDTO(e: ExecutionRow): ExecutionDTO {
  return {
    id: e.id,
    serverId: e.serverId,
    sessionId: e.sessionId,
    source: e.source,
    requester: e.requester,
    commandSanitized: e.commandSanitized,
    level: e.level,
    flags: e.flags,
    status: e.status,
    exitCode: e.exitCode,
    signal: e.signal,
    startedAt: e.startedAt,
    finishedAt: e.finishedAt,
    truncated: e.truncated,
    outputBytes: e.outputBytes,
    denialReason: e.denialReason,
    approvalId: e.approvalId
  }
}

type Handler = (payload: never, ev: IpcEventLike) => unknown | Promise<unknown>

export function buildHandlers(d: IpcDeps): Record<Channel, Handler> {
  const s = d.services
  const name = (id: string): string => s.serverRepo.get(id)?.name ?? '(deleted)'
  const apprDto = (a: ApprovalRow): ApprovalDTO => approvalToDTO(a, name(a.serverId))

  const dashboard = (): DashboardDTO => ({
    serverCount: s.serverRepo.list().length,
    activeSessions: s.sessions.activeCount(),
    pendingApprovals: s.authz.pendingCount(),
    mcpListening: s.mcp.listening,
    mcpClients: s.mcp.clientCount,
    recentExecutions: s.executionRepo.list({ limit: 8 }).map(executionToDTO),
    securityEvents24h: s.audit.countSecurityEventsSince(Date.now() - 86_400_000),
    auditChain: s.audit.lastVerify(),
    credentialBackend: s.creds.backendName(),
    credentialsAvailable: s.creds.available()
  })

  return {
    'app:info': () => ({
      ...d.appInfo,
      credentialBackend: s.creds.backendName(),
      credentialsAvailable: s.creds.available()
    }),
    'app:openLogsFolder': async () => {
      await d.openLogsFolder()
      return true
    },
    'dashboard:get': dashboard,
    'servers:list': () => s.servers.listPrivate(),
    'servers:create': (p: never) => s.servers.create(p),
    'servers:update': (p: { id: string; patch: Record<string, never> }) => s.servers.update(p.id, p.patch),
    'servers:delete': (p: { id: string }) => {
      s.servers.delete(p.id)
      return true
    },
    'servers:setSecret': (p: { id: string; kind: 'password' | 'passphrase'; secret: string }) => s.servers.setSecret(p.id, p.kind, p.secret),
    'servers:clearSecret': (p: { id: string; kind: 'password' | 'passphrase' }) => s.servers.clearSecret(p.id, p.kind),
    'servers:pickKeyPath': () => d.pickKeyPath(),
    'sessions:list': () => s.sessions.list(),
    'sessions:connect': (p: { serverId: string }) => s.sessions.open(p.serverId),
    'sessions:disconnect': (p: { sessionId: string }) => {
      s.sessions.disconnect(p.sessionId, 'user')
      return true
    },
    'knownHosts:list': () => s.hostKeys.list(),
    'knownHosts:remove': async (p: { host: string; port: number; keyType: string }) => ({
      removed: await s.hostKeys.removeWithConfirmation(p.host, p.port, p.keyType)
    }),
    'terminal:open': async (p: { sessionId: string; cols: number; rows: number }, ev: IpcEventLike) => {
      // Record the originating renderer so the shell.opened audit event is attributable.
      await s.sessions.openShell(p.sessionId, p.cols, p.rows, ev.sender?.id ?? null)
      return true
    },
    'terminal:input': (p: { sessionId: string; data: string }) => {
      s.sessions.shellInput(p.sessionId, p.data)
      return true
    },
    'terminal:resize': (p: { sessionId: string; cols: number; rows: number }) => {
      s.sessions.shellResize(p.sessionId, p.cols, p.rows)
      return true
    },
    'terminal:close': (p: { sessionId: string }) => {
      s.sessions.closeShell(p.sessionId)
      return true
    },
    'commands:execute': (p: { serverId: string; sessionId: string; command: string; timeoutMs?: number; maxOutputBytes?: number; clientCommandId?: string }) => {
      // SECURITY: source is hard-coded to 'user' by the IPC transport.
      return s.exec.execute(p, 'user')
    },
    'commands:cancel': (p: { commandId: string }) => ({ cancelled: s.exec.cancel(p.commandId) }),
    'approvals:list': () => s.authz.list().map(apprDto),
    'executions:list': (p: Parameters<Services['exec']['list']>[0]) => s.exec.list(p).map(executionToDTO),
    'executions:get': (p: { id: string }) => {
      const e = s.exec.get(p.id)
      if (!e) throw new Error('not found')
      return executionToDTO(e)
    },
    'executions:output': (p: { id: string; afterSeq: number; maxBytes: number }) => {
      const o = s.exec.getOutput(p.id, p.afterSeq, p.maxBytes)
      if (!o) throw new Error('not found')
      return o
    },
    'executions:clear': async () => {
      const ok = await d.confirmClearHistory()
      return { cleared: ok ? s.exec.clearHistory() : 0 }
    },
    'security:events': () => s.audit.listSecurityEvents(),
    'audit:verify': () => s.audit.verify(),
    'audit:list': (p: { limit: number }) => s.audit.list(p.limit),
    'mcp:status': () => s.mcp.status(s.settings().mcpEnabled),
    'mcp:setEnabled': async (p: { enabled: boolean }) => {
      await s.setMcpEnabled(p.enabled)
      return s.mcp.status(s.settings().mcpEnabled)
    },
    'mcp:disconnectClient': (p: { clientId: string }) => {
      s.mcp.disconnectClient(p.clientId)
      return s.mcp.status(s.settings().mcpEnabled)
    },
    'settings:get': () => s.settings(),
    'settings:set': async (p: Partial<Settings>) => {
      const { mcpEnabled, ...rest } = p
      if (Object.keys(rest).length) {
        s.settingsRepo.patch(rest)
        s.audit.log('settings.changed', 'user', rest)
      }
      if (mcpEnabled !== undefined) await s.setMcpEnabled(mcpEnabled)
      return s.settings()
    }
  }
}

/** Register every allowlisted IPC channel: sender + origin check -> strict Zod -> handler -> sanitized envelope. */
export function registerIpc(ipcMain: IpcMainLike, d: IpcDeps): void {
  const handlers = buildHandlers(d)
  for (const ch of CHANNELS) {
    ipcMain.handle(ch, async (event, ...args: unknown[]): Promise<Envelope<unknown>> => {
      try {
        const expectedId = d.getExpectedWebContentsId?.()
        if (!isTrustedEvent(event, d.trustedOrigin, expectedId)) {
          d.services.audit.securityEvent('ipc_untrusted_sender', 'critical', {
            channel: ch,
            senderId: event.sender?.id ?? null,
            url: String(event.senderFrame?.url ?? 'none').slice(0, 200)
          })
          return { ok: false, error: { code: 'forbidden', message: 'untrusted sender' } }
        }
        if (args.length > 1) throw new ZodError([])
        const payload = channelSchemas[ch].parse(args[0])
        const data = await (handlers[ch] as (p: unknown, e: IpcEventLike) => unknown)(payload, event)
        return { ok: true, data }
      } catch (e) {
        return { ok: false, error: sanitizeError(e, d.services.creds.redactionValues()) }
      }
    })
  }
}

export function wireEvents(s: Services, send: (event: string, payload: unknown) => void): void {
  s.bus.on('shell-data', (sessionId: string, data: string) => send(EVENTS.terminalData, { sessionId, data }))
  s.bus.on('shell-closed', (sessionId: string, reason: string) => send(EVENTS.terminalClosed, { sessionId, reason }))
  for (const [bus, evt] of [
    ['sessions', EVENTS.sessionsChanged],
    ['approvals', EVENTS.approvalsChanged],
    ['knownHosts', EVENTS.knownHostsChanged],
    ['mcp', EVENTS.mcpChanged],
    ['executions', EVENTS.executionsChanged],
    ['security', EVENTS.securityChanged]
  ] as const) {
    s.bus.on(bus, () => send(evt, null))
  }
}
