import type { ToolName } from '../../../shared/bridge'
import type { ServerRepo } from '../db/repositories'
import type { AuditLogger } from '../audit/audit-logger'
import type { ExecutionService } from '../execution/execution-service'
import type { ServerService } from '../servers/server-service'
import type { SessionManager } from '../ssh/session-manager'
import { redactText } from '../security/redaction'
import { ToolError } from './bridge-server'

export interface RouterDeps {
  serverRepo: ServerRepo
  servers: ServerService
  sessions: SessionManager
  exec: ExecutionService
  audit: AuditLogger
  secrets: () => Iterable<string>
}

/**
 * Routes ONLY the 5 authoritative MCP tools from NEXUS-BUILD-PLAN.md:
 *   1. nexus_list_servers       (public info only; never keyPath or credentials)
 *   2. nexus_list_sessions      (connected sessions on MCP-enabled servers only)
 *   3. nexus_run_command        (always source='claude' -> ExecutionService -> CommandAuthorizer -> native dialog)
 *   4. nexus_get_history        (sanitized/redacted history for MCP-enabled servers, limit <= 100)
 *   5. nexus_read_terminal_tail (bounded ANSI-stripped & redacted tail <= 200 lines)
 *
 * MCP CANNOT create/delete servers, open/close/reconnect sessions, access credentials, or approve commands.
 */
export class ToolRouter {
  constructor(private readonly d: RouterDeps) {}

  private requireMcpServer(serverId: string) {
    const s = this.d.serverRepo.get(serverId)
    if (!s) throw new ToolError('unknown_server', 'unknown server')
    if (!s.mcpAccessEnabled) throw new ToolError('mcp_access_disabled', 'MCP access is disabled for this server')
    return s
  }

  async call(client: { name: string }, tool: ToolName, a: Record<string, unknown>): Promise<unknown> {
    const requester = `mcp:${client.name}`
    const d = this.d

    d.audit.log('mcp.call', requester, {
      tool,
      args: tool === 'nexus_run_command' ? { ...a, command: redactText(String(a.command ?? ''), d.secrets()) } : a
    })

    switch (tool) {
      case 'nexus_list_servers': {
        return { servers: d.servers.listPublicForMcp() }
      }

      case 'nexus_list_sessions': {
        const connected = d.sessions.listConnected().filter((s) => !!d.serverRepo.get(s.serverId)?.mcpAccessEnabled)
        return {
          sessions: connected.map((s) => ({
            sessionId: s.id,
            serverId: s.serverId,
            serverName: s.serverName,
            title: s.title,
            state: s.state,
            openedAt: s.openedAt
          }))
        }
      }

      case 'nexus_run_command': {
        const serverId = a.serverId as string
        const sessionId = a.sessionId as string
        const command = a.command as string
        const timeoutMs = a.timeoutMs as number | undefined
        const maxOutputBytes = a.maxOutputBytes as number | undefined
        this.requireMcpServer(serverId)

        // SECURITY: source is hard-coded to 'claude' by this transport — never read from payload.
        const result = await d.exec.execute({ serverId, sessionId, command, requester, timeoutMs, maxOutputBytes }, 'claude')
        return result
      }

      case 'nexus_get_history': {
        const serverId = a.serverId as string | undefined
        const limit = Math.min(100, Math.max(1, (a.limit as number | undefined) ?? 25))
        if (serverId) this.requireMcpServer(serverId)
        const rows = d.exec
          .list({ serverId, limit })
          .filter((e) => !!d.serverRepo.get(e.serverId)?.mcpAccessEnabled)
        return {
          history: rows.map((e) => ({
            commandId: e.id,
            serverId: e.serverId,
            sessionId: e.sessionId,
            source: e.source,
            command: e.commandSanitized,
            risk: e.level,
            status: e.status,
            exitCode: e.exitCode,
            startedAt: e.startedAt,
            finishedAt: e.finishedAt,
            truncated: e.truncated,
            denialReason: e.denialReason
          }))
        }
      }

      case 'nexus_read_terminal_tail': {
        const sessionId = a.sessionId as string
        const lines = Math.min(200, Math.max(1, (a.lines as number | undefined) ?? 50))
        const sess = d.sessions.get(sessionId)
        if (!sess || sess.state !== 'connected') throw new ToolError('session_not_connected', 'session is not connected')
        this.requireMcpServer(sess.serverId)
        const tail = d.sessions.readTerminalTail(sessionId, lines)
        if (tail === null) throw new ToolError('session_not_connected', 'session has no active buffer')
        return { sessionId, lines, redacted: true, tail }
      }

      default: {
        const unreachable: never = tool
        throw new ToolError('unknown_tool', `unknown tool: ${String(unreachable).slice(0, 40)}`)
      }
    }
  }
}
