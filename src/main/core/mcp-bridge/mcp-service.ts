import { EventEmitter } from 'node:events'
import { rmSync } from 'node:fs'
import { dirname } from 'node:path'
import type { McpCallDTO, McpStatusDTO } from '../../../shared/types'
import type { AuditLogger } from '../audit/audit-logger'
import { BridgeServer } from './bridge-server'
import { newEndpoint, newPipePath, writeEndpointFile } from './pipe'
import type { ToolRouter } from './tool-router'

export class McpService extends EventEmitter {
  private bridge: BridgeServer | null = null
  private pipeName: string | null = null
  private recent: McpCallDTO[] = []

  constructor(
    private readonly o: {
      router: ToolRouter
      audit: AuditLogger
      endpointFile: string
      serverScriptPath: string
      platform?: NodeJS.Platform
      limits?: ConstructorParameters<typeof BridgeServer>[0]['limits']
    }
  ) {
    super()
  }

  get listening(): boolean {
    return this.bridge?.listening ?? false
  }

  /** Number of authenticated MCP clients — distinct from "the pipe is listening". */
  get clientCount(): number {
    return this.bridge?.clients().length ?? 0
  }

  async start(): Promise<void> {
    if (this.bridge) return
    const platform = this.o.platform ?? process.platform
    const pipePath = newPipePath(platform, dirname(this.o.endpointFile))
    const ep = newEndpoint(pipePath)
    const bridge = new BridgeServer({
      pipePath,
      secret: ep.secret,
      audit: this.o.audit,
      platform,
      limits: this.o.limits,
      handler: (c, t, a) => this.o.router.call(c, t, a)
    })
    bridge.on('changed', () => this.emit('changed'))
    bridge.on('call', (c: { ts: number; client: string; tool: string; ok: boolean; code?: string }) => {
      this.recent.unshift({ ts: c.ts, client: c.client, tool: c.tool, ok: c.ok, summary: c.ok ? 'ok' : (c.code ?? 'error') })
      this.recent.length = Math.min(this.recent.length, 50)
      this.emit('changed')
    })
    await bridge.start()
    try {
      writeEndpointFile(this.o.endpointFile, ep, platform)
    } catch (e) {
      await bridge.stop()
      throw e
    }
    this.bridge = bridge
    this.pipeName = pipePath
    this.o.audit.log('mcp.started', 'system', { pipe: pipePath.replace(/[0-9a-f]{8,}$/, '<redacted>') })
    this.emit('changed')
  }

  async stop(): Promise<void> {
    const b = this.bridge
    this.bridge = null
    this.pipeName = null
    if (b) await b.stop()
    try { rmSync(this.o.endpointFile, { force: true }) } catch { /* ignore */ }
    if (b) this.o.audit.log('mcp.stopped', 'system', {})
    this.emit('changed')
  }

  disconnectClient(id: string): boolean {
    return this.bridge?.disconnectClient(id) ?? false
  }

  status(enabled: boolean): McpStatusDTO {
    const p = this.o.serverScriptPath
    return {
      enabled,
      listening: this.listening,
      pipeName: this.pipeName ? this.pipeName.replace(/[0-9a-f]{8,}$/, '<per-launch>') : null,
      endpointFile: this.listening ? this.o.endpointFile : null,
      clients: this.bridge?.clients() ?? [],
      recentCalls: this.recent,
      registrationCommand: `claude mcp add nexus --scope project -- node "${p}"`,
      jsonConfig: JSON.stringify({ mcpServers: { nexus: { command: 'node', args: [p] } } }, null, 2)
    }
  }
}
