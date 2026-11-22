import { EventEmitter } from 'node:events'
import { chmodSync, existsSync, unlinkSync } from 'node:fs'
import net from 'node:net'
import { randomUUID } from 'node:crypto'
import {
  AuthFrame, BRIDGE_VERSION, FrameDecoder, RequestFrame, encodeFrame, newNonce, toolSchemas, verifyHmac, type ToolName
} from '../../../shared/bridge'
import type { McpClientDTO } from '../../../shared/types'
import type { AuditLogger } from '../audit/audit-logger'

export class ToolError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message)
    this.name = 'ToolError'
  }
}

export type ToolHandler = (client: { id: string; name: string }, tool: ToolName, args: Record<string, unknown>) => Promise<unknown>

export interface BridgeLimits {
  maxConnections: number
  ratePerSec: number
  idleMs: number
  authDeadlineMs: number
  maxInFlight: number
  lockoutAfter: number
  lockoutMs: number
}

export const DEFAULT_LIMITS: BridgeLimits = {
  maxConnections: 8,
  ratePerSec: 10,
  idleMs: 10 * 60_000,
  authDeadlineMs: 5_000,
  maxInFlight: 4,
  lockoutAfter: 5,
  lockoutMs: 30_000
}

interface Conn {
  id: string
  sock: net.Socket
  name: string
  version: string
  connectedAt: number
  calls: number
  authed: boolean
}

export class BridgeServer extends EventEmitter {
  private server: net.Server | null = null
  private conns = new Map<string, Conn>()
  private failures: number[] = []
  private lockedUntil = 0

  constructor(
    private opts: {
      pipePath: string
      secret: string
      handler: ToolHandler
      audit: AuditLogger
      limits?: Partial<BridgeLimits>
      now?: () => number
      platform?: NodeJS.Platform
    }
  ) {
    super()
  }

  private get lim(): BridgeLimits { return { ...DEFAULT_LIMITS, ...this.opts.limits } }
  private now = (): number => (this.opts.now ?? Date.now)()
  get listening(): boolean { return this.server?.listening ?? false }
  get pipePath(): string { return this.opts.pipePath }

  clients(): McpClientDTO[] {
    return [...this.conns.values()]
      .filter((c) => c.authed)
      .map((c) => ({ id: c.id, name: c.name, version: c.version, connectedAt: c.connectedAt, calls: c.calls }))
  }

  disconnectClient(id: string): boolean {
    const c = this.conns.get(id)
    if (!c) return false
    c.sock.destroy()
    return true
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      if ((this.opts.platform ?? process.platform) !== 'win32' && existsSync(this.opts.pipePath)) {
        try { unlinkSync(this.opts.pipePath) } catch { /* ignore */ }
      }
      const srv = net.createServer({ allowHalfOpen: false }, (s) => this.onConnection(s))
      srv.maxConnections = this.lim.maxConnections
      srv.once('error', reject)
      srv.listen(this.opts.pipePath, () => {
        if ((this.opts.platform ?? process.platform) !== 'win32') {
          try { chmodSync(this.opts.pipePath, 0o600) } catch { /* ignore */ }
        }
        this.server = srv
        resolve()
      })
    })
  }

  async stop(): Promise<void> {
    for (const c of this.conns.values()) c.sock.destroy()
    this.conns.clear()
    const s = this.server
    this.server = null
    if (s) await new Promise<void>((r) => s.close(() => r()))
    if ((this.opts.platform ?? process.platform) !== 'win32' && existsSync(this.opts.pipePath)) {
      try { unlinkSync(this.opts.pipePath) } catch { /* ignore */ }
    }
    this.emit('changed')
  }

  private authFailure(reason: string): void {
    const t = this.now()
    this.failures = this.failures.filter((x) => t - x < 60_000)
    this.failures.push(t)
    this.opts.audit.securityEvent('mcp_auth_failure', 'critical', { reason, recentFailures: this.failures.length })
    if (this.failures.length >= this.lim.lockoutAfter) {
      this.lockedUntil = t + this.lim.lockoutMs
      this.opts.audit.securityEvent('mcp_lockout', 'critical', { untilMs: this.lim.lockoutMs })
    }
  }

  private onConnection(sock: net.Socket): void {
    const lim = this.lim
    if (this.now() < this.lockedUntil || this.conns.size >= lim.maxConnections) {
      sock.destroy()
      return
    }
    const conn: Conn = { id: randomUUID(), sock, name: 'unauthenticated', version: '', connectedAt: this.now(), calls: 0, authed: false }
    this.conns.set(conn.id, conn)
    const dec = new FrameDecoder()
    const nonce = newNonce()
    let inFlight = 0
    let tokens = lim.ratePerSec
    let last = this.now()

    const send = (o: unknown): void => {
      if (!sock.destroyed) {
        try { sock.write(encodeFrame(o)) } catch { sock.destroy() }
      }
    }
    const fatal = (code: string, message: string): void => {
      send({ type: 'fatal', code, message })
      sock.end()
      setTimeout(() => sock.destroy(), 50).unref()
    }
    const authTimer = setTimeout(() => {
      if (!conn.authed) {
        this.authFailure('handshake timeout')
        fatal('auth_timeout', 'handshake timed out')
      }
    }, lim.authDeadlineMs)
    authTimer.unref()
    sock.setTimeout(lim.idleMs, () => fatal('idle_timeout', 'idle timeout'))
    sock.on('close', () => { clearTimeout(authTimer); this.conns.delete(conn.id); this.emit('changed') })
    sock.on('error', () => sock.destroy())
    send({ type: 'hello', v: BRIDGE_VERSION, nonce })

    sock.on('data', (chunk: Buffer) => {
      let frames: unknown[]
      try { frames = dec.push(chunk) } catch { this.authFailure('malformed or oversized frame'); return fatal('bad_frame', 'malformed frame') }
      for (const f of frames) {
        if (!conn.authed) {
          const p = AuthFrame.safeParse(f)
          if (!p.success) { this.authFailure('invalid auth frame'); return fatal('auth_failed', 'authentication failed') }
          if (!verifyHmac(this.opts.secret, nonce, p.data.clientNonce, p.data.hmac)) {
            this.authFailure('hmac mismatch')
            return fatal('auth_failed', 'authentication failed')
          }
          conn.authed = true
          conn.name = p.data.client.name
          conn.version = p.data.client.version
          clearTimeout(authTimer)
          this.opts.audit.log('mcp.client.connected', `mcp:${conn.name}`, { clientId: conn.id, version: conn.version })
          send({ type: 'ready' })
          this.emit('changed')
          continue
        }
        const r = RequestFrame.safeParse(f)
        if (!r.success) {
          const maybeId = typeof f === 'object' && f !== null && typeof (f as { id?: unknown }).id === 'string' ? (f as { id: string }).id : 'unknown'
          send({ type: 'response', id: maybeId, ok: false, error: { code: 'unknown_method', message: 'invalid request frame or disallowed tool' } })
          continue
        }
        const { id, tool, args } = r.data
        const t = this.now()
        tokens = Math.min(lim.ratePerSec, tokens + ((t - last) / 1000) * lim.ratePerSec)
        last = t
        if (tokens < 1) {
          send({ type: 'response', id, ok: false, error: { code: 'rate_limited', message: 'too many requests' } })
          continue
        }
        tokens -= 1
        if (inFlight >= lim.maxInFlight) {
          send({ type: 'response', id, ok: false, error: { code: 'busy', message: 'too many in-flight requests' } })
          continue
        }
        const parsed = toolSchemas[tool].safeParse(args)
        if (!parsed.success) {
          send({
            type: 'response',
            id,
            ok: false,
            error: { code: 'invalid_args', message: parsed.error.issues.map((i) => `${i.path.join('.') || 'args'}: ${i.message}`).join('; ').slice(0, 500) }
          })
          continue
        }
        inFlight++
        conn.calls++
        this.handle(conn, tool, parsed.data as Record<string, unknown>)
          .then((resp) => send({ type: 'response', id, ...resp }))
          .finally(() => { inFlight-- })
      }
    })
  }

  private async handle(conn: Conn, tool: ToolName, args: Record<string, unknown>): Promise<{ ok: true; result: unknown } | { ok: false; error: { code: string; message: string } }> {
    try {
      const result = await this.opts.handler({ id: conn.id, name: conn.name }, tool, args)
      this.emit('call', { ts: this.now(), client: conn.name, tool, ok: true })
      return { ok: true, result }
    } catch (e) {
      const code =
        e instanceof ToolError
          ? e.code
          : (e as Error).name === 'AuthorizationError' && typeof (e as { code?: unknown }).code === 'string'
            ? (e as { code: string }).code
            : 'internal'
      const message = code === 'internal' ? 'internal error' : (e as Error).message
      if (code === 'internal') this.opts.audit.log('mcp.internal_error', `mcp:${conn.name}`, { tool, message: (e as Error).message })
      this.emit('call', { ts: this.now(), client: conn.name, tool, ok: false, code })
      return { ok: false, error: { code, message } }
    }
  }
}
