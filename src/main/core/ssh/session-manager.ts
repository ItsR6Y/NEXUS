import { EventEmitter } from 'node:events'
import { readFileSync } from 'node:fs'
import { StringDecoder } from 'node:string_decoder'
import { Client, type ClientChannel, type ConnectConfig } from 'ssh2'
import type { ConnectResult, SessionDTO, SessionState } from '../../../shared/types'
import type { Settings } from '../../../shared/ipc'
import type { SessionRepo, SessionRow, ServerRepo, ServerRow } from '../db/repositories'
import type { CredentialStore } from '../credentials/credential-store'
import type { AuditLogger } from '../audit/audit-logger'
import type { CommandAuthorizer, ResolvedExecutionContext } from '../security/authorization'
import { redactText } from '../security/redaction'

function clearSecretBuffer(value: Buffer | null): void {
  if (value) value.fill(0)
}
import { HostKeyService, type HostKeyVerifyOutcome } from './host-keys'
import { TerminalTailBuffer } from './terminal-tail'

export interface ExecHandlers {
  onData(text: string, stream: 'stdout' | 'stderr'): void
  onExit(info: { code: number | null; signal: string | null }): void
  onError(err: Error): void
}

export interface ExecHandle {
  cancel(signal?: string): void
}

export interface ExecRunner {
  runExec(sessionId: string, epoch: number, command: string, h: ExecHandlers): ExecHandle
}

interface LiveSession {
  client: Client
  serverId: string
  shell: ClientChannel | null
  tail: TerminalTailBuffer
  pendingOut: string
  flushTimer: ReturnType<typeof setTimeout> | null
  closing: boolean
}

export interface SessionManagerDeps {
  servers: ServerRepo
  sessions: SessionRepo
  creds: CredentialStore
  hostKeys: HostKeyService
  audit: AuditLogger
  authz: () => CommandAuthorizer
  settings: () => Settings
  clientFactory?: () => Client
}

const SHELL_FLUSH_MS = 16
const SHELL_FLUSH_BYTES = 64 * 1024
const HIGH_WATERMARK_BYTES = 256 * 1024

interface PendingConnect {
  serverId: string
  cancel: () => void
}

export class SessionManager extends EventEmitter implements ExecRunner {
  private readonly live = new Map<string, LiveSession>()
  /** Connection attempts that have not yet reached `ready`; cancellable via disconnect(). */
  private readonly pending = new Map<string, PendingConnect>()

  constructor(private readonly d: SessionManagerDeps) {
    super()
  }

  get(sessionId: string): { id: string; serverId: string; title: string; epoch: number; state: string } | null {
    const s = this.d.sessions.get(sessionId)
    if (!s) return null
    const state = s.state === 'connected' && !this.live.has(sessionId) ? 'disconnected' : s.state
    return { id: s.id, serverId: s.serverId, title: s.title, epoch: s.epoch, state }
  }

  /** Authoritative context resolver passed into CommandAuthorizer.authorize(). Verifies session ownership. */
  resolveExecutionContext = (serverId: string, sessionId: string): ResolvedExecutionContext | null => {
    const server = this.d.servers.get(serverId)
    if (!server) return null
    const session = this.get(sessionId)
    if (!session || session.serverId !== serverId) return null
    return {
      serverId: server.id,
      serverName: server.name,
      sessionId: session.id,
      sessionTitle: session.title,
      epoch: session.epoch,
      connected: session.state === 'connected' && this.live.has(sessionId),
      policy: server.approvalPolicy,
      mcpAccessEnabled: server.mcpAccessEnabled
    }
  }

  toDTO(s: SessionRow): SessionDTO {
    const server = this.d.servers.get(s.serverId)
    const state = (this.get(s.id)?.state ?? s.state) as SessionState
    return {
      id: s.id,
      serverId: s.serverId,
      serverName: server?.name ?? '(deleted)',
      title: s.title,
      epoch: s.epoch,
      state,
      openedAt: s.openedAt,
      closedAt: s.closedAt,
      hasShell: !!this.live.get(s.id)?.shell,
      error: s.error
    }
  }

  list(serverId?: string): SessionDTO[] {
    return this.d.sessions.list(serverId).map((s) => this.toDTO(s))
  }

  listConnected(): SessionDTO[] {
    return this.list().filter((s) => s.state === 'connected' && this.live.has(s.id))
  }

  activeFor(serverId: string): SessionRow | null {
    return this.d.sessions.list(serverId).find((s) => this.live.has(s.id) && s.state === 'connected') ?? null
  }

  activeCount(): number {
    return this.live.size
  }

  /** GUI-only: MCP has no path to open or close sessions. */
  async open(serverId: string): Promise<ConnectResult> {
    const server = this.d.servers.get(serverId)
    if (!server) return { status: 'error', code: 'unknown_server', message: 'unknown server' }
    const seq = this.d.sessions.nextSequence(serverId)
    const session = this.d.sessions.create(serverId, `${server.name} #${seq}`)
    const result = await this.establish(session, server)
    if (result.status !== 'connected') {
      // An attempt that never established a connection must not leave a permanent history row.
      if (this.d.sessions.remove(session.id)) this.emit('changed')
    }
    return result
  }

  private async establish(session: SessionRow, server: ServerRow): Promise<ConnectResult> {
    const d = this.d
    let password: string | undefined
    let passphrase: string | undefined
    let keyBuf: Buffer | null = null

    try {
      if (server.authType === 'password') {
        const ok = d.creds.useSecret(server.id, 'password', (p) => {
          password = p
          return true
        })
        if (!ok) return this.fail(session, { status: 'needs_user_input', serverId: server.id, reason: 'no password stored for this server' })
      } else {
        if (!server.keyPath) {
          return this.fail(session, { status: 'needs_user_input', serverId: server.id, reason: 'no private key path configured for this server' })
        }
        try {
          // Read-only in main at connect time; never auto-generate or overwrite user keys.
          keyBuf = readFileSync(server.keyPath)
        } catch {
          return this.fail(session, { status: 'error', code: 'key_unreadable', message: 'private key file is missing or unreadable' })
        }
        d.creds.useSecret(server.id, 'passphrase', (p) => {
          passphrase = p
          return true
        })
      }
    } catch (e) {
      clearSecretBuffer(keyBuf)
      keyBuf = null
      return this.fail(session, { status: 'error', code: 'credential_error', message: redactText((e as Error).message, d.creds.redactionValues()) })
    }

    d.sessions.setState(session.id, 'connecting')
    this.emit('changed')
    d.audit.log('ssh.connect.begin', 'user', { serverId: server.id, sessionId: session.id, host: server.host, port: server.port })

    const client = d.clientFactory ? d.clientFactory() : new Client()
    let hostOutcome: HostKeyVerifyOutcome | null = null
    // Cancellation state for a connection that is still in its handshake.
    let cancelled = false
    this.pending.set(session.id, {
      serverId: server.id,
      cancel: () => {
        cancelled = true
        try { client.end() } catch { /* ignore */ }
      }
    })

    const zeroKey = (): void => {
      if (keyBuf) {
        keyBuf.fill(0)
        keyBuf = null
      }
      password = undefined
      passphrase = undefined
    }

    return new Promise<ConnectResult>((resolve) => {
      let settled = false
      const finish = (r: ConnectResult): void => {
        if (settled) return
        settled = true
        this.pending.delete(session.id)
        zeroKey()
        resolve(r)
      }
      const cancelResult: ConnectResult = { status: 'error', code: 'cancelled', message: 'connection cancelled before it was established' }

      const toHostResult = (ho: HostKeyVerifyOutcome): ConnectResult => {
        if (ho.accepted) return { status: 'error', code: 'internal', message: 'unexpected state' }
        if (ho.state === 'mismatch') {
          return {
            status: 'host_key_mismatch',
            serverId: server.id,
            algorithm: ho.keyType,
            expectedFingerprint: ho.expectedFingerprint,
            actualFingerprint: ho.fingerprint
          }
        }
        return { status: 'host_key_rejected', serverId: server.id, fingerprint: ho.fingerprint, reason: ho.reason }
      }

      client.on('ready', () => {
        if (cancelled) {
          try { client.end() } catch { /* ignore */ }
          return finish(cancelResult)
        }
        const epoch = d.sessions.bumpEpoch(session.id)
        d.authz().invalidateSession(session.id, 'connection epoch changed')
        d.sessions.setState(session.id, 'connected')
        this.live.set(session.id, {
          client,
          serverId: server.id,
          shell: null,
          tail: new TerminalTailBuffer(d.settings().terminalTailBytes),
          pendingOut: '',
          flushTimer: null,
          closing: false
        })
        d.audit.log('ssh.connected', 'system', { serverId: server.id, sessionId: session.id, epoch })
        this.emit('changed')
        const updated = d.sessions.get(session.id)
        if (!updated) return finish({ status: 'error', code: 'session_missing', message: 'session disappeared' })
        finish({ status: 'connected', session: this.toDTO(updated) })
      })

      client.on('error', (_err: Error) => {
        if (cancelled) return finish(cancelResult)
        // Transport errors can include hostnames, usernames, and ports; expose only a stable message.
        const msg = 'SSH connection failed'
        if (hostOutcome && !hostOutcome.accepted) {
          const res = toHostResult(hostOutcome)
          if (!settled) this.fail(session, res)
          return finish(res)
        }
        d.audit.log('ssh.connect.error', 'system', { serverId: server.id, sessionId: session.id, message: msg })
        if (!settled) {
          d.sessions.setState(session.id, 'error', msg)
          this.emit('changed')
          finish({ status: 'error', code: 'ssh_error', message: msg })
        } else {
          this.teardown(session.id, `error: ${msg}`, true)
        }
      })

      client.on('close', () => {
        if (cancelled) return finish(cancelResult)
        if (hostOutcome && !hostOutcome.accepted) {
          const res = toHostResult(hostOutcome)
          if (!settled) this.fail(session, res)
          return finish(res)
        }
        if (!settled) {
          d.sessions.setState(session.id, 'error', 'connection closed')
          this.emit('changed')
          finish({ status: 'error', code: 'connection_closed', message: 'connection closed before authentication completed' })
        } else if (this.live.get(session.id)?.client === client) {
          this.teardown(session.id, 'remote closed', true)
        }
      })

      const cfg: ConnectConfig = {
        host: server.host,
        port: server.port,
        username: server.username,
        readyTimeout: 20_000,
        keepaliveInterval: 15_000,
        keepaliveCountMax: 3,
        tryKeyboard: false,
        hostVerifier: (key: Buffer, verify: (ok: boolean) => void) => {
          void d.hostKeys
            .verify(server, key)
            .then((outcome) => {
              hostOutcome = outcome
              verify(outcome.accepted)
            })
            .catch(() => {
              verify(false)
            })
        }
      }
      if (server.authType === 'password') {
        cfg.password = password
      } else if (keyBuf) {
        cfg.privateKey = keyBuf
        if (passphrase) cfg.passphrase = passphrase
      }

      try {
        client.connect(cfg)
      } catch (e) {
        const msg = redactText((e as Error).message, d.creds.redactionValues())
        d.sessions.setState(session.id, 'error', msg)
        finish({ status: 'error', code: 'ssh_error', message: msg })
      }
    })
  }

  private fail(session: SessionRow, r: ConnectResult): ConnectResult {
    const errText = r.status === 'error' ? r.message : r.status
    this.d.sessions.setState(session.id, r.status === 'error' ? 'error' : 'disconnected', errText)
    this.emit('changed')
    return r
  }

  disconnect(sessionId: string, reason = 'user'): void {
    this.teardown(sessionId, reason, true)
  }

  disconnectServer(serverId: string, reason: string): void {
    for (const [id, l] of [...this.live]) {
      if (l.serverId === serverId) this.teardown(id, reason, true)
    }
    for (const [id, p] of [...this.pending]) {
      if (p.serverId === serverId) this.teardown(id, reason, true)
    }
  }

  disconnectAll(): void {
    for (const id of [...this.live.keys(), ...this.pending.keys()]) this.teardown(id, 'app shutdown', true)
  }

  private teardown(sessionId: string, reason: string, markState: boolean): void {
    // A connection attempt that is still in its handshake has no live entry yet; cancel it here.
    const p = this.pending.get(sessionId)
    if (p) {
      this.pending.delete(sessionId)
      p.cancel()
      this.d.audit.log('ssh.connect.cancelled', 'user', { sessionId, serverId: p.serverId, reason })
    }
    const l = this.live.get(sessionId)
    if (l) {
      l.closing = true
      if (l.flushTimer) clearTimeout(l.flushTimer)
      this.live.delete(sessionId)
      try { l.shell?.close() } catch { /* ignore */ }
      try { l.client.end() } catch { /* ignore */ }
      this.emit('shell-closed', sessionId, reason)
    }
    if (markState) {
      const s = this.d.sessions.get(sessionId)
      if (s && s.state !== 'disconnected') this.d.sessions.setState(sessionId, 'disconnected')
    }
    this.d.authz().invalidateSession(sessionId, `session ${reason}`)
    if (l) this.d.audit.log('ssh.disconnected', 'system', { sessionId, serverId: l.serverId, reason })
    this.emit('changed')
  }

  // ---- Interactive PTY shell (user keystrokes are not approval-gated per plan §1 #6) ----
  openShell(sessionId: string, cols: number, rows: number, webContentsId: number | null = null): Promise<void> {
    const l = this.live.get(sessionId)
    if (!l) return Promise.reject(new Error('session is not connected'))
    if (l.shell) {
      try { l.shell.setWindow(rows, cols, 0, 0) } catch { /* ignore */ }
      return Promise.resolve()
    }
    return new Promise((resolve, reject) => {
      l.client.shell({ term: 'xterm-256color', cols, rows }, (err, stream) => {
        if (err) return reject(err)
        l.shell = stream
        const dec = new StringDecoder('utf8')

        const flush = (): void => {
          if (l.flushTimer) { clearTimeout(l.flushTimer); l.flushTimer = null }
          if (!l.pendingOut) return
          const batch = l.pendingOut
          l.pendingOut = ''
          this.emit('shell-data', sessionId, batch)
          if (stream.isPaused()) stream.resume()
        }

        const enqueue = (text: string): void => {
          l.tail.append(text)
          l.pendingOut += text
          if (Buffer.byteLength(l.pendingOut, 'utf8') >= HIGH_WATERMARK_BYTES && !stream.isPaused()) {
            stream.pause()
          }
          if (Buffer.byteLength(l.pendingOut, 'utf8') >= SHELL_FLUSH_BYTES) {
            flush()
          } else if (!l.flushTimer) {
            l.flushTimer = setTimeout(flush, SHELL_FLUSH_MS)
            l.flushTimer.unref()
          }
        }

        stream.on('data', (b: Buffer) => enqueue(dec.write(b)))
        stream.stderr.on('data', (b: Buffer) => enqueue(b.toString('utf8')))
        stream.on('close', () => {
          const rem = dec.end()
          if (rem) enqueue(rem)
          flush()
          if (l.shell === stream) l.shell = null
          if (!l.closing) this.emit('shell-closed', sessionId, 'shell exited')
          this.emit('changed')
        })
        // The originating renderer is recorded so an interactive shell can be traced to a window.
        this.d.audit.log('shell.opened', 'user', { sessionId, serverId: l.serverId, webContentsId })
        this.emit('changed')
        resolve()
      })
    })
  }

  shellInput(sessionId: string, data: string): void {
    const l = this.live.get(sessionId)
    if (!l || !l.shell) throw new Error('no open shell')
    l.shell.write(data)
  }

  shellResize(sessionId: string, cols: number, rows: number): void {
    try { this.live.get(sessionId)?.shell?.setWindow(rows, cols, 0, 0) } catch { /* ignore */ }
  }

  closeShell(sessionId: string): void {
    try { this.live.get(sessionId)?.shell?.close() } catch { /* ignore */ }
  }

  /** Read bounded, ANSI-stripped, redacted terminal tail for MCP `nexus_read_terminal_tail`. */
  readTerminalTail(sessionId: string, lines: number): string | null {
    const l = this.live.get(sessionId)
    if (!l) return null
    l.tail.setMaxBytes(this.d.settings().terminalTailBytes)
    return l.tail.readTail(lines, this.d.creds.redactionValues())
  }

  // ---- Separate programmatic exec channel (only called by ExecutionService) ----
  runExec(sessionId: string, epoch: number, command: string, h: ExecHandlers): ExecHandle {
    const l = this.live.get(sessionId)
    const cur = this.d.sessions.get(sessionId)
    if (!l || !cur || cur.epoch !== epoch) {
      throw new Error('session is not connected at the authorized connection epoch')
    }
    let stream: ClientChannel | null = null
    let cancelled: string | null = null
    l.client.exec(command, (err, s) => {
      if (err) return h.onError(err)
      stream = s
      if (cancelled) {
        try { s.signal(cancelled); s.close() } catch { /* ignore */ }
      }
      const out = new StringDecoder('utf8')
      const er = new StringDecoder('utf8')
      s.on('data', (b: Buffer) => h.onData(out.write(b), 'stdout'))
      s.stderr.on('data', (b: Buffer) => h.onData(er.write(b), 'stderr'))
      s.on('close', (code: number | null, signal: string | null) => {
        const a = out.end()
        if (a) h.onData(a, 'stdout')
        const b = er.end()
        if (b) h.onData(b, 'stderr')
        h.onExit({ code: code ?? null, signal: signal ?? null })
      })
      s.on('error', (e: Error) => h.onError(e))
    })
    return {
      cancel: (sig = 'KILL') => {
        cancelled = sig
        try { stream?.signal(sig); stream?.close() } catch { /* ignore */ }
      }
    }
  }
}
