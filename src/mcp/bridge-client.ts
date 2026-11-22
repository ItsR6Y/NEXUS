import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import net from 'node:net'
import { homedir } from 'node:os'
import { join } from 'node:path'
import {
  AuthFrame, EndpointFile, FatalFrame, FrameDecoder, HelloFrame, ReadyFrame, ResponseFrame,
  computeHmac, encodeFrame, type ToolName
} from '../shared/bridge'

export class BridgeError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message)
    this.name = 'BridgeError'
  }
}

export function defaultEndpointFile(env: NodeJS.ProcessEnv = process.env, platform = process.platform): string {
  if (env.NEXUS_MCP_ENDPOINT) return env.NEXUS_MCP_ENDPOINT
  if (platform === 'win32') return join(env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), 'NEXUS', 'bridge.json')
  if (platform === 'darwin') return join(homedir(), 'Library', 'Application Support', 'NEXUS', 'bridge.json')
  return join(env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'NEXUS', 'bridge.json')
}

interface Pending {
  resolve: (v: unknown) => void
  reject: (e: Error) => void
  timer: NodeJS.Timeout
}

/** Authenticated client for the NEXUS named pipe. Zero SSH, DB, credential, or Electron imports. */
export class BridgeClient {
  private sock: net.Socket | null = null
  private pending = new Map<string, Pending>()
  private seq = 0

  constructor(private readonly o: { endpointFile: string; clientName: string; clientVersion: string; timeoutMs?: number }) {}

  private async connect(): Promise<net.Socket> {
    if (this.sock && !this.sock.destroyed) return this.sock
    let ep
    try {
      ep = EndpointFile.parse(JSON.parse(readFileSync(this.o.endpointFile, 'utf8')))
    } catch {
      throw new BridgeError('app_not_running', 'NEXUS Terminal is not running or MCP is disabled. Start NEXUS and enable MCP in the Claude / MCP view.')
    }

    const sock = await new Promise<net.Socket>((resolve, reject) => {
      const s = net.connect(ep.pipeName)
      const dec = new FrameDecoder()
      const clientNonce = randomBytes(32).toString('hex')
      let stage: 'hello' | 'ready' | 'open' = 'hello'
      const timer = setTimeout(() => {
        s.destroy()
        reject(new BridgeError('handshake_timeout', 'handshake with NEXUS timed out'))
      }, 5_000)

      s.on('error', () => {
        clearTimeout(timer)
        reject(new BridgeError('app_not_running', 'cannot reach NEXUS Terminal (ensure the app is running with MCP enabled)'))
      })

      s.on('data', (chunk: Buffer) => {
        let frames: unknown[]
        try { frames = dec.push(chunk) } catch { s.destroy(); return reject(new BridgeError('bad_frame', 'malformed frame from NEXUS')) }
        for (const f of frames) {
          if (stage === 'hello') {
            const h = HelloFrame.safeParse(f)
            if (!h.success) { s.destroy(); clearTimeout(timer); return reject(new BridgeError('protocol', 'unexpected handshake frame')) }
            s.write(
              encodeFrame(
                AuthFrame.parse({
                  type: 'auth',
                  clientNonce,
                  hmac: computeHmac(ep.secret, h.data.nonce, clientNonce),
                  client: { name: this.o.clientName, version: this.o.clientVersion }
                })
              )
            )
            stage = 'ready'
          } else if (stage === 'ready') {
            if (ReadyFrame.safeParse(f).success) {
              stage = 'open'
              clearTimeout(timer)
              resolve(s)
            } else {
              const x = FatalFrame.safeParse(f)
              clearTimeout(timer)
              s.destroy()
              return reject(new BridgeError(x.success ? x.data.code : 'protocol', x.success ? x.data.message : 'handshake rejected'))
            }
          } else {
            this.onFrame(f)
          }
        }
      })

      s.on('close', () => {
        for (const [id, p] of this.pending) {
          clearTimeout(p.timer)
          p.reject(new BridgeError('disconnected', 'connection to NEXUS closed'))
          this.pending.delete(id)
        }
        if (this.sock === s) this.sock = null
      })
    })
    this.sock = sock
    return sock
  }

  private onFrame(f: unknown): void {
    const r = ResponseFrame.safeParse(f)
    if (!r.success) return
    const p = this.pending.get(r.data.id)
    if (!p) return
    this.pending.delete(r.data.id)
    clearTimeout(p.timer)
    if (r.data.ok) p.resolve(r.data.result)
    else p.reject(new BridgeError(r.data.error.code, r.data.error.message))
  }

  async call(tool: ToolName, args: Record<string, unknown>): Promise<unknown> {
    const sock = await this.connect()
    const id = `r${++this.seq}`
    return new Promise((resolve, reject) => {
      // Allow up to 11 minutes because nexus_run_command may wait for native user approval + command timeout.
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new BridgeError('timeout', 'NEXUS did not respond in time'))
      }, this.o.timeoutMs ?? 660_000)
      this.pending.set(id, { resolve, reject, timer })
      sock.write(encodeFrame({ type: 'request', id, tool, args }))
    })
  }

  close(): void {
    this.sock?.destroy()
  }
}
