import { timingSafeEqual } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import { Server, utils } from 'ssh2'

export interface FakeShellChannel {
  write(data: string): boolean
  end(): void
  close(): void
}

export interface FakeSshClientConnection {
  end(): void
  on(event: 'close', listener: () => void): this
  on(event: 'error', listener: (error: Error) => void): this
  on(event: 'authentication', listener: (context: FakeAuthContext) => void): this
  on(event: 'ready', listener: () => void): this
  on(event: 'session', listener: (accept: () => FakeSession) => void): this
}

export interface FakeAuthContext {
  username: string
  method: string
  password?: string
  key: { data: Buffer }
  signature?: Buffer
  blob: Buffer
  hashAlgo?: string
  accept(): void
  reject(methods?: string[]): void
}

export interface FakeSession {
  on(event: 'pty' | 'window-change', listener: (accept?: () => void) => void): this
  on(event: 'shell', listener: (accept: () => FakeShellChannel) => void): this
  on(event: 'exec', listener: (accept: () => FakeExecChannel, reject: () => void, info: { command: string }) => void): this
}

export interface FakeExecChannel {
  write(data: string): boolean
  end(): void
  close(): void
  exit(codeOrSignal: number | string): void
  signal(signal: string): void
  stderr: { write(data: string): boolean }
  on(event: 'close' | 'signal', listener: () => void): this
}

export interface TestSshServer {
  port: number
  hostKeyPrivatePem: string
  hostKeyPublic: Buffer
  commands: string[]
  setShellBehavior(handler: (command: string, channel: FakeShellChannel) => void): void
  close(): Promise<void>
}

export const TEST_USER = 'tester'
export const TEST_PASSWORD = 'test-only-password-canary-99'

function generateValidEd25519(): { privatePem: string; publicSsh: Buffer; parsedPub: ReturnType<typeof utils.parseKey> } {
  for (let i = 0; i < 50; i++) {
    const kp = utils.generateKeyPairSync('ed25519')
    const a = utils.parseKey(kp.private)
    const b = utils.parseKey(kp.public)
    const priv = Array.isArray(a) ? a[0] : a
    const pub = Array.isArray(b) ? b[0] : b
    if (priv && !(priv instanceof Error) && pub && !(pub instanceof Error)) {
      return { privatePem: kp.private, publicSsh: pub.getPublicSSH(), parsedPub: pub }
    }
  }
  throw new Error('could not generate a valid ed25519 keypair')
}

export function generateClientKeypair(): { privatePem: string; publicSsh: Buffer } {
  const { privatePem, publicSsh } = generateValidEd25519()
  return { privatePem, publicSsh }
}

/**
 * Pure Node.js in-process ssh2 Server for deterministic Windows & Linux testing (zero external `sh` dependency).
 * Supports password auth AND exact public-key signature verification, interactive echo shell, and scripted exec.
 */
export async function startSshServer(opts: {
  password?: string
  authorizedPublicKey?: Buffer
  hostKeyPrivatePem?: string
  authenticationDelayMs?: number
  port?: number
} = {}): Promise<TestSshServer> {
  let hostPriv: string
  let hostPub: Buffer
  if (opts.hostKeyPrivatePem) {
    const parsed = utils.parseKey(opts.hostKeyPrivatePem)
    const key = Array.isArray(parsed) ? parsed[0] : parsed
    if (!key || key instanceof Error) throw new Error('invalid hostKeyPrivatePem')
    hostPriv = opts.hostKeyPrivatePem
    hostPub = key.getPublicSSH()
  } else {
    const gen = generateValidEd25519()
    hostPriv = gen.privatePem
    hostPub = gen.publicSsh
  }

  const commands: string[] = []
  const password = opts.password ?? TEST_PASSWORD
  const clients = new Set<{ end(): void }>()
  const shellStreams = new Set<{ close(): void }>()
  let shellBehavior: (command: string, channel: FakeShellChannel) => void = (command, channel) => {
    commands.push('SHELL:' + command)
    if (command.startsWith('echo ')) channel.write(command.slice(5) + '\r\n')
    else channel.write(`RAN:${command}\r\n`)
  }

  const server = new Server({ hostKeys: [hostPriv] }, (client) => {
    clients.add(client)
    client.on('close', () => clients.delete(client))
    client.on('error', () => undefined)

    client.on('authentication', (ctx) => {
      const decide = (): void => {
        if (ctx.username !== TEST_USER) return ctx.reject(['password', 'publickey'])
        if (ctx.method === 'password' && ctx.password === password) {
          return ctx.accept()
        }
        if (ctx.method === 'publickey' && opts.authorizedPublicKey) {
          const expected = opts.authorizedPublicKey
          const incoming = ctx.key.data
          if (incoming.length === expected.length && timingSafeEqual(incoming, expected)) {
            if (!ctx.signature) return ctx.accept()
            const parsed = utils.parseKey(expected)
            const k = Array.isArray(parsed) ? parsed[0] : parsed
            if (k && !(k instanceof Error) && k.verify(ctx.blob, ctx.signature, ctx.hashAlgo)) {
              return ctx.accept()
            }
          }
        }
        ctx.reject(['password', 'publickey'])
      }
      if (opts.authenticationDelayMs) setTimeout(decide, opts.authenticationDelayMs)
      else decide()
    })

    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
        session.on('pty', (a) => a && a())
        session.on('window-change', (a) => a && a())

        session.on('shell', (a) => {
          const ch = a()
          shellStreams.add(ch)
          ch.on('close', () => shellStreams.delete(ch))
          let line = ''
          ch.write('\x1b[32mwelcome$ \x1b[0m')
          ch.on('data', (d: Buffer) => {
            for (const c of d.toString('utf8')) {
              if (c === '\r') {
                const cmd = line
                line = ''
                ch.write('\r\n')
                shellBehavior(cmd, ch)
                ch.write('$ ')
              } else if (c === '\x7f') {
                line = line.slice(0, -1)
              } else {
                line += c
                ch.write(c)
              }
            }
          })
        })

        session.on('exec', (accept2, _reject, info) => {
          const ch = accept2()
          const cmd = info.command.trim()
          commands.push(cmd)

          let timer: ReturnType<typeof setTimeout> | null = null
          const cleanup = (): void => { if (timer) { clearTimeout(timer); timer = null } }
          ch.on('close', cleanup)
          ch.on('signal', () => { cleanup(); try { ch.exit('KILL'); ch.end() } catch { /* ignore */ } })

          if (cmd === 'pwd') {
            ch.write('/home/tester\n')
            ch.exit(0)
            ch.end()
          } else if (cmd === 'whoami') {
            ch.write('tester\n')
            ch.exit(0)
            ch.end()
          } else if (cmd.startsWith('echo ')) {
            ch.write(cmd.slice(5) + '\n')
            ch.exit(0)
            ch.end()
          } else if (cmd.startsWith('sleep ')) {
            const ms = Math.min(60_000, Math.max(50, Number(cmd.slice(6)) * 1000))
            timer = setTimeout(() => {
              ch.write('slept\n')
              ch.exit(0)
              ch.end()
            }, ms)
          } else if (cmd.startsWith('flood ')) {
            const kb = Math.min(2048, Math.max(1, Number(cmd.slice(6)) || 64))
            const chunk = 'A'.repeat(1024) + '\n'
            for (let i = 0; i < kb; i++) ch.write(chunk)
            ch.exit(0)
            ch.end()
          } else if (cmd.startsWith('exit ')) {
            const code = Number(cmd.slice(5)) || 1
            ch.stderr.write('failed cleanly\n')
            ch.exit(code)
            ch.end()
          } else {
            ch.write(`OK:${cmd}\n`)
            ch.exit(0)
            ch.end()
          }
        })
      })
    })
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(opts.port ?? 0, '127.0.0.1', () => {
      server.removeListener('error', reject)
      resolve()
    })
  })
  const port = (server.address() as AddressInfo).port
  let closed: Promise<void> | null = null
  return {
    port,
    hostKeyPrivatePem: hostPriv,
    hostKeyPublic: hostPub,
    commands,
    setShellBehavior(handler: (command: string, channel: FakeShellChannel) => void) {
      shellBehavior = handler
    },
    close: () => {
      if (closed) return closed
      closed = new Promise((resolve) => {
        for (const stream of shellStreams) { try { stream.close() } catch { /* ignore */ } }
        for (const c of clients) { try { c.end() } catch { /* ignore */ } }
        server.close(() => resolve())
      })
      return closed
    }
  }
}
