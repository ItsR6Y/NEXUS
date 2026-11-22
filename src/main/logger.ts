import { appendFileSync, existsSync, mkdirSync, renameSync, statSync, unlinkSync } from 'node:fs'
import { dirname } from 'node:path'
import { redactText, redactValue } from './core/security/redaction'

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export interface LoggerOptions {
  logFile: string
  maxBytes?: number
  maxFiles?: number
  getSecrets?: () => Iterable<string>
  now?: () => number
}

/**
 * Redacted, size-rotated JSON-lines file logger (<userData>/logs/nexus.log).
 * Every message and metadata field passes through redactText/redactValue before hitting disk.
 */
export class FileLogger {
  private readonly maxBytes: number
  private readonly maxFiles: number
  private readonly getSecrets: () => Iterable<string>
  private readonly now: () => number

  constructor(private readonly opts: LoggerOptions) {
    this.maxBytes = opts.maxBytes ?? 2 * 1024 * 1024 // 2 MB
    this.maxFiles = opts.maxFiles ?? 5
    this.getSecrets = opts.getSecrets ?? (() => [])
    this.now = opts.now ?? Date.now
    mkdirSync(dirname(opts.logFile), { recursive: true })
  }

  debug(event: string, meta?: Record<string, unknown>): void { this.write('debug', event, meta) }
  info(event: string, meta?: Record<string, unknown>): void { this.write('info', event, meta) }
  warn(event: string, meta?: Record<string, unknown>): void { this.write('warn', event, meta) }
  error(event: string, meta?: Record<string, unknown>): void { this.write('error', event, meta) }

  private rotateIfNeeded(): void {
    if (!existsSync(this.opts.logFile)) return
    try {
      if (statSync(this.opts.logFile).size < this.maxBytes) return
    } catch {
      return
    }
    for (let i = this.maxFiles - 1; i >= 1; i--) {
      const src = i === 1 ? this.opts.logFile : `${this.opts.logFile}.${i - 1}`
      const dst = `${this.opts.logFile}.${i}`
      if (existsSync(dst)) {
        try { unlinkSync(dst) } catch { /* ignore */ }
      }
      if (existsSync(src)) {
        try { renameSync(src, dst) } catch { /* ignore */ }
      }
    }
  }

  private write(level: LogLevel, event: string, meta?: Record<string, unknown>): void {
    const secrets = this.getSecrets()
    const entry = {
      ts: new Date(this.now()).toISOString(),
      level,
      event: redactText(event, secrets),
      ...(meta ? { meta: redactValue(meta, secrets) } : {})
    }
    try {
      this.rotateIfNeeded()
      appendFileSync(this.opts.logFile, JSON.stringify(entry) + '\n', { encoding: 'utf8', mode: 0o600 })
    } catch {
      // Never crash the main process on a log write failure.
    }
  }
}
