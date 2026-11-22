import { EventEmitter } from 'node:events'
import type { CommandSource, ExecutionResult, ExecutionStatus, OutputPage } from '../../../shared/types'
import type { ExecutionRepo, ExecutionRow } from '../db/repositories'
import type { AuditLogger } from '../audit/audit-logger'
import {
  AuthorizationError,
  CommandAuthorizer,
  isAuthorizedExecution,
  type AuthorizedExecution,
  type ContextResolver
} from '../security/authorization'
import { StreamRedactor, redactText } from '../security/redaction'
import type { ExecHandle, ExecRunner } from '../ssh/session-manager'
import { stripAnsi } from '../ssh/terminal-tail'

interface LiveExecStore {
  chunks: { seq: number; text: string; bytes: number }[]
  next: number
  rawBytes: number
  truncated: boolean
  done: boolean
  status: ExecutionStatus
  handle: ExecHandle | null
  abortController: AbortController
}

export interface ExecuteInput {
  serverId: string
  sessionId: string
  command: string
  requester?: string
  timeoutMs?: number
  maxOutputBytes?: number
  /** Renderer-generated id known before `commands:execute` resolves, so Cancel can target an in-flight command. */
  clientCommandId?: string
}

const KEEP_IN_MEMORY = 50

/**
 * Single shared ExecutionService for every programmatic command (GUI Run Command bar and MCP nexus_run_command).
 * 1. Authorizes through CommandAuthorizer (which enforces policy & native OS approval dialogs).
 * 2. Denied commands record a sanitized 'denied' history row and generate ZERO remote SSH calls.
 * 3. Approved commands execute on a dedicated SSH exec channel with hard timeout, output cap, ANSI strip, and redaction.
 */
export class ExecutionService extends EventEmitter {
  private readonly stores = new Map<string, LiveExecStore>()
  /** Abort controllers for commands still awaiting authorization, keyed by client id. */
  private readonly pending = new Map<string, AbortController>()

  constructor(
    private readonly authorizer: CommandAuthorizer,
    private readonly resolveContext: ContextResolver,
    private readonly repo: ExecutionRepo,
    private readonly runner: ExecRunner,
    private readonly audit: AuditLogger,
    private readonly secrets: () => Iterable<string>,
    private readonly setTimer: typeof setTimeout = setTimeout
  ) {
    super()
  }

  async execute(input: ExecuteInput, source: CommandSource, externalSignal?: AbortSignal): Promise<ExecutionResult> {
    const requester = source === 'user' ? 'user' : input.requester ?? 'mcp:claude'
    const clientCommandId = input.clientCommandId ?? null

    // Register the client id before authorization so Cancel works while the native dialog is still open.
    const pendingAc = clientCommandId ? new AbortController() : null
    if (clientCommandId && pendingAc) {
      this.pending.set(clientCommandId, pendingAc)
      if (externalSignal?.aborted) pendingAc.abort()
      else externalSignal?.addEventListener('abort', () => pendingAc.abort(), { once: true })
    }
    const signal = pendingAc?.signal ?? externalSignal

    try {
      const outcome = await this.authorizer.authorize(
        {
          serverId: input.serverId,
          sessionId: input.sessionId,
          command: input.command,
          requester,
          params: { timeoutMs: input.timeoutMs, maxOutputBytes: input.maxOutputBytes },
          clientCommandId: clientCommandId ?? undefined
        },
        source,
        this.resolveContext
      )

      if (!outcome.allowed) {
        // Record denied attempt in history if server & session exist; NEVER invoke SSH.
        let commandId = 'denied'
        try {
          const ctx = this.resolveContext(input.serverId, input.sessionId)
          if (ctx) {
            const row = this.repo.create({
              serverId: input.serverId,
              sessionId: input.sessionId,
              source,
              requester,
              commandSanitized: outcome.commandSanitized,
              level: outcome.decision.level,
              flags: outcome.decision.flags,
              status: 'denied',
              denialReason: outcome.reason,
              approvalId: null
            })
            commandId = row.id
            this.emit('changed')
          }
        } catch {
          /* ignore history insert when server/session does not exist */
        }
        this.audit.log('execution.denied', requester, {
          commandId,
          serverId: input.serverId,
          sessionId: input.sessionId,
          source,
          code: outcome.code,
          reason: outcome.reason,
          level: outcome.decision.level,
          command: outcome.commandSanitized
        })
        return { status: 'denied', commandId, reason: `${outcome.code}: ${outcome.reason}`, level: outcome.decision.level }
      }

      return this.runAuthorized(outcome.auth, signal)
    } finally {
      if (clientCommandId) this.pending.delete(clientCommandId)
    }
  }

  /** Low-level execution entry point guarded by WeakSet-branded AuthorizedExecution token. */
  runAuthorized(auth: AuthorizedExecution, externalSignal?: AbortSignal): Promise<ExecutionResult> {
    if (!isAuthorizedExecution(auth)) {
      throw new AuthorizationError('forbidden', 'execution requires an AuthorizedExecution minted by CommandAuthorizer')
    }

    const startedAt = Date.now()
    const row = this.repo.create({
      id: auth.clientCommandId ?? undefined,
      serverId: auth.serverId,
      sessionId: auth.sessionId,
      source: auth.source,
      requester: auth.requester,
      commandSanitized: auth.commandSanitized,
      level: auth.level,
      flags: auth.flags,
      approvalId: auth.approvalId
    })

    const ac = new AbortController()
    const st: LiveExecStore = {
      chunks: [],
      next: 1,
      rawBytes: 0,
      truncated: false,
      done: false,
      status: 'running',
      handle: null,
      abortController: ac
    }
    this.stores.set(row.id, st)
    this.evict()
    this.audit.log('execution.started', auth.requester, {
      executionId: row.id,
      serverId: auth.serverId,
      sessionId: auth.sessionId,
      source: auth.source,
      level: auth.level,
      approvalId: auth.approvalId,
      command: row.commandSanitized
    })
    this.emit('changed')

    return new Promise<ExecutionResult>((resolve) => {
      const stdoutRedactor = new StreamRedactor(this.secrets)
      const stderrRedactor = new StreamRedactor(this.secrets)
      let stdoutAcc = ''
      let stderrAcc = ''
      let finished = false
      let timer: ReturnType<typeof setTimeout> | null = null

      const pushChunk = (text: string, stream: 'stdout' | 'stderr'): void => {
        if (!text) return
        const clean = stripAnsi(text)
        if (!clean) return
        if (stream === 'stdout') stdoutAcc += clean
        else stderrAcc += clean
        st.chunks.push({ seq: st.next++, text: clean, bytes: Buffer.byteLength(clean, 'utf8') })
      }

      const onAbort = (): void => {
        if (!finished) {
          st.status = 'cancelled'
          st.handle?.cancel('KILL')
          finish('cancelled', null, 'CANCELLED')
        }
      }
      ac.signal.addEventListener('abort', onAbort, { once: true })
      externalSignal?.addEventListener('abort', onAbort, { once: true })

      const finish = (status: ExecutionStatus, exitCode: number | null, signal: string | null, errMsg?: string): void => {
        if (finished) return
        finished = true
        if (timer) clearTimeout(timer)
        ac.signal.removeEventListener('abort', onAbort)
        externalSignal?.removeEventListener('abort', onAbort)

        pushChunk(stdoutRedactor.flush(), 'stdout')
        pushChunk(stderrRedactor.flush(), 'stderr')
        if (st.truncated) {
          st.chunks.push({ seq: st.next++, text: '\n[output truncated]\n', bytes: 20 })
        }
        st.done = true
        st.status = status
        // Re-run eviction now that this store is reclaimable.
        this.evict()
        const durationMs = Math.max(0, Date.now() - startedAt)
        const combinedOutput = st.chunks.map((c) => c.text).join('')
        this.repo.finish(row.id, { status, exitCode, signal, truncated: st.truncated, output: combinedOutput })
        this.audit.log('execution.finished', auth.requester, {
          executionId: row.id,
          status,
          exitCode,
          signal,
          truncated: st.truncated,
          durationMs
        })
        this.emit('changed')

        if (status === 'timeout' || status === 'cancelled') {
          resolve({ status, commandId: row.id, stdout: stdoutAcc, stderr: stderrAcc, truncated: st.truncated, durationMs })
        } else if (status === 'failed') {
          resolve({ status: 'error', commandId: row.id, code: 'exec_failed', message: errMsg ?? 'remote execution failed' })
        } else {
          resolve({ status: 'completed', commandId: row.id, exitCode, signal, stdout: stdoutAcc, stderr: stderrAcc, truncated: st.truncated, durationMs })
        }
      }

      // An already-aborted signal must never reach SSH (listeners only fire on future aborts).
      if (externalSignal?.aborted) {
        onAbort()
        return
      }

      try {
        st.handle = this.runner.runExec(auth.sessionId, auth.epoch, auth.command, {
          onData: (text, stream) => {
            if (finished || st.truncated) return
            const room = auth.maxOutputBytes - st.rawBytes
            const bytes = Buffer.byteLength(text, 'utf8')
            let slice = text
            if (bytes > room) {
              slice = Buffer.from(text, 'utf8').subarray(0, Math.max(room, 0)).toString('utf8')
              st.truncated = true
            }
            st.rawBytes += Math.min(bytes, Math.max(room, 0))
            const red = stream === 'stdout' ? stdoutRedactor.push(slice) : stderrRedactor.push(slice)
            pushChunk(red, stream)
            if (st.truncated) {
              // Stop streaming immediately when output limit is hit.
              st.handle?.cancel('KILL')
              finish('completed', null, 'OUTPUT_LIMIT')
            }
          },
          onExit: ({ code, signal }) => finish(st.status === 'cancelled' ? 'cancelled' : 'completed', code, signal),
          onError: (e) => {
            const safe = redactText(e.message, this.secrets())
            pushChunk(`\n[execution error: ${safe}]\n`, 'stderr')
            finish('failed', null, null, safe)
          }
        })

        timer = this.setTimer(() => {
          if (!finished) {
            st.status = 'timeout'
            st.handle?.cancel('KILL')
            finish('timeout', null, 'TIMEOUT')
          }
        }, auth.timeoutMs)
        if (timer && typeof timer === 'object' && 'unref' in timer) timer.unref()
      } catch (e) {
        const safe = redactText((e as Error).message, this.secrets())
        pushChunk(`[could not start: ${safe}]\n`, 'stderr')
        finish('failed', null, null, safe)
      }
    })
  }

  cancel(commandId: string): boolean {
    const st = this.stores.get(commandId)
    if (st && !st.done) {
      st.abortController.abort()
      return true
    }
    // Still waiting on the native approval dialog: abort before execution starts.
    const pending = this.pending.get(commandId)
    if (pending) {
      pending.abort()
      return true
    }
    return false
  }

  get(id: string): ExecutionRow | null {
    return this.repo.get(id)
  }

  list(f: Parameters<ExecutionRepo['list']>[0]): ExecutionRow[] {
    return this.repo.list(f)
  }

  pruneRetention(retentionDays: number, now = Date.now()): number {
    const cutoff = now - Math.max(1, retentionDays) * 86_400_000
    return this.repo.pruneOlderThan(cutoff)
  }

  clearHistory(): number {
    const n = this.repo.clearAll()
    this.emit('changed')
    return n
  }

  getOutput(id: string, afterSeq: number, maxBytes: number): OutputPage | null {
    const row = this.repo.get(id)
    if (!row) return null
    const st = this.stores.get(id)
    if (!st) {
      if (afterSeq >= 1) return { text: '', nextSeq: afterSeq, done: row.status !== 'running', truncated: row.truncated, status: row.status }
      return { text: row.output.slice(0, maxBytes), nextSeq: 1, done: row.status !== 'running', truncated: row.truncated || row.output.length > maxBytes, status: row.status }
    }
    let text = ''
    let bytes = 0
    let next = afterSeq
    for (const c of st.chunks) {
      if (c.seq <= afterSeq) continue
      if (bytes + c.bytes > maxBytes && bytes > 0) break
      text += c.text
      bytes += c.bytes
      next = c.seq
      if (bytes >= maxBytes) break
    }
    const caughtUp = next >= st.next - 1
    return { text, nextSeq: next, done: st.done && caughtUp, truncated: st.truncated, status: st.status }
  }

  private evict(): void {
    if (this.stores.size <= KEEP_IN_MEMORY) return
    // Walk the whole map: a still-running oldest store must not block newer completed ones from
    // being reclaimed.
    for (const [k, st] of this.stores) {
      if (this.stores.size <= KEEP_IN_MEMORY) break
      if (st.done) this.stores.delete(k)
    }
  }
}
