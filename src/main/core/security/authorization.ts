import { createHash } from 'node:crypto'
import type { Settings } from '../../../shared/ipc'
import { POLICY_VERSION, type ApprovalPolicy, type PolicyDecision, type RiskLevel } from '../../../shared/policy-types'
import type { CommandSource } from '../../../shared/types'
import type { ApprovalRepo, ApprovalRow } from '../db/repositories/approvals'
import type { AuditLogger } from '../audit/audit-logger'
import type { ApprovalPresenter } from '../../security/approvals-ui'
import { classifyCommand } from './policy-engine'
import { redactText } from './redaction'

export type AuthCode =
  | 'unknown_session'
  | 'unknown_server'
  | 'session_server_mismatch'
  | 'session_not_connected'
  | 'stale_epoch'
  | 'mcp_access_disabled'
  | 'approval_denied'
  | 'approval_expired'
  | 'approval_not_found'
  | 'approval_not_approved'
  | 'approval_binding_mismatch'
  | 'approval_consumed'
  | 'forbidden'
  | 'policy_changed'

export class AuthorizationError extends Error {
  constructor(
    public readonly code: AuthCode,
    message: string,
    public readonly decision?: PolicyDecision
  ) {
    super(message)
    this.name = 'AuthorizationError'
  }
}

export interface ResolvedExecutionContext {
  serverId: string
  serverName: string
  sessionId: string
  sessionTitle: string
  epoch: number
  connected: boolean
  policy: ApprovalPolicy
  mcpAccessEnabled: boolean
}

export type ContextResolver = (serverId: string, sessionId: string) => ResolvedExecutionContext | null

export interface ExecParams {
  timeoutMs: number
  maxOutputBytes: number
}

export interface AuthorizeInput {
  serverId: string
  sessionId: string
  command: string
  requester: string
  params?: Partial<ExecParams>
  /** Client-supplied id used as the execution row id so the UI can cancel before the call resolves. */
  clientCommandId?: string
}

declare const authBrand: unique symbol

/** Proof that an execution passed the single CommandAuthorizer gate. Only mintable inside this module. */
export interface AuthorizedExecution {
  readonly [authBrand]: true
  readonly serverId: string
  readonly sessionId: string
  readonly epoch: number
  readonly command: string
  readonly commandSanitized: string
  readonly timeoutMs: number
  readonly maxOutputBytes: number
  readonly source: CommandSource
  readonly requester: string
  readonly level: RiskLevel
  readonly flags: string[]
  readonly approvalId: string | null
  readonly clientCommandId: string | null
}

const minted = new WeakSet<object>()
export function isAuthorizedExecution(x: unknown): x is AuthorizedExecution {
  return typeof x === 'object' && x !== null && minted.has(x)
}

/** Cryptographic binding over exact raw command bytes + server + session + epoch + caps + source + policyVersion. */
export function bindingHash(f: {
  command: string
  serverId: string
  sessionId: string
  epoch: number
  timeoutMs: number
  maxOutputBytes: number
  source: CommandSource
  requester: string
  policyVersion: string
}): string {
  return createHash('sha256')
    .update(JSON.stringify([f.command, f.serverId, f.sessionId, f.epoch, f.timeoutMs, f.maxOutputBytes, f.source, f.requester, f.policyVersion]))
    .digest('hex')
}

export type AuthorizeOutcome =
  | { allowed: true; auth: AuthorizedExecution; decision: PolicyDecision }
  | { allowed: false; code: AuthCode; reason: string; decision: PolicyDecision; commandSanitized: string }

/**
 * Single shared CommandAuthorizer for both GUI programmatic execution ('user') and MCP ('claude').
 * - `source` is supplied by the transport layer, never by untrusted payload.
 * - Raw commands with inline secrets are NEVER written to SQLite approvals; only redacted text is persisted,
 *   while exact-byte binding is enforced via `bindingHash` in memory.
 * - Approvals are decided exclusively via the main-process `ApprovalPresenter` (native OS dialog).
 */
export class CommandAuthorizer {
  constructor(
    private readonly approvals: ApprovalRepo,
    private readonly settings: () => Settings,
    private readonly audit: AuditLogger,
    private readonly presenter: ApprovalPresenter,
    private readonly onApprovalsChanged: () => void = () => undefined,
    private readonly now: () => number = Date.now,
    private readonly secrets: () => Iterable<string> = () => []
  ) {}

  classify(command: string): PolicyDecision {
    return classifyCommand(command)
  }

  private resolveParams(p?: Partial<ExecParams>): ExecParams {
    const s = this.settings()
    return {
      timeoutMs: p?.timeoutMs ?? s.defaultExecTimeoutMs,
      maxOutputBytes: p?.maxOutputBytes ?? s.defaultMaxOutputBytes
    }
  }

  private ttlMs(level: RiskLevel): number {
    const base = this.settings().approvalTtlSeconds * 1000
    if (level === 'DESTRUCTIVE') return Math.min(base, 60_000)
    if (level === 'CRITICAL') return Math.min(base, 90_000)
    return base
  }

  /** Determine whether a command requires explicit native approval under server policy + source + settings. */
  needsApproval(decision: PolicyDecision, policy: ApprovalPolicy, source: CommandSource): boolean {
    if (policy === 'always') return true
    if (decision.requiresApproval) return true
    const low = decision.level === 'LOW'
    if (source === 'claude') {
      if (policy === 'ask') return true
      // policy === 'sensitive': auto-run LOW for MCP only if the user explicitly enabled settings.mcpAutoRunLow (default false).
      return low ? !this.settings().mcpAutoRunLow : true
    }
    if (policy === 'ask') return !low
    // 'sensitive' GUI: auto-run LOW and MEDIUM; HIGH and above always ask.
    return !low && decision.level !== 'MEDIUM'
  }

  /**
   * Authorizes a command end-to-end: validates session ownership, classifies, invokes native approval if required,
   * atomically consumes single-use approval, re-verifies epoch & binding, and mints a WeakSet-branded AuthorizedExecution.
   */
  async authorize(
    input: AuthorizeInput,
    source: CommandSource,
    resolveContext: ContextResolver
  ): Promise<AuthorizeOutcome> {
    this.sweep()
    const decision = classifyCommand(input.command)
    const commandSanitized = redactText(input.command, this.secrets())
    const ctx = resolveContext(input.serverId, input.sessionId)

    if (!ctx) {
      this.audit.securityEvent('session_ownership_or_missing', 'warning', {
        source,
        requester: input.requester,
        serverId: input.serverId,
        sessionId: input.sessionId
      }, input.serverId)
      return { allowed: false, code: 'session_server_mismatch', reason: 'session not found or does not belong to server', decision, commandSanitized }
    }
    if (!ctx.connected) {
      return { allowed: false, code: 'session_not_connected', reason: 'session is not connected', decision, commandSanitized }
    }
    if (source === 'claude' && !ctx.mcpAccessEnabled) {
      return { allowed: false, code: 'mcp_access_disabled', reason: 'MCP access is disabled for this server', decision, commandSanitized }
    }

    const params = this.resolveParams(input.params)
    let approvalId: string | null = null

    if (this.needsApproval(decision, ctx.policy, source)) {
      const createdAt = this.now()
      const ttl = this.ttlMs(decision.level)
      const expiresAt = createdAt + ttl
      const expectedHash = bindingHash({
        command: input.command,
        serverId: input.serverId,
        sessionId: input.sessionId,
        epoch: ctx.epoch,
        timeoutMs: params.timeoutMs,
        maxOutputBytes: params.maxOutputBytes,
        source,
        requester: input.requester,
        policyVersion: decision.policyVersion
      })

      // Persist ONLY the redacted command text to SQLite — never raw secrets.
      const row = this.approvals.create({
        bindingHash: expectedHash,
        commandSanitized,
        serverId: input.serverId,
        sessionId: input.sessionId,
        epoch: ctx.epoch,
        timeoutMs: params.timeoutMs,
        maxOutputBytes: params.maxOutputBytes,
        source,
        requester: input.requester,
        level: decision.level,
        reasons: decision.reasons,
        flags: decision.flags,
        policyVersion: decision.policyVersion,
        createdAt,
        expiresAt
      })
      this.audit.log('approval.requested', input.requester, {
        approvalId: row.id,
        serverId: input.serverId,
        sessionId: input.sessionId,
        source,
        level: decision.level,
        command: commandSanitized
      })
      this.onApprovalsChanged()

      // Present native main-process OS dialog with hard expiry timer.
      const ac = new AbortController()
      const outcome = await new Promise<'approve' | 'deny' | 'expired'>((resolve) => {
        let settled = false
        const done = (v: 'approve' | 'deny' | 'expired'): void => {
          if (settled) return
          settled = true
          clearTimeout(timer)
          resolve(v)
        }
        const timer = setTimeout(() => {
          ac.abort()
          done('expired')
        }, Math.max(1, expiresAt - this.now()))
        timer.unref()

        this.presenter
          .present(
            {
              approvalId: row.id,
              source,
              requester: input.requester,
              serverName: ctx.serverName,
              sessionTitle: ctx.sessionTitle,
              level: decision.level,
              reasons: decision.reasons,
              flags: decision.flags,
              commandRedacted: commandSanitized,
              timeoutRemainingSec: Math.max(1, Math.ceil((expiresAt - this.now()) / 1000))
            },
            ac.signal
          )
          .then((res) => done(res))
          .catch(() => done('deny'))
      })

      this.sweep()
      const currentNow = this.now()
      if (outcome === 'expired' || currentNow >= expiresAt) {
        this.approvals.markExpired(currentNow)
        this.audit.log('approval.expired', 'system', { approvalId: row.id, serverId: input.serverId })
        this.onApprovalsChanged()
        return { allowed: false, code: 'approval_expired', reason: 'approval timed out before user decision', decision, commandSanitized }
      }

      if (outcome !== 'approve') {
        this.approvals.decide(row.id, 'rejected', currentNow)
        this.audit.log('approval.rejected', 'user', { approvalId: row.id, serverId: input.serverId })
        this.onApprovalsChanged()
        return { allowed: false, code: 'approval_denied', reason: 'command denied by user', decision, commandSanitized }
      }

      // Re-verify live context & epoch after dialog returns (session may have closed/reconnected while waiting).
      const afterCtx = resolveContext(input.serverId, input.sessionId)
      if (!afterCtx || !afterCtx.connected || afterCtx.epoch !== ctx.epoch) {
        this.approvals.invalidate(row.id, 'session closed or epoch changed during approval')
        this.onApprovalsChanged()
        return { allowed: false, code: 'stale_epoch', reason: 'session changed while waiting for approval', decision, commandSanitized }
      }
      if (source === 'claude' && !afterCtx.mcpAccessEnabled) {
        this.approvals.invalidate(row.id, 'MCP access disabled during approval')
        this.onApprovalsChanged()
        return { allowed: false, code: 'mcp_access_disabled', reason: 'MCP access was disabled', decision, commandSanitized }
      }

      if (!this.approvals.decide(row.id, 'approved', currentNow)) {
        this.onApprovalsChanged()
        return { allowed: false, code: 'approval_expired', reason: 'approval expired or invalidated before recording', decision, commandSanitized }
      }
      this.audit.log('approval.approved', 'user', { approvalId: row.id, level: decision.level, serverId: input.serverId })

      // Atomically consume single-use approval via verifyAndConsumeApproval.
      const consumed = this.consumeApproved(row.id, {
        command: input.command,
        serverId: input.serverId,
        sessionId: input.sessionId,
        epoch: afterCtx.epoch,
        timeoutMs: params.timeoutMs,
        maxOutputBytes: params.maxOutputBytes,
        source,
        requester: input.requester,
        policyVersion: decision.policyVersion
      })
      this.onApprovalsChanged()
      if (!consumed.ok) {
        return { allowed: false, code: consumed.code, reason: consumed.reason, decision, commandSanitized }
      }
      approvalId = row.id
    }

    const auth = {
      serverId: input.serverId,
      sessionId: input.sessionId,
      epoch: ctx.epoch,
      command: input.command,
      commandSanitized,
      timeoutMs: params.timeoutMs,
      maxOutputBytes: params.maxOutputBytes,
      source,
      requester: input.requester,
      level: decision.level,
      flags: decision.flags,
      approvalId,
      clientCommandId: input.clientCommandId ?? null
    } as unknown as AuthorizedExecution

    minted.add(auth)
    return { allowed: true, auth: Object.freeze(auth), decision }
  }

  /**
   * Atomically verify binding, expiry, policy version, epoch, and single-use status, then consume.
   * Exposed so unit/integration tests can directly test replay, expiry, and binding-mismatch defenses.
   */
  consumeApproved(
    approvalId: string,
    expected: {
      command: string
      serverId: string
      sessionId: string
      epoch: number
      timeoutMs: number
      maxOutputBytes: number
      source: CommandSource
      requester: string
      policyVersion: string
    }
  ): { ok: true } | { ok: false; code: AuthCode; reason: string } {
    this.sweep()
    const a = this.approvals.get(approvalId)
    if (!a) return { ok: false, code: 'approval_not_found', reason: 'approval not found' }
    if (a.status === 'consumed') {
      this.audit.securityEvent('approval_abuse', 'critical', { approvalId: a.id, requester: expected.requester, reason: 'replay of consumed approval' }, expected.serverId)
      return { ok: false, code: 'approval_consumed', reason: 'approval already used' }
    }
    if (a.status === 'expired' || a.expiresAt <= this.now()) {
      return { ok: false, code: 'approval_expired', reason: 'approval expired' }
    }
    if (a.status !== 'approved') {
      return { ok: false, code: 'approval_not_approved', reason: `approval is ${a.status}` }
    }
    if (a.policyVersion !== POLICY_VERSION) {
      this.approvals.invalidate(a.id, 'policy version changed')
      return { ok: false, code: 'policy_changed', reason: 'policy version changed' }
    }
    if (a.epoch !== expected.epoch) {
      this.approvals.invalidate(a.id, 'connection epoch changed')
      return { ok: false, code: 'stale_epoch', reason: 'session reconnected since approval' }
    }
    const expectHash = bindingHash(expected)
    if (
      a.bindingHash !== expectHash ||
      a.serverId !== expected.serverId ||
      a.sessionId !== expected.sessionId ||
      a.source !== expected.source ||
      a.requester !== expected.requester
    ) {
      this.audit.securityEvent('approval_abuse', 'critical', { approvalId: a.id, requester: expected.requester, reason: 'binding mismatch' }, expected.serverId)
      return { ok: false, code: 'approval_binding_mismatch', reason: 'approval binding mismatch' }
    }
    if (!this.approvals.consume(a.id, this.now())) {
      return { ok: false, code: 'approval_consumed', reason: 'approval already consumed or expired' }
    }
    return { ok: true }
  }

  list(): ApprovalRow[] {
    this.sweep()
    return this.approvals.list()
  }

  pendingCount(): number {
    this.sweep()
    return this.approvals.list(500).filter((a) => a.status === 'pending').length
  }

  sweep(): void {
    this.approvals.markExpired(this.now())
    this.approvals.invalidateOtherPolicyVersions(POLICY_VERSION)
  }

  invalidateSession(sessionId: string, reason: string): number {
    const n = this.approvals.invalidateBySession(sessionId, reason)
    if (n) {
      this.audit.log('approval.invalidated', 'system', { sessionId, reason, count: n })
      this.onApprovalsChanged()
    }
    return n
  }

  invalidateServer(serverId: string, reason: string): number {
    const n = this.approvals.invalidateByServer(serverId, reason)
    if (n) {
      this.audit.log('approval.invalidated', 'system', { serverId, reason, count: n })
      this.onApprovalsChanged()
    }
    return n
  }

  invalidateAllOnStartup(): number {
    return this.approvals.invalidateAllActive('application restarted')
  }
}
