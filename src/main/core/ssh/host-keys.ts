import { createHash } from 'node:crypto'
import type { KnownHostDTO } from '../../../shared/types'
import type { KnownHostRepo } from '../db/repositories/servers'
import type { AuditLogger } from '../audit/audit-logger'
import type { HostKeyPresenter, HostKeyTypeMismatchInfo } from '../../ssh/hostkey-prompt'

export function fingerprintOf(key: Buffer): string {
  return 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '')
}

export function algorithmOf(key: Buffer): string {
  if (key.length < 4) return 'unknown'
  const len = key.readUInt32BE(0)
  return key.length >= 4 + len && len < 64 ? key.subarray(4, 4 + len).toString('ascii') : 'unknown'
}

export type HostKeyVerifyOutcome =
  | { accepted: true; state: 'matched' | 'trusted_first_use'; keyType: string; fingerprint: string }
  | { accepted: false; state: 'rejected' | 'timeout'; keyType: string; fingerprint: string; reason: string }
  | { accepted: false; state: 'mismatch'; keyType: string; fingerprint: string; expectedFingerprint: string }

const FIRST_USE_TIMEOUT_MS = 60_000

/**
 * Strict SSH host-key verification service.
 * - Known & matches -> accept, update last_seen_at.
 * - Known & differs -> hard reject, emit host_key_mismatch security event, no bypass.
 * - Unknown -> pause connect, invoke native HostKeyPresenter (default Reject, 60s timeout = Reject).
 */
export class HostKeyService {
  constructor(
    private readonly repo: KnownHostRepo,
    private readonly presenter: HostKeyPresenter,
    private readonly audit: AuditLogger,
    private readonly onChanged: () => void = () => undefined,
    private readonly now: () => number = Date.now,
    private readonly promptTimeoutMs: number = FIRST_USE_TIMEOUT_MS
  ) {}

  list(): KnownHostDTO[] {
    return this.repo.list()
  }

  getForEndpoint(host: string, port: number): KnownHostDTO | null {
    return this.repo.listForEndpoint(host, port)[0] ?? null
  }

  listForEndpoint(host: string, port: number): KnownHostDTO[] {
    return this.repo.listForEndpoint(host, port)
  }

  async verify(server: { id: string; name: string; host: string; port: number }, key: Buffer): Promise<HostKeyVerifyOutcome> {
    const fingerprint = fingerprintOf(key)
    const keyType = algorithmOf(key)
    const existing = this.repo.get(server.host, server.port, keyType)

    if (existing) {
      if (existing.fingerprintSha256 === fingerprint) {
        this.repo.touch(server.host, server.port, keyType, this.now())
        return { accepted: true, state: 'matched', keyType, fingerprint }
      }
      this.audit.securityEvent(
        'host_key_mismatch',
        'critical',
        { host: server.host, port: server.port, keyType, expected: existing.fingerprintSha256, actual: fingerprint },
        server.id
      )
      await this.presenter.presentMismatch({
        serverName: server.name,
        host: server.host,
        port: server.port,
        keyType,
        expectedFingerprint: existing.fingerprintSha256,
        actualFingerprint: fingerprint
      })
      return {
        accepted: false,
        state: 'mismatch',
        keyType,
        fingerprint,
        expectedFingerprint: existing.fingerprintSha256
      }
    }

    // The endpoint is already pinned, but with a different key type. Treat as a distinct,
    // named warning (default Reject) instead of a routine first-use prompt.
    const pinnedForEndpoint = this.repo.listForEndpoint(server.host, server.port)
    if (pinnedForEndpoint.length > 0) {
      const pin = pinnedForEndpoint[0]
      const info: HostKeyTypeMismatchInfo = {
        serverName: server.name,
        host: server.host,
        port: server.port,
        pinnedKeyType: pin.keyType,
        presentedKeyType: keyType,
        pinnedFingerprint: pin.fingerprintSha256,
        presentedFingerprint: fingerprint
      }
      this.audit.securityEvent(
        'host_key_type_mismatch',
        'critical',
        {
          host: server.host,
          port: server.port,
          presentedKeyType: keyType,
          pinnedKeyType: pin.keyType,
          pinnedFingerprint: pin.fingerprintSha256,
          presentedFingerprint: fingerprint
        },
        server.id
      )
      const accepted = await this.presenter.presentTypeMismatch(info)
      if (!accepted) {
        this.audit.log('hostkey.rejected', 'user', {
          serverId: server.id,
          host: server.host,
          port: server.port,
          keyType,
          pinnedKeyType: pin.keyType,
          fingerprint,
          reason: 'host key type differs from the pinned key type'
        })
        return {
          accepted: false,
          state: 'rejected',
          keyType,
          fingerprint,
          reason: 'host key type differs from the pinned key type'
        }
      }
      this.repo.insert(server.host, server.port, keyType, fingerprint, this.now())
      this.audit.log('hostkey.trusted', 'user', {
        serverId: server.id,
        host: server.host,
        port: server.port,
        keyType,
        fingerprint,
        previousKeyType: pin.keyType
      })
      this.onChanged()
      return { accepted: true, state: 'trusted_first_use', keyType, fingerprint }
    }

    // Unknown host key: native first-use prompt with hard 60s timeout (fail closed).
    const ac = new AbortController()
    const decision = await new Promise<'accept' | 'reject' | 'timeout'>((resolve) => {
      let settled = false
      const done = (v: 'accept' | 'reject' | 'timeout'): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(v)
      }
      const timer = setTimeout(() => {
        ac.abort()
        done('timeout')
      }, this.promptTimeoutMs)
      timer.unref()

      this.presenter
        .presentUnknown({ serverName: server.name, host: server.host, port: server.port, keyType, fingerprintSha256: fingerprint }, ac.signal)
        .then((ok) => done(ok ? 'accept' : 'reject'))
        .catch(() => done('reject'))
    })

    if (decision === 'accept') {
      this.repo.insert(server.host, server.port, keyType, fingerprint, this.now())
      this.audit.log('hostkey.trusted', 'user', { serverId: server.id, host: server.host, port: server.port, keyType, fingerprint })
      this.onChanged()
      return { accepted: true, state: 'trusted_first_use', keyType, fingerprint }
    }

    const reason = decision === 'timeout' ? 'host key confirmation timed out' : 'host key rejected by user'
    this.audit.log('hostkey.rejected', 'user', { serverId: server.id, host: server.host, port: server.port, keyType, fingerprint, reason })
    return { accepted: false, state: decision === 'timeout' ? 'timeout' : 'rejected', keyType, fingerprint, reason }
  }

  /** Explicit user-confirmed removal of a stored known host (the only recovery from a changed host key). */
  async removeWithConfirmation(host: string, port: number, keyType: string): Promise<boolean> {
    const existing = this.repo.get(host, port, keyType)
    if (!existing) return false
    const confirmed = await this.presenter.confirmAction(
      'Remove Known Host Key',
      `Remove stored SSH host key for ${host}:${port}?`,
      `Key type: ${keyType}\nFingerprint: ${existing.fingerprintSha256}\n\nThe next connection will prompt you to verify the host key again.`,
      'Remove Key'
    )
    if (!confirmed) return false
    const removed = this.repo.remove(host, port, keyType)
    if (removed) {
      this.audit.securityEvent('host_key_removed', 'warning', { host, port, keyType, fingerprint: existing.fingerprintSha256 })
      this.onChanged()
    }
    return removed
  }
}
