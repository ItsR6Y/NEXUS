import type { CredentialRefRepo } from '../db/repositories/servers'
import type { SecretKind } from '../../../shared/types'

export const KEYRING_SERVICE = 'NEXUS Terminal'

export interface SecretCipher {
  isAvailable(): boolean
  encrypt(plain: string): Buffer
  decrypt(blob: Buffer): string
}

export class CredentialError extends Error {
  constructor(
    public readonly code: 'encryption_unavailable' | 'not_found' | 'decrypt_failed' | 'keyring_error',
    message: string
  ) {
    super(message)
    this.name = 'CredentialError'
  }
}

export interface CredentialStore {
  backendName(): string
  available(): boolean
  set(serverId: string, kind: SecretKind, secret: string): void
  has(serverId: string, kind: SecretKind): boolean
  kinds(serverId: string): SecretKind[]
  delete(serverId: string, kind: SecretKind): void
  deleteAllFor(serverId: string): void
  /** Decrypt for immediate connect-time use inside main process only. */
  useSecret<T>(serverId: string, kind: SecretKind, fn: (secret: string) => T): T | null
  primeRedaction(serverIds: string[]): void
  redactionValues(): string[]
}

/** Fallback store backed by Electron safeStorage (Windows DPAPI ciphertext in SQLite). Fails closed if unavailable. */
export class SafeStorageCredentialStore implements CredentialStore {
  private readonly known = new Map<string, string>()

  constructor(private readonly repo: CredentialRefRepo, private readonly cipher: SecretCipher) {}

  backendName(): string { return 'safeStorage (DPAPI)' }
  available(): boolean { return this.cipher.isAvailable() }

  set(serverId: string, kind: SecretKind, secret: string): void {
    if (!this.cipher.isAvailable()) {
      throw new CredentialError('encryption_unavailable', 'OS secret storage is unavailable; refusing to store credentials')
    }
    if (!secret) throw new CredentialError('not_found', 'empty secret')
    this.repo.put(serverId, kind, this.cipher.encrypt(secret))
    this.known.set(`${serverId}:${kind}`, secret)
  }

  has(serverId: string, kind: SecretKind): boolean { return this.repo.getBlob(serverId, kind) !== null }
  kinds(serverId: string): SecretKind[] { return this.repo.kinds(serverId) }

  delete(serverId: string, kind: SecretKind): void {
    this.repo.delete(serverId, kind)
    this.known.delete(`${serverId}:${kind}`)
  }

  deleteAllFor(serverId: string): void {
    for (const k of this.repo.kinds(serverId)) this.delete(serverId, k)
    this.repo.deleteAll(serverId)
  }

  useSecret<T>(serverId: string, kind: SecretKind, fn: (secret: string) => T): T | null {
    const blob = this.repo.getBlob(serverId, kind)
    if (!blob) return null
    if (!this.cipher.isAvailable()) {
      throw new CredentialError('encryption_unavailable', 'OS secret storage is unavailable')
    }
    let plain: string
    try {
      plain = this.cipher.decrypt(blob)
    } catch {
      throw new CredentialError('decrypt_failed', 'could not decrypt stored credential')
    }
    this.known.set(`${serverId}:${kind}`, plain)
    return fn(plain)
  }

  primeRedaction(): void {
    if (!this.cipher.isAvailable()) return
    for (const b of this.repo.allBlobs()) {
      try {
        this.known.set(`${b.serverId}:${b.kind}`, this.cipher.decrypt(b.blob))
      } catch {
        /* unreadable blob */
      }
    }
  }

  redactionValues(): string[] { return [...this.known.values()] }
}

interface KeyringEntryLike {
  setPassword(password: string): void
  getPassword(): string | null
  deletePassword(): boolean
}
type EntryCtor = new (service: string, account: string) => KeyringEntryLike

/** Primary OS credential store backed by @napi-rs/keyring (Windows Credential Manager / macOS Keychain / Secret Service). */
export class KeyringCredentialStore implements CredentialStore {
  private readonly known = new Map<string, string>()
  private probe: { at: number; ok: boolean } | null = null
  private static readonly PROBE_ACCOUNT = '__nexus_availability_probe__'
  private static readonly PROBE_TTL_MS = 30_000

  constructor(private readonly Entry: EntryCtor, private readonly now: () => number = Date.now) {}

  backendName(): string { return 'OS Keyring (@napi-rs/keyring)' }

  /**
   * Cheap read-only probe of the OS keyring. A locked/blocked/misbehaving backend must not
   * be reported as available; the result is cached briefly so the dashboard cannot hammer the keyring.
   */
  available(): boolean {
    const cached = this.probe
    if (cached && this.now() - cached.at < KeyringCredentialStore.PROBE_TTL_MS) return cached.ok
    let ok: boolean
    try {
      // Reading a reserved, never-written account is non-destructive and tolerates null.
      new this.Entry(KEYRING_SERVICE, KeyringCredentialStore.PROBE_ACCOUNT).getPassword()
      ok = true
    } catch {
      ok = false
    }
    this.probe = { at: this.now(), ok }
    return ok
  }

  private entry(serverId: string, kind: SecretKind): KeyringEntryLike {
    return new this.Entry(KEYRING_SERVICE, `${serverId}:${kind}`)
  }

  set(serverId: string, kind: SecretKind, secret: string): void {
    if (!secret) throw new CredentialError('not_found', 'empty secret')
    try {
      this.entry(serverId, kind).setPassword(secret)
      this.known.set(`${serverId}:${kind}`, secret)
    } catch (e) {
      throw new CredentialError('keyring_error', `failed to store secret in OS keyring: ${(e as Error).message}`)
    }
  }

  has(serverId: string, kind: SecretKind): boolean {
    try {
      return this.entry(serverId, kind).getPassword() !== null
    } catch {
      return false
    }
  }

  kinds(serverId: string): SecretKind[] {
    const out: SecretKind[] = []
    if (this.has(serverId, 'password')) out.push('password')
    if (this.has(serverId, 'passphrase')) out.push('passphrase')
    return out
  }

  delete(serverId: string, kind: SecretKind): void {
    try {
      this.entry(serverId, kind).deletePassword()
    } catch {
      /* ignore missing entry */
    }
    this.known.delete(`${serverId}:${kind}`)
  }

  deleteAllFor(serverId: string): void {
    this.delete(serverId, 'password')
    this.delete(serverId, 'passphrase')
  }

  useSecret<T>(serverId: string, kind: SecretKind, fn: (secret: string) => T): T | null {
    let value: string | null
    try {
      value = this.entry(serverId, kind).getPassword()
    } catch {
      return null
    }
    if (!value) return null
    this.known.set(`${serverId}:${kind}`, value)
    return fn(value)
  }

  primeRedaction(serverIds: string[]): void {
    for (const sid of serverIds) {
      for (const kind of ['password', 'passphrase'] as const) {
        try {
          const v = this.entry(sid, kind).getPassword()
          if (v) this.known.set(`${sid}:${kind}`, v)
        } catch {
          /* ignore */
        }
      }
    }
  }

  redactionValues(): string[] { return [...this.known.values()] }
}

/** Prefer @napi-rs/keyring per NEXUS-BUILD-PLAN.md; gracefully fall back to safeStorage if native binding cannot load. */
export async function createDefaultCredentialStore(
  repo: CredentialRefRepo,
  cipher: SecretCipher,
  preferKeyring = true
): Promise<CredentialStore> {
  if (preferKeyring) {
    try {
      const mod = (await import('@napi-rs/keyring')) as { Entry?: EntryCtor }
      if (mod.Entry) {
        // Smoke-probe Entry instantiation (does not write any credential).
        new mod.Entry(KEYRING_SERVICE, '__probe__')
        return new KeyringCredentialStore(mod.Entry)
      }
    } catch {
      // Fall back to Electron safeStorage (DPAPI) below.
    }
  }
  return new SafeStorageCredentialStore(repo, cipher)
}
