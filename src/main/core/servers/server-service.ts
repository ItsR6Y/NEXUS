import type { SecretKind, ServerPrivateInfo, ServerPublicInfo } from '../../../shared/types'
import type { ServerFields, ServerRepo, ServerRow } from '../db/repositories'
import type { CredentialStore } from '../credentials/credential-store'
import type { AuditLogger } from '../audit/audit-logger'
import type { CommandAuthorizer } from '../security/authorization'
import type { SessionManager } from '../ssh/session-manager'
import type { HostKeyService } from '../ssh/host-keys'

export class ServerService {
  constructor(
    private readonly servers: ServerRepo,
    private readonly hostKeys: HostKeyService,
    private readonly creds: CredentialStore,
    private readonly sessions: SessionManager,
    private readonly authz: CommandAuthorizer,
    private readonly audit: AuditLogger
  ) {}

  /** Public projection safe for MCP and logs: NEVER contains keyPath or secret fields. */
  toPublicInfo(s: ServerRow): ServerPublicInfo {
    return {
      id: s.id,
      name: s.name,
      host: s.host,
      port: s.port,
      username: s.username,
      authType: s.authType,
      approvalPolicy: s.approvalPolicy,
      mcpAccessEnabled: s.mcpAccessEnabled,
      connected: !!this.sessions.activeFor(s.id)
    }
  }

  /** GUI-only projection including keyPath (path on disk only) and boolean credential flags. */
  toPrivateInfo(s: ServerRow): ServerPrivateInfo {
    const kinds = this.creds.kinds(s.id)
    const kh = this.hostKeys.getForEndpoint(s.host, s.port)
    return {
      ...this.toPublicInfo(s),
      keyPath: s.keyPath,
      credentials: { password: kinds.includes('password'), passphrase: kinds.includes('passphrase') },
      knownHost: kh,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt
    }
  }

  listPrivate(): ServerPrivateInfo[] {
    return this.servers.list().map((s) => this.toPrivateInfo(s))
  }

  listPublicForMcp(): ServerPublicInfo[] {
    return this.servers.list().filter((s) => s.mcpAccessEnabled).map((s) => this.toPublicInfo(s))
  }

  getPrivate(id: string): ServerPrivateInfo {
    const s = this.servers.get(id)
    if (!s) throw new Error('server not found')
    return this.toPrivateInfo(s)
  }

  create(f: ServerFields): ServerPrivateInfo {
    const s = this.servers.create(f)
    this.audit.log('server.created', 'user', {
      serverId: s.id, name: s.name, host: s.host, port: s.port, username: s.username, authType: s.authType, approvalPolicy: s.approvalPolicy
    })
    return this.toPrivateInfo(s)
  }

  update(id: string, patch: Partial<ServerFields>): ServerPrivateInfo {
    const before = this.servers.get(id)
    if (!before) throw new Error('server not found')
    const after = this.servers.update(id, patch)
    if (!after) throw new Error('server not found')
    const endpointChanged = before.host !== after.host || before.port !== after.port
    const identityChanged = endpointChanged || before.username !== after.username || before.authType !== after.authType || before.keyPath !== after.keyPath
    if (identityChanged || before.mcpAccessEnabled !== after.mcpAccessEnabled || before.approvalPolicy !== after.approvalPolicy) {
      if (identityChanged) this.sessions.disconnectServer(id, 'server connection settings changed')
      this.authz.invalidateServer(id, identityChanged ? 'server connection settings changed' : 'server policy changed')
    }
    this.audit.log('server.updated', 'user', { serverId: id, changed: Object.keys(patch) })
    return this.toPrivateInfo(after)
  }

  delete(id: string): void {
    const server = this.servers.get(id)
    // Known-host trust is keyed by (host, port), not by server id, so deleting a server
    // deliberately KEEPS its pins: a re-created server for the same endpoint stays verified
    // and will not silently re-prompt for a key it already trusted.
    const pins = server ? this.hostKeys.listForEndpoint(server.host, server.port) : []
    this.sessions.disconnectServer(id, 'server deleted')
    this.authz.invalidateServer(id, 'server deleted')
    this.creds.deleteAllFor(id)
    this.servers.delete(id)
    this.audit.log('server.deleted', 'user', {
      serverId: id,
      name: server?.name ?? null,
      host: server?.host ?? null,
      port: server?.port ?? null,
      retainedKnownHostPins: pins.length,
      retainedKeyTypes: pins.map((p) => p.keyType)
    })
  }

  setSecret(id: string, kind: SecretKind, secret: string): ServerPrivateInfo {
    if (!this.servers.get(id)) throw new Error('server not found')
    this.creds.set(id, kind, secret)
    this.sessions.disconnectServer(id, 'credential changed')
    this.authz.invalidateServer(id, 'credential changed')
    this.audit.log('credential.set', 'user', { serverId: id, kind })
    return this.getPrivate(id)
  }

  clearSecret(id: string, kind: SecretKind): ServerPrivateInfo {
    if (!this.servers.get(id)) throw new Error('server not found')
    this.creds.delete(id, kind)
    this.authz.invalidateServer(id, 'credential removed')
    this.audit.log('credential.removed', 'user', { serverId: id, kind })
    return this.getPrivate(id)
  }
}
