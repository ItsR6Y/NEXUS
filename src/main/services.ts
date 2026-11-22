import { EventEmitter } from 'node:events'
import { DEFAULT_SETTINGS, type Settings } from '../shared/ipc'
import { AuditLogger } from './core/audit/audit-logger'
import { SafeStorageCredentialStore, type CredentialStore, type SecretCipher } from './core/credentials/credential-store'
import type { Db } from './core/db/database'
import { ApprovalRepo, CredentialRefRepo, ExecutionRepo, KnownHostRepo, ServerRepo, SessionRepo, SettingsRepo } from './core/db/repositories'
import { ExecutionService } from './core/execution/execution-service'
import { McpService } from './core/mcp-bridge/mcp-service'
import { ToolRouter } from './core/mcp-bridge/tool-router'
import { ServerService } from './core/servers/server-service'
import { CommandAuthorizer } from './core/security/authorization'
import { HostKeyService } from './core/ssh/host-keys'
import { SessionManager } from './core/ssh/session-manager'
import { FileLogger } from './logger'
import { resolveAppPaths } from './paths'
import type { ApprovalPresenter } from './security/approvals-ui'
import type { HostKeyPresenter } from './ssh/hostkey-prompt'
import type { Client } from 'ssh2'

export interface ServicesOptions {
  db: Db
  credentialStore?: CredentialStore
  cipher?: SecretCipher
  approvalPresenter: ApprovalPresenter
  hostKeyPresenter: HostKeyPresenter
  userDataDir: string
  mcpServerPath: string
  endpointFile?: string
  platform?: NodeJS.Platform
  clientFactory?: () => Client
  now?: () => number
  hostKeyPromptTimeoutMs?: number
  mcpLimits?: ConstructorParameters<typeof McpService>[0]['limits']
}

/** Dependency-injected composition root. Electron-free so integration tests exercise the full main backend. */
export class Services {
  readonly bus = new EventEmitter()
  readonly settingsRepo: SettingsRepo
  readonly serverRepo: ServerRepo
  readonly sessionRepo: SessionRepo
  readonly executionRepo: ExecutionRepo
  readonly approvalRepo: ApprovalRepo
  readonly knownHostRepo: KnownHostRepo
  readonly creds: CredentialStore
  readonly logger: FileLogger
  readonly audit: AuditLogger
  readonly hostKeys: HostKeyService
  readonly sessions: SessionManager
  readonly authz: CommandAuthorizer
  readonly exec: ExecutionService
  readonly servers: ServerService
  readonly router: ToolRouter
  readonly mcp: McpService
  private sweeper: NodeJS.Timeout | null = null
  private retentionTimer: NodeJS.Timeout | null = null

  constructor(readonly o: ServicesOptions) {
    const { db } = o
    const paths = resolveAppPaths(o.userDataDir)
    this.settingsRepo = new SettingsRepo(db)
    this.serverRepo = new ServerRepo(db)
    this.sessionRepo = new SessionRepo(db)
    this.executionRepo = new ExecutionRepo(db)
    this.approvalRepo = new ApprovalRepo(db)
    this.knownHostRepo = new KnownHostRepo(db)

    if (o.credentialStore) {
      this.creds = o.credentialStore
    } else if (o.cipher) {
      this.creds = new SafeStorageCredentialStore(new CredentialRefRepo(db), o.cipher)
    } else {
      throw new Error('Services requires either credentialStore or cipher')
    }

    const secrets = (): string[] => this.creds.redactionValues()
    this.logger = new FileLogger({ logFile: paths.logFile, getSecrets: secrets, now: o.now })
    this.audit = new AuditLogger(db, secrets, o.now)
    this.hostKeys = new HostKeyService(
      this.knownHostRepo,
      o.hostKeyPresenter,
      this.audit,
      () => this.bus.emit('knownHosts'),
      o.now,
      o.hostKeyPromptTimeoutMs
    )
    this.sessions = new SessionManager({
      servers: this.serverRepo,
      sessions: this.sessionRepo,
      creds: this.creds,
      hostKeys: this.hostKeys,
      audit: this.audit,
      authz: () => this.authz,
      settings: () => this.settings(),
      clientFactory: o.clientFactory
    })
    this.authz = new CommandAuthorizer(
      this.approvalRepo,
      () => this.settings(),
      this.audit,
      o.approvalPresenter,
      () => this.bus.emit('approvals'),
      o.now,
      secrets
    )
    this.exec = new ExecutionService(
      this.authz,
      this.sessions.resolveExecutionContext,
      this.executionRepo,
      this.sessions,
      this.audit,
      secrets
    )
    this.servers = new ServerService(this.serverRepo, this.hostKeys, this.creds, this.sessions, this.authz, this.audit)
    this.router = new ToolRouter({
      serverRepo: this.serverRepo,
      servers: this.servers,
      sessions: this.sessions,
      exec: this.exec,
      audit: this.audit,
      secrets
    })
    this.mcp = new McpService({
      router: this.router,
      audit: this.audit,
      endpointFile: o.endpointFile ?? paths.bridgeFile,
      serverScriptPath: o.mcpServerPath,
      platform: o.platform,
      limits: o.mcpLimits
    })

    this.sessions.on('changed', () => this.bus.emit('sessions'))
    this.sessions.on('shell-data', (id: string, data: string) => this.bus.emit('shell-data', id, data))
    this.sessions.on('shell-closed', (id: string, reason: string) => this.bus.emit('shell-closed', id, reason))
    this.exec.on('changed', () => this.bus.emit('executions'))
    this.audit.on('security', () => this.bus.emit('security'))
    this.mcp.on('changed', () => this.bus.emit('mcp'))
  }

  settings(): Settings {
    return this.settingsRepo.getAll()
  }

  async init(): Promise<void> {
    this.sessionRepo.markAllDisconnected()
    this.executionRepo.failRunning()
    this.authz.invalidateAllOnStartup()
    this.creds.primeRedaction(this.serverRepo.list().map((s) => s.id))
    const pruned = this.pruneRetention()
    this.logger.info('app.started', { credentialBackend: this.creds.backendName(), prunedHistory: pruned.history, prunedApprovals: pruned.approvals })
    this.audit.log('app.started', 'system', { credentialBackend: this.creds.backendName(), credentialsAvailable: this.creds.available() })
    // Seed the cached integrity result once per launch; the dashboard only extends it afterwards.
    this.audit.verify()

    this.sweeper = setInterval(() => {
      this.authz.sweep()
      this.bus.emit('approvals')
    }, 5_000)
    this.sweeper.unref()

    this.retentionTimer = setInterval(() => {
      this.pruneRetention()
    }, 24 * 60 * 60 * 1000)
    this.retentionTimer.unref()

    if (this.settings().mcpEnabled) {
      try {
        await this.mcp.start()
      } catch (e) {
        this.logger.warn('mcp.start_failed', { message: (e as Error).message })
        this.audit.securityEvent('mcp_start_failed', 'warning', { message: (e as Error).message })
      }
    }
  }

  /** Daily retention: execution history plus decided approvals older than the history window. */
  pruneRetention(now = (this.o.now ?? Date.now)()): { history: number; approvals: number } {
    const days = this.settings().historyRetentionDays
    const cutoff = now - Math.max(1, days) * 86_400_000
    return {
      history: this.exec.pruneRetention(days, now),
      approvals: this.approvalRepo.pruneDecidedBefore(cutoff)
    }
  }

  async setMcpEnabled(enabled: boolean): Promise<void> {
    this.settingsRepo.patch({ mcpEnabled: enabled })
    this.audit.log('settings.changed', 'user', { mcpEnabled: enabled })
    if (enabled) await this.mcp.start()
    else await this.mcp.stop()
  }

  async shutdown(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper)
    if (this.retentionTimer) clearInterval(this.retentionTimer)
    await this.mcp.stop()
    this.sessions.disconnectAll()
    this.logger.info('app.shutdown')
    this.o.db.close()
  }
}

export { DEFAULT_SETTINGS }
