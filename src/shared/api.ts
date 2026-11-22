import type {
  ApprovalDTO, AuditDTO, AuditVerifyResult, ConnectResult, DashboardDTO, Envelope, ExecutionDTO, ExecutionFilter,
  ExecutionResult, KnownHostDTO, McpStatusDTO, OutputPage, SecretKind, SecurityEventDTO, ServerPrivateInfo, SessionDTO
} from './types'
import type { ApprovalPolicy } from './policy-types'
import type { Settings } from './ipc'

export interface ServerDraftInput {
  name: string
  host: string
  port: number
  username: string
  authType: 'password' | 'key'
  keyPath?: string | null
  approvalPolicy: ApprovalPolicy
  mcpAccessEnabled: boolean
}

type Unsub = () => void

/**
 * The single, explicit, deeply-frozen API exposed to the renderer via contextBridge.
 * SECURITY: No generic invoke(), no approval decision methods, and no host-key trust methods exist here.
 */
export interface NexusApi {
  app: {
    info(): Promise<Envelope<{ version: string; platform: string; credentialBackend: string; credentialsAvailable: boolean }>>
    openLogsFolder(): Promise<Envelope<true>>
  }
  dashboard: { get(): Promise<Envelope<DashboardDTO>> }
  servers: {
    list(): Promise<Envelope<ServerPrivateInfo[]>>
    create(input: ServerDraftInput): Promise<Envelope<ServerPrivateInfo>>
    update(id: string, patch: Partial<ServerDraftInput>): Promise<Envelope<ServerPrivateInfo>>
    delete(id: string): Promise<Envelope<true>>
    setSecret(id: string, kind: SecretKind, secret: string): Promise<Envelope<ServerPrivateInfo>>
    clearSecret(id: string, kind: SecretKind): Promise<Envelope<ServerPrivateInfo>>
    pickKeyPath(): Promise<Envelope<string | null>>
  }
  sessions: {
    list(): Promise<Envelope<SessionDTO[]>>
    connect(serverId: string): Promise<Envelope<ConnectResult>>
    disconnect(sessionId: string): Promise<Envelope<true>>
  }
  knownHosts: {
    list(): Promise<Envelope<KnownHostDTO[]>>
    remove(host: string, port: number, keyType: string): Promise<Envelope<{ removed: boolean }>>
  }
  terminal: {
    open(sessionId: string, cols: number, rows: number): Promise<Envelope<true>>
    input(sessionId: string, data: string): Promise<Envelope<true>>
    resize(sessionId: string, cols: number, rows: number): Promise<Envelope<true>>
    close(sessionId: string): Promise<Envelope<true>>
  }
  commands: {
    execute(input: { serverId: string; sessionId: string; command: string; timeoutMs?: number; maxOutputBytes?: number; clientCommandId?: string }): Promise<Envelope<ExecutionResult>>
    cancel(commandId: string): Promise<Envelope<{ cancelled: boolean }>>
  }
  /** Read-only approval audit view. Decisions are exclusively handled by main-process native OS dialogs. */
  approvals: {
    list(): Promise<Envelope<ApprovalDTO[]>>
  }
  executions: {
    list(filter: ExecutionFilter): Promise<Envelope<ExecutionDTO[]>>
    get(id: string): Promise<Envelope<ExecutionDTO>>
    output(id: string, afterSeq: number, maxBytes: number): Promise<Envelope<OutputPage>>
    clear(): Promise<Envelope<{ cleared: number }>>
  }
  security: { events(): Promise<Envelope<SecurityEventDTO[]>> }
  audit: { verify(): Promise<Envelope<AuditVerifyResult>>; list(limit: number): Promise<Envelope<AuditDTO[]>> }
  mcp: {
    status(): Promise<Envelope<McpStatusDTO>>
    setEnabled(enabled: boolean): Promise<Envelope<McpStatusDTO>>
    disconnectClient(clientId: string): Promise<Envelope<McpStatusDTO>>
  }
  settings: {
    get(): Promise<Envelope<Settings>>
    set(patch: Partial<Settings>): Promise<Envelope<Settings>>
  }
  on: {
    terminalData(cb: (e: { sessionId: string; data: string }) => void): Unsub
    terminalClosed(cb: (e: { sessionId: string; reason: string }) => void): Unsub
    sessionsChanged(cb: () => void): Unsub
    approvalsChanged(cb: () => void): Unsub
    knownHostsChanged(cb: () => void): Unsub
    mcpChanged(cb: () => void): Unsub
    executionsChanged(cb: () => void): Unsub
    securityChanged(cb: () => void): Unsub
  }
}

declare global {
  interface Window { nexus: NexusApi }
}
