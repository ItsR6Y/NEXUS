import type { ApprovalPolicy, RiskLevel } from './policy-types'

export type AuthType = 'password' | 'key'
export type SecretKind = 'password' | 'passphrase'
export type SessionState = 'connecting' | 'connected' | 'disconnected' | 'error'
export type CommandSource = 'user' | 'claude'
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled' | 'invalidated' | 'consumed'
export type ExecutionStatus = 'running' | 'completed' | 'failed' | 'timeout' | 'cancelled' | 'denied'

export interface KnownHostDTO {
  host: string
  port: number
  keyType: string
  fingerprintSha256: string
  firstSeenAt: number
  lastSeenAt: number
}

/** Public server info safe for MCP and logs: NEVER contains keyPath or secret material. */
export interface ServerPublicInfo {
  id: string
  name: string
  host: string
  port: number
  username: string
  authType: AuthType
  approvalPolicy: ApprovalPolicy
  mcpAccessEnabled: boolean
  connected: boolean
}

/** GUI-only server DTO: may expose keyPath (path on disk, never contents) and boolean credential flags. */
export interface ServerPrivateInfo extends ServerPublicInfo {
  keyPath: string | null
  credentials: { password: boolean; passphrase: boolean }
  knownHost: KnownHostDTO | null
  createdAt: number
  updatedAt: number
}

export interface SessionDTO {
  id: string
  serverId: string
  serverName: string
  title: string
  epoch: number
  state: SessionState
  openedAt: number
  closedAt: number | null
  hasShell: boolean
  error: string | null
}

export interface ApprovalDTO {
  id: string
  /** Always redacted before persistence and display. Raw command bytes are never stored. */
  commandSanitized: string
  serverId: string
  serverName: string
  sessionId: string
  epoch: number
  level: RiskLevel
  reasons: string[]
  flags: string[]
  source: CommandSource
  requester: string
  status: ApprovalStatus
  createdAt: number
  expiresAt: number
  timeoutMs: number
  maxOutputBytes: number
  invalidationReason: string | null
}

export interface ExecutionDTO {
  id: string
  serverId: string
  sessionId: string
  source: CommandSource
  requester: string
  commandSanitized: string
  level: RiskLevel
  flags: string[]
  status: ExecutionStatus
  exitCode: number | null
  signal: string | null
  startedAt: number
  finishedAt: number | null
  truncated: boolean
  /** Byte length of the persisted output; the text itself is fetched via `executions:output`. */
  outputBytes: number
  denialReason: string | null
  approvalId: string | null
}

export type ExecutionResult =
  | {
      status: 'completed'
      commandId: string
      exitCode: number | null
      signal: string | null
      stdout: string
      stderr: string
      truncated: boolean
      durationMs: number
    }
  | {
      status: 'timeout' | 'cancelled'
      commandId: string
      stdout: string
      stderr: string
      truncated: boolean
      durationMs: number
    }
  | {
      status: 'denied'
      commandId: string
      reason: string
      level: RiskLevel
    }
  | {
      status: 'error'
      commandId: string
      code: string
      message: string
    }

export interface ExecutionFilter {
  serverId?: string
  sessionId?: string
  source?: CommandSource
  level?: RiskLevel
  status?: ExecutionStatus
  limit?: number
  offset?: number
}

export interface OutputPage {
  text: string
  nextSeq: number
  done: boolean
  truncated: boolean
  status: ExecutionStatus
}

export interface AuditDTO {
  id: number
  ts: number
  kind: string
  actor: string
  data: Record<string, unknown>
  hash: string
}

export interface SecurityEventDTO {
  id: number
  ts: number
  type: string
  severity: 'info' | 'warning' | 'critical'
  serverId: string | null
  details: Record<string, unknown>
}

export interface AuditVerifyResult {
  ok: boolean
  entries: number
  brokenAt: number | null
}

export interface McpClientDTO {
  id: string
  name: string
  version: string
  connectedAt: number
  calls: number
}

export interface McpCallDTO {
  ts: number
  client: string
  tool: string
  ok: boolean
  summary: string
}

export interface McpStatusDTO {
  enabled: boolean
  listening: boolean
  pipeName: string | null
  endpointFile: string | null
  clients: McpClientDTO[]
  recentCalls: McpCallDTO[]
  registrationCommand: string
  jsonConfig: string
}

export interface DashboardDTO {
  serverCount: number
  activeSessions: number
  pendingApprovals: number
  mcpListening: boolean
  /** Authenticated MCP clients currently attached — listening is not the same as connected. */
  mcpClients: number
  recentExecutions: ExecutionDTO[]
  securityEvents24h: number
  auditChain: AuditVerifyResult
  credentialBackend: string
  credentialsAvailable: boolean
}

export type ConnectResult =
  | { status: 'connected'; session: SessionDTO }
  | { status: 'host_key_rejected'; serverId: string; fingerprint: string; reason: string }
  | { status: 'host_key_mismatch'; serverId: string; algorithm: string; expectedFingerprint: string; actualFingerprint: string }
  | { status: 'needs_user_input'; serverId: string; reason: string }
  | { status: 'error'; code: string; message: string }

export interface Result<T> { ok: true; data: T }
export interface Failure { ok: false; error: { code: string; message: string } }
export type Envelope<T> = Result<T> | Failure
