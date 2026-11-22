import { z } from 'zod'
import { APPROVAL_POLICIES, RISK_LEVELS } from './policy-types'

export const MAX_COMMAND_LENGTH = 16384
export const DEFAULT_EXEC_TIMEOUT_MS = 30_000
export const MAX_EXEC_TIMEOUT_MS = 600_000
export const DEFAULT_MAX_OUTPUT_BYTES = 262_144
export const MAX_MAX_OUTPUT_BYTES = 4_194_304
export const DEFAULT_TAIL_BYTES = 262_144

export const idSchema = z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/)
export const fingerprintSchema = z.string().min(10).max(128).regex(/^SHA256:[A-Za-z0-9+/=]+$/)

const hostRegex = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+)$/

export const serverInputShape = {
  name: z.string().trim().min(1).max(80),
  host: z.string().trim().min(1).max(253).regex(hostRegex, 'invalid host'),
  port: z.number().int().min(1).max(65535),
  username: z.string().trim().min(1).max(64).regex(/^[^\s:/\\\u0000-\u001f]+$/, 'invalid username'),
  authType: z.enum(['password', 'key']),
  keyPath: z.string().trim().min(1).max(1024).nullable().optional(),
  approvalPolicy: z.enum(APPROVAL_POLICIES),
  mcpAccessEnabled: z.boolean()
}

export const ServerInput = z.strictObject(serverInputShape)
export const ServerPatch = z.strictObject(serverInputShape).partial()

export const settingsShape = {
  /** Must stay strictly below the MCP bridge idle timeout (600 s) so an approved command never outlives its caller. */
  approvalTtlSeconds: z.number().int().min(15).max(480),
  mcpEnabled: z.boolean(),
  /** Default false: Claude/MCP requires native approval even for LOW-risk commands unless explicitly enabled. */
  mcpAutoRunLow: z.boolean(),
  defaultExecTimeoutMs: z.number().int().min(1000).max(MAX_EXEC_TIMEOUT_MS),
  defaultMaxOutputBytes: z.number().int().min(4096).max(MAX_MAX_OUTPUT_BYTES),
  terminalTailBytes: z.number().int().min(16384).max(1_048_576),
  historyRetentionDays: z.number().int().min(1).max(365),
  scrollback: z.number().int().min(500).max(100000),
  fontSize: z.number().int().min(10).max(24),
  cursorBlink: z.boolean(),
  theme: z.enum(['nexus-dark', 'midnight', 'matrix'])
}

export const SettingsSchema = z.strictObject(settingsShape)
export const SettingsPatchSchema = z.strictObject(settingsShape).partial()
export type Settings = z.infer<typeof SettingsSchema>

export const DEFAULT_SETTINGS: Settings = {
  approvalTtlSeconds: 120,
  mcpEnabled: false,
  mcpAutoRunLow: false,
  defaultExecTimeoutMs: DEFAULT_EXEC_TIMEOUT_MS,
  defaultMaxOutputBytes: DEFAULT_MAX_OUTPUT_BYTES,
  terminalTailBytes: DEFAULT_TAIL_BYTES,
  historyRetentionDays: 30,
  scrollback: 10000,
  fontSize: 13,
  cursorBlink: true,
  theme: 'nexus-dark'
}

const dims = { cols: z.number().int().min(1).max(500), rows: z.number().int().min(1).max(300) }

export const ExecutionFilterSchema = z.strictObject({
  serverId: idSchema.optional(),
  sessionId: idSchema.optional(),
  source: z.enum(['user', 'claude']).optional(),
  level: z.enum(RISK_LEVELS).optional(),
  status: z.enum(['running', 'completed', 'failed', 'timeout', 'cancelled', 'denied']).optional(),
  limit: z.number().int().min(1).max(500).optional(),
  offset: z.number().int().min(0).max(1_000_000).optional()
})

/**
 * Request payload schema for every IPC invoke channel.
 * SECURITY: Notice there are NO channels for approving commands or trusting/replacing host keys.
 * All security-authority decisions occur exclusively in main-process native OS dialogs.
 */
export const channelSchemas = {
  'app:info': z.undefined(),
  'app:openLogsFolder': z.undefined(),
  'dashboard:get': z.undefined(),
  'servers:list': z.undefined(),
  'servers:create': ServerInput,
  'servers:update': z.strictObject({ id: idSchema, patch: ServerPatch }),
  'servers:delete': z.strictObject({ id: idSchema }),
  'servers:setSecret': z.strictObject({ id: idSchema, kind: z.enum(['password', 'passphrase']), secret: z.string().min(1).max(8192) }),
  'servers:clearSecret': z.strictObject({ id: idSchema, kind: z.enum(['password', 'passphrase']) }),
  'servers:pickKeyPath': z.undefined(),
  'sessions:list': z.undefined(),
  'sessions:connect': z.strictObject({ serverId: idSchema }),
  'sessions:disconnect': z.strictObject({ sessionId: idSchema }),
  'knownHosts:list': z.undefined(),
  'knownHosts:remove': z.strictObject({ host: z.string().min(1).max(253), port: z.number().int().min(1).max(65535), keyType: z.string().min(1).max(64) }),
  'terminal:open': z.strictObject({ sessionId: idSchema, ...dims }),
  'terminal:input': z.strictObject({ sessionId: idSchema, data: z.string().max(65536) }),
  'terminal:resize': z.strictObject({ sessionId: idSchema, ...dims }),
  'terminal:close': z.strictObject({ sessionId: idSchema }),
  'commands:execute': z.strictObject({
    serverId: idSchema,
    sessionId: idSchema,
    command: z.string().min(1).max(MAX_COMMAND_LENGTH),
    timeoutMs: z.number().int().min(1000).max(MAX_EXEC_TIMEOUT_MS).optional(),
    maxOutputBytes: z.number().int().min(1024).max(MAX_MAX_OUTPUT_BYTES).optional(),
    clientCommandId: idSchema.optional()
  }),
  'commands:cancel': z.strictObject({ commandId: idSchema }),
  'approvals:list': z.undefined(),
  'executions:list': ExecutionFilterSchema,
  'executions:get': z.strictObject({ id: idSchema }),
  'executions:output': z.strictObject({ id: idSchema, afterSeq: z.number().int().min(0), maxBytes: z.number().int().min(1).max(262144) }),
  'executions:clear': z.undefined(),
  'security:events': z.undefined(),
  'audit:verify': z.undefined(),
  'audit:list': z.strictObject({ limit: z.number().int().min(1).max(500) }),
  'mcp:status': z.undefined(),
  'mcp:setEnabled': z.strictObject({ enabled: z.boolean() }),
  'mcp:disconnectClient': z.strictObject({ clientId: idSchema }),
  'settings:get': z.undefined(),
  'settings:set': SettingsPatchSchema
} as const satisfies Record<string, z.ZodType>

export type Channel = keyof typeof channelSchemas
export const CHANNELS = Object.keys(channelSchemas) as Channel[]

export { EVENTS, type EventName } from './events'
