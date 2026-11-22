/**
 * Authenticated named-pipe bridge protocol between the stdio MCP process and Electron main.
 * Enforces the EXACT 5-tool MCP contract from NEXUS-BUILD-PLAN.md.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import { DEFAULT_EXEC_TIMEOUT_MS, DEFAULT_MAX_OUTPUT_BYTES, MAX_COMMAND_LENGTH, MAX_EXEC_TIMEOUT_MS, MAX_MAX_OUTPUT_BYTES, idSchema } from './ipc'

export const BRIDGE_VERSION = 1
export const MAX_FRAME_BYTES = 1_048_576

/** Authoritative 5-tool MCP surface. No session lifecycle, server creation, credential, or approval tools. */
export const TOOL_NAMES = [
  'nexus_list_servers',
  'nexus_list_sessions',
  'nexus_run_command',
  'nexus_get_history',
  'nexus_read_terminal_tail'
] as const
export type ToolName = (typeof TOOL_NAMES)[number]

export const toolInputShapes = {
  nexus_list_servers: {},
  nexus_list_sessions: {},
  nexus_run_command: {
    serverId: idSchema,
    sessionId: idSchema,
    command: z.string().min(1).max(MAX_COMMAND_LENGTH),
    timeoutMs: z.number().int().min(1000).max(MAX_EXEC_TIMEOUT_MS).optional(),
    maxOutputBytes: z.number().int().min(1024).max(MAX_MAX_OUTPUT_BYTES).optional()
  },
  nexus_get_history: {
    serverId: idSchema.optional(),
    limit: z.number().int().min(1).max(100).optional()
  },
  nexus_read_terminal_tail: {
    sessionId: idSchema,
    lines: z.number().int().min(1).max(200).optional()
  }
} as const satisfies Record<ToolName, z.ZodRawShape>

/** Every tool schema uses strictObject so spoofed fields (source, approved, risk, policy) are rejected. */
export const toolSchemas = {
  nexus_list_servers: z.strictObject(toolInputShapes.nexus_list_servers),
  nexus_list_sessions: z.strictObject(toolInputShapes.nexus_list_sessions),
  nexus_run_command: z.strictObject(toolInputShapes.nexus_run_command),
  nexus_get_history: z.strictObject(toolInputShapes.nexus_get_history),
  nexus_read_terminal_tail: z.strictObject(toolInputShapes.nexus_read_terminal_tail)
} as const

export function resolveExecParams(
  p: { timeoutMs?: number; maxOutputBytes?: number },
  defaults?: { timeoutMs?: number; maxOutputBytes?: number }
): { timeoutMs: number; maxOutputBytes: number } {
  return {
    timeoutMs: p.timeoutMs ?? defaults?.timeoutMs ?? DEFAULT_EXEC_TIMEOUT_MS,
    maxOutputBytes: p.maxOutputBytes ?? defaults?.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES
  }
}

const hex = (len: number) => z.string().regex(new RegExp(`^[0-9a-f]{${len}}$`))

export const HelloFrame = z.strictObject({ type: z.literal('hello'), v: z.literal(BRIDGE_VERSION), nonce: hex(64) })
export const AuthFrame = z.strictObject({
  type: z.literal('auth'),
  clientNonce: hex(64),
  hmac: hex(64),
  client: z.strictObject({
    name: z.string().min(1).max(64).regex(/^[A-Za-z0-9._ -]+$/),
    version: z.string().min(1).max(32).regex(/^[A-Za-z0-9._+-]+$/)
  })
})
export const ReadyFrame = z.strictObject({ type: z.literal('ready') })
export const RequestFrame = z.strictObject({
  type: z.literal('request'),
  id: z.string().min(1).max(64),
  tool: z.enum(TOOL_NAMES),
  args: z.record(z.string(), z.unknown())
})
export const ErrorBody = z.strictObject({ code: z.string().max(64), message: z.string().max(2000) })
export const ResponseFrame = z.discriminatedUnion('ok', [
  z.strictObject({ type: z.literal('response'), id: z.string(), ok: z.literal(true), result: z.unknown() }),
  z.strictObject({ type: z.literal('response'), id: z.string(), ok: z.literal(false), error: ErrorBody })
])
export const FatalFrame = z.strictObject({ type: z.literal('fatal'), code: z.string().max(64), message: z.string().max(500) })
export const EndpointFile = z.strictObject({
  version: z.literal(BRIDGE_VERSION),
  pipeName: z.string().min(1).max(260),
  secret: hex(64),
  pid: z.number().int().positive()
})
export type EndpointFileT = z.infer<typeof EndpointFile>

export function newNonce(): string { return randomBytes(32).toString('hex') }

export function computeHmac(secretHex: string, serverNonce: string, clientNonce: string): string {
  return createHmac('sha256', Buffer.from(secretHex, 'hex')).update(Buffer.from(serverNonce + clientNonce, 'utf8')).digest('hex')
}

export function verifyHmac(secretHex: string, serverNonce: string, clientNonce: string, given: string): boolean {
  const a = Buffer.from(computeHmac(secretHex, serverNonce, clientNonce), 'hex')
  const b = Buffer.from(given, 'hex')
  return a.length === b.length && timingSafeEqual(a, b)
}

export function encodeFrame(obj: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(obj), 'utf8')
  if (body.length > MAX_FRAME_BYTES) throw new Error('frame too large')
  const head = Buffer.alloc(4)
  head.writeUInt32BE(body.length, 0)
  return Buffer.concat([head, body])
}

/** Length-prefixed JSON decoder with a hard size cap. Throws on oversize or invalid JSON. */
export class FrameDecoder {
  private buf: Buffer = Buffer.alloc(0)
  push(chunk: Buffer): unknown[] {
    this.buf = Buffer.concat([this.buf, chunk])
    const out: unknown[] = []
    for (;;) {
      if (this.buf.length < 4) break
      const len = this.buf.readUInt32BE(0)
      if (len > MAX_FRAME_BYTES) throw new Error('frame exceeds size limit')
      if (this.buf.length < 4 + len) break
      const body = this.buf.subarray(4, 4 + len)
      this.buf = this.buf.subarray(4 + len)
      out.push(JSON.parse(body.toString('utf8')))
    }
    if (this.buf.length > MAX_FRAME_BYTES + 4) throw new Error('buffer overflow')
    return out
  }
}
