import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { z } from 'zod'
import { TOOL_NAMES, toolInputShapes, type ToolName } from '../shared/bridge'
import { BridgeClient, BridgeError, defaultEndpointFile } from './bridge-client'

const VERSION = '1.0.0'

interface Meta {
  title: string
  description: string
  readOnly: boolean
  destructive: boolean
  idempotent: boolean
}

const META: Record<ToolName, Meta> = {
  nexus_list_servers: {
    title: 'List NEXUS servers',
    description: 'List configured SSH servers that the user explicitly enabled for MCP access (public info only; never key paths or secrets).',
    readOnly: true,
    destructive: false,
    idempotent: true
  },
  nexus_list_sessions: {
    title: 'List connected SSH sessions',
    description: 'List currently connected SSH sessions on MCP-enabled servers. MCP cannot open, close, or reconnect sessions.',
    readOnly: true,
    destructive: false,
    idempotent: true
  },
  nexus_run_command: {
    title: 'Run command on an SSH session',
    description: 'Run a command on a connected SSH session through NEXUS authorization. Blocks until the user decides in a native OS approval dialog (or expiry). Returns ANSI-stripped, secret-redacted output.',
    readOnly: false,
    destructive: true,
    idempotent: false
  },
  nexus_get_history: {
    title: 'Get command history',
    description: 'Retrieve sanitized, secret-redacted command execution history for MCP-enabled servers (limit <= 100).',
    readOnly: true,
    destructive: false,
    idempotent: true
  },
  nexus_read_terminal_tail: {
    title: 'Read terminal tail',
    description: 'Read the bounded, ANSI-stripped, secret-redacted tail of an active SSH terminal buffer (lines <= 200).',
    readOnly: true,
    destructive: false,
    idempotent: true
  }
}

export function buildServer(client: BridgeClient): McpServer {
  const server = new McpServer({ name: 'nexus', version: VERSION })

  for (const name of TOOL_NAMES) {
    const m = META[name]
    server.registerTool(
      name,
      {
        title: m.title,
        description: m.description,
        inputSchema: toolInputShapes[name] as z.ZodRawShape,
        annotations: {
          title: m.title,
          readOnlyHint: m.readOnly,
          destructiveHint: m.destructive,
          idempotentHint: m.idempotent,
          openWorldHint: !m.readOnly
        }
      },
      async (args: Record<string, unknown>) => {
        try {
          const result = (await client.call(name, args)) as Record<string, unknown>
          // Per NEXUS-BUILD-PLAN.md §7: mark command denials, timeouts, and execution errors as isError: true.
          const isDeniedOrError =
            name === 'nexus_run_command' &&
            (result.status === 'denied' || result.status === 'error' || result.status === 'timeout')
          return {
            isError: isDeniedOrError,
            content: [{ type: 'text' as const, text: JSON.stringify(result) }],
            structuredContent: result
          }
        } catch (e) {
          const err = e instanceof BridgeError ? { code: e.code, message: e.message } : { code: 'internal', message: 'unexpected error' }
          return {
            isError: true,
            content: [{ type: 'text' as const, text: JSON.stringify({ error: err }) }]
          }
        }
      }
    )
  }

  return server
}

async function main(): Promise<void> {
  const client = new BridgeClient({
    endpointFile: defaultEndpointFile(),
    clientName: process.env.NEXUS_MCP_CLIENT_NAME ?? 'claude-code',
    clientVersion: VERSION
  })
  const server = buildServer(client)
  await server.connect(new StdioServerTransport())
  process.on('SIGINT', () => { client.close(); process.exit(0) })
}

const isMain = typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isMain) {
  main().catch((e: unknown) => {
    process.stderr.write(`nexus-mcp fatal: ${(e as Error)?.message ?? 'startup error'}\n`)
    process.exit(1)
  })
}
