import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import net from 'node:net'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { resolve } from 'node:path'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { TOOL_NAMES, encodeFrame } from '../../src/shared/bridge'
import { BridgeClient } from '../../src/mcp/bridge-client'
import { makeHarness, type Harness } from '../fixtures/harness'

let h: Harness | null = null
let client: BridgeClient | null = null
let stdioClient: Client | null = null
afterEach(async () => {
  client?.close()
  client = null
  if (stdioClient) { await stdioClient.close(); stdioClient = null }
  if (h) { await h.cleanup(); h = null }
})

describe('MCP bridge authentication and exact 5-tool contract', () => {
  it('exposes exactly the 5 mandated MCP tools and rejects forbidden lifecycle/approval tools and spoofed fields', async () => {
    expect([...TOOL_NAMES]).toEqual([
      'nexus_list_servers',
      'nexus_list_sessions',
      'nexus_run_command',
      'nexus_get_history',
      'nexus_read_terminal_tail'
    ])

    h = await makeHarness({ approvalPolicy: 'ask', mcpAccess: true })
    await h.svc.setMcpEnabled(true)
    const sid = await h.connect()
    const epFile = join(h.dir, 'bridge.json')
    client = new BridgeClient({ endpointFile: epFile, clientName: 'test-claude', clientVersion: '1.0.0' })

    // 1. nexus_list_servers returns public info only
    const servers = (await client.call('nexus_list_servers', {})) as { servers: Record<string, unknown>[] }
    expect(servers.servers.length).toBe(1)
    expect('keyPath' in servers.servers[0]).toBe(false)
    expect('credentials' in servers.servers[0]).toBe(false)

    // 2. nexus_list_sessions returns connected sessions
    const sessions = (await client.call('nexus_list_sessions', {})) as { sessions: { sessionId: string }[] }
    expect(sessions.sessions.length).toBe(1)
    expect(sessions.sessions[0].sessionId).toBe(sid)

    // 3. nexus_run_command denied via native presenter -> ZERO SSH exec calls
    h.approvals.handler = async () => 'deny'
    const denied = (await client.call('nexus_run_command', {
      serverId: h.serverId,
      sessionId: sid,
      command: 'rm -rf /tmp/x'
    })) as { status: string }
    expect(denied.status).toBe('denied')
    expect(h.ssh.commands).toEqual([])

    // 4. Spoofed source/approved fields rejected by strict schema
    await expect(
      client.call('nexus_run_command', {
        serverId: h.serverId,
        sessionId: sid,
        command: 'pwd',
        source: 'user',
        approved: true
      })
    ).rejects.toThrow(/Unrecognized key/i)

    // 5. Approved nexus_run_command runs and redacts canary secrets
    h.approvals.handler = async () => 'approve'
    const ok = (await client.call('nexus_run_command', {
      serverId: h.serverId,
      sessionId: sid,
      command: 'echo AKIAIOSFODNN7EXAMPLE'
    })) as { status: string; stdout: string }
    expect(ok.status).toBe('completed')
    expect(ok.stdout).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(ok.stdout).toContain('[REDACTED]')

    // 6. nexus_get_history returns sanitized records
    const hist = (await client.call('nexus_get_history', { limit: 10 })) as { history: { command: string }[] }
    expect(hist.history.length).toBeGreaterThanOrEqual(2)
    expect(JSON.stringify(hist)).not.toContain('AKIAIOSFODNN7EXAMPLE')

    // 7. nexus_read_terminal_tail returns ANSI-stripped redacted output
    await h.svc.sessions.openShell(sid, 80, 24)
    h.svc.sessions.shellInput(sid, 'echo hello-tail\r')
    await new Promise((r) => setTimeout(r, 150))
    const tail = (await client.call('nexus_read_terminal_tail', { sessionId: sid, lines: 20 })) as { tail: string; redacted: boolean }
    expect(tail.redacted).toBe(true)
    expect(tail.tail).toContain('hello-tail')
    expect(tail.tail).not.toContain('\x1b[')
  })

  it('runs the built MCP stdio server over its real stdio and named-pipe bridge', async () => {
    h = await makeHarness({ approvalPolicy: 'ask', mcpAccess: true })
    await h.svc.setMcpEnabled(true)
    const sid = await h.connect()
    const epFile = join(h.dir, 'bridge.json')
    client = new BridgeClient({ endpointFile: epFile, clientName: 'stage-e-pipe-client', clientVersion: '1.0.0' })
    const mcpBundle = resolve(process.cwd(), 'out/mcp/nexus-mcp.mjs')
    // `out/mcp/nexus-mcp.mjs` is a build artifact: `npm test` may legitimately run before
    // `npm run build` on a clean tree, so build just the MCP bundle when it is absent.
    if (!existsSync(mcpBundle)) execFileSync(process.execPath, [resolve(process.cwd(), 'scripts/build-mcp.mjs')], { stdio: 'ignore' })
    stdioClient = new Client({ name: 'stage-e-test-client', version: '1.0.0' })
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [mcpBundle],
      env: { ...process.env, NEXUS_MCP_ENDPOINT: epFile },
      stderr: 'pipe'
    })
    await stdioClient.connect(transport)

    const listedTools = await stdioClient.listTools()
    expect(listedTools.tools.map((tool) => tool.name)).toEqual([...TOOL_NAMES])
    expect(listedTools.tools.some((tool) => /credential|approve|open session|close session/i.test(tool.name))).toBe(false)

    const servers = await stdioClient.callTool({ name: 'nexus_list_servers', arguments: {} })
    expect(servers.isError).not.toBe(true)
    expect(JSON.stringify(servers)).not.toContain('credentials')

    const sessions = await stdioClient.callTool({ name: 'nexus_list_sessions', arguments: {} })
    expect(JSON.stringify(sessions)).toContain(sid)

    h.approvals.handler = async () => 'deny'
    const denied = await stdioClient.callTool({
      name: 'nexus_run_command',
      arguments: { serverId: h.serverId, sessionId: sid, command: 'pwd' }
    })
    expect(denied.isError).toBe(true)
    expect(h.ssh.commands).toEqual([])

    h.approvals.handler = async () => 'approve'
    const executed = await stdioClient.callTool({
      name: 'nexus_run_command',
      arguments: { serverId: h.serverId, sessionId: sid, command: 'pwd' }
    })
    expect(executed.isError).not.toBe(true)
    expect(JSON.stringify(executed)).toContain('/home/tester')
    expect(h.ssh.commands).toEqual(['pwd'])

    const beforeMalformed = [...h.ssh.commands]
    const malformed = await stdioClient.callTool({
      name: 'nexus_run_command',
      arguments: { serverId: h.serverId, sessionId: sid, command: '' }
    })
    expect(malformed.isError).toBe(true)
    expect(h.ssh.commands).toEqual(beforeMalformed)

    const history = await stdioClient.callTool({ name: 'nexus_get_history', arguments: { limit: 10 } })
    expect(JSON.stringify(history)).toContain('pwd')
    await stdioClient.close()
    stdioClient = null
    expect(h.svc.mcp.listening).toBe(true)
    expect((await client.call('nexus_list_servers', {}))).toHaveProperty('servers')
    await h.svc.mcp.stop()
    await expect(client.call('nexus_list_servers', {})).rejects.toThrow()
  })

  it('rejects bad HMAC authentication tokens and closes the pipe', async () => {
    h = await makeHarness({ mcpAccess: true })
    await h.svc.setMcpEnabled(true)
    const ep = JSON.parse(readFileSync(join(h.dir, 'bridge.json'), 'utf8')) as { pipeName: string }

    const closed = await new Promise<boolean>((resolve) => {
      const sock = net.connect(ep.pipeName)
      sock.once('data', () => {
        sock.write(
          encodeFrame({
            type: 'auth',
            clientNonce: '0'.repeat(64),
            hmac: 'f'.repeat(64),
            client: { name: 'attacker', version: '1.0' }
          })
        )
      })
      sock.on('close', () => resolve(true))
      sock.on('error', () => resolve(true))
    })
    expect(closed).toBe(true)
    expect(h.svc.audit.listSecurityEvents().some((e) => e.type === 'mcp_auth_failure')).toBe(true)
  })
})
