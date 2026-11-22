import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { TOOL_NAMES } from '../../src/shared/bridge'
import { makeHarness, type Harness } from '../fixtures/harness'

/**
 * live Claude Code client against the real NEXUS MCP bridge.
 *
 * Requires the built MCP bundle (`npm run build`) and Claude Code on PATH.
 * Opt-in because it spends model quota:
 *   NEXUS_LIVE_CLAUDE=1 NEXUS_LIVE_CLAUDE_MODEL=gpt-6-luna npx vitest run tests/integration/stage3-claude-live.test.ts
 */
const live = process.env['NEXUS_LIVE_CLAUDE'] === '1'
const model = process.env['NEXUS_LIVE_CLAUDE_MODEL'] ?? 'gpt-6-luna'
const claudeBin = process.env['NEXUS_CLAUDE_BIN'] ?? 'claude'

let h: Harness | null = null
let cfgDir: string | null = null
afterEach(async () => {
  if (h) { await h.cleanup(); h = null }
  if (cfgDir) { rmSync(cfgDir, { recursive: true, force: true }); cfgDir = null }
})

interface ParsedRun {
  initTools: string[]
  mcpServers: { name: string; status: string }[]
  toolUses: { name: string; input: Record<string, unknown> }[]
  toolResults: string[]
  raw: string
}

async function runClaude(prompt: string, mcpConfig: string): Promise<ParsedRun> {
  const allowed = TOOL_NAMES.map((n) => `mcp__nexus__${n}`).join(',')
  const args = [
    '-p',
    '--model', model,
    '--mcp-config', mcpConfig,
    '--strict-mcp-config',
    '--output-format', 'stream-json',
    '--verbose',
    '--allowedTools', allowed,
    '--disallowedTools', 'Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,Task,NotebookEdit'
  ]
  const child = spawn(claudeBin, args, { windowsHide: true, env: process.env })
  let out = ''
  let err = ''
  child.stdout.on('data', (d: Buffer) => { out += d.toString('utf8') })
  child.stderr.on('data', (d: Buffer) => { err += d.toString('utf8') })
  child.stdin.write(prompt)
  child.stdin.end()

  const exitCode = await new Promise<number | null>((r) => {
    const t = setTimeout(() => { child.kill(); r(-1) }, 240_000)
    child.on('close', (code) => { clearTimeout(t); r(code) })
  })

  const parsed: ParsedRun = { initTools: [], mcpServers: [], toolUses: [], toolResults: [], raw: out + '\n' + err }
  const uses = new Map<string, { name: string; input: Record<string, unknown> }>()
  for (const line of out.split(/\r?\n/)) {
    if (!line.startsWith('{')) continue
    let ev: Record<string, unknown>
    try { ev = JSON.parse(line) as Record<string, unknown> } catch { continue }
    if (ev['type'] === 'system' && ev['subtype'] === 'init') {
      parsed.initTools = (ev['tools'] as string[] | undefined) ?? []
      parsed.mcpServers = (ev['mcp_servers'] as { name: string; status: string }[] | undefined) ?? []
    }
    if (ev['type'] === 'assistant') {
      const msg = ev['message'] as { content?: { type: string; id?: string; name?: string; input?: Record<string, unknown> }[] }
      for (const block of msg.content ?? []) {
        if (block.type === 'tool_use' && block.name && block.id) {
          uses.set(block.id, { name: block.name, input: block.input ?? {} })
          parsed.toolUses.push({ name: block.name, input: block.input ?? {} })
        }
      }
    }
    if (ev['type'] === 'user') {
      const msg = ev['message'] as { content?: { type: string; tool_use_id?: string; content?: unknown }[] }
      for (const block of msg.content ?? []) {
        if (block.type === 'tool_result') {
          const txt = typeof block.content === 'string' ? block.content : JSON.stringify(block.content)
          parsed.toolResults.push(txt)
        }
      }
    }
  }
  if (exitCode !== 0 && parsed.toolUses.length === 0) {
    console.log('[stage-c] claude exit', exitCode, err.slice(0, 500))
  }
  return parsed
}

describe.skipIf(!live)('live Claude Code client over the real authenticated MCP bridge', () => {
  it('discovers exactly five tools, executes an approved command, and denies an unapproved one with zero SSH', async () => {
    h = await makeHarness({ approvalPolicy: 'always', mcpAccess: true })
    await h.svc.setMcpEnabled(true)
    const sid = await h.connect()
    await h.svc.sessions.openShell(sid, 80, 24)
    h.svc.sessions.shellInput(sid, 'echo tail-marker-ok\r')
    await new Promise((r) => setTimeout(r, 300))

    // Approve only the harmless read-only command; deny everything else.
    h.approvals.handler = async (req) => (req.commandRedacted.trim() === 'pwd' ? 'approve' : 'deny')

    cfgDir = mkdtempSync(join(tmpdir(), 'nexus-stage3-claude-'))
    const mcpConfig = join(cfgDir, 'mcp.json')
    writeFileSync(mcpConfig, JSON.stringify({
      mcpServers: {
        nexus: {
          command: process.execPath,
          args: [resolve(process.cwd(), 'out/mcp/nexus-mcp.mjs')],
          env: { NEXUS_MCP_ENDPOINT: join(h.dir, 'bridge.json') }
        }
      }
    }, null, 2))

    const prompt = [
      'Use ONLY the mcp__nexus tools. Perform these calls in order, exactly once each:',
      '1. nexus_list_servers with {}',
      '2. nexus_list_sessions with {}',
      `3. nexus_run_command with serverId=${h.serverId} sessionId=${sid} command=pwd`,
      `4. nexus_run_command with serverId=${h.serverId} sessionId=${sid} command=whoami`,
      '5. nexus_get_history with {"limit":10}',
      `6. nexus_read_terminal_tail with sessionId=${sid} lines=20`,
      'Do not retry a call that fails. When finished, reply DONE.'
    ].join('\n')

    const run = await runClaude(prompt, mcpConfig)

    // Discovery: the real Claude Code MCP client sees the exact five tools and no others.
    expect(run.mcpServers.some((s) => s.name === 'nexus' && s.status === 'connected')).toBe(true)
    const nexusTools = run.initTools.filter((t) => t.startsWith('mcp__nexus__')).sort()
    expect(nexusTools).toEqual(TOOL_NAMES.map((n) => `mcp__nexus__${n}`).sort())
    expect(run.raw).not.toMatch(/mcp__nexus__nexus_(create|delete|approve|trust|credential|open|close|reconnect)/)

    // Calls actually made through the live client.
    const called = new Set(
      run.toolUses.filter((t) => t.name.startsWith('mcp__nexus__')).map((t) => t.name.replace('mcp__nexus__', ''))
    )
    expect(called).toEqual(new Set(TOOL_NAMES))
    // Only Claude Code's own ToolSearch may appear outside the NEXUS namespace.
    const nonNexus = run.toolUses.map((t) => t.name).filter((n) => !n.startsWith('mcp__nexus__'))
    expect(nonNexus.every((n) => n === 'ToolSearch')).toBe(true)

    // Approved read-only command executed over SSH and returned its output.
    expect(run.raw).toContain('/home/tester')
    expect(h.ssh.commands).toContain('pwd')

    // Denied command never reached SSH; the denial result is sanitized.
    expect(h.ssh.commands).not.toContain('whoami')
    const deniedResult = run.toolResults.find((t) => /"status"\s*:\s*"denied"/.test(t))
    expect(deniedResult).toBeTruthy()

    // History and terminal tail are served through the same bridge.
    expect(run.raw).toContain('nexus_get_history')
    expect(run.raw).toContain('tail-marker-ok')

    // No credential material or trust-control surface is exposed to the client.
    expect(run.raw).not.toMatch(/keyPath|privateKey|passphrase":|credentialStore/i)

    console.log('[stage-c] live claude', JSON.stringify({
      model,
      discovered: nexusTools.length,
      called: [...called],
      sshCommands: h.ssh.commands
    }))
  }, 300_000)
})
