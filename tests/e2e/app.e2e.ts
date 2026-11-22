import { _electron as electron, expect, test } from '@playwright/test'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('launches hardened NEXUS Terminal over nexus-app:// with zero Node globals and read-only approval UI', async () => {
  const userData = mkdtempSync(join(tmpdir(), 'nexus-e2e-'))
  const app = await electron.launch({
    args: ['.', '--e2e'],
    env: { ...process.env, NEXUS_E2E: '1', NEXUS_E2E_USERDATA: userData }
  })
  try {
    const page = await app.firstWindow()
    const rendererErrors: string[] = []
    page.on('pageerror', (error) => rendererErrors.push(error.message))
    await page.waitForSelector('[data-testid="nav-dashboard"]')

    const url = page.url()
    expect(url.startsWith('nexus-app://app/')).toBe(true)

    const globals = await page.evaluate(() => {
      // In a browser renderer globalThis is window; use the cross-platform global type here.
      const renderer = globalThis as unknown as {
        require?: unknown
        process?: unknown
        nexus: { invoke?: unknown; approvals: Record<string, unknown> }
      }
      return {
        hasRequire: typeof renderer.require !== 'undefined',
        hasProcess: typeof renderer.process !== 'undefined',
        hasInvoke: typeof renderer.nexus.invoke !== 'undefined',
        approvalKeys: Object.keys(renderer.nexus.approvals)
      }
    })
    expect(globals.hasRequire).toBe(false)
    expect(globals.hasProcess).toBe(false)
    expect(globals.hasInvoke).toBe(false)
    expect(globals.approvalKeys).toEqual(['list'])

    await page.click('[data-testid="nav-mcp"]')
    await expect(page.getByText('nexus_read_terminal_tail')).toBeVisible()

    await page.click('[data-testid="nav-knownHosts"]')
    await expect(page.getByRole('heading', { name: 'Known Hosts' })).toBeVisible()

    // Exercise a real renderer-to-main request through the narrow preload API.
    const servers = await page.evaluate(async () => {
      const renderer = globalThis as unknown as { nexus: { servers: { list: () => Promise<{ ok: boolean; data?: unknown[] }> } } }
      return renderer.nexus.servers.list()
    })
    expect(servers).toEqual({ ok: true, data: [] })

    // Confirm the preload rejects an invalid IPC payload and the main process
    // returns a sanitized error envelope rather than throwing into the renderer.
    const invalidCreate = await page.evaluate(async () => {
      const renderer = globalThis as unknown as { nexus: { servers: { create: (input: unknown) => Promise<{ ok: boolean; error?: { code: string } }> } } }
      return renderer.nexus.servers.create({})
    })
    expect(invalidCreate.ok).toBe(false)
    expect(invalidCreate.error?.code).toBe('invalid_input')

    const missingSetSecret = await page.evaluate(async () => {
      const renderer = globalThis as unknown as {
        nexus: { servers: { setSecret: (id: string, kind: 'password', secret: string) => Promise<{ ok: boolean; error?: { code: string } }> } }
      }
      return renderer.nexus.servers.setSecret('missing-server-for-e2e', 'password', 'irrelevant')
    })
    expect(missingSetSecret.ok).toBe(false)
    expect(missingSetSecret.error?.code).toBe('not_found')
    expect(rendererErrors).toEqual([])

    const artifactDir = join(process.cwd(), 'artifacts', 'e2e')
    mkdirSync(artifactDir, { recursive: true })
    await page.screenshot({ path: join(artifactDir, 'known-hosts.png'), fullPage: true })
  } finally {
    await app.close()
    rmSync(userData, { recursive: true, force: true })
  }
})
