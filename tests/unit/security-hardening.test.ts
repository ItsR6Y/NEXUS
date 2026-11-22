import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { buildCsp } from '../../src/main/csp'
import { APP_ORIGIN, resolveRendererAsset } from '../../src/main/protocol'
import { buildWebPreferences, isAllowedOrigin } from '../../src/main/window'
import { buildPreloadApi } from '../../src/preload/index'

describe('Electron window, CSP, nexus-app:// protocol, and preload hardening', () => {
  it('enforces all hardened BrowserWindow webPreferences flags', () => {
    const prefs = buildWebPreferences('/app/out/preload/index.js')
    expect(prefs.contextIsolation).toBe(true)
    expect(prefs.nodeIntegration).toBe(false)
    expect(prefs.sandbox).toBe(true)
    expect(prefs.webSecurity).toBe(true)
    expect(prefs.allowRunningInsecureContent).toBe(false)
    expect(prefs.webviewTag).toBe(false)
    expect(prefs.experimentalFeatures).toBe(false)
    expect(prefs.spellcheck).toBe(false)
  })

  it('enforces strict production CSP without unsafe-eval or wildcards', () => {
    const prod = buildCsp(false)
    expect(prod).not.toContain('unsafe-eval')
    expect(prod).not.toContain('*')
    expect(prod).toContain("default-src 'self'")
    expect(prod).toContain("script-src 'self'")
    expect(prod).toContain("object-src 'none'")
    expect(prod).toContain("frame-ancestors 'none'")
    expect(prod).toContain("form-action 'self'")
  })

  it('blocks path traversal, encoded traversal, backslashes, wrong hosts, and symlink escapes in nexus-app://', () => {
    const root = mkdtempSync(join(tmpdir(), 'nexus-proto-'))
    const outside = mkdtempSync(join(tmpdir(), 'nexus-outside-'))
    try {
      writeFileSync(join(root, 'index.html'), '<h1>ok</h1>')
      writeFileSync(join(outside, 'secret.txt'), 'nope')
      try { symlinkSync(join(outside, 'secret.txt'), join(root, 'escape.txt')) } catch { /* Windows non-admin symlink skip */ }

      expect(resolveRendererAsset(`${APP_ORIGIN}/index.html`, root)).toBe(join(root, 'index.html'))
      expect(resolveRendererAsset(`${APP_ORIGIN}/`, root)).toBe(join(root, 'index.html'))

      for (const bad of [
        `${APP_ORIGIN}/../secret.txt`,
        `${APP_ORIGIN}/%2e%2e/secret.txt`,
        `${APP_ORIGIN}/..%2f..%2fetc/passwd`,
        `${APP_ORIGIN}/..\\secret.txt`,
        `${APP_ORIGIN}/escape.txt`,
        'nexus-app://evil/index.html',
        'file:///etc/passwd',
        'https://evil.example/index.html'
      ]) {
        expect(resolveRendererAsset(bad, root), bad).toBeNull()
      }
      expect(isAllowedOrigin(`${APP_ORIGIN}/index.html`, APP_ORIGIN)).toBe(true)
      expect(isAllowedOrigin(`${APP_ORIGIN}/nested/page.html`, APP_ORIGIN)).toBe(true)
      for (const untrusted of [
        'nexus-app://evil/index.html',
        'nexus-app://app:444/index.html',
        'nexus-app://user@app/index.html',
        'nexus-app://user:secret@app/index.html',
        'https://app/index.html',
        'file:///C:/Users/index.html'
      ]) {
        expect(isAllowedOrigin(untrusted, APP_ORIGIN), untrusted).toBe(false)
      }
      expect(isAllowedOrigin('http://localhost:5173/page', 'http://localhost:5173')).toBe(true)
      expect(isAllowedOrigin('http://localhost.evil:5173/page', 'http://localhost:5173')).toBe(false)
      expect(isAllowedOrigin('https://user@localhost:5173/page', 'https://localhost:5173')).toBe(false)
      expect(isAllowedOrigin('nexus-app://app/index.html', 'file://')).toBe(false)
    } finally {
      rmSync(root, { recursive: true, force: true })
      rmSync(outside, { recursive: true, force: true })
    }
  })

  it('exposes a deeply frozen preload API with zero generic invoke or authority decision methods', () => {
    const api = buildPreloadApi({
      invoke: async () => ({ ok: true, data: null }),
      on: () => undefined,
      removeListener: () => undefined
    }) as unknown as Record<string, Record<string, unknown>>

    expect(Object.isFrozen(api)).toBe(true)
    expect(Object.isFrozen(api.approvals)).toBe(true)
    expect('invoke' in api).toBe(false)
    expect('send' in api).toBe(false)
    expect('hostKeys' in api).toBe(false)
    expect(Object.keys(api.approvals)).toEqual(['list'])
    expect('approve' in api.approvals).toBe(false)
    expect('reject' in api.approvals).toBe(false)
    expect('guard' in api.terminal).toBe(false)
  })
})
