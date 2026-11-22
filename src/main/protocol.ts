import { protocol } from 'electron'
import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs'
import { extname, resolve, sep } from 'node:path'
import { buildCsp } from './csp'

export const APP_SCHEME = 'nexus-app'
export const APP_HOST = 'app'
export const APP_ORIGIN = `${APP_SCHEME}://${APP_HOST}`

/**
 * Validate a full renderer URL against the trusted origin. Custom schemes have opaque
 * URL.origin values, so validate their parsed scheme/host explicitly instead.
 */
export function isTrustedRendererUrl(url: string, trustedOrigin: string): boolean {
  try {
    const parsed = new URL(url)
    if (trustedOrigin === APP_ORIGIN) {
      return parsed.protocol === `${APP_SCHEME}:` &&
        parsed.hostname === APP_HOST &&
        parsed.username === '' &&
        parsed.password === '' &&
        parsed.port === ''
    }

    const expected = new URL(trustedOrigin)
    if (expected.protocol !== 'http:' && expected.protocol !== 'https:') return false
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.origin === expected.origin
  } catch {
    return false
  }
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf'
}

/** Content-hashed build output: safe to cache forever. HTML must always revalidate (NEXUS-028). */
const CACHEABLE_EXT = new Set(['.js', '.mjs', '.css', '.woff', '.woff2', '.ttf', '.png', '.svg', '.ico'])

export function cacheControlFor(assetPath: string): string {
  const ext = extname(assetPath).toLowerCase()
  return ext !== '' && CACHEABLE_EXT.has(ext) ? 'public, max-age=31536000, immutable' : 'no-cache'
}

/** Register `nexus-app://` as privileged before app.whenReady(). */
export function registerAppScheme(): void {
  protocol.registerSchemesAsPrivileged([
    {
      scheme: APP_SCHEME,
      privileges: {
        standard: true,
        secure: true,
        supportFetchAPI: true,
        corsEnabled: true
      }
    }
  ])
}

/**
 * Pure path resolver exported for unit-testing traversal, URL decoding, backslash, and symlink defenses.
 * Returns null if the request URL attempts to escape `rendererRoot` or targets an invalid host.
 */
export function resolveRendererAsset(requestUrl: string, rendererRoot: string): string | null {
  let parsed: URL
  try {
    parsed = new URL(requestUrl)
  } catch {
    return null
  }
  if (parsed.protocol !== `${APP_SCHEME}:` || parsed.hostname !== APP_HOST) return null
  if (parsed.username || parsed.password || parsed.port) return null

  let decoded: string
  try {
    decoded = decodeURIComponent(parsed.pathname)
  } catch {
    return null
  }
  // Reject NUL bytes, backslashes, or traversal segments even after decoding.
  if (decoded.includes('\0') || decoded.includes('\\')) return null
  const segments = decoded.split('/')
  if (segments.some((s) => s === '..')) return null

  const rel = decoded === '/' || decoded === '' ? 'index.html' : decoded.replace(/^\/+/, '')
  const rootReal = existsSync(rendererRoot) ? realpathSync(rendererRoot) : resolve(rendererRoot)
  const candidate = resolve(rootReal, rel)
  const rootPrefix = rootReal.endsWith(sep) ? rootReal : rootReal + sep
  if (candidate !== rootReal && !candidate.startsWith(rootPrefix)) return null
  if (!existsSync(candidate)) return null

  const stat = lstatSync(candidate)
  if (!stat.isFile()) return null
  const candidateReal = realpathSync(candidate)
  if (!candidateReal.startsWith(rootPrefix)) return null
  return candidateReal
}

/** Install `protocol.handle('nexus-app', ...)` serving static assets strictly from `rendererRoot`. */
export function installAppProtocol(rendererRoot: string): void {
  const csp = buildCsp(false)
  protocol.handle(APP_SCHEME, (request) => {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method Not Allowed', { status: 405 })
    }
    const assetPath = resolveRendererAsset(request.url, rendererRoot)
    if (!assetPath) {
      return new Response('Not Found', { status: 404 })
    }
    const ext = extname(assetPath).toLowerCase()
    const body = readFileSync(assetPath)
    return new Response(body, {
      status: 200,
      headers: {
        'Content-Type': MIME[ext] ?? 'application/octet-stream',
        'Cache-Control': cacheControlFor(assetPath),
        'Content-Security-Policy': csp,
        'X-Content-Type-Options': 'nosniff',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
      }
    })
  })
}
