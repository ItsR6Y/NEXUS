import { describe, expect, it } from 'vitest'
import { cacheControlFor } from '../../src/main/protocol'

describe('nexus-app:// asset cache headers', () => {
  it('never caches the HTML entry point', () => {
    expect(cacheControlFor('index.html')).toBe('no-cache')
    expect(cacheControlFor('nested/page.html')).toBe('no-cache')
  })

  it('marks content-hashed static assets immutable', () => {
    expect(cacheControlFor('assets/index-CnU1YGOX.js')).toBe('public, max-age=31536000, immutable')
    expect(cacheControlFor('assets/index-BrkID-YC.css')).toBe('public, max-age=31536000, immutable')
    expect(cacheControlFor('assets/inter-latin-wght-normal-Dx9Z.woff2')).toBe('public, max-age=31536000, immutable')
  })

  it('falls back to revalidation for anything else', () => {
    expect(cacheControlFor('manifest.json')).toBe('no-cache')
    expect(cacheControlFor('noextension')).toBe('no-cache')
  })
})
