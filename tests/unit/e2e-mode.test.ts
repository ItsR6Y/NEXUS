import { describe, expect, it } from 'vitest'
import { resolveE2EPlaintext } from '../../src/main/security/e2e-mode'

describe('E2E plaintext credential mode', () => {
  const base = {
    isPackaged: false,
    argv: ['electron', '.', '--e2e'],
    env: { NEXUS_E2E: '1', NEXUS_E2E_USERDATA: '/tmp/nexus-e2e' } as Record<string, string | undefined>
  }

  it('is enabled only for an unpackaged run with the --e2e flag and an explicit userData dir', () => {
    expect(resolveE2EPlaintext(base)).toBe(true)
  })

  it('is unreachable in packaged builds', () => {
    expect(resolveE2EPlaintext({ ...base, isPackaged: true })).toBe(false)
  })

  it('is unreachable without the --e2e argv flag', () => {
    expect(resolveE2EPlaintext({ ...base, argv: ['electron', '.'] })).toBe(false)
  })

  it('is unreachable without an explicit NEXUS_E2E_USERDATA path', () => {
    expect(resolveE2EPlaintext({ ...base, env: { NEXUS_E2E: '1' } })).toBe(false)
    expect(resolveE2EPlaintext({ ...base, env: { NEXUS_E2E: '1', NEXUS_E2E_USERDATA: '   ' } })).toBe(false)
  })

  it('still requires NEXUS_E2E=1', () => {
    expect(resolveE2EPlaintext({ ...base, env: { NEXUS_E2E_USERDATA: '/tmp/nexus-e2e' } })).toBe(false)
  })
})
