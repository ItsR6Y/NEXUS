/**
 * The E2E plaintext credential mode is a test-only affordance.
 * It must be loud and hard to reach: an unpackaged build alone is not enough, so we require
 * the explicit `--e2e` argv flag, NEXUS_E2E=1, and a dedicated userData directory.
 */
export interface E2EModeInput {
  isPackaged: boolean
  argv: readonly string[]
  env: Record<string, string | undefined>
}

export function resolveE2EPlaintext(input: E2EModeInput): boolean {
  if (input.isPackaged) return false
  if (!input.argv.includes('--e2e')) return false
  if (input.env['NEXUS_E2E'] !== '1') return false
  const userData = input.env['NEXUS_E2E_USERDATA']
  return typeof userData === 'string' && userData.trim().length > 0
}
