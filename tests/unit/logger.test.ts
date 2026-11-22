import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { FileLogger } from '../../src/main/logger'

describe('FileLogger', () => {
  it('redacts secrets and rotates when maxBytes is exceeded', () => {
    const dir = mkdtempSync(join(tmpdir(), 'nexus-log-'))
    try {
      const logFile = join(dir, 'nexus.log')
      const logger = new FileLogger({ logFile, maxBytes: 200, maxFiles: 3, getSecrets: () => ['top-secret-canary'] })
      for (let i = 0; i < 6; i++) {
        logger.info(`event-${i} top-secret-canary`, { detail: 'Authorization: Bearer supersecretvalue1234567890' })
      }
      const content = readFileSync(logFile, 'utf8')
      expect(content).not.toContain('top-secret-canary')
      expect(content).not.toContain('supersecretvalue1234567890')
      expect(existsSync(`${logFile}.1`)).toBe(true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
