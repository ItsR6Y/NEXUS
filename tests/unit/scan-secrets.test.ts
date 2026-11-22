import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { scanTree } from '../../scripts/lib/scan.mjs'

describe('scan-secrets utility', () => {
  it('flags forbidden files and leaked tokens', () => {
    const dir = mkdtempSync(join(tmpdir(), 'nexus-scan-'))
    try {
      writeFileSync(join(dir, 'clean.ts'), 'export const x = 42\n')
      expect(scanTree(dir)).toEqual([])
      writeFileSync(join(dir, '.env'), 'FOO=bar\n')
      writeFileSync(join(dir, 'leak.ts'), 'const k = "AKIAIOSFODNN7EXAMPLE"\n')
      const hits = scanTree(dir)
      expect(hits.some((h: string) => h.includes('.env'))).toBe(true)
      expect(hits.some((h: string) => h.includes('AWS access key'))).toBe(true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
