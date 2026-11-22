import { build } from 'esbuild'
import { mkdirSync, readFileSync } from 'node:fs'

mkdirSync('out/mcp', { recursive: true })
const outfile = 'out/mcp/nexus-mcp.mjs'

await build({
  entryPoints: ['src/mcp/server.ts'],
  outfile,
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  banner: {
    js: '#!/usr/bin/env node\nimport { createRequire } from "node:module"; const require = createRequire(import.meta.url);'
  },
  legalComments: 'none',
  logLevel: 'info',
  // Security guardrail: MCP process must never bundle Electron, SSH, SQLite, or keyring code.
  external: ['electron', 'ssh2', 'node:sqlite', '@napi-rs/keyring']
})

const bundled = readFileSync(outfile, 'utf8')
for (const forbidden of ['"electron"', "'electron'", '"ssh2"', "'ssh2'", 'node:sqlite', '@napi-rs/keyring']) {
  if (bundled.includes(forbidden)) {
    throw new Error(`build-mcp security check failed: forbidden reference ${forbidden} found in ${outfile}`)
  }
}
console.log(`build-mcp: verified clean bundle at ${outfile}`)
