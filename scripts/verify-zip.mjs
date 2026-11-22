import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'

const zip = resolve(process.argv[2] ?? 'NEXUS-FINAL.zip')
const TOP = 'NEXUS-FINAL'
const REQUIRED = [
  'package.json', 'README.md', 'LICENSE', 'tsconfig.json', 'electron.vite.config.ts',
  'docs/ARCHITECTURE.md', 'docs/SECURITY.md', 'docs/SECURITY-REVIEW.md', 'docs/MCP.md', 'docs/TESTING.md',
  'build/icon.ico', 'src/main/index.ts', 'src/main/protocol.ts', 'src/main/window.ts', 'src/preload/index.ts',
  'src/mcp/server.ts', 'src/renderer/src/App.tsx', 'tests/unit/policy-corpus.test.ts'
]
const FORBIDDEN = [/(^|\/)node_modules\//, /(^|\/)\.git\//, /(^|\/)out\//, /(^|\/)release\//, /(^|\/)\.env/, /\.(pem|key|p12|pfx|log|bak|db)$/]

// Windows `tar` reads a `C:\...` argument as a remote host, so run it from the archive's own
// directory and pass the file name only.
const zipDir = dirname(zip)
const zipName = basename(zip)

function listZip() {
  const r = process.platform === 'win32'
    ? spawnSync('tar', ['-tf', zipName], { cwd: zipDir, encoding: 'utf8', maxBuffer: 1 << 28 })
    : spawnSync('unzip', ['-Z1', zip], { encoding: 'utf8', maxBuffer: 1 << 28 })
  return r.status === 0 ? r.stdout.split(/\r?\n/).filter(Boolean) : null
}

if (!existsSync(zip)) { console.error('FAIL: ZIP not found:', zip); process.exit(1) }
const entries = listZip()
if (!entries || entries.length === 0) { console.error('FAIL: could not read ZIP'); process.exit(1) }
const set = new Set(entries)
const missing = REQUIRED.filter((f) => !set.has(`${TOP}/${f}`))
const bad = entries.filter((e) => FORBIDDEN.some((re) => re.test(e)))
if (missing.length) { console.error('FAIL: missing required files:', missing); process.exit(1) }
if (bad.length) { console.error('FAIL: forbidden entries:', bad); process.exit(1) }

const tmp = mkdtempSync(join(tmpdir(), 'nexus-verify-'))
try {
  // Copy the archive into the extraction directory so Windows `tar` gets no absolute paths.
  let x
  if (process.platform === 'win32') {
    copyFileSync(zip, join(tmp, zipName))
    x = spawnSync('tar', ['-xf', zipName], { cwd: tmp })
  } else {
    x = spawnSync('unzip', ['-q', zip, '-d', tmp])
  }
  if (x.status !== 0) { console.error('FAIL: extract failed'); process.exit(1) }
  const scan = spawnSync(process.execPath, [join(tmp, TOP, 'scripts', 'scan-secrets.mjs'), join(tmp, TOP)], { encoding: 'utf8' })
  if (scan.status !== 0) { console.error('FAIL: secret scan:', scan.stdout, scan.stderr); process.exit(1) }
  console.log(`PASS: verified ${entries.length} entries in ${zip}`)
} finally {
  rmSync(tmp, { recursive: true, force: true })
}
