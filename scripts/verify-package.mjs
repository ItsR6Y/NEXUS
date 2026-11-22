// Verify the packaged Windows artifacts: installer present, asar contents, native keyring binary,
// MCP bundle, and absence of dev/test/secret artefacts. Exits non-zero on any violation.
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, relative, resolve } from 'node:path'

const require = createRequire(import.meta.url)
const asar = require('@electron/asar')

const root = resolve(process.argv[2] ?? 'release')
const requireInstaller = !process.argv.includes('--no-installer')
const failures = []
const notes = []

function check(ok, message) {
  if (ok) notes.push(`ok   ${message}`)
  else failures.push(message)
}

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

const unpacked = join(root, 'win-unpacked')
const exe = join(unpacked, 'NEXUS Terminal.exe')
const installer = join(root, 'NEXUS-Terminal-Setup.exe')
const archive = join(root, 'NEXUS-Terminal-1.0.0-windows-x64-archive.zip')
const asarFile = join(unpacked, 'resources', 'app.asar')
const mcpBundle = join(unpacked, 'resources', 'mcp', 'nexus-mcp.mjs')

check(existsSync(exe), `packaged executable exists: ${exe}`)
check(existsSync(asarFile), `app.asar exists: ${asarFile}`)
check(existsSync(mcpBundle), `MCP bundle shipped as an extra resource: ${mcpBundle}`)
check(!existsSync(join(unpacked, 'resources', 'app.asar.unpacked', 'out', 'mcp')),
  'MCP bundle is not duplicated inside asar.unpacked')

if (requireInstaller) {
  check(existsSync(installer), `NSIS installer exists: ${installer}`)
  if (existsSync(installer)) {
    const mb = statSync(installer).size / (1024 * 1024)
    check(mb > 20, `installer size is plausible (${mb.toFixed(1)} MiB)`)
    notes.push(`sha256 ${sha256(installer)}  ${installer}`)
  }
}
if (existsSync(archive)) notes.push(`sha256 ${sha256(archive)}  ${archive}`)
else notes.push('note archive not built (zip target optional for this run)')

if (existsSync(asarFile)) {
  const entries = asar.listPackage(asarFile).map((e) => e.replace(/\\/g, '/'))
  const required = [
    '/out/main/index.js',
    '/out/preload/index.js',
    '/out/renderer/index.html',
    '/package.json'
  ]
  for (const r of required) check(entries.includes(r), `app.asar contains ${r}`)

  const forbidden = [
    [/^\/src\//, 'renderer/main source'],
    [/^\/tests\//, 'test source'],
    [/^\/docs\//, 'documentation'],
    [/^\/artifacts\//, 'build artifacts'],
    [/^\/out\/mcp\//, 'duplicated MCP bundle'],
    [/\.map$/, 'sourcemap'],
    [/(^|\/)\.env/, 'dotenv file'],
    [/\.(db|db-wal|db-shm|sqlite)$/, 'database file'],
    [/\.log$/, 'log file'],
    [/\.(pem|key|p12|pfx)$/, 'key material'],
    [/^\/node_modules\/\.bin\//, 'dependency bins']
  ]
  for (const [re, label] of forbidden) {
    const hit = entries.find((e) => re.test(e))
    check(!hit, `app.asar has no ${label}${hit ? ` (found ${hit})` : ''}`)
  }
  notes.push(`app.asar entries: ${entries.length}`)
}

const unpackedNative = join(unpacked, 'resources', 'app.asar.unpacked', 'node_modules', '@napi-rs')
if (existsSync(unpackedNative)) {
  const dirs = readdirSync(unpackedNative)
  check(dirs.includes('keyring-win32-x64-msvc'),
    `Windows x64 keyring package unpacked (${dirs.join(', ')})`)
  const nativeDir = join(unpackedNative, 'keyring-win32-x64-msvc')
  const nodes = existsSync(nativeDir) ? readdirSync(nativeDir).filter((f) => f.endsWith('.node')) : []
  check(nodes.length > 0, `keyring native binary present (${nodes.join(', ') || 'none'})`)
} else {
  failures.push('app.asar.unpacked has no @napi-rs directory — keyring would fall back to safeStorage')
}

// Walk resources/ so stray user data or secrets shipped by accident are caught.
const offender = []
const banned = [/\.(db|db-wal|db-shm)$/, /\.log$/, /(^|\/)\.env/, /\.(pem|key|p12|pfx)$/]
function walk(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    const rel = relative(unpacked, full).replace(/\\/g, '/')
    if (banned.some((re) => re.test(rel))) offender.push(rel)
    const st = statSync(full)
    if (st.isDirectory()) walk(full)
  }
}
if (existsSync(unpacked)) walk(unpacked)
check(offender.length === 0, `packaged tree has no user data, logs or key material${
  offender.length ? ` (found ${offender.slice(0, 5).join(', ')})` : ''}`)

for (const line of notes) console.log(line)
if (failures.length) {
  for (const f of failures) console.error(`FAIL ${f}`)
  process.exit(1)
}
console.log(`verify-package: PASS (${notes.length} checks)`)
