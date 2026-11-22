import { spawnSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, renameSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'

export const EXCLUDE_DIRS = new Set(['node_modules', '.git', 'out', 'dist', 'release', 'test-results', 'playwright-report', 'coverage', 'artifacts', '.vite', '.cache'])
export const EXCLUDE_FILE = [/^\.env/, /\.log$/, /\.pem$/, /\.key$/, /\.p12$/, /\.pfx$/, /\.bak$/, /\.db(-wal|-shm)?$/, /^id_(rsa|dsa|ecdsa|ed25519)/, /\.tsbuildinfo$/, /^npm-debug/, /\.DS_Store$/]
export const TOP = 'NEXUS-FINAL'

function stamp() {
  const d = new Date()
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
}

function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', shell: false })
  if (r.error) throw r.error
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed (${r.status}): ${(r.stderr || r.stdout || '').slice(0, 400)}`)
  return r.stdout
}

export function createZip({ root, out }) {
  const stage = mkdtempSync(join(tmpdir(), 'nexus-stage-'))
  try {
    const dest = join(stage, TOP)
    mkdirSync(dest)
    cpSync(root, dest, {
      recursive: true,
      filter: (src) => {
        const n = basename(src)
        if (src === root) return true
        if (EXCLUDE_DIRS.has(n)) return false
        return !EXCLUDE_FILE.some((re) => re.test(n))
      }
    })
    if (existsSync(out)) renameSync(out, out.replace(/\.zip$/, `.previous-${stamp()}.zip`))
    mkdirSync(dirname(out), { recursive: true })
    // Write the archive next to the staged tree with a relative name: Windows `tar` treats a
    // `C:\...` argument as a remote host ("Cannot connect to C:"), and relative names work
    // for both bsdtar and GNU tar.
    if (process.platform === 'win32') {
      run('tar', ['-a', '-cf', `${TOP}.zip`, TOP], stage)
      renameSync(join(stage, `${TOP}.zip`), out)
    } else {
      run('zip', ['-qr', out, TOP], stage)
    }
  } finally {
    if (stage.startsWith(join(tmpdir(), 'nexus-stage-'))) rmSync(stage, { recursive: true, force: true })
  }
}

if (resolve(process.argv[1] ?? '') === resolve(import.meta.filename)) {
  const out = resolve(process.argv[2] ?? join(process.cwd(), '..', 'NEXUS-FINAL.zip'))
  createZip({ root: process.cwd(), out })
  console.log(`package-zip: wrote ${out}`)
}
