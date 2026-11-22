import { readdirSync, readFileSync, statSync } from 'node:fs'
import { basename, join, relative } from 'node:path'

export const SKIP_DIRS = new Set(['node_modules', 'out', 'release', '.git', 'dist', 'test-results', 'playwright-report'])
export const CONTENT_RULES = [
  ['private key block', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\s]{40,}-----END/],
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/], ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/], ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{20,}\b/],
  ['Anthropic/OpenAI key', /\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b/], ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['npm auth token', /(?:_authToken|_password|_auth)\s*=\s*[^\s$]{6,}/], ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ['hard-coded password assignment', /\b(?:password|passwd|secret|api_?key)\s*[:=]\s*['"][^'"\s]{12,}['"]/i]
]
export const FILENAME_RULES = [
  ['environment file', /^\.env(\..+)?$/], ['private key file', /^(id_(rsa|dsa|ecdsa|ed25519)|.*\.(pem|key|p12|pfx|ppk))$/i], ['credentials file', /^(\.netrc|\.git-credentials|credentials\.json)$/]
]

/** Walk a tree and report possible secrets. `allow` = regexes over repo-relative paths that may contain fake credentials. */
export function scanTree(root, { allow = [] } = {}) {
  const hits = []
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue
      const p = join(dir, name)
      const st = statSync(p)
      if (st.isDirectory()) { walk(p); continue }
      const rel = relative(root, p).replaceAll('\\', '/')
      for (const [label, re] of FILENAME_RULES) if (re.test(basename(p))) hits.push(`${rel}: ${label}`)
      if (st.size > 2_000_000) continue
      if (allow.some((a) => a.test(rel))) continue
      let text
      try { text = readFileSync(p, 'utf8') } catch { continue }
      for (const [label, re] of CONTENT_RULES) if (re.test(text)) hits.push(`${rel}: ${label}`)
    }
  }
  walk(root)
  return hits
}
