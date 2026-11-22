const MARK = '[REDACTED]'
const KEY_BEGIN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/
const KEY_END = /-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/
const KEY_BLOCK = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/g

const PATTERNS: [RegExp, string][] = [
  [/\b(authorization\s*:\s*)(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]+/gi, `$1${MARK}`],
  [/\bbearer\s+[A-Za-z0-9._~+/=-]{16,}/gi, `Bearer ${MARK}`],
  [/\b([A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s"',;]+)/gi, `$1$2${MARK}`],
  [/(--(?:password|passwd|passphrase|token|secret|api-key|apikey|auth-token)(?:=|\s+))("[^"\n]*"|'[^'\n]*'|[^\s"']+)/gi, `$1${MARK}`],
  [/\b(sshpass\s+-p\s*)("[^"\n]*"|'[^'\n]*'|\S+)/gi, `$1${MARK}`],
  // mysql-style concatenated password flag: `mysql -pSECRET`. Scoped to mysql clients so
  // unrelated flags such as `find -print` are never mangled.
  [/\b((?:mysql|mariadb|mysqldump|mysqladmin)\b[^\n]*?\s-p)(\S+)/gi, `$1${MARK}`],
  // curl/wget style user:password flag: `curl -u user:SECRET`.
  [/\s-u\s+([^\s:]+):(\S+)/g, ` -u $1:${MARK}`],
  [/\b([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+):([^\s@/]+)@/gi, `$1:${MARK}@`],
  [/\bAKIA[0-9A-Z]{16}\b/g, MARK],
  [/\bASIA[0-9A-Z]{16}\b/g, MARK],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, MARK],
  [/\bgithub_pat_[A-Za-z0-9_]{30,}\b/g, MARK],
  [/\bglpat-[A-Za-z0-9_-]{16,}\b/g, MARK],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, MARK],
  [/\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b/g, MARK],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, MARK],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, MARK],
  [/\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, MARK],
  [/\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, MARK],
  [/^([a-z_][a-z0-9_.-]*):\$[0-9a-z]+\$[^:\n]+:/gim, `$1:[REDACTED HASH]:`],
  [/\$(?:1|2[abxy]?|5|6|7|y)\$[A-Za-z0-9./$,=-]{8,}/g, '[REDACTED HASH]']
]

/** Expand a secret into the strings that must be matched exactly (multi-line secrets add per-line entries). */
function expandSecrets(secrets: Iterable<string>): string[] {
  const out = new Set<string>()
  for (const s of secrets) {
    // Exact matching has no length floor: a legal 1-3 character password must still be
    // removed. Pattern matching stays conservative to avoid pathological over-redaction.
    if (!s) continue
    out.add(s)
    if (s.includes('\n')) for (const line of s.split(/\r?\n/)) { const t = line.trim(); if (t.length >= 16 && !/^-----(BEGIN|END)/.test(t)) out.add(t) }
  }
  return [...out].sort((a, b) => b.length - a.length)
}

function applyPatterns(text: string, exact: string[]): string {
  let t = text
  for (const s of exact) if (t.includes(s)) t = t.split(s).join(MARK)
  for (const [re, rep] of PATTERNS) t = t.replace(re, rep)
  return t
}

/** One-shot redaction of a complete string. */
export function redactText(text: string, secrets: Iterable<string> = []): string {
  const exact = expandSecrets(secrets)
  const withoutKeys = text.replace(KEY_BLOCK, '[REDACTED PRIVATE KEY]')
  return applyPatterns(withoutKeys, exact)
}

/** Deeply redact all string leaves of a JSON-like value. */
export function redactValue<T>(v: T, secrets: Iterable<string> = []): T {
  const exact = [...secrets]
  const walk = (x: unknown): unknown => {
    if (typeof x === 'string') return redactText(x, exact)
    if (Array.isArray(x)) return x.map(walk)
    if (x && typeof x === 'object') return Object.fromEntries(Object.entries(x as Record<string, unknown>).map(([k, val]) => [k, walk(val)]))
    return x
  }
  return walk(v) as T
}

/**
 * Streaming redactor with a rolling buffer: complete lines are redacted and emitted; the trailing partial
 * line is held so secrets (and keyword=value patterns) split across chunk boundaries are still caught.
 */
export class StreamRedactor {
  private pending = ''
  private inKey = false
  constructor(private getSecrets: () => Iterable<string> = () => []) {}

  push(chunk: string): string {
    this.pending += chunk
    let out = ''
    // Expand the secret list once per chunk, not once per line plus once for the tail.
    const exact = expandSecrets(this.getSecrets())
    for (;;) {
      const idx = this.pending.indexOf('\n')
      if (idx < 0) break
      const line = this.pending.slice(0, idx + 1)
      this.pending = this.pending.slice(idx + 1)
      out += this.line(line, exact)
    }
    if (this.inKey) {
      // An open private-key block is held in full until its END marker arrives.
      return out
    }
    const maxS = exact.reduce((m, s) => Math.max(m, s.length), 0)
    if (this.pending.length > 4096) {
      const begin = this.pending.search(KEY_BEGIN)
      const end = this.pending.search(KEY_END)
      if (begin >= 0 && (end < 0 || end < begin)) {
        // A private key started but has not ended: emit the safe prefix and hold the rest of the
        // block without ever flushing key body bytes.
        out += applyPatterns(this.pending.slice(0, begin).replace(KEY_BLOCK, '[REDACTED PRIVATE KEY]'), exact)
        this.pending = this.pending.slice(begin)
        this.inKey = true
        return out
      }
      const red = applyPatterns(this.pending.replace(KEY_BLOCK, '[REDACTED PRIVATE KEY]'), exact)
      const keep = Math.min(red.length, Math.max(maxS - 1, 0) + 256)
      out += red.slice(0, red.length - keep)
      this.pending = red.slice(red.length - keep)
    }
    return out
  }

  flush(): string {
    const r = this.pending ? this.line(this.pending, expandSecrets(this.getSecrets())) : ''
    this.pending = ''
    this.inKey = false
    return r
  }

  private line(l: string, exact: string[]): string {
    if (this.inKey) {
      if (KEY_END.test(l)) this.inKey = false
      return ''
    }
    if (KEY_BEGIN.test(l)) {
      if (KEY_END.test(l)) return applyPatterns(l.replace(KEY_BLOCK, '[REDACTED PRIVATE KEY]'), exact)
      this.inKey = true
      return '[REDACTED PRIVATE KEY]\n'
    }
    return applyPatterns(l, exact)
  }
}
