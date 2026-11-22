/**
 * Conservative POSIX-shell tokenizer. It does NOT execute or expand anything; it only splits a command
 * line into simple commands, words, redirections, and nested substitution sources so the policy engine
 * can analyze them. Anything it cannot understand produces `error` (callers must fail closed).
 */
export type Op = ';' | '&&' | '||' | '|' | '|&' | '&' | '\n' | '(' | ')'

export interface Word {
  value: string
  raw: string
  dynamic: boolean
  quoted: boolean
  glob: boolean
  midQuote: boolean
  startsAssign: boolean
  procSub: boolean
}
export interface Redir { op: string; fd: string | null; target: Word | null }
export interface Segment { words: Word[]; redirs: Redir[]; before: Op | null; after: Op | null }
export interface Sub { src: string; kind: 'command' | 'backtick' | 'process' }
export interface Heredoc { delim: string; quoted: boolean; body: string }
export interface Tokenized {
  segments: Segment[]
  subs: Sub[]
  heredocs: Heredoc[]
  flags: Set<string>
  error: string | null
}

const WS = new Set([' ', '\t'])
const NAME_START = /[A-Za-z_]/
const NAME_CHAR = /[A-Za-z0-9_]/

/** Index of the matching closer for an opener whose body starts at `i`, or -1. Quote- and nesting-aware. */
export function scanBalanced(s: string, i: number, open: string, close: string): number {
  let depth = 1
  while (i < s.length) {
    const c = s[i]
    if (c === '\\') { i += 2; continue }
    if (c === "'") { const j = s.indexOf("'", i + 1); if (j < 0) return -1; i = j + 1; continue }
    if (c === '"') {
      i++
      while (i < s.length && s[i] !== '"') { if (s[i] === '\\') i++; i++ }
      if (i >= s.length) return -1
      i++; continue
    }
    if (c === '`') { const j = findBacktick(s, i + 1); if (j < 0) return -1; i = j + 1; continue }
    if (c === open) depth++
    else if (c === close) { depth--; if (depth === 0) return i }
    i++
  }
  return -1
}
function findBacktick(s: string, i: number): number {
  while (i < s.length) {
    if (s[i] === '\\') { i += 2; continue }
    if (s[i] === '`') return i
    i++
  }
  return -1
}

export function decodeAnsiC(body: string): string {
  let out = ''
  for (let i = 0; i < body.length; i++) {
    const c = body[i]
    if (c !== '\\') { out += c; continue }
    const n = body[++i]
    switch (n) {
      case 'n': out += '\n'; break
      case 't': out += '\t'; break
      case 'r': out += '\r'; break
      case 'a': out += '\x07'; break
      case 'b': out += '\b'; break
      case 'e': case 'E': out += '\x1b'; break
      case 'f': out += '\f'; break
      case 'v': out += '\v'; break
      case '\\': out += '\\'; break
      case "'": out += "'"; break
      case '"': out += '"'; break
      case 'x': { const m = /^[0-9a-fA-F]{1,2}/.exec(body.slice(i + 1)); if (m) { out += String.fromCharCode(parseInt(m[0], 16)); i += m[0].length } else out += '\\x'; break }
      case 'u': { const m = /^[0-9a-fA-F]{1,4}/.exec(body.slice(i + 1)); if (m) { out += String.fromCodePoint(parseInt(m[0], 16)); i += m[0].length } else out += '\\u'; break }
      case 'U': { const m = /^[0-9a-fA-F]{1,8}/.exec(body.slice(i + 1)); if (m) { try { out += String.fromCodePoint(parseInt(m[0], 16)) } catch { out += '?' } i += m[0].length } else out += '\\U'; break }
      case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': {
        const m = /^[0-7]{1,3}/.exec(body.slice(i)); out += String.fromCharCode(parseInt(m![0], 8)); i += m![0].length - 1; break
      }
      default: out += '\\' + (n ?? '')
    }
  }
  return out
}

interface WB { value: string; raw: string; dynamic: boolean; quoted: boolean; glob: boolean; unq: number; qparts: number; procSub: boolean }

export function tokenize(src: string): Tokenized {
  const segments: Segment[] = []
  const subs: Sub[] = []
  const heredocs: Heredoc[] = []
  const flags = new Set<string>()
  let error: string | null = null
  let cur: Segment = { words: [], redirs: [], before: null, after: null }
  let w: WB | null = null
  let pendingRedir: Redir | null = null
  const pendingHeredocs: { redir: Redir; stripTabs: boolean }[] = []
  let parenDepth = 0
  let i = 0
  const n = src.length

  const fail = (m: string): void => { if (!error) error = m }
  const bw = (): WB => (w ??= { value: '', raw: '', dynamic: false, quoted: false, glob: false, unq: 0, qparts: 0, procSub: false })
  const finishWord = (): void => {
    if (!w) return
    const word: Word = {
      value: w.value, raw: w.raw, dynamic: w.dynamic, quoted: w.quoted, glob: w.glob,
      midQuote: w.qparts > 0 && w.unq > 0, procSub: w.procSub,
      startsAssign: /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(w.raw)
    }
    w = null
    if (word.glob) flags.add('glob')
    if (pendingRedir) {
      pendingRedir.target = word
      pendingRedir = null
    } else cur.words.push(word)
  }
  const pushSegment = (after: Op | null): void => {
    if (cur.words.length || cur.redirs.length) {
      cur.after = after
      segments.push(cur)
    } else if (after && after !== '(' && after !== ')' && after !== '\n' && after !== ';' && segments.length === 0) {
      flags.add('syntax_oddity')
    }
    cur = { words: [], redirs: [], before: after, after: null }
  }
  const op = (o: Op): void => {
    finishWord()
    if (pendingRedir) fail('redirection without target')
    const had = cur.words.length > 0 || cur.redirs.length > 0
    if (!had && (o === '|' || o === '&&' || o === '||' || o === '|&')) flags.add('syntax_oddity')
    if (!had && o === ';' && segments.length === 0) flags.add('syntax_oddity')
    pushSegment(o)
  }

  while (i < n && !error) {
    const c = src[i]
    if (WS.has(c)) { finishWord(); i++; continue }
    if (c === '\\') {
      if (src[i + 1] === '\n') { i += 2; continue }
      if (i + 1 >= n) { fail('trailing backslash'); break }
      const b = bw(); b.value += src[i + 1]; b.raw += c + src[i + 1]; b.quoted = true; b.qparts++; i += 2; continue
    }
    if (c === '\n') {
      finishWord(); if (pendingRedir) { fail('redirection without target'); break }
      flags.add('multiline')
      pushSegment('\n'); i++
      for (const h of pendingHeredocs) {
        const delim = h.redir.target?.value ?? ''
        const quoted = !!h.redir.target?.quoted
        let body = ''
        let found = false
        while (i <= n) {
          if (i >= n) break
          let j = src.indexOf('\n', i); if (j < 0) j = n
          const line = src.slice(i, j)
          i = Math.min(j + 1, n + 1)
          const cmp = h.stripTabs ? line.replace(/^\t+/, '') : line
          if (cmp === delim) { found = true; break }
          body += line + '\n'
        }
        if (!found) flags.add('heredoc_unterminated')
        heredocs.push({ delim, quoted, body })
        if (!quoted && /\$\(|`|\$\{/.test(body)) flags.add('heredoc_expansion')
      }
      pendingHeredocs.length = 0
      continue
    }
    if (c === '#' && !w) { while (i < n && src[i] !== '\n') i++; flags.add('comment'); continue }
    if (c === "'") {
      const j = src.indexOf("'", i + 1); if (j < 0) { fail('unterminated single quote'); break }
      const b = bw(); b.value += src.slice(i + 1, j); b.raw += src.slice(i, j + 1); b.quoted = true; b.qparts++; i = j + 1; continue
    }
    if (c === '"') {
      const b = bw(); b.qparts++; b.quoted = true; b.raw += '"'; i++
      let closed = false
      while (i < n) {
        const d = src[i]
        if (d === '"') { closed = true; i++; b.raw += '"'; break }
        if (d === '\\') {
          const e = src[i + 1]
          if (e === undefined) break
          if (e === '\n') { i += 2; continue }
          if ('$`"\\'.includes(e)) { b.value += e; b.raw += d + e; i += 2; continue }
          b.value += d; b.raw += d; i++; continue
        }
        if (d === '$' && src[i + 1] === '(') {
          if (src[i + 2] === '(') { const j = src.indexOf('))', i + 3); if (j < 0) { fail('unterminated arithmetic'); break } b.dynamic = true; flags.add('arithmetic'); b.raw += src.slice(i, j + 2); b.value += src.slice(i, j + 2); i = j + 2; continue }
          const j = scanBalanced(src, i + 2, '(', ')'); if (j < 0) { fail('unterminated command substitution'); break }
          subs.push({ src: src.slice(i + 2, j), kind: 'command' }); b.dynamic = true; b.raw += src.slice(i, j + 1); b.value += src.slice(i, j + 1); i = j + 1; continue
        }
        if (d === '$' && src[i + 1] === '{') {
          const j = scanBalanced(src, i + 2, '{', '}'); if (j < 0) { fail('unterminated parameter expansion'); break }
          b.dynamic = true; flags.add('param_expansion'); b.raw += src.slice(i, j + 1); b.value += src.slice(i, j + 1); i = j + 1; continue
        }
        if (d === '`') {
          const j = findBacktick(src, i + 1); if (j < 0) { fail('unterminated backtick'); break }
          subs.push({ src: src.slice(i + 1, j).replace(/\\([`\\$])/g, '$1'), kind: 'backtick' }); b.dynamic = true; b.raw += src.slice(i, j + 1); b.value += src.slice(i, j + 1); i = j + 1; continue
        }
        if (d === '$' && /[A-Za-z_@*#?$!0-9-]/.test(src[i + 1] ?? '')) {
          let j = i + 1
          if (NAME_START.test(src[j])) { while (j < n && NAME_CHAR.test(src[j])) j++ } else j++
          b.dynamic = true; flags.add('variable_expansion'); b.raw += src.slice(i, j); b.value += src.slice(i, j); i = j; continue
        }
        b.value += d; b.raw += d; i++
      }
      if (!closed && !error) fail('unterminated double quote')
      continue
    }
    if (c === '$') {
      const nx = src[i + 1]
      if (nx === "'") {
        let j = i + 2
        while (j < n && src[j] !== "'") { if (src[j] === '\\') j++; j++ }
        if (j >= n) { fail('unterminated ANSI-C quote'); break }
        const b = bw(); b.value += decodeAnsiC(src.slice(i + 2, j)); b.raw += src.slice(i, j + 1); b.quoted = true; b.qparts++; flags.add('ansi_c_quoting'); i = j + 1; continue
      }
      if (nx === '"') { i++; continue }
      if (nx === '(') {
        const b = bw(); b.unq++
        if (src[i + 2] === '(') { const j = src.indexOf('))', i + 3); if (j < 0) { fail('unterminated arithmetic'); break } b.dynamic = true; flags.add('arithmetic'); b.raw += src.slice(i, j + 2); b.value += src.slice(i, j + 2); i = j + 2; continue }
        const j = scanBalanced(src, i + 2, '(', ')'); if (j < 0) { fail('unterminated command substitution'); break }
        subs.push({ src: src.slice(i + 2, j), kind: 'command' }); b.dynamic = true; b.raw += src.slice(i, j + 1); b.value += src.slice(i, j + 1); i = j + 1; continue
      }
      if (nx === '{') {
        const j = scanBalanced(src, i + 2, '{', '}'); if (j < 0) { fail('unterminated parameter expansion'); break }
        const b = bw(); b.unq++; b.dynamic = true; flags.add('param_expansion'); b.raw += src.slice(i, j + 1); b.value += src.slice(i, j + 1); i = j + 1; continue
      }
      if (nx !== undefined && /[A-Za-z_@*#?$!0-9-]/.test(nx)) {
        let j = i + 1
        if (NAME_START.test(src[j])) { while (j < n && NAME_CHAR.test(src[j])) j++ } else j++
        const b = bw(); b.unq++; b.dynamic = true; flags.add('variable_expansion'); b.raw += src.slice(i, j); b.value += src.slice(i, j); i = j; continue
      }
      const b = bw(); b.unq++; b.value += '$'; b.raw += '$'; i++; continue
    }
    if (c === '`') {
      const j = findBacktick(src, i + 1); if (j < 0) { fail('unterminated backtick'); break }
      subs.push({ src: src.slice(i + 1, j).replace(/\\([`\\$])/g, '$1'), kind: 'backtick' })
      const b = bw(); b.unq++; b.dynamic = true; b.raw += src.slice(i, j + 1); b.value += src.slice(i, j + 1); i = j + 1; continue
    }
    if ((c === '<' || c === '>') && src[i + 1] === '(') {
      const j = scanBalanced(src, i + 2, '(', ')'); if (j < 0) { fail('unterminated process substitution'); break }
      subs.push({ src: src.slice(i + 2, j), kind: 'process' })
      const b = bw(); b.unq++; b.dynamic = true; b.procSub = true; flags.add('process_substitution'); b.raw += src.slice(i, j + 1); b.value += src.slice(i, j + 1); i = j + 1; continue
    }
    if (c === '<' || c === '>' || (c === '&' && src[i + 1] === '>')) {
      let fd: string | null = null
      const cw = w as WB | null
      if (cw && !cw.quoted && !cw.dynamic && /^[0-9]+$/.test(cw.raw) && c !== '&') { fd = cw.raw; w = null } else finishWord()
      if (pendingRedir) { fail('redirection without target'); break }
      let o: string
      if (c === '&') { o = src[i + 2] === '>' ? '&>>' : '&>' }
      else if (c === '>') o = src[i + 1] === '>' ? '>>' : src[i + 1] === '|' ? '>|' : src[i + 1] === '&' ? '>&' : '>'
      else o = src.startsWith('<<<', i) ? '<<<' : src.startsWith('<<-', i) ? '<<-' : src.startsWith('<<', i) ? '<<' : src[i + 1] === '>' ? '<>' : src[i + 1] === '&' ? '<&' : '<'
      i += o.length
      const r: Redir = { op: o, fd, target: null }
      cur.redirs.push(r)
      pendingRedir = r
      if (o === '<<' || o === '<<-') pendingHeredocs.push({ redir: r, stripTabs: o === '<<-' })
      continue
    }
    if (c === '|') { if (src[i + 1] === '|') { op('||'); i += 2 } else if (src[i + 1] === '&') { op('|&'); i += 2 } else { op('|'); i++ } continue }
    if (c === '&') { if (src[i + 1] === '&') { op('&&'); i += 2 } else { op('&'); i++ } continue }
    if (c === ';') { if (src[i + 1] === ';' || src[i + 1] === '&') { flags.add('compound'); i += 2 } else i++; op(';'); continue }
    if (c === '(') { parenDepth++; flags.add('subshell'); op('('); i++; continue }
    if (c === ')') { parenDepth--; if (parenDepth < 0) { fail('unbalanced parenthesis'); break } op(')'); i++; continue }
    const b = bw(); b.unq++
    if (c === '*' || c === '?' || c === '[') b.glob = true
    if (c === '{' && w && /\{[^}]*(,|\.\.)[^}]*\}/.test(src.slice(i))) flags.add('brace_expansion')
    b.value += c; b.raw += c; i++
  }
  if (!error) {
    finishWord()
    if (pendingRedir) fail('redirection without target')
    if (parenDepth !== 0) fail('unbalanced parenthesis')
    pushSegment(null)
    const last = segments[segments.length - 1]
    if (last && (last.after === '|' || last.after === '&&' || last.after === '||' || last.after === '|&')) flags.add('syntax_oddity')
  }
  // Fix segment `before` links (pushSegment tracks them via pendingBefore).
  return { segments, subs, heredocs, flags, error }
}
