import { MAX_COMMAND_LENGTH } from '../../../shared/ipc'
import { POLICY_VERSION, type PolicyDecision, type RiskLevel } from '../../../shared/policy-types'
import { Acc, checkEnvAssign, dispatch, isInterpName, isShellName, resolveName, type Ctx, type SegInfo } from './command-rules'
import { classifyWordPath } from './paths'
import { scanBalanced, tokenize, type Redir, type Segment, type Tokenized, type Word } from './tokenizer'

const MAX_DEPTH = 4
const MAX_SEGMENTS = 60
const BIDI = /[\u202A-\u202E\u2066-\u2069\u061C\u200E\u200F]/
const INVISIBLE = /[\u200B-\u200D\u2060\uFEFF\u00AD\u180E]/
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/
const KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', '!', '{', '}', 'coproc', 'time'])
const COMPOUND_HEADS = new Set(['for', 'case', 'select', 'function', 'esac', 'in'])
const DOWNLOADERS = /^(curl|wget|fetch|aria2c|lynx|links|nc|ncat|netcat|socat|scp|sftp|ftp|telnet)$/

/**
 * Authoritative conservative read-only LOW allowlist per NEXUS-BUILD-PLAN.md.
 * Only single-segment, cleanly-parsed invocations of these 9 commands (without sensitive paths,
 * redirects, variable expansion, or composition) may ever classify as LOW.
 */
export const CONSERVATIVE_LOW_COMMANDS = new Set([
  'pwd', 'whoami', 'id', 'uname', 'uptime', 'date', 'hostname', 'ls', 'df'
])

/** Flags that always prevent a LOW verdict (the parse is not clean). */
const DISQUALIFY = [
  'multiline', 'non_ascii', 'unicode_trick', 'variable_expansion', 'param_expansion', 'arithmetic',
  'command_substitution', 'process_substitution', 'background', 'compound', 'subshell', 'syntax_oddity',
  'heredoc', 'ansi_c_quoting', 'obfuscated_executable', 'dynamic_argument', 'brace_expansion',
  'too_long', 'env_assignment', 'assignment_only', 'composed_command', 'non_allowlisted'
]

function analyzeScript(src: string, depth: number, acc: Acc): void {
  if (depth > MAX_DEPTH) { acc.raise('HIGH', 'nesting too deep to analyze', 'too_deep'); acc.unparseable = true; return }
  const tk: Tokenized = tokenize(src)
  if (tk.error) { acc.raise('HIGH', `unparseable command: ${tk.error}`, 'unparseable'); acc.unparseable = true; return }
  for (const f of tk.flags) acc.flag(f)
  if (tk.flags.has('heredoc_expansion')) acc.raise('HIGH', 'heredoc body contains substitutions', 'heredoc_expansion')
  if (tk.heredocs.length) acc.flag('heredoc')
  if (tk.segments.length > MAX_SEGMENTS) { acc.raise('HIGH', 'command too complex to analyze', 'over_complex'); acc.unparseable = true; return }

  // Authoritative requirement: composed commands (pipes, &&, ||, ;, &, multiline) always require approval.
  if (tk.segments.length > 1 || tk.segments.some((segment) => segment.after === '&')) {
    acc.raise('MEDIUM', 'composed command (chained, piped, or backgrounded) requires approval', 'composed_command')
  }

  let downloaderSub = false
  for (const h of tk.heredocs) {
    if (h.quoted) continue
    for (let i = 0; i < h.body.length; i++) {
      if (h.body[i] === '\\') { i++; continue }
      if (h.body[i] === '$' && h.body[i + 1] === '(') {
        const j = scanBalanced(h.body, i + 2, '(', ')')
        if (j > 0) { tk.subs.push({ src: h.body.slice(i + 2, j), kind: 'command' }); i = j }
      } else if (h.body[i] === '`') {
        const j = h.body.indexOf('`', i + 1)
        if (j > 0) { tk.subs.push({ src: h.body.slice(i + 1, j), kind: 'backtick' }); i = j }
      }
    }
  }
  for (const s of tk.subs) {
    acc.raise('MEDIUM', 'contains command or process substitution', 'command_substitution')
    const subAcc = new Acc()
    analyzeScript(s.src, depth + 1, subAcc)
    mergeInto(acc, subAcc)
    if (subAcc.flags.has('downloader')) downloaderSub = true
  }

  const info: SegInfo[] = []
  tk.segments.forEach((seg) => {
    const si: SegInfo = { shellLike: false, downloader: false, decoder: false }
    info.push(si)
    analyzeSegment(seg, si, depth, acc, downloaderSub)
    if (seg.after === '&') acc.raise('MEDIUM', 'runs in the background', 'background')
    if (si.downloader) acc.flag('downloader')
  })

  for (let k = 1; k < tk.segments.length; k++) {
    const piped = tk.segments[k].before === '|' || tk.segments[k].before === '|&'
    if (!piped || !info[k].shellLike) continue
    let up = k - 1
    let download = false
    let decode = false
    for (;;) {
      if (info[up].downloader) download = true
      if (info[up].decoder) decode = true
      const prev = tk.segments[up].before
      if ((prev === '|' || prev === '|&') && up > 0) up--
      else break
    }
    if (download) acc.raise('CRITICAL', 'downloads and executes code (pipe to shell)', 'download_execute')
    else if (decode) acc.raise('CRITICAL', 'decodes and executes code (encoded execution)', 'encoded_execution')
    else acc.raise('CRITICAL', 'pipes data into a shell or interpreter', 'pipe_to_shell')
  }
}

function mergeInto(into: Acc, from: Acc): void {
  into.raise(from.level, ...(from.reasons.length ? [from.reasons[from.reasons.length - 1]] : ['nested']) as [string])
  for (const r of from.reasons) if (!into.reasons.includes(r)) into.reasons.push(r)
  for (const f of from.flags) into.flags.add(f)
  if (from.unparseable) into.unparseable = true
}

function analyzeRedirs(redirs: Redir[], acc: Acc): void {
  for (const r of redirs) {
    const t = r.target
    if (!t) continue
    if (r.op === '<<' || r.op === '<<-' || r.op === '<<<') { acc.flag('heredoc'); continue }
    if (r.op === '>&' || r.op === '<&') { if (/^[0-9-]+$/.test(t.value)) continue }
    const writes = r.op.includes('>') || r.op.includes('<>')
    if (t.dynamic) { acc.raise('HIGH', 'redirection target is dynamic', 'dynamic_redirect_target'); continue }
    const kind = classifyWordPath(t)
    if (!writes && kind === 'device') { acc.raise('HIGH', 'reads a raw device', 'device_access'); continue }
    if (kind === 'credential') acc.raise('CRITICAL', 'redirection touches credential or key material', 'credential_access')
    else if (writes && kind === 'device') acc.raise('DESTRUCTIVE', 'redirect writes to a raw device', 'device_write')
    else if (writes && kind === 'system') acc.raise('HIGH', 'redirect writes to a system path', 'system_path')
    else if (writes && !/^\/dev\/(null|stdout|stderr|tty)$/.test(t.value)) acc.raise('MEDIUM', 'redirect writes to a file', 'file_write')
  }
}

function analyzeSegment(seg: Segment, si: SegInfo, depth: number, acc: Acc, downloaderSub: boolean): void {
  analyzeRedirs(seg.redirs, acc)
  const ctx: Ctx = {
    acc, seg: si, downloaderSub, wrapDepth: 0,
    analyzeScript: (src) => analyzeScript(src, depth + 1, acc),
    analyzeWords: (words) => analyzeWords(words, ctx, depth)
  }
  if (seg.words.length === 0) return
  analyzeWords(seg.words, ctx, depth)
}

function analyzeWords(input: Word[], ctx: Ctx, depth: number): void {
  const acc = ctx.acc
  let words = input
  let sawAssign = false
  for (;;) {
    const w = words[0]
    if (!w) break
    if (w.startsAssign) { sawAssign = true; checkEnvAssign(w, ctx); if (w.dynamic) acc.flag('dynamic_argument'); words = words.slice(1); continue }
    if (!w.quoted && KEYWORDS.has(w.value)) { if (w.value !== 'time') acc.raise('MEDIUM', 'compound shell construct', 'compound'); words = words.slice(1); continue }
    break
  }
  if (words.length === 0) { if (sawAssign) acc.raise('MEDIUM', 'variable assignment only', 'assignment_only'); return }
  const head = words[0]
  if (!head.quoted && (COMPOUND_HEADS.has(head.value) || /\(\)$/.test(head.value))) {
    acc.raise('MEDIUM', 'compound shell construct (loop/case/function)', 'compound')
    if (head.value === 'for' || head.value === 'select' || head.value === 'case') return
  }
  if (head.dynamic) { acc.raise('HIGH', 'executable name is built dynamically', 'dynamic_executable'); return }
  if (head.midQuote) acc.flag('obfuscated_executable')
  const { name, explicit, trusted } = resolveName(head.value)
  if (!trusted) {
    acc.raise('HIGH', `executes a local program or script by path: ${head.value.slice(0, 80)}`, 'local_executable')
    return
  }
  if (explicit) acc.flag('explicit_path')
  if (DOWNLOADERS.test(name)) ctx.seg.downloader = true
  if (ctx.wrapDepth > 6) { acc.raise('HIGH', 'wrapper nesting too deep', 'too_deep'); return }

  if (!CONSERVATIVE_LOW_COMMANDS.has(name)) {
    acc.raise('MEDIUM', `command "${name}" is outside the strict read-only auto-allow set`, 'non_allowlisted')
  }

  void depth
  if (isShellName(name) || isInterpName(name)) { /* handled in dispatch */ }
  dispatch(name, words.slice(1), ctx)
}

export function classifyCommand(command: string): PolicyDecision {
  const acc = new Acc()
  if (typeof command !== 'string' || command.trim() === '') {
    acc.raise('MEDIUM', 'empty command', 'empty_command')
    return finalize(acc)
  }
  if (command.length > MAX_COMMAND_LENGTH) { acc.raise('HIGH', 'command exceeds maximum length', 'too_long'); acc.unparseable = true; return finalize(acc) }
  if (command.includes('\u0000')) { acc.raise('HIGH', 'command contains a NUL byte', 'control_chars'); acc.unparseable = true; return finalize(acc) }
  if (CONTROL.test(command)) { acc.raise('HIGH', 'command contains control characters', 'control_chars'); acc.unparseable = true; return finalize(acc) }
  if (command.includes('\r')) { acc.raise('HIGH', 'command contains carriage returns', 'control_chars'); acc.unparseable = true; return finalize(acc) }
  if (BIDI.test(command) || INVISIBLE.test(command)) acc.raise('HIGH', 'command contains bidirectional or invisible Unicode characters', 'unicode_trick')
  if (/[^\u0000-\u007F]/.test(command)) acc.raise('MEDIUM', 'command contains non-ASCII characters (possible lookalikes)', 'non_ascii')
  if (command.length > 4096) acc.raise('MEDIUM', 'unusually long command', 'too_long')
  if (/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/.test(command)) acc.raise('DESTRUCTIVE', 'fork bomb pattern', 'fork_bomb')
  analyzeScript(command, 0, acc)
  return finalize(acc)
}

function finalize(acc: Acc): PolicyDecision {
  let level: RiskLevel = acc.level
  if (level === 'LOW' && DISQUALIFY.some((f) => acc.flags.has(f))) {
    level = 'MEDIUM'
    acc.reasons.push('parse is not fully clean (' + DISQUALIFY.filter((f) => acc.flags.has(f)).join(', ') + ')')
  }
  if (acc.unparseable && (level === 'LOW' || level === 'MEDIUM')) level = 'HIGH'
  const unknown = acc.flags.has('unknown_executable') || acc.flags.has('unknown_flag') || acc.flags.has('unreviewed_script')
  return {
    level,
    reasons: acc.reasons.length ? acc.reasons : ['read-only command on the strict 9-command allowlist'],
    flags: [...acc.flags].sort(),
    requiresApproval: level !== 'LOW',
    parseConfidence: acc.unparseable ? 0 : unknown ? 0.5 : 1,
    policyVersion: POLICY_VERSION
  }
}
