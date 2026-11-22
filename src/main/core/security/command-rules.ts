import type { Word } from './tokenizer'
import type { RiskLevel } from '../../../shared/policy-types'
import { classifyWordPath, isRootish } from './paths'

export class Acc {
  level: RiskLevel = 'LOW'
  reasons: string[] = []
  flags = new Set<string>()
  unparseable = false
  private rank = (l: RiskLevel): number => ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'DESTRUCTIVE'].indexOf(l)
  raise(level: RiskLevel, reason: string, flag?: string): void {
    if (this.rank(level) > this.rank(this.level)) this.level = level
    if (!this.reasons.includes(reason)) this.reasons.push(reason)
    if (flag) this.flags.add(flag)
  }
  flag(f: string): void { this.flags.add(f) }
}
export interface SegInfo { shellLike: boolean; downloader: boolean; decoder: boolean }
export interface Ctx {
  acc: Acc
  seg: SegInfo
  /** True when this script contains a command/process substitution that downloads (curl/wget/...). */
  downloaderSub: boolean
  analyzeWords(words: Word[]): void
  analyzeScript(src: string): void
  /** Wrapper recursion guard. */
  wrapDepth: number
}

interface Parsed { shorts: string[]; longs: string[]; positional: Word[]; flagWords: Word[]; numeric: boolean }
export function parseArgs(args: Word[]): Parsed {
  const p: Parsed = { shorts: [], longs: [], positional: [], flagWords: [], numeric: false }
  let endOpts = false
  for (const a of args) {
    const v = a.value
    if (endOpts || a.dynamic || v === '-' || !v.startsWith('-') || v.length === 1) { p.positional.push(a); continue }
    if (v === '--') { endOpts = true; continue }
    p.flagWords.push(a)
    if (v.startsWith('--')) p.longs.push(v.slice(2).split('=')[0])
    else if (/^-[0-9]+$/.test(v)) p.numeric = true
    else for (const ch of v.slice(1)) if (!/[0-9]/.test(ch)) p.shorts.push(ch)
  }
  return p
}

// ---- read-only allowlists -------------------------------------------------
interface RoSpec { short: string; long: string[]; maxPositional?: number }
const ro = (short: string, long = ''): RoSpec => ({ short, long: long.split(' ').filter(Boolean) })
const RO: Record<string, RoSpec> = {
  ls: ro('lahAFRSdtrcCiLnpqsuUvxXZ1gGoBbkmNQTDfHI', 'all almost-all human-readable classify recursive size reverse sort time color directory inode dereference numeric-uid-gid literal si author group format full-time hide ignore indicator-style kibibytes quote-name show-control-chars width tabsize time-style'),
  dir: ro('lahAFRSdtrcCiLnpqsuUvx1gGo'), vdir: ro('lahAFRSdtrcCiLnpqsuUvx1gGo'),
  pwd: ro('LP', 'logical physical'), whoami: ro(''), id: ro('gGnruZ', 'group groups name real user context'), groups: ro(''),
  hostname: ro('sfiIadAy', 'short fqdn ip-address all-ip-addresses domain alias all-fqdns long'), uname: ro('asnrvmpioU', 'all kernel-name nodename kernel-release kernel-version machine processor hardware-platform operating-system'),
  date: ro('uRdI', 'utc universal rfc-email iso-8601 date rfc-3339'), uptime: ro('pcs', 'pretty since'), arch: ro(''), nproc: ro('', 'all'),
  df: ro('hHTiPaklmxt', 'human-readable si inodes local portability print-type total all block-size type exclude-type'), du: ro('ahskxcHLdSbmt', 'human-readable summarize apparent-size total max-depth one-file-system block-size si time dereference exclude'),
  free: ro('bkmgtshlw', 'bytes kibi mebi gibi human si lohi total wide seconds count'), ps: ro('aAxefFlLjuwWHhmMoOpPqrsStTUVyYZCcgGnN', 'forest sort no-headers headers format pid ppid user group cols columns width lines rows version'),
  top: ro('bcHdnoOiSsw1', 'help'), pgrep: ro('afilnoxuUGsPtvc', 'full list-full list-name newest oldest exact euid uid pgroup session count'), pidof: ro('sxcnoq'), pstree: ro('apuhnlUgsc'),
  cat: ro('nbsTEvAetu', 'number number-nonblank squeeze-blank show-all show-ends show-tabs show-nonprinting'), tac: ro('', 'before'), head: ro('nc', 'lines bytes quiet silent verbose'), tail: ro('nqcfFsv', 'lines bytes follow quiet silent verbose retry'),
  wc: ro('lwcmL', 'lines words bytes chars max-line-length'), nl: ro('bnwsvi'), od: ro('AtjNvwxcdoabfDOCsSXFhHiIlL'), hexdump: ro('Cbcdnosv'), strings: ro('afnotew', 'all bytes'), file: ro('bhiLkprsz', 'brief mime mime-type mime-encoding dereference'),
  stat: ro('cfLtF', 'format file-system dereference terse printf'), readlink: ro('fenmqsvz', 'canonicalize canonicalize-existing canonicalize-missing'), realpath: ro('esmLPqz', 'canonicalize-existing canonicalize-missing logical physical strip no-symlinks relative-to relative-base'),
  basename: ro('asz', 'multiple suffix zero'), dirname: ro('z', 'zero'), which: ro('a', 'all'), whereis: ro('bmsu'), type: ro('afptP'),
  lscpu: ro('abceghpsxJ', 'extended parse online offline json'), lsblk: ro('abdfimnoprstJPOe', 'all bytes nodeps fs output paths pairs raw topology json list'), lsusb: ro('tvsdD'), lspci: ro('vnnkmtbDxs'), lsmod: ro(''),
  lsof: ro('nPiUlt?sbCOwXv', ''), netstat: ro('tuxlpanrseicgvWCFMo46', ''), ss: ro('tuxlpanrseiomOHA46dsc0', 'tcp udp unix listening processes numeric all summary extended info options memory'),
  ping: ro('cnqW46wiv', ''), traceroute: ro('n46mqwI', ''), tracepath: ro('n46mp', ''), dig: ro('xt46', ''), nslookup: ro(''), host: ro('atvw46', ''), getent: ro(''),
  sort: ro('bdfghiMnrRsuVzct', 'reverse numeric-sort unique ignore-case human-numeric-sort version-sort general-numeric-sort month-sort key field-separator stable'), uniq: ro('cdfiuszw', 'count repeated unique ignore-case skip-fields'),
  cut: ro('bcdfnsz', 'bytes characters delimiter fields only-delimited complement output-delimiter'), tr: ro('cdsC', 'complement delete squeeze-repeats truncate-set1'), paste: ro('sdz'), join: ro('ai1jtv'), comm: ro('123'), column: ro('ts'), fold: ro('bsw'), fmt: ro('wcstu'), rev: ro(''), expand: ro('it'), unexpand: ro('at'),
  seq: ro('fsw'), md5sum: ro('bctw', 'binary check text tag'), sha1sum: ro('bctw'), sha256sum: ro('bctw'), sha512sum: ro('bctw'), b2sum: ro('bctw'), cksum: ro(''), diff: ro('uciqrsyNwbBEZaTU', 'unified context brief recursive report-identical-files side-by-side new-file ignore-all-space ignore-space-change ignore-blank-lines text'), cmp: ro('lsbi'),
  grep: ro('EFGPiIvwxcLlonqsHhrRAaBCzTUZmbe', 'extended-regexp fixed-strings basic-regexp perl-regexp ignore-case invert-match word-regexp line-regexp count files-with-matches files-without-match only-matching line-number quiet no-messages with-filename no-filename recursive dereference-recursive after-context before-context context text null max-count color colour include exclude exclude-dir binary-files regexp'),
  egrep: ro('iIvwxcLlonqsHhrRAaBCzTUZmbe'), fgrep: ro('iIvwxcLlonqsHhrRAaBCzTUZmbe'), zgrep: ro('iIvwxcLlonqsHhrRAaBCzTUZmbe'), rg: ro('iIvwxcLlonqsHhrAaBCuUmtTgjeEFSwzN', 'ignore-case count files-with-matches line-number hidden no-ignore type glob json fixed-strings'),
  tree: ro('adfiplsugDFLCnqNHRx', 'dirsfirst noreport charset'), lsattr: ro('adRVvl'), getfacl: ro('RLPdntsceaALp'), sestatus: ro('vbc'), getenforce: ro(''), nm: ro(''), ldd: ro('vdru'), locate: ro('ibcleLNqrS', 'ignore-case basename count existing limit regex'),
  echo: ro('neE'), printf: ro(''), sleep: ro(''), true: ro(''), false: ro(''), test: ro('bcdefghkLnoprsStuwxzGONa'), '[': ro('bcdefghkLnoprsStuwxzGONa'), '[[': ro('bcdefghkLnoprsStuwxzGONa'), cd: ro('LPe@'), ':': ro(''),
  jq: ro('cnrasSCMeRj', 'compact-output null-input raw-output slurp sort-keys color-output monochrome-output exit-status raw-input join-output arg argjson tab indent'),
  w: ro('hsfuiop'), who: ro('abdHlmpqrstTuw', 'all boot heading count'), last: ro('adfFiRnwxt', ''), lastlog: ro('bCtTu'), lastb: ro('adfFiRnwxt'), dmesg: ro('HkLlPrTtxuT', 'human kernel ctime notime reltime raw level facility'),
  journalctl: ro('ubknpPrxeoaSUqtCDMF', 'no-pager unit boot lines priority reverse since until output catalog no-hostname utc dmesg system user quiet since list-boots disk-usage output-fields'),
  vmstat: ro('adfmnpStswV'), iostat: ro('cdhkmNptxXyz'), mpstat: ro('AIPTu'), sar: ro('AbBdFHIqrRSuvwWy'),
  lsb_release: ro('aidrcs', 'all id description release codename short'), hostnamectl: ro(''), timedatectl: ro(''), loginctl: ro(''), resolvectl: ro(''),
  uptimed: ro(''), xxd: ro('bcgilpsuCEeaAhv'), base64: ro('dw', 'decode wrap ignore-garbage'), tput: ro('T'), stty: ro('a'), tty: ro('s')
}
const RO_SUBCMD: Record<string, { subs: string[]; flagsOk?: RegExp }> = {
  hostnamectl: { subs: ['status'] }, timedatectl: { subs: ['status', 'show', 'list-timezones'] }, loginctl: { subs: ['list-sessions', 'list-users', 'show-session', 'show-user', 'user-status', 'session-status'] }, resolvectl: { subs: ['status', 'query', 'statistics'] }
}

function checkRo(name: string, spec: RoSpec, args: Word[], ctx: Ctx): void {
  const p = parseArgs(args)
  const sub = RO_SUBCMD[name]
  if (sub) {
    const first = p.positional[0]?.value
    if (first && !sub.subs.includes(first)) { ctx.acc.raise('HIGH', `${name} ${first}: state-changing subcommand`, 'state_change'); return }
  }
  if (name === 'hostname' && p.positional.length > 0) { ctx.acc.raise('HIGH', 'hostname change', 'hostname_change'); return }
  if (name === 'date' && (p.shorts.includes('s') || p.longs.includes('set'))) { ctx.acc.raise('HIGH', 'system clock change', 'system_time_change'); return }
  if (name === 'base64' && (p.shorts.includes('d') || p.longs.includes('decode'))) { ctx.seg.decoder = true; ctx.acc.flag('encoded_content') }
  if (name === 'xxd' && p.shorts.includes('r')) { ctx.seg.decoder = true; ctx.acc.flag('encoded_content') }
  if (name === 'xxd' && p.positional.length > 1) { ctx.acc.raise('MEDIUM', 'xxd writes output file', 'file_write'); return }
  if (name === 'uniq' && p.positional.length > 1) { ctx.acc.raise('MEDIUM', 'uniq writes output file', 'file_write'); return }
  if (name === 'ping' && !p.shorts.includes('c')) { ctx.acc.raise('MEDIUM', 'ping without -c is unbounded', 'unbounded'); return }
  if (name === 'top' && !(p.shorts.includes('b') && p.shorts.includes('n'))) { ctx.acc.raise('MEDIUM', 'top without -b -n is interactive', 'interactive'); return }
  for (const s of p.shorts) if (!spec.short.includes(s)) { ctx.acc.raise('MEDIUM', `${name}: flag -${s} not on read-only allowlist`, 'unknown_flag'); return }
  for (const l of p.longs) if (!spec.long.includes(l) && !(l === 'help' || l === 'version')) { ctx.acc.raise('MEDIUM', `${name}: flag --${l} not on read-only allowlist`, 'unknown_flag'); return }
  if (p.numeric && !/^(head|tail|ls|nl|fold|fmt|grep|egrep|fgrep|zgrep|rg|sort|uniq|cut|tree|top|sleep|printf|seq|echo)$/.test(name)) { ctx.acc.raise('MEDIUM', `${name}: numeric flag`, 'unknown_flag') }
}

// ---- helpers --------------------------------------------------------------
function pathsEscalate(args: Word[], ctx: Ctx, write: boolean): void {
  for (const a of args) {
    const c = classifyWordPath(a)
    if (c === 'credential') ctx.acc.raise(write ? 'CRITICAL' : 'CRITICAL', 'touches credential or key material', 'credential_access')
    else if (c === 'device') ctx.acc.raise(write ? 'DESTRUCTIVE' : 'HIGH', 'raw device access', 'device_access')
    else if (c === 'system' && write) ctx.acc.raise('HIGH', 'modifies a system path', 'system_path')
  }
}
const firstPos = (p: Parsed): string => p.positional[0]?.value ?? ''

type Handler = (args: Word[], ctx: Ctx) => void
const H: Record<string, Handler> = {}
const alias = (names: string[], h: Handler): void => { for (const n of names) H[n] = h }

function unwrapIndex(args: Word[], valued: string[], skipAssign = false): number {
  let i = 0
  while (i < args.length) {
    const a = args[i].value
    if (a === '--') { i++; break }
    if (skipAssign && args[i].startsAssign) { i++; continue }
    if (a.startsWith('-') && a.length > 1) {
      if (valued.includes(a)) { i += 2; continue }
      if (!a.startsWith('--') && /^-[A-Za-z]+$/.test(a) && valued.includes('-' + a[a.length - 1])) { i += 2; continue }
      i++; continue
    }
    break
  }
  return i
}
function wrap(args: Word[], ctx: Ctx, idx: number, level: RiskLevel, reason: string, flag: string): void {
  ctx.acc.raise(level, reason, flag)
  const inner = args.slice(idx)
  if (inner.length === 0) return
  if (ctx.wrapDepth >= 6) { ctx.acc.raise('HIGH', 'wrapper nesting too deep', 'too_deep'); ctx.acc.unparseable = true; return }
  ctx.wrapDepth++
  ctx.analyzeWords(inner)
  ctx.wrapDepth--
}

// wrappers
H.sudo = (a, c) => {
  const p = parseArgs(a)
  const idx = unwrapIndex(a, ['-u', '-g', '-h', '-p', '-C', '-r', '-t', '-U', '-D', '-R', '-T'], true)
  if (idx >= a.length) {
    if (p.shorts.some((s) => 'lvkK'.includes(s)) && !p.shorts.some((s) => 'is'.includes(s))) c.acc.raise('MEDIUM', 'sudo queries privileges', 'privilege_escalation')
    else c.acc.raise('HIGH', 'sudo without command (privileged shell)', 'privilege_escalation')
    return
  }
  if (p.shorts.some((s) => 'is'.includes(s)) && !p.shorts.includes('u')) { c.acc.raise('HIGH', 'sudo shell mode', 'privilege_escalation') }
  wrap(a, c, idx, 'MEDIUM', 'runs with elevated privileges', 'privilege_escalation')
}
H.doas = H.sudo
H.su = (a, c) => {
  c.acc.raise('HIGH', 'su switches user', 'privilege_escalation')
  const p = parseArgs(a)
  const ci = a.findIndex((w) => w.value === '-c' || w.value === '--command')
  if (ci >= 0 && a[ci + 1]) { if (a[ci + 1].dynamic) c.acc.raise('HIGH', 'dynamic su command', 'dynamic_shell_code'); else c.analyzeScript(a[ci + 1].value) }
  else c.seg.shellLike = p.positional.length >= 0
}
H.env = (a, c) => {
  const idx = unwrapIndex(a, ['-u', '--unset', '-C', '--chdir', '-S', '--split-string'], true)
  for (const w of a.slice(0, idx)) if (w.startsAssign) checkEnvAssign(w, c)
  const si = a.findIndex((w) => w.value === '-S' || w.value === '--split-string')
  if (si >= 0 && a[si + 1] && !a[si + 1].dynamic) { c.acc.raise('MEDIUM', 'env -S runs a command string', 'wrapper'); c.analyzeScript(a[si + 1].value); return }
  if (idx >= a.length) { c.acc.raise('MEDIUM', 'prints the environment (may expose secrets)', 'env_dump'); return }
  wrap(a, c, idx, 'MEDIUM', 'runs through env', 'wrapper')
}
const wrapSpec: Record<string, string[]> = { nohup: [], setsid: [], unbuffer: [], builtin: [], exec: ['-a'], time: ['-f', '--format', '-o', '--output'], stdbuf: ['-i', '-o', '-e'], nice: ['-n', '--adjustment'], ionice: ['-c', '-n', '-p', '-P', '-u'], taskset: [], timeout: ['-s', '--signal', '-k', '--kill-after'], chrt: [], flock: ['-w', '-E'] }
for (const [name, valued] of Object.entries(wrapSpec)) {
  H[name] = (a, c) => {
    let idx = unwrapIndex(a, valued)
    if (name === 'timeout' || name === 'taskset' || name === 'flock') idx += 1 // duration / mask / lockfile
    if (name === 'chrt') idx += 1
    wrap(a, c, Math.min(idx, a.length), 'LOW', `${name} wrapper`, 'wrapper')
  }
}
H.command = (a, c) => {
  const p = parseArgs(a)
  if (p.shorts.includes('v') || p.shorts.includes('V')) return
  wrap(a, c, unwrapIndex(a, []), 'LOW', 'command wrapper', 'wrapper')
}
H.watch = (a, c) => {
  const idx = unwrapIndex(a, ['-n', '--interval', '-d'])
  const inner = a.slice(idx)
  c.acc.raise('MEDIUM', 'watch runs a command repeatedly', 'long_running')
  if (inner.some((w) => w.dynamic)) { c.acc.raise('HIGH', 'dynamic command under watch', 'dynamic_executable'); return }
  c.analyzeScript(inner.map((w) => w.value).join(' '))
}
H.xargs = (a, c) => {
  const idx = unwrapIndex(a, ['-n', '-P', '-I', '-L', '-s', '-E', '-d', '-a', '--max-args', '--max-procs', '--replace', '--delimiter', '-l', '-i'])
  c.acc.raise('MEDIUM', 'xargs runs commands with stdin-derived arguments', 'xargs')
  c.acc.flag('dynamic_argument')
  const inner = a.slice(idx)
  if (inner.length === 0) return
  const synthetic: Word = { value: '{stdin}', raw: '{stdin}', dynamic: true, quoted: false, glob: false, midQuote: false, startsAssign: false, procSub: false }
  wrap([...inner, synthetic], c, 0, 'MEDIUM', 'xargs inner command', 'wrapper')
}
H.chroot = (a, c) => { wrap(a, c, Math.min(unwrapIndex(a, ['--userspec', '--groups']) + 1, a.length), 'HIGH', 'chroot', 'privilege_escalation') }
alias(['strace', 'ltrace', 'gdb', 'valgrind', 'perf'], (_a, c) => c.acc.raise('HIGH', 'debugger/tracer can inspect or alter processes', 'debugger'))

const DANGEROUS_ENV = /^(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|PATH|IFS|BASH_ENV|ENV|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|PS4|NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|LESSOPEN|PAGER|EDITOR|VISUAL|HOME)\+?=/
export function checkEnvAssign(w: Word, c: Ctx): void {
  c.acc.flag('env_assignment')
  if (DANGEROUS_ENV.test(w.raw)) c.acc.raise('HIGH', 'sets a security-sensitive environment variable', 'dangerous_env')
}

// shells / interpreters
const SHELLS = /^(sh|bash|zsh|dash|ksh|ash|csh|tcsh|fish|rbash|mksh|busybox)$/
const INTERPS = /^(python[0-9.]*|perl|ruby|node|nodejs|php|lua|luajit|rscript|tclsh|deno|bun|julia|pwsh|powershell|osascript|expect|groovy|scala|swift)$/
export function isShellName(n: string): boolean { return SHELLS.test(n) }
export function isInterpName(n: string): boolean { return INTERPS.test(n) }
function shell(name: string, a: Word[], c: Ctx): void {
  if (name === 'busybox') { if (a[0]?.value === 'sh' || a[0]?.value === 'ash') a = a.slice(1); else { c.acc.raise('MEDIUM', 'busybox applet', 'unknown_executable'); return } }
  const p = parseArgs(a)
  if (p.longs.length === 1 && p.shorts.length === 0 && ['version', 'help'].includes(p.longs[0]) && p.positional.length === 0) return
  const ci = a.findIndex((w) => /^-[A-Za-z]*c[A-Za-z]*$/.test(w.value) && !w.dynamic)
  if (ci >= 0) {
    const script = a.slice(ci + 1).find((w) => !w.value.startsWith('-') || w.dynamic)
    c.acc.raise('MEDIUM', 'nested shell command string', 'nested_shell')
    if (!script) { c.acc.raise('HIGH', 'shell -c without a script', 'unparseable'); c.acc.unparseable = true; return }
    if (script.dynamic) { c.acc.raise(c.downloaderSub ? 'CRITICAL' : 'HIGH', c.downloaderSub ? 'executes downloaded code' : 'shell runs dynamically built code', c.downloaderSub ? 'download_execute' : 'dynamic_shell_code'); return }
    c.analyzeScript(script.value)
    return
  }
  c.seg.shellLike = true
  c.acc.raise(c.downloaderSub ? 'CRITICAL' : 'HIGH', c.downloaderSub ? 'executes downloaded code' : 'shell runs a script or stdin', c.downloaderSub ? 'download_execute' : 'script_execution')
}
function interp(a: Word[], c: Ctx): void {
  if (a.length > 0 && a.every((w) => /^(--version|-V|-v|-version|--help|-h)$/.test(w.value))) return
  c.seg.shellLike = true
  const inline = a.some((w) => /^(-c|-e|-E|-r|-R|-p|--eval|--eval-code|-x|-n|-i)$/.test(w.value) || /^-[a-zA-Z]*[ceE]$/.test(w.value))
  c.acc.raise(c.downloaderSub ? 'CRITICAL' : 'HIGH', inline ? 'inline interpreter code cannot be analyzed' : 'runs a script with an interpreter', c.downloaderSub ? 'download_execute' : inline ? 'inline_interpreter_code' : 'script_execution')
}
H.eval = (a, c) => {
  c.acc.raise('HIGH', 'eval executes constructed code', 'eval')
  if (a.some((w) => w.dynamic)) { if (c.downloaderSub) c.acc.raise('CRITICAL', 'executes downloaded code', 'download_execute'); return }
  c.analyzeScript(a.map((w) => w.value).join(' '))
}
alias(['source', '.'], (_a, c) => { c.seg.shellLike = true; c.acc.raise(c.downloaderSub ? 'CRITICAL' : 'HIGH', 'sources a script', c.downloaderSub ? 'download_execute' : 'script_execution') })

// awk / sed
alias(['awk', 'gawk', 'mawk', 'nawk'], (_a, c) => c.acc.raise('MEDIUM', 'awk programs can execute commands and write files', 'inline_interpreter_code'))
const SAFE_SED = /^(?:(?:\d+|\$|\/[^/\\\n]*\/)(?:,(?:\d+|\$|\/[^/\\\n]*\/))?!?)?(?:p|d|q|=)?$|^s\/[^/\\\n]*\/[^/\\\n]*\/[gpIi0-9]*$/
H.sed = (a, c) => {
  const p = parseArgs(a)
  if (p.shorts.includes('i') || p.longs.includes('in-place')) { pathsEscalate(p.positional.slice(1), c, true); c.acc.raise('MEDIUM', 'sed edits files in place', 'file_write'); return }
  if (p.shorts.some((s) => !'nEesrz'.includes(s) || s === 'e' || s === 'f') || p.longs.length) { c.acc.raise('MEDIUM', 'sed with unreviewed options/script file', 'unknown_flag'); return }
  const script = p.positional[0]
  if (!script || script.dynamic || !SAFE_SED.test(script.value)) c.acc.raise('MEDIUM', 'sed script not on safe allowlist', 'unreviewed_script')
}
H.find = (a, c) => {
  const OK = new Set(['-name', '-iname', '-path', '-ipath', '-wholename', '-regex', '-iregex', '-type', '-maxdepth', '-mindepth', '-mtime', '-mmin', '-atime', '-amin', '-ctime', '-cmin', '-newer', '-size', '-user', '-group', '-perm', '-empty', '-print', '-print0', '-ls', '-not', '-and', '-or', '-o', '-a', '!', '(', ')', '-prune', '-true', '-false', '-readable', '-writable', '-executable', '-xdev', '-mount', '-depth', '-follow', '-L', '-P', '-H', '-samefile', '-inum', '-links', '-lname', '-uid', '-gid', '-nouser', '-nogroup', '-regextype', '-printf', '-quit', '-fstype', '-noleaf', '-daystart', '-newermt'])
  for (let i = 0; i < a.length; i++) {
    const v = a[i].value
    if (['-exec', '-execdir', '-ok', '-okdir'].includes(v)) {
      let j = i + 1
      while (j < a.length && a[j].value !== ';' && a[j].value !== '+') j++
      c.acc.raise('MEDIUM', 'find -exec runs commands', 'find_exec')
      const inner = a.slice(i + 1, j).map((w) => (w.value === '{}' ? { ...w, dynamic: true } : w))
      if (inner.length) wrap(inner, c, 0, 'MEDIUM', 'find -exec', 'wrapper')
      i = j; continue
    }
    if (v === '-delete') { c.acc.raise('DESTRUCTIVE', 'find -delete removes every match', 'mass_deletion'); continue }
    if (/^-(fprint0?|fprintf|fls)$/.test(v)) { c.acc.raise('MEDIUM', 'find writes results to a file', 'file_write'); pathsEscalate(a.slice(i + 1, i + 2), c, true); i++; continue }
    if (v.startsWith('-') && v.length > 1 && !OK.has(v) && !/^-[0-9]+$/.test(v)) { c.acc.raise('MEDIUM', `find predicate ${v} not on allowlist`, 'unknown_flag') }
  }
}
H.tee = (a, c) => {
  const p = parseArgs(a)
  if (!p.positional.length) return
  pathsEscalate(p.positional, c, true)
  c.acc.raise('MEDIUM', 'tee writes files', 'file_write')
}

// file operations
H.rm = (a, c) => {
  const p = parseArgs(a)
  const rec = p.shorts.includes('r') || p.shorts.includes('R') || p.longs.includes('recursive')
  pathsEscalate(p.positional, c, true)
  const sys = p.positional.some((w) => classifyWordPath(w) === 'system')
  if (p.longs.includes('no-preserve-root') || p.positional.some(isRootish)) c.acc.raise('DESTRUCTIVE', 'deletes a root, home or system directory tree', 'root_wipe')
  else if (rec) c.acc.raise('DESTRUCTIVE', 'recursive deletion is irreversible', 'recursive_delete')
  else if (sys) c.acc.raise('CRITICAL', 'deletes a system file', 'system_path')
  else if (p.positional.some((w) => w.glob)) c.acc.raise('HIGH', 'deletes many files by glob', 'mass_deletion')
  else c.acc.raise('HIGH', 'deletes files', 'file_delete')
  if (p.positional.some((w) => w.dynamic)) c.acc.flag('dynamic_delete_target')
}
alias(['shred', 'srm', 'wipe', 'wipefs', 'blkdiscard'], (_a, c) => c.acc.raise('DESTRUCTIVE', 'irreversibly destroys data', 'destructive_tool'))
H.truncate = (a, c) => { pathsEscalate(parseArgs(a).positional, c, true); c.acc.raise('HIGH', 'truncate can destroy file contents', 'file_write') }
H.dd = (a, c) => {
  const of = a.find((w) => w.value.startsWith('of='))
  if (!of) { c.acc.raise('MEDIUM', 'dd without output file', 'file_read'); pathsEscalate(a, c, false); return }
  const t = of.value.slice(3)
  if (t.startsWith('/dev/') && t !== '/dev/null' && t !== '/dev/stdout') c.acc.raise('DESTRUCTIVE', 'dd writes to a raw device', 'device_write')
  else { c.acc.raise('HIGH', 'dd writes data', 'file_write'); pathsEscalate([{ ...of, value: t }], c, true) }
}
H.mv = (a, c) => { const p = parseArgs(a); pathsEscalate(p.positional, c, true); c.acc.raise('MEDIUM', 'moves or renames files', 'file_write') }
H.cp = (a, c) => { const p = parseArgs(a); pathsEscalate(p.positional.slice(-1), c, true); pathsEscalate(p.positional.slice(0, -1), c, false); c.acc.raise('MEDIUM', 'copies files', 'file_write') }
alias(['mkdir', 'touch', 'mktemp', 'ln', 'install', 'rename'], (a, c) => { pathsEscalate(parseArgs(a).positional, c, true); c.acc.raise('MEDIUM', 'creates or links filesystem entries', 'file_write') })
alias(['chmod', 'chown', 'chgrp', 'setfacl', 'chattr', 'chcon'], (a, c) => {
  const p = parseArgs(a)
  const rec = p.shorts.includes('R') || p.longs.includes('recursive')
  c.acc.raise('HIGH', 'changes permissions or ownership', 'permission_change')
  if (rec && p.positional.slice(1).some((w) => isRootish(w) || classifyWordPath(w) === 'system' || w.glob)) c.acc.raise('CRITICAL', 'recursive permission/ownership change on broad or system paths', 'recursive_permission_change')
  if (p.positional.some((w) => /^(0?777|a\+rwx|ugo\+rwx|o\+w)$/.test(w.value))) c.acc.raise('HIGH', 'makes files world-writable', 'world_writable')
  pathsEscalate(p.positional, c, true)
})

// process / system control
H.kill = (a, c) => {
  c.acc.raise('HIGH', 'kills processes', 'process_kill')
  if (a.some((w) => /^(1|-1|0)$/.test(w.value) && !w.value.startsWith('-s'))) c.acc.raise('CRITICAL', 'kills init or every process', 'process_kill_critical')
}
alias(['killall', 'pkill'], (a, c) => {
  c.acc.raise('HIGH', 'kills processes', 'process_kill')
  if (a.some((w) => /^(sshd?|systemd|init|dbus|NetworkManager|systemd-networkd)$/.test(w.value))) c.acc.raise('CRITICAL', 'kills a critical system process', 'process_kill_critical')
})
alias(['shutdown', 'reboot', 'halt', 'poweroff', 'telinit', 'kexec'], (_a, c) => c.acc.raise('CRITICAL', 'shuts down or reboots the host', 'power_control'))
H.init = (a, c) => { c.acc.raise(a.some((w) => /^[06]$/.test(w.value)) ? 'CRITICAL' : 'HIGH', 'changes runlevel', 'power_control') }
alias(['passwd', 'chpasswd', 'usermod', 'useradd', 'userdel', 'groupadd', 'groupdel', 'groupmod', 'adduser', 'deluser', 'visudo', 'vipw', 'newusers', 'chage', 'gpasswd', 'pwconv'], (_a, c) => c.acc.raise('CRITICAL', 'modifies user accounts or privileges', 'user_management'))
alias(['modprobe', 'insmod', 'rmmod', 'depmod', 'sysctl-w', 'grub-install', 'update-grub', 'dracut', 'update-initramfs', 'swapoff', 'swapon'], (_a, c) => c.acc.raise('CRITICAL', 'kernel or boot configuration change', 'kernel_change'))
H.sysctl = (a, c) => {
  const p = parseArgs(a)
  if (p.shorts.includes('w') || p.shorts.includes('p') || a.some((w) => w.value.includes('='))) c.acc.raise('CRITICAL', 'changes kernel parameters', 'kernel_change')
  else if (!p.positional.length && !p.shorts.includes('a')) c.acc.raise('MEDIUM', 'sysctl invocation not understood', 'unknown_flag')
}
alias(['fdisk', 'sfdisk', 'cfdisk', 'parted', 'gdisk', 'sgdisk', 'cryptsetup', 'lvremove', 'vgremove', 'pvremove', 'lvreduce', 'lvresize', 'resize2fs', 'mdadm', 'zpool', 'zfs'], (a, c) => {
  const p = parseArgs(a)
  if (p.shorts.length === 1 && (p.shorts[0] === 'l') && !p.positional.length) c.acc.raise('MEDIUM', 'lists partition tables', 'disk_listing')
  else c.acc.raise('DESTRUCTIVE', 'disk, partition or volume management', 'disk_tool')
})
H.mount = (a, c) => { const p = parseArgs(a); if (!p.positional.length && !p.shorts.length && !p.longs.length) return; c.acc.raise('HIGH', 'mounts a filesystem', 'mount_change') }
H.umount = (_a, c) => c.acc.raise('HIGH', 'unmounts a filesystem', 'mount_change')
alias(['iptables', 'ip6tables', 'ebtables', 'arptables'], (a, c) => {
  const p = parseArgs(a)
  const change = p.shorts.some((s) => 'ADIRFZNXPEC'.includes(s)) || p.longs.some((l) => /^(append|delete|insert|replace|flush|zero|new-chain|delete-chain|policy|rename-chain)$/.test(l))
  if (change) c.acc.raise('CRITICAL', 'firewall change can lock you out', 'firewall_change')
  else c.acc.raise('MEDIUM', 'firewall listing', 'firewall_listing')
})
H.nft = (a, c) => { const f = firstPos(parseArgs(a)); if (f === 'list') c.acc.raise('MEDIUM', 'firewall listing', 'firewall_listing'); else c.acc.raise('CRITICAL', 'firewall change can lock you out', 'firewall_change') }
H.ufw = (a, c) => { const f = firstPos(parseArgs(a)); if (f === 'status') c.acc.raise('MEDIUM', 'firewall listing', 'firewall_listing'); else c.acc.raise('CRITICAL', 'firewall change can lock you out', 'firewall_change') }
H['firewall-cmd'] = (a, c) => { if (a.every((w) => /^--(list-|state|get-|query-)/.test(w.value))) c.acc.raise('MEDIUM', 'firewall listing', 'firewall_listing'); else c.acc.raise('CRITICAL', 'firewall change can lock you out', 'firewall_change') }
H.ip = (a, c) => {
  const p = parseArgs(a)
  if (p.shorts.includes('b') && !p.longs.includes('brief')) { c.acc.raise('HIGH', 'ip -batch executes a script', 'script_execution'); return }
  const [obj, act] = [p.positional[0]?.value, p.positional[1]?.value]
  if (obj === 'netns' && act === 'exec') { c.acc.raise('HIGH', 'ip netns exec runs commands', 'wrapper'); return }
  if (!obj) return
  if (!/^(a|addr|address|l|link|r|route|n|neigh|neighbor|neighbour|rule|maddr|tunnel|netns|monitor)$/.test(obj)) { c.acc.raise('MEDIUM', 'ip object not on allowlist', 'unknown_flag'); return }
  if (act && !/^(show|list|ls|lst|s|l|get|help)$/.test(act)) c.acc.raise('CRITICAL', 'changes network configuration', 'network_change')
}
H.ifconfig = (a, c) => { if (parseArgs(a).positional.length > 1) c.acc.raise('CRITICAL', 'changes network configuration', 'network_change') }
alias(['route', 'arp'], (a, c) => { if (parseArgs(a).positional.length) c.acc.raise('CRITICAL', 'changes routing/ARP state', 'network_change') })

const SVC_READ = /^(status|is-active|is-enabled|is-failed|list-units|list-unit-files|list-timers|list-sockets|list-dependencies|show|cat|get-default)$/
const SVC_POWER = /^(poweroff|reboot|halt|kexec|rescue|emergency|suspend|hibernate|hybrid-sleep|isolate)$/
const SVC_CRIT = /^(sshd?|ssh\.service|sshd\.service|networking|network|networkmanager|systemd-networkd|dbus|systemd-logind|ufw|firewalld|iptables)(\.service)?$/i
H.systemctl = (a, c) => {
  const p = parseArgs(a)
  const sub = p.positional[0]?.value ?? ''
  if (p.longs.length === 1 && p.longs[0] === 'version' || (!sub && p.shorts.length === 0 && !p.longs.length)) return
  if (SVC_POWER.test(sub)) { c.acc.raise('CRITICAL', 'systemctl power/target change', 'power_control'); return }
  if (SVC_READ.test(sub)) return
  const target = p.positional[1]?.value ?? ''
  if (/^(stop|disable|mask|kill)$/.test(sub) && SVC_CRIT.test(target)) { c.acc.raise('CRITICAL', 'stops a service required for remote access/networking', 'service_critical'); return }
  c.acc.raise('HIGH', `systemctl ${sub || '(unknown)'} changes service state`, 'service_change')
}
H.service = (a, c) => {
  const p = parseArgs(a)
  if (p.longs.includes('status-all')) return
  const [svc, act] = [p.positional[0]?.value ?? '', p.positional[1]?.value ?? '']
  if (act === 'status') return
  if (/^(stop|disable)$/.test(act) && SVC_CRIT.test(svc)) c.acc.raise('CRITICAL', 'stops a service required for remote access/networking', 'service_critical')
  else c.acc.raise('HIGH', 'changes service state', 'service_change')
}
H.crontab = (a, c) => {
  const p = parseArgs(a)
  if (p.shorts.includes('l') && p.shorts.length === 1) return
  if (p.shorts.includes('r')) c.acc.raise('DESTRUCTIVE', 'removes all cron jobs', 'persistence')
  else c.acc.raise('HIGH', 'modifies scheduled jobs (persistence)', 'persistence')
}
H.atq = () => undefined
alias(['at', 'batch', 'atrm', 'systemd-run', 'anacron'], (_a, c) => c.acc.raise('HIGH', 'schedules deferred execution (persistence)', 'persistence'))
alias(['history', 'printenv', 'set', 'declare', 'typeset', 'export', 'alias', 'unalias', 'unset', 'readonly', 'local', 'trap', 'umask', 'ulimit', 'shopt', 'enable', 'bind', 'hash', 'fc'], (_a, c) => c.acc.raise('MEDIUM', 'shell state or environment access (may expose secrets)', 'env_dump'))
alias(['read', 'wait', 'jobs', 'fg', 'bg', 'disown', 'exit', 'return', 'break', 'continue', 'shift', 'getopts'], (_a, c) => c.acc.raise('MEDIUM', 'shell control builtin', 'compound'))
alias(['curl', 'wget', 'fetch', 'aria2c', 'lynx', 'links'], (a, c) => {
  c.seg.downloader = true
  c.acc.raise('MEDIUM', 'network download/upload', 'network_egress')
  const p = parseArgs(a)
  const outs = a.filter((_w, i) => /^(-o|-O|--output|-T|--upload-file|-d|--data|-F|--form|--data-binary|-X|--request)$/.test(a[i - 1]?.value ?? ''))
  if (p.shorts.includes('O') || p.shorts.includes('o') || p.shorts.includes('T') || p.shorts.includes('d') || p.shorts.includes('F') || p.shorts.includes('X') || p.longs.some((l) => /^(output|output-document|upload-file|data.*|form|post-.*|request)$/.test(l)) || outs.length) {
    c.acc.raise('MEDIUM', 'writes or sends data', 'file_write'); pathsEscalate(outs, c, true)
  }
  pathsEscalate(p.positional, c, true)
})
alias(['ssh', 'mosh'], (a, c) => {
  c.acc.raise('HIGH', 'opens a nested SSH connection', 'nested_ssh')
  const p = parseArgs(a)
  const idx = unwrapIndex(a, ['-p', '-i', '-l', '-o', '-F', '-J', '-L', '-R', '-D', '-b', '-c', '-E', '-e', '-m', '-O', '-Q', '-S', '-W', '-w'])
  const rest = a.slice(idx + 1)
  void p
  if (rest.length) { if (rest.some((w) => w.dynamic)) c.acc.raise('HIGH', 'dynamic remote command', 'dynamic_shell_code'); else c.analyzeScript(rest.map((w) => w.value).join(' ')) }
})
alias(['scp', 'sftp', 'rsync', 'rclone', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ftp'], (a, c) => {
  c.acc.raise('HIGH', 'network transfer or raw socket tool', 'network_transfer')
  const p = parseArgs(a)
  if (p.longs.some((l) => /^delete/.test(l))) c.acc.raise('DESTRUCTIVE', 'rsync --delete removes destination files', 'mass_deletion')
  if (p.shorts.includes('e') || p.longs.includes('exec') || p.shorts.includes('c')) c.acc.raise('CRITICAL', 'tool can spawn a remote command/shell', 'reverse_shell')
})
alias(['mysql', 'mysqldump', 'psql', 'sqlite3', 'mongo', 'mongosh', 'redis-cli', 'sqlcmd'], (a, c) => {
  c.acc.raise('HIGH', 'database client executes statements', 'database_access')
  if (a.some((w) => /\b(drop\s+(table|database|schema)|truncate|delete\s+from|flushall|flushdb|alter\s+table)\b/i.test(w.value))) c.acc.raise('DESTRUCTIVE', 'destructive SQL/database command', 'destructive_sql')
})
alias(['gzip', 'gunzip', 'zcat', 'bzcat', 'xzcat', 'unxz', 'bunzip2', 'unzip', 'tar', 'zip', 'xz', 'bzip2', '7z', 'cpio', 'ar'], (a, c) => {
  const p = parseArgs(a)
  const first = a[0]?.value ?? ''
  const listOnly = (first === '-t' || /^-?[a-zA-Z]*t[a-zA-Z]*$/.test(first)) && !/[xcrud]/.test(first.replace('-', ''))
  if ((p.shorts.includes('c') && p.shorts.length <= 2) || p.shorts.includes('p')) { c.seg.decoder = true; c.acc.flag('encoded_content') }
  if (listOnly) { c.acc.raise('MEDIUM', 'archive listing', 'archive'); return }
  c.acc.raise('MEDIUM', 'archive tool writes or extracts files', 'file_write')
  pathsEscalate(p.positional, c, true)
})
H.openssl = (a, c) => {
  const f = firstPos(parseArgs(a))
  if (/^(enc|base64|aes|des)/.test(f) && a.some((w) => w.value === '-d')) { c.seg.decoder = true; c.acc.flag('encoded_content') }
  if (/^(version|help|x509|s_client|verify|dgst|rand)$/.test(f)) { c.acc.raise('MEDIUM', 'openssl invocation', 'unknown_flag'); return }
  c.acc.raise('MEDIUM', 'openssl invocation not on allowlist', 'unknown_flag')
}
H.script = (_a, c) => c.acc.raise('HIGH', 'script spawns a recorded shell', 'script_execution')
alias(['screen', 'tmux'], (_a, c) => c.acc.raise('HIGH', 'terminal multiplexer can run detached commands', 'persistence'))

// package managers & container tools
function sub(readSubs: string[], level: RiskLevel = 'HIGH', reason = 'changes installed software'): Handler {
  return (a, c) => {
    const p = parseArgs(a)
    if (a.length === 0 || (p.longs.length === 1 && ['version', 'help'].includes(p.longs[0]) && !p.positional.length) || (p.shorts.length === 1 && ['v', 'V', 'h'].includes(p.shorts[0]) && !p.positional.length)) return
    const s = p.positional[0]?.value ?? ''
    if (readSubs.includes(s)) return
    c.acc.raise(level, `${s || 'unknown subcommand'}: ${reason}`, 'package_change')
  }
}
alias(['apt', 'apt-get', 'aptitude'], sub(['list', 'show', 'search', 'policy', 'depends', 'rdepends', 'madison', 'showpkg']))
H['apt-cache'] = () => undefined
H['dpkg-query'] = () => undefined
H.dpkg = (a, c) => { const p = parseArgs(a); if (p.shorts.some((s) => 'lLsSpC'.includes(s)) && !p.shorts.some((s) => 'irPIiuf'.includes(s)) || p.longs.some((l) => /^(list|listfiles|status|search|print-architecture|audit)$/.test(l))) return; c.acc.raise('HIGH', 'changes installed software', 'package_change') }
alias(['yum', 'dnf', 'microdnf'], sub(['list', 'info', 'search', 'provides', 'repolist', 'check-update', 'whatprovides', 'deplist', 'repoquery']))
H.rpm = (a, c) => { if (a.some((w) => /^-[a-zA-Z]*[qV]/.test(w.value) && !/^-[a-zA-Z]*[ieU]/.test(w.value)) || a.some((w) => w.value === '--query')) return; c.acc.raise('HIGH', 'changes installed software', 'package_change') }
H.apk = sub(['info', 'list', 'search', 'policy'])
H.pacman = (a, c) => { if (a.some((w) => /^-(Q[a-z]*|Ss|Si|Sl|F[a-z]*)$/.test(w.value))) return; c.acc.raise('HIGH', 'changes installed software', 'package_change') }
alias(['snap', 'flatpak', 'brew'], sub(['list', 'info', 'find', 'search']))
alias(['pip', 'pip3'], sub(['list', 'show', 'freeze', 'check', 'config', 'help', 'debug', 'index']))
alias(['npm', 'yarn', 'pnpm', 'npx'], (a, c) => {
  const p = parseArgs(a)
  const s = p.positional[0]?.value ?? ''
  if (/^(ls|list|view|info|outdated|ping|root|prefix|whoami)$/.test(s) || (a.length === 1 && /^(-v|--version)$/.test(a[0].value))) return
  c.acc.raise('HIGH', 'package manager may run install/lifecycle scripts', 'package_change')
})
alias(['gem', 'cargo', 'go', 'composer', 'cpan', 'make', 'cmake', 'gcc', 'cc', 'g++', 'clang', 'rustc', 'javac', 'mvn', 'gradle', 'ansible', 'ansible-playbook', 'terraform', 'puppet', 'chef-client', 'salt', 'helm'], (a, c) => {
  if (a.length === 1 && /^(-v|--version|version)$/.test(a[0].value)) return
  c.acc.raise('HIGH', 'build/automation tool executes arbitrary project code', 'script_execution')
})
alias(['docker', 'podman', 'nerdctl'], (a, c) => {
  const p = parseArgs(a)
  const s = p.positional[0]?.value ?? ''
  const s2 = p.positional[1]?.value ?? ''
  if (/^(ps|images|logs|inspect|version|info|top|port|diff|history|stats|events|search|container|image|network|volume|system)$/.test(s)) {
    if ((s === 'container' || s === 'image' || s === 'network' || s === 'volume') && !/^(ls|list|inspect)$/.test(s2)) { c.acc.raise(/^(rm|remove|prune)$/.test(s2) ? 'DESTRUCTIVE' : 'HIGH', 'container resource change', 'container_change'); return }
    if (s === 'system' && s2 !== 'df' && s2 !== 'info') { c.acc.raise('DESTRUCTIVE', 'docker system prune removes data', 'destructive_tool'); return }
    return
  }
  if (/^(prune|rm|rmi|kill)$/.test(s) || a.some((w) => w.value === 'prune')) { c.acc.raise('DESTRUCTIVE', 'removes containers/images/volumes', 'destructive_tool'); return }
  const vols: string[] = []
  a.forEach((w, i) => {
    if (w.value === '-v' || w.value === '--volume' || w.value === '--mount') vols.push(a[i + 1]?.value ?? '')
    else if (/^-v./.test(w.value)) vols.push(w.value.slice(2))
    else if (/^--(volume|mount)=/.test(w.value)) vols.push(w.value.split('=').slice(1).join('='))
  })
  const badMount = vols.some((v) => /^(?:type=bind,)?(?:source=|src=)?(\/|\/etc|\/root|\/proc|\/sys|\/dev|\/var\/run\/docker\.sock|\/run\/docker\.sock)(?=[:,]|$)/.test(v))
  if (a.some((w) => /^--(privileged|pid=host|ipc=host|userns=host|net=host|network=host|cap-add=(ALL|SYS_ADMIN))$/.test(w.value)) || badMount) { c.acc.raise('CRITICAL', 'privileged container or host root mount', 'container_escape'); return }
  c.acc.raise('HIGH', 'container operation changes state or executes code', 'container_change')
})
H.kubectl = (a, c) => {
  const p = parseArgs(a)
  const s = p.positional[0]?.value ?? ''
  if (/^(get|describe|logs|top|version|api-resources|api-versions|explain|cluster-info)$/.test(s)) {
    if (p.positional.some((w) => /^(secrets?|secret\/.*)$/i.test(w.value))) c.acc.raise('HIGH', 'reads Kubernetes secrets', 'credential_access')
    return
  }
  if (s === 'config' && p.positional[1]?.value === 'view') { c.acc.raise('HIGH', 'config view may expose credentials', 'credential_access'); return }
  c.acc.raise(/^(delete|drain|replace)$/.test(s) ? 'DESTRUCTIVE' : 'HIGH', 'changes cluster state', 'cluster_change')
}
H.git = (a, c) => {
  const p = parseArgs(a)
  if (a.some((w) => w.value === '-c' || /^--(exec-path|upload-pack|receive-pack|output|ext-diff|textconv)/.test(w.value))) { c.acc.raise('HIGH', 'git option can execute programs', 'script_execution'); return }
  const s = p.positional[0]?.value ?? ''
  const mod = a.map((w) => w.value)
  if (/^(status|log|diff|show|rev-parse|ls-files|describe|blame|shortlog|ls-tree|cat-file|reflog|grep|rev-list|name-rev|whatchanged|count-objects|version)$/.test(s) && !mod.includes('--output')) return
  if (s === 'branch' && !mod.some((x) => /^-[dDmMcC]$|^--(delete|move|copy)/.test(x))) return
  if (s === 'remote' && (!mod[1] || mod[1] === '-v')) return
  if (s === 'stash' && p.positional[1]?.value === 'list') return
  if (s === 'tag' && !mod.some((x) => /^-[dfas]$/.test(x))) return
  if (/^(reset|clean|checkout|restore|rebase|filter-branch|gc|prune|update-ref)$/.test(s) && (mod.includes('--hard') || mod.some((x) => /^-[a-z]*f/.test(x)) || mod.includes('.'))) {
    c.acc.raise(s === 'clean' ? 'DESTRUCTIVE' : 'HIGH', 'discards work irreversibly', 'destructive_tool'); return
  }
  if (s === 'push' && mod.some((x) => /^(-f|--force|--force-with-lease|--delete|--mirror)$/.test(x))) { c.acc.raise('HIGH', 'force push rewrites remote history', 'destructive_tool'); return }
  c.acc.raise('MEDIUM', `git ${s || '(unknown)'} modifies repository or network state`, 'repo_change')
}

export function resolveName(raw: string): { name: string; explicit: boolean; trusted: boolean } {
  const m = /^(\/usr\/local\/s?bin|\/usr\/s?bin|\/s?bin)\/([^/]+)$/.exec(raw)
  if (m) return { name: m[2], explicit: true, trusted: true }
  if (raw.includes('/')) return { name: raw, explicit: true, trusted: false }
  return { name: raw, explicit: false, trusted: true }
}

export function dispatch(name: string, args: Word[], ctx: Ctx): void {
  const acc = ctx.acc
  // Sensitive-path operands escalate regardless of the command (reads of secrets, device access).
  for (const a of args) {
    const k = classifyWordPath(a)
    if (k === 'credential') acc.raise('CRITICAL', 'touches credential or key material', 'credential_access')
  }
  if (SHELLS.test(name)) return shell(name, args, ctx)
  if (INTERPS.test(name)) return interp(args, ctx)
  if (/^mkfs(\.|$)|^mke2fs$|^mkswap$|^mkfs/.test(name)) { acc.raise('DESTRUCTIVE', 'creates a filesystem (destroys data)', 'destructive_tool'); return }
  const h = H[name]
  if (h) return h(args, ctx)
  const spec = RO[name]
  if (spec) return checkRo(name, spec, args, ctx)
  acc.raise('MEDIUM', `unknown executable: ${name}`, 'unknown_executable')
}
