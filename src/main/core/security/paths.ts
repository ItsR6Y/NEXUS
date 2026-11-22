import type { Word } from './tokenizer'

export type PathClass = 'credential' | 'device' | 'system' | null

const CREDENTIAL: RegExp[] = [
  /(^|\/)\.ssh(\/|$)/, /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/, /(^|\/)authorized_keys2?$/,
  /\/etc\/(shadow|gshadow|sudoers|security\/opasswd|ssl\/private|ssh\/ssh_host_[a-z0-9_]*_key)/, /\/etc\/sudoers\.d(\/|$)/, /^\/etc\/master\.passwd$/,
  /\.(pem|key|p12|pfx|keystore|jks|kdbx|ovpn)$/i, /(^|\/)\.env(\.[\w.-]+)?$/, /(^|\/)\.aws(\/|$)/, /(^|\/)\.config\/gcloud/, /(^|\/)\.azure(\/|$)/,
  /(^|\/)\.kube\/config/, /(^|\/)\.docker\/config\.json/, /(^|\/)\.git-credentials/, /(^|\/)\.netrc/, /(^|\/)\.npmrc/, /(^|\/)\.pypirc/, /(^|\/)\.pgpass/,
  /(^|\/)\.my\.cnf/, /(^|\/)\.gnupg(\/|$)/, /\/proc\/[^/]+\/environ/, /(^|\/)\.(bash|zsh|sh)_history$/, /(^|\/)credentials(\.json)?$/i, /(^|\/)\.htpasswd$/,
  /(^|\/)(secrets?|vault)\.(ya?ml|json|txt)$/i
]
const SAFE_DEV = /^\/dev\/(null|zero|random|urandom|full|tty|stdin|stdout|stderr|fd\/\d+|pts\/\d+|console)$/
const SYSTEM = /^\/(etc|boot|usr|bin|sbin|lib|lib32|lib64|libx32|var\/lib|var\/spool|var\/log|root|sys|proc|opt|srv|run)(\/|$)/

export function normalizePath(p: string): string {
  return p.replace(/\/{2,}/g, '/').replace(/(^|\/)\.\/(?=.)/g, '$1').replace(/\/(?!\.\.)[^/]+\/\.\.(?=\/|$)/g, '')
}

export function classifyPath(raw: string): PathClass {
  const p = normalizePath(raw.trim())
  if (!p) return null
  for (const re of CREDENTIAL) if (re.test(p)) return 'credential'
  if (p.startsWith('/dev/')) return SAFE_DEV.test(p) ? null : 'device'
  if (SYSTEM.test(p)) return 'system'
  return null
}

/** Check a word both by value and raw text (so quoting/dynamic parts cannot hide a sensitive path). */
export function classifyWordPath(w: Word): PathClass {
  const a = classifyPath(w.value)
  if (a) return a
  if (w.value.includes('=')) { const b = classifyPath(w.value.slice(w.value.indexOf('=') + 1)); if (b) return b }
  return w.dynamic ? classifyPath(w.raw.replace(/\$\{?HOME\}?/g, '~')) : null
}

const ROOTISH = new Set(['/', '/*', '/.', '/..', '~', '~/', '~/*', '~/.', '*', '.', '..', './', '../', '/home', '/home/', '/home/*', '/root', '/root/', '/etc', '/usr', '/var', '/boot', '/bin', '/sbin', '/lib', '/lib64', '/opt', '/srv', '/dev', '/sys', '/proc'])
export function isRootish(w: Word): boolean {
  const v = normalizePath(w.value)
  if (ROOTISH.has(v) || /^\/\*+$/.test(v)) return true
  return /^"?\$\{?HOME\}?"?(\/\*?)?$/.test(w.raw) || /^\/(etc|usr|var|boot|bin|sbin|lib|lib64)\/\*$/.test(v)
}
