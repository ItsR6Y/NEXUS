import { useCallback, useEffect, useState } from 'react'
import type { Envelope } from '../../../shared/types'

export class ApiError extends Error {
  constructor(public code: string, message: string) {
    super(message)
  }
}

export async function unwrap<T>(p: Promise<Envelope<T>>): Promise<T> {
  const r = await p
  if (!r.ok) throw new ApiError(r.error.code, r.error.message)
  return r.data
}

type Sub = (cb: () => void) => () => void
const n = (): Window['nexus']['on'] => window.nexus.on

export const ev = {
  sessions: ((cb) => n().sessionsChanged(cb)) as Sub,
  approvals: ((cb) => n().approvalsChanged(cb)) as Sub,
  knownHosts: ((cb) => n().knownHostsChanged(cb)) as Sub,
  mcp: ((cb) => n().mcpChanged(cb)) as Sub,
  executions: ((cb) => n().executionsChanged(cb)) as Sub,
  security: ((cb) => n().securityChanged(cb)) as Sub
}

export const SUBS = {
  none: [] as Sub[],
  servers: [ev.sessions, ev.approvals, ev.knownHosts] as Sub[],
  sessions: [ev.sessions] as Sub[],
  approvals: [ev.approvals, ev.sessions] as Sub[],
  knownHosts: [ev.knownHosts] as Sub[],
  mcp: [ev.mcp] as Sub[],
  dashboard: [ev.sessions, ev.approvals, ev.mcp, ev.executions, ev.security, ev.knownHosts] as Sub[],
  executions: [ev.executions] as Sub[],
  security: [ev.security] as Sub[]
}

export function useLive<T>(
  loader: () => Promise<Envelope<T>>,
  subs: Sub[] = SUBS.none
): { data: T | null; error: string | null; loading: boolean; reload: () => void } {
  const [state, setState] = useState<{ data: T | null; error: string | null; loading: boolean }>({
    data: null,
    error: null,
    loading: true
  })

  const reload = useCallback(() => {
    loader()
      .then((r) => setState((s) => (r.ok ? { data: r.data, error: null, loading: false } : { data: s.data, error: r.error.message, loading: false })))
      .catch((e: Error) => setState((s) => ({ ...s, error: e.message, loading: false })))
  }, [loader])

  useEffect(() => {
    reload()
    const offs = subs.map((s) => s(reload))
    return () => offs.forEach((o) => o())
  }, [reload, subs])

  return { ...state, reload }
}

export function visualize(cmd: string): string {
  return [...cmd]
    .map((c) => {
      const cp = c.codePointAt(0)!
      return cp === 10 ? '⏎\n' : cp === 9 ? '→' : cp < 32 || cp === 127 || cp > 126 ? `⟦U+${cp.toString(16).toUpperCase().padStart(4, '0')}⟧` : c
    })
    .join('')
}

export const fmtTime = (ms: number): string => new Date(ms).toLocaleString()
export const copy = (t: string): void => { void navigator.clipboard.writeText(t) }
