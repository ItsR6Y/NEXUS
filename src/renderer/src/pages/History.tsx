import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { RISK_LEVELS, type RiskLevel } from '../../../shared/policy-types'
import type { ExecutionDTO, ExecutionFilter } from '../../../shared/types'
import { Button, Empty, LevelBadge, Modal, Mono, Page, inputCls } from '../components/ui'
import { SUBS, fmtTime, unwrap, useLive } from '../lib/live'

const loadServers = (): ReturnType<typeof window.nexus.servers.list> => window.nexus.servers.list()

export function History(): ReactNode {
  const [f, setF] = useState<ExecutionFilter>({ limit: 200 })
  const loader = useCallback(() => window.nexus.executions.list(f), [f])
  const { data, reload } = useLive(loader, SUBS.executions)
  const servers = useLive(loadServers)
  const [sel, setSel] = useState<ExecutionDTO | null>(null)
  const [output, setOutput] = useState<{ text: string; truncated: boolean } | null>(null)

  // Output is no longer part of list payloads: fetch it per selected row.
  useEffect(() => {
    if (!sel) return
    let stale = false
    void window.nexus.executions.output(sel.id, 0, 262_144).then((env) => {
      if (stale) return
      setOutput(env.ok ? { text: env.data.text, truncated: env.data.truncated } : { text: '', truncated: false })
    })
    return () => { stale = true }
  }, [sel])

  const set = (patch: ExecutionFilter): void => setF((p) => ({ ...p, ...patch }))
  const sev = (v: string): RiskLevel | undefined => (v ? (v as RiskLevel) : undefined)

  const exportJson = (): void => {
    if (!data) return
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `nexus-history-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const clearHistory = async (): Promise<void> => {
    await unwrap(window.nexus.executions.clear())
    reload()
  }

  return (
    <Page
      title="Command History"
      subtitle="Sanitized, secret-redacted programmatic executions from GUI and Claude (MCP)"
      actions={
        <>
          <Button onClick={exportJson} disabled={!data?.length}>Export JSON</Button>
          <Button variant="danger" onClick={() => void clearHistory()} disabled={!data?.length}>Clear history</Button>
        </>
      }
    >
      <div className="mb-4 flex flex-wrap gap-2">
        <select aria-label="Server" className={`${inputCls} !w-auto`} onChange={(e) => set({ serverId: e.target.value || undefined })}>
          <option value="">All servers</option>
          {servers.data?.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
        <select aria-label="Source" className={`${inputCls} !w-auto`} onChange={(e) => set({ source: (e.target.value || undefined) as 'user' | 'claude' | undefined })}>
          <option value="">All sources</option>
          <option value="user">User (GUI)</option>
          <option value="claude">Claude (MCP)</option>
        </select>
        <select aria-label="Risk level" className={`${inputCls} !w-auto`} onChange={(e) => set({ level: sev(e.target.value) })}>
          <option value="">All levels</option>
          {RISK_LEVELS.map((l) => <option key={l}>{l}</option>)}
        </select>
        <select aria-label="Status" className={`${inputCls} !w-auto`} onChange={(e) => set({ status: (e.target.value || undefined) as ExecutionFilter['status'] })}>
          <option value="">All statuses</option>
          {['running', 'completed', 'denied', 'failed', 'timeout', 'cancelled'].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      {!data?.length ? (
        <Empty>No matching command executions.</Empty>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-muted">
            <tr><th className="pb-2">Level</th><th>Command (redacted)</th><th>Source</th><th>Status</th><th>When</th></tr>
          </thead>
          <tbody>
            {data.map((e) => (
              <tr key={e.id} className="cursor-pointer border-t border-line hover:bg-panel2" onClick={() => { setOutput(null); setSel(e) }} tabIndex={0} onKeyDown={(k) => { if (k.key === 'Enter') { setOutput(null); setSel(e) } }}>
                <td className="py-2 pr-3"><LevelBadge level={e.level} /></td>
                <td className="max-w-md truncate py-2 font-mono text-xs" title={e.commandSanitized}>{e.commandSanitized}</td>
                <td className="px-3 text-xs text-muted">{e.source} ({e.requester})</td>
                <td className="px-3 text-xs">{e.status}{e.exitCode !== null ? ` (exit ${e.exitCode})` : ''}</td>
                <td className="text-xs text-muted">{fmtTime(e.startedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {sel && (
        <Modal wide title="Execution detail" onClose={() => setSel(null)}>
          <div className="mb-2 flex gap-2">
            <LevelBadge level={sel.level} />
            <span className="text-xs text-muted">{sel.source} · {sel.requester} · {sel.status} · {fmtTime(sel.startedAt)}</span>
          </div>
          <div className="mb-1 text-xs text-muted">Command (redacted)</div>
          <Mono>{sel.commandSanitized}</Mono>
          {sel.denialReason && (
            <>
              <div className="mb-1 mt-3 text-xs text-crit">Denial reason</div>
              <Mono>{sel.denialReason}</Mono>
            </>
          )}
          <div className="mb-1 mt-3 text-xs text-muted">Output (ANSI-stripped & redacted){(output?.truncated ?? sel.truncated) ? ' — truncated' : ''}</div>
          <Mono className="max-h-96">{output ? output.text || '(no output)' : 'Loading…'}</Mono>
          <div className="mt-4 flex justify-end"><Button onClick={() => setSel(null)}>Close</Button></div>
        </Modal>
      )}
    </Page>
  )
}
