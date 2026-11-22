import { useEffect, useState, type ReactNode } from 'react'
import { Card, Empty, LevelBadge, Mono, Page } from '../components/ui'
import { SUBS, fmtTime, useLive, visualize } from '../lib/live'

const load = (): ReturnType<typeof window.nexus.approvals.list> => window.nexus.approvals.list()

function useNow(): number {
  const [n, setN] = useState(() => Date.now())
  useEffect(() => {
    const i = setInterval(() => setN(Date.now()), 1000)
    return () => clearInterval(i)
  }, [])
  return n
}

/**
 * Read-only approval log.
 * SECURITY: Renderer has NO approval decision methods. Decisions occur strictly in main-process native OS dialogs.
 */
export function Approvals(): ReactNode {
  const { data, error } = useLive(load, SUBS.approvals)
  const now = useNow()
  const pending = data?.filter((a) => a.status === 'pending' && a.expiresAt > now) ?? []
  const recent = data?.filter((a) => !(a.status === 'pending' && a.expiresAt > now)) ?? []

  return (
    <Page
      title="Approvals (Read-Only)"
      subtitle="All approvals are decided exclusively via native OS dialogs in the Electron main process. Neither the renderer nor MCP can approve commands."
    >
      {error && <p role="alert" className="text-bad">{error}</p>}
      <div className="space-y-4">
        {pending.length === 0 ? (
          <Empty>No approvals currently waiting on a native OS dialog.</Empty>
        ) : (
          pending.map((a) => {
            const left = Math.max(0, Math.ceil((a.expiresAt - now) / 1000))
            return (
              <Card key={a.id} className={a.level === 'DESTRUCTIVE' || a.level === 'CRITICAL' ? '!border-crit' : ''}>
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <LevelBadge level={a.level} />
                  <span className="text-sm">on <b>{a.serverName}</b></span>
                  <span className="text-xs text-muted">source: {a.source} ({a.requester})</span>
                  <span className={`ml-auto text-xs ${left < 15 ? 'text-bad' : 'text-muted'}`}>expires in {left}s · decide in native dialog</span>
                </div>
                <Mono className="max-h-48">{visualize(a.commandSanitized)}</Mono>
                <ul className="mt-2 list-disc pl-5 text-xs text-muted">{a.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
              </Card>
            )
          })
        )}

        {recent.length > 0 && (
          <Card title="Recent approval decisions (redacted)">
            <table className="w-full text-sm">
              <tbody>
                {recent.slice(0, 60).map((a) => (
                  <tr key={a.id} className="border-t border-line first:border-0">
                    <td className="py-2 pr-3"><LevelBadge level={a.level} /></td>
                    <td className="w-full max-w-0 truncate py-2 font-mono text-xs" title={a.commandSanitized}>{a.commandSanitized}</td>
                    <td className="py-2 pl-3 text-xs text-muted">{a.source}</td>
                    <td className="py-2 pl-3 text-xs">{a.status}{a.invalidationReason ? ` — ${a.invalidationReason}` : ''}</td>
                    <td className="py-2 pl-3 text-xs text-muted">{fmtTime(a.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </div>
    </Page>
  )
}
