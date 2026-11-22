import type { ReactNode } from 'react'
import type { PageId } from '../App'
import { Card, Empty, LevelBadge, Page, StatusDot } from '../components/ui'
import { SUBS, fmtTime, useLive } from '../lib/live'

const load = (): ReturnType<typeof window.nexus.dashboard.get> => window.nexus.dashboard.get()

export function Dashboard({ go }: { go: (p: PageId) => void }): ReactNode {
  const { data: d, error } = useLive(load, SUBS.dashboard)
  const stat = (label: string, value: ReactNode, on?: () => void, tone = ''): ReactNode => (
    <button type="button" onClick={on} disabled={!on} className="rounded-lg border border-line bg-panel p-4 text-left transition enabled:hover:border-accent disabled:cursor-default">
      <div className="text-xs uppercase tracking-wider text-muted">{label}</div>
      <div className={`mt-1 text-3xl font-semibold ${tone}`}>{value}</div>
    </button>
  )

  return (
    <Page title="Dashboard" subtitle="Overview of servers, active SSH sessions, and security posture">
      {error && <p role="alert" className="mb-3 text-bad">{error}</p>}
      {d && (
        <div className="space-y-5">
          {!d.credentialsAvailable && (
            <div role="alert" className="rounded-lg border border-crit bg-crit/10 p-4 text-sm">
              <b>OS credential storage is unavailable.</b> NEXUS will refuse to save passwords or passphrases until it is available.
            </div>
          )}
          {!d.auditChain.ok && (
            <div role="alert" className="rounded-lg border border-crit bg-crit/10 p-4 text-sm">
              <b>Audit log integrity check FAILED</b> at entry #{d.auditChain.brokenAt}.
            </div>
          )}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {stat('Servers', d.serverCount, () => go('servers'))}
            {stat('Active sessions', d.activeSessions, () => go('terminal'))}
            {stat('Pending approvals', d.pendingApprovals, () => go('approvals'), d.pendingApprovals ? 'text-crit' : '')}
            {stat('Security events (24h)', d.securityEvents24h, () => go('security'), d.securityEvents24h ? 'text-warn' : '')}
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <Card title="Security Posture" className="lg:col-span-1">
              <div className="space-y-2.5">
                <div><StatusDot on={d.mcpListening} label={d.mcpListening ? 'MCP bridge listening (5 tools)' : 'MCP bridge off'} /></div>
                <div><StatusDot on={d.auditChain.ok} label={`Audit chain ${d.auditChain.ok ? 'verified' : 'BROKEN'} (${d.auditChain.entries})`} /></div>
                <div><StatusDot on={d.credentialsAvailable} label={`Credentials: ${d.credentialBackend}`} /></div>
                <div><StatusDot on label="Native main-process approval dialogs" /></div>
              </div>
            </Card>
            <Card title="Recent executions" className="lg:col-span-2">
              {d.recentExecutions.length === 0 ? (
                <Empty>No programmatic executions yet.</Empty>
              ) : (
                <table className="w-full text-sm">
                  <tbody>
                    {d.recentExecutions.map((e) => (
                      <tr key={e.id} className="border-t border-line first:border-0">
                        <td className="py-2 pr-3"><LevelBadge level={e.level} /></td>
                        <td className="w-full max-w-0 truncate py-2 font-mono text-xs" title={e.commandSanitized}>{e.commandSanitized}</td>
                        <td className="py-2 pl-3 text-xs text-muted">{e.source} · {e.status}</td>
                        <td className="py-2 pl-3 text-xs text-muted">{fmtTime(e.startedAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          </div>
        </div>
      )}
    </Page>
  )
}
