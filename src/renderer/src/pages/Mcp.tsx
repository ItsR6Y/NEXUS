import { useState, type ReactNode } from 'react'
import { Button, Card, Empty, Mono, Page, StatusDot } from '../components/ui'
import { SUBS, copy, fmtTime, unwrap, useLive } from '../lib/live'

const load = (): ReturnType<typeof window.nexus.mcp.status> => window.nexus.mcp.status()

function CopyBtn({ text, label }: { text: string; label: string }): ReactNode {
  return <Button onClick={() => copy(text)} aria-label={`Copy ${label}`}>Copy</Button>
}

export function McpPage(): ReactNode {
  const { data: s, reload, error } = useLive(load, SUBS.mcp)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const toggle = async (): Promise<void> => {
    if (!s) return
    setBusy(true)
    setErr(null)
    try {
      await unwrap(window.nexus.mcp.setEnabled(!s.enabled))
    } catch (e) {
      setErr((e as Error).message)
    }
    setBusy(false)
    reload()
  }

  return (
    <Page
      title="Claude / MCP"
      subtitle="Authenticated local named-pipe bridge exposing exactly 5 restricted tools. MCP cannot open/close sessions, read credentials, or approve commands."
    >
      {(error || err) && <p role="alert" className="mb-3 text-bad">{err ?? error}</p>}
      {s && (
        <div className="space-y-4">
          <Card title="Bridge master switch">
            <div className="flex items-center justify-between gap-4">
              <div>
                <StatusDot on={s.listening} label={s.listening ? 'Listening on HMAC-authenticated local pipe' : 'Off — pipe stopped and bridge.json removed'} />
                <p className="mt-1 text-xs text-muted">Off by default. Generates a fresh 256-bit HMAC secret per launch.</p>
              </div>
              <Button variant={s.enabled ? 'danger' : 'primary'} disabled={busy} data-testid="mcp-toggle" onClick={() => void toggle()}>
                {s.enabled ? 'Disable MCP' : 'Enable MCP'}
              </Button>
            </div>
          </Card>

          <Card title="Exposed MCP tools (exact 5-tool contract)">
            <ul className="grid gap-1.5 font-mono text-xs text-fg sm:grid-cols-2">
              <li>1. nexus_list_servers <span className="text-muted">(public info only)</span></li>
              <li>2. nexus_list_sessions <span className="text-muted">(connected only)</span></li>
              <li>3. nexus_run_command <span className="text-muted">(native approval gated)</span></li>
              <li>4. nexus_get_history <span className="text-muted">(redacted, limit ≤ 100)</span></li>
              <li>5. nexus_read_terminal_tail <span className="text-muted">(ANSI-stripped & redacted, ≤ 200 lines)</span></li>
            </ul>
          </Card>

          <Card title="Connect Claude Code (manual registration)">
            <p className="mb-2 text-sm text-muted">Run once in your terminal (NEXUS never modifies your Claude settings automatically):</p>
            <div className="flex gap-2">
              <Mono className="flex-1">{s.registrationCommand}</Mono>
              <CopyBtn text={s.registrationCommand} label="command" />
            </div>
            <p className="mb-2 mt-4 text-sm text-muted">Or add to your project MCP JSON config:</p>
            <div className="flex gap-2">
              <Mono className="flex-1">{s.jsonConfig}</Mono>
              <CopyBtn text={s.jsonConfig} label="JSON config" />
            </div>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title={`Connected clients (${s.clients.length})`}>
              {s.clients.length === 0 ? (
                <Empty>No MCP client connected.</Empty>
              ) : (
                s.clients.map((c) => (
                  <div key={c.id} className="flex items-center justify-between border-t border-line py-2 first:border-0">
                    <div>
                      <b>{c.name}</b>{' '}
                      <span className="text-xs text-muted">v{c.version} · {c.calls} calls · since {fmtTime(c.connectedAt)}</span>
                    </div>
                    <Button variant="danger" onClick={() => void unwrap(window.nexus.mcp.disconnectClient(c.id)).then(reload)}>Disconnect</Button>
                  </div>
                ))
              )}
            </Card>
            <Card title="Recent tool calls">
              {s.recentCalls.length === 0 ? (
                <Empty>No calls yet.</Empty>
              ) : (
                <table className="w-full text-xs">
                  <tbody>
                    {s.recentCalls.slice(0, 15).map((c, i) => (
                      <tr key={i} className="border-t border-line first:border-0">
                        <td className="py-1 font-mono">{c.tool}</td>
                        <td className="text-muted">{c.client}</td>
                        <td className={c.ok ? 'text-ok' : 'text-bad'}>{c.summary}</td>
                        <td className="text-right text-muted">{new Date(c.ts).toLocaleTimeString()}</td>
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
