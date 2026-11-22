import { useState, type ReactNode } from 'react'
import type { AuditVerifyResult } from '../../../shared/types'
import { Button, Page } from '../components/ui'
import { SUBS, fmtTime, unwrap, useLive } from '../lib/live'

const load = (): ReturnType<typeof window.nexus.audit.list> => window.nexus.audit.list(300)

export function Audit(): ReactNode {
  const { data, reload } = useLive(load, SUBS.dashboard)
  const [v, setV] = useState<AuditVerifyResult | null>(null)
  const verify = async (): Promise<void> => { setV(await unwrap(window.nexus.audit.verify())); reload() }

  return (
    <Page
      title="Audit Log"
      subtitle="Append-only, SHA-256 hash-chained SQLite log. Secrets are redacted before writing."
      actions={<Button variant="primary" data-testid="verify-audit" onClick={() => void verify()}>Verify integrity</Button>}
    >
      {v && (
        <p role="status" className={`mb-3 rounded-lg border p-3 text-sm ${v.ok ? 'border-ok/50 text-ok' : 'border-crit text-crit'}`}>
          {v.ok ? `Chain intact: ${v.entries} entries verified.` : `Chain BROKEN at entry #${v.brokenAt}.`}
        </p>
      )}
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase text-muted">
          <tr><th className="pb-2">#</th><th>Time</th><th>Event</th><th>Actor</th><th>Details</th><th>Hash</th></tr>
        </thead>
        <tbody>
          {data?.map((a) => (
            <tr key={a.id} className="border-t border-line align-top">
              <td className="py-1.5 pr-3 text-xs text-muted">{a.id}</td>
              <td className="pr-3 text-xs text-muted">{fmtTime(a.ts)}</td>
              <td className="pr-3 font-mono text-xs">{a.kind}</td>
              <td className="pr-3 text-xs">{a.actor}</td>
              <td className="max-w-md truncate font-mono text-xs text-muted" title={JSON.stringify(a.data)}>{JSON.stringify(a.data)}</td>
              <td className="font-mono text-[11px] text-muted">{a.hash.slice(0, 10)}…</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Page>
  )
}
