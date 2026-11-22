import { useState, type ReactNode } from 'react'
import type { AuditVerifyResult } from '../../../shared/types'
import { Button, Card, Empty, Page } from '../components/ui'
import { SUBS, fmtTime, unwrap, useLive } from '../lib/live'

const load = (): ReturnType<typeof window.nexus.security.events> => window.nexus.security.events()
const SEV = { info: 'text-muted border-line', warning: 'text-warn border-warn/50', critical: 'text-crit border-crit/60' } as const
const TITLES: Record<string, string> = {
  host_key_mismatch: 'Host key changed (blocked)',
  host_key_removed: 'Known host key removed',
  approval_abuse: 'Approval misuse attempt',
  session_ownership_or_missing: 'Session ownership mismatch',
  mcp_auth_failure: 'MCP authentication failure',
  mcp_lockout: 'MCP connections locked out',
  ipc_untrusted_sender: 'Untrusted IPC sender blocked',
  mcp_start_failed: 'MCP bridge failed to start'
}

export function Security(): ReactNode {
  const { data } = useLive(load, SUBS.security)
  const [chain, setChain] = useState<AuditVerifyResult | null>(null)
  const verify = async (): Promise<void> => setChain(await unwrap(window.nexus.audit.verify()))

  return (
    <Page title="Security Events" subtitle="Anomalies, blocked attempts, and audit-chain integrity">
      <Card title="Audit-chain integrity" className="mb-4" actions={<Button data-testid="verify-chain" onClick={() => void verify()}>Verify now</Button>}>
        <p role="status" className={`text-sm ${chain ? (chain.ok ? 'text-ok' : 'text-crit') : 'text-muted'}`}>
          {chain ? (chain.ok ? `Intact — ${chain.entries} entries verified.` : `BROKEN at entry #${chain.brokenAt}.`) : 'Click "Verify now" to recompute the SHA-256 hash chain.'}
        </p>
      </Card>
      {!data?.length ? (
        <Empty>No security events recorded.</Empty>
      ) : (
        <div className="space-y-2">
          {data.map((e) => (
            <Card key={e.id} className={`!p-3 ${SEV[e.severity]}`}>
              <div className="flex items-center gap-3">
                <span className="rounded border px-2 py-0.5 text-xs font-bold uppercase">{e.severity}</span>
                <b className="text-fg">{TITLES[e.type] ?? e.type}</b>
                <span className="ml-auto text-xs text-muted">{fmtTime(e.ts)}</span>
              </div>
              <pre className="mt-2 overflow-auto font-mono text-xs text-muted">{JSON.stringify(e.details, null, 2)}</pre>
            </Card>
          ))}
        </div>
      )}
    </Page>
  )
}
