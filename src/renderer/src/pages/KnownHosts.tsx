import { useState, type ReactNode } from 'react'
import type { KnownHostDTO } from '../../../shared/types'
import { Button, Empty, Page } from '../components/ui'
import { SUBS, fmtTime, unwrap, useLive } from '../lib/live'

const load = (): ReturnType<typeof window.nexus.knownHosts.list> => window.nexus.knownHosts.list()

export function KnownHosts(): ReactNode {
  const { data, error, reload } = useLive(load, SUBS.knownHosts)
  const [msg, setMsg] = useState<string | null>(null)

  const remove = async (h: KnownHostDTO): Promise<void> => {
    setMsg(null)
    try {
      const res = await unwrap(window.nexus.knownHosts.remove(h.host, h.port, h.keyType))
      if (res.removed) {
        setMsg(`Removed stored key for ${h.host}:${h.port} (${h.keyType}).`)
        reload()
      }
    } catch (e) {
      setMsg((e as Error).message)
    }
  }

  return (
    <Page
      title="Known Hosts"
      subtitle="Strict SSH host-key verification store. Changed host keys are always hard-blocked until you explicitly remove the old entry here."
    >
      {(error || msg) && <p role="status" className="mb-3 rounded-lg border border-line bg-panel p-3 text-sm text-muted">{error ?? msg}</p>}
      {!data?.length ? (
        <Empty>No trusted SSH host keys stored yet. Connect to a server to verify its fingerprint via a native OS dialog.</Empty>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-muted">
            <tr>
              <th className="pb-2">Host</th>
              <th>Type</th>
              <th>SHA256 Fingerprint</th>
              <th>First seen</th>
              <th>Last seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.map((h) => (
              <tr key={`${h.host}:${h.port}:${h.keyType}`} className="border-t border-line">
                <td className="py-2 pr-3 font-mono text-xs">{h.host}:{h.port}</td>
                <td className="pr-3 font-mono text-xs text-muted">{h.keyType}</td>
                <td className="pr-3 font-mono text-xs">{h.fingerprintSha256}</td>
                <td className="pr-3 text-xs text-muted">{fmtTime(h.firstSeenAt)}</td>
                <td className="pr-3 text-xs text-muted">{fmtTime(h.lastSeenAt)}</td>
                <td className="py-2 text-right">
                  <Button variant="danger" onClick={() => void remove(h)}>Remove</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Page>
  )
}
