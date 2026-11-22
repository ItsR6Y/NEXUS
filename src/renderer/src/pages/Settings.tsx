import { useState, type ReactNode } from 'react'
import type { Settings } from '../../../shared/ipc'
import { Button, Card, Field, Input, Page, inputCls } from '../components/ui'
import { unwrap, useLive } from '../lib/live'

const load = (): ReturnType<typeof window.nexus.settings.get> => window.nexus.settings.get()
const info = (): ReturnType<typeof window.nexus.app.info> => window.nexus.app.info()

export function SettingsPage({ onChanged }: { onChanged: () => void }): ReactNode {
  const { data: s, reload } = useLive(load)
  const app = useLive(info)
  const [err, setErr] = useState<string | null>(null)

  const save = async (patch: Partial<Settings>): Promise<void> => {
    try {
      await unwrap(window.nexus.settings.set(patch))
      setErr(null)
      reload()
      onChanged()
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  const num = (k: keyof Settings, label: string, min: number, max: number, hint?: string): ReactNode => (
    <Field label={label} hint={hint}>
      {(id) => (
        <Input
          id={id}
          type="number"
          min={min}
          max={max}
          defaultValue={s?.[k] as number}
          onBlur={(e) => {
            const v = Number(e.target.value)
            if (v >= min && v <= max && v !== s?.[k]) void save({ [k]: v } as Partial<Settings>)
          }}
        />
      )}
    </Field>
  )

  const check = (k: keyof Settings, label: string, hint: string): ReactNode => (
    <label className="mb-3 flex items-start gap-2 text-sm">
      <input type="checkbox" className="mt-1" checked={!!s?.[k]} onChange={(e) => void save({ [k]: e.target.checked } as Partial<Settings>)} />
      <span>{label}<span className="block text-xs text-muted">{hint}</span></span>
    </label>
  )

  return (
    <Page title="Settings" actions={<Button onClick={() => void window.nexus.app.openLogsFolder()}>Open logs folder</Button>}>
      {err && <p role="alert" className="mb-3 text-bad">{err}</p>}
      {s && (
        <div className="grid max-w-4xl gap-4 lg:grid-cols-2">
          <Card title="Authorization & Retention">
            {check(
              'mcpAutoRunLow',
              'Allow Claude (MCP) to auto-run strict LOW read-only commands on "sensitive" servers',
              'Default OFF. Even when enabled, only 9 single-segment read-only commands (pwd, whoami, id, uname, uptime, date, hostname, ls, df) on "sensitive" servers auto-run; composed commands always ask.'
            )}
            {num('approvalTtlSeconds', 'Approval timeout (seconds)', 15, 480, 'Capped below the 10-minute MCP idle timeout. CRITICAL (≤90s) and DESTRUCTIVE (≤60s) expire sooner.')}
            {num('defaultExecTimeoutMs', 'Default command timeout (ms)', 1000, 600000)}
            {num('defaultMaxOutputBytes', 'Default max output bytes', 4096, 4194304)}
            {num('terminalTailBytes', 'Terminal tail ring-buffer bytes', 16384, 1048576)}
            {num('historyRetentionDays', 'History retention (days)', 1, 365)}
          </Card>
          <Card title="Terminal & Appearance">
            {num('fontSize', 'Font size (px)', 10, 24)}
            {num('scrollback', 'Scrollback lines', 500, 100000)}
            {check('cursorBlink', 'Blinking cursor', 'Respects prefers-reduced-motion.')}
            <Field label="Theme">
              {(id) => (
                <select id={id} className={inputCls} value={s.theme} onChange={(e) => void save({ theme: e.target.value as Settings['theme'] })}>
                  <option value="nexus-dark">Nexus Dark</option>
                  <option value="midnight">Midnight</option>
                  <option value="matrix">Matrix</option>
                </select>
              )}
            </Field>
          </Card>
          <Card title="System & Storage" className="lg:col-span-2">
            <dl className="grid grid-cols-2 gap-1 text-sm">
              <dt className="text-muted">Version</dt><dd>{app.data?.version}</dd>
              <dt className="text-muted">Platform</dt><dd>{app.data?.platform}</dd>
              <dt className="text-muted">Database</dt><dd>Built-in node:sqlite (WAL + FK)</dd>
              <dt className="text-muted">Credential backend</dt><dd>{app.data?.credentialBackend} ({app.data?.credentialsAvailable ? 'available' : 'UNAVAILABLE'})</dd>
            </dl>
          </Card>
        </div>
      )}
    </Page>
  )
}
