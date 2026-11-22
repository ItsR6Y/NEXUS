import { useState, type ReactNode } from 'react'
import type { ApprovalPolicy } from '../../../shared/policy-types'
import type { ServerDraftInput } from '../../../shared/api'
import type { ConnectResult, ServerPrivateInfo } from '../../../shared/types'
import type { PageId } from '../App'
import { Button, Card, Empty, Field, Input, Modal, Page, StatusDot, inputCls } from '../components/ui'
import { SUBS, unwrap, useLive } from '../lib/live'

const load = (): ReturnType<typeof window.nexus.servers.list> => window.nexus.servers.list()
const loadSessions = (): ReturnType<typeof window.nexus.sessions.list> => window.nexus.sessions.list()

const blank: ServerDraftInput = {
  name: '',
  host: '',
  port: 22,
  username: '',
  authType: 'password',
  keyPath: null,
  approvalPolicy: 'ask',
  mcpAccessEnabled: false
}

export function Servers({ go }: { go: (p: PageId, session?: string) => void }): ReactNode {
  const servers = useLive(load, SUBS.servers)
  const sessions = useLive(loadSessions, SUBS.sessions)
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState<ServerPrivateInfo | 'new' | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [confirmDel, setConfirmDel] = useState<ServerPrivateInfo | null>(null)

  const connect = async (s: ServerPrivateInfo): Promise<void> => {
    setMsg(null)
    setBusyId(s.id)
    try {
      const r: ConnectResult = await unwrap(window.nexus.sessions.connect(s.id))
      if (r.status === 'connected') {
        go('terminal', r.session.id)
      } else if (r.status === 'host_key_mismatch') {
        setMsg(`HOST KEY MISMATCH for ${s.name} (${s.host}:${s.port}). Expected ${r.expectedFingerprint}, got ${r.actualFingerprint}. Remove the old key in Known Hosts only if expected.`)
      } else if (r.status === 'host_key_rejected') {
        setMsg(`Connection cancelled: ${r.reason} (${r.fingerprint}).`)
      } else if (r.status === 'needs_user_input') {
        setMsg(`${s.name}: ${r.reason}. Edit the server to configure credentials.`)
        setEditing(s)
      } else {
        setMsg(`Could not connect: ${r.message}`)
      }
    } catch (e) {
      setMsg((e as Error).message)
    } finally {
      setBusyId(null)
    }
  }

  const active = (id: string): number => sessions.data?.filter((x) => x.serverId === id && x.state === 'connected').length ?? 0
  const filtered = (servers.data ?? []).filter((s) => `${s.name} ${s.host} ${s.username}`.toLowerCase().includes(search.toLowerCase()))

  return (
    <Page
      title="Servers"
      subtitle="Strict SSH host-key verification via native OS dialogs. Secrets are write-only and stay in OS credential storage."
      actions={<Button variant="primary" data-testid="add-server" onClick={() => setEditing('new')}>+ Add server</Button>}
    >
      <div className="mb-4 max-w-sm">
        <Input aria-label="Search servers" placeholder="Filter servers by name, host, or user…" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      {msg && <p role="alert" data-testid="server-msg" className="mb-3 rounded-lg border border-warn/50 bg-warn/10 p-3 text-sm text-warn">{msg}</p>}
      {filtered.length === 0 && <Empty>No matching servers. Click "+ Add server" to configure an SSH target.</Empty>}
      <div className="grid gap-4 lg:grid-cols-2">
        {filtered.map((s) => (
          <Card key={s.id}>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-base font-semibold" data-testid="server-name">{s.name}</div>
                <div className="font-mono text-xs text-muted">{s.username}@{s.host}:{s.port}</div>
              </div>
              <StatusDot on={active(s.id) > 0} label={active(s.id) > 0 ? `${active(s.id)} connected` : 'offline'} />
            </div>
            <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted">
              <dt>Auth</dt>
              <dd className="truncate text-fg" title={s.keyPath ?? undefined}>
                {s.authType === 'password'
                  ? s.credentials.password ? 'password (stored)' : 'password — not set'
                  : s.keyPath ? `key: ${s.keyPath}${s.credentials.passphrase ? ' (+passphrase)' : ''}` : 'key path — not set'}
              </dd>
              <dt>Known host</dt>
              <dd className="truncate font-mono text-fg" title={s.knownHost?.fingerprintSha256}>
                {s.knownHost ? s.knownHost.fingerprintSha256 : 'not yet trusted'}
              </dd>
              <dt>Approval policy</dt>
              <dd className="font-mono text-fg">{s.approvalPolicy}</dd>
              <dt>Claude (MCP)</dt>
              <dd className="text-fg">{s.mcpAccessEnabled ? 'allowed (gated)' : 'blocked'}</dd>
            </dl>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button variant="primary" data-testid="connect" disabled={busyId === s.id} onClick={() => void connect(s)}>
                {busyId === s.id ? 'Connecting…' : 'Connect'}
              </Button>
              <Button onClick={() => setEditing(s)}>Edit</Button>
              <Button variant="danger" onClick={() => setConfirmDel(s)}>Delete</Button>
            </div>
          </Card>
        ))}
      </div>
      {editing && (
        <ServerForm
          server={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); servers.reload() }}
        />
      )}
      {confirmDel && (
        <Modal title={`Delete “${confirmDel.name}”?`} onClose={() => setConfirmDel(null)} tone="danger">
          <p className="text-sm text-muted">This removes the server, its stored credentials, and history. Active sessions are closed and approvals invalidated.</p>
          <p className="mt-2 text-sm text-muted">Trusted SSH host-key pins for this host and port are <strong>kept</strong> — remove them in Known Hosts if the server is being replaced.</p>
          <div className="mt-4 flex justify-end gap-2">
            <Button onClick={() => setConfirmDel(null)}>Cancel</Button>
            <Button variant="danger" onClick={() => void unwrap(window.nexus.servers.delete(confirmDel.id)).then(() => { setConfirmDel(null); servers.reload() })}>Delete</Button>
          </div>
        </Modal>
      )}
    </Page>
  )
}

function ServerForm({ server, onClose, onSaved }: { server: ServerPrivateInfo | null; onClose: () => void; onSaved: () => void }): ReactNode {
  const [f, setF] = useState<ServerDraftInput>(
    server
      ? {
          name: server.name,
          host: server.host,
          port: server.port,
          username: server.username,
          authType: server.authType,
          keyPath: server.keyPath,
          approvalPolicy: server.approvalPolicy,
          mcpAccessEnabled: server.mcpAccessEnabled
        }
      : blank
  )
  const [secret, setSecret] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const set = <K extends keyof ServerDraftInput>(k: K, v: ServerDraftInput[K]): void => setF((p) => ({ ...p, [k]: v }))

  const pickKey = async (): Promise<void> => {
    try {
      const path = await unwrap(window.nexus.servers.pickKeyPath())
      if (path) set('keyPath', path)
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  const save = async (): Promise<void> => {
    setBusy(true)
    setErr(null)
    try {
      const payload: ServerDraftInput = { ...f, keyPath: f.authType === 'key' ? (f.keyPath?.trim() || null) : null }
      const s = server ? await unwrap(window.nexus.servers.update(server.id, payload)) : await unwrap(window.nexus.servers.create(payload))
      if (secret) {
        await unwrap(window.nexus.servers.setSecret(s.id, f.authType === 'password' ? 'password' : 'passphrase', secret))
      }
      setSecret('')
      onSaved()
    } catch (e) {
      setErr((e as Error).message)
      setBusy(false)
    }
  }

  const wipe = (kind: 'password' | 'passphrase'): void => {
    if (server) void unwrap(window.nexus.servers.clearSecret(server.id, kind)).then(onSaved)
  }

  return (
    <Modal title={server ? `Edit ${server.name}` : 'Add server'} onClose={onClose}>
      <Field label="Name">{(id) => <Input id={id} data-testid="f-name" value={f.name} onChange={(e) => set('name', e.target.value)} />}</Field>
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2">
          <Field label="Host">{(id) => <Input id={id} data-testid="f-host" value={f.host} onChange={(e) => set('host', e.target.value)} placeholder="127.0.0.1 or prod.example.com" />}</Field>
        </div>
        <Field label="Port">{(id) => <Input id={id} data-testid="f-port" type="number" value={f.port} onChange={(e) => set('port', Number(e.target.value))} />}</Field>
      </div>
      <Field label="Username">{(id) => <Input id={id} data-testid="f-user" value={f.username} onChange={(e) => set('username', e.target.value)} autoComplete="off" />}</Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Authentication">
          {(id) => (
            <select id={id} className={inputCls} data-testid="f-auth" value={f.authType} onChange={(e) => set('authType', e.target.value as 'password' | 'key')}>
              <option value="password">Password</option>
              <option value="key">Private key (file path)</option>
            </select>
          )}
        </Field>
        <Field label="Approval policy">
          {(id) => (
            <select id={id} className={inputCls} data-testid="f-policy" value={f.approvalPolicy} onChange={(e) => set('approvalPolicy', e.target.value as ApprovalPolicy)}>
              <option value="ask">ask (MCP always asks)</option>
              <option value="always">always (every command asks)</option>
              <option value="sensitive">sensitive (LOW + MEDIUM auto, HIGH+ asks)</option>
            </select>
          )}
        </Field>
      </div>

      {f.authType === 'password' ? (
        <>
          <Field label={server?.credentials.password ? 'Replace password (leave blank to keep)' : 'Password'} hint="Write-only: stored in OS credential storage, never displayed again.">
            {(id) => <Input id={id} data-testid="f-secret" type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} />}
          </Field>
          {server?.credentials.password && <div className="mb-3"><Button variant="danger" onClick={() => wipe('password')}>Remove stored password</Button></div>}
        </>
      ) : (
        <>
          <Field label="Private key path on disk" hint="Private key contents stay on disk and are read only in Electron main at connect time.">
            {(id) => (
              <div className="flex gap-2">
                <Input id={id} data-testid="f-keypath" value={f.keyPath ?? ''} onChange={(e) => set('keyPath', e.target.value || null)} placeholder="C:\Users\you\.ssh\id_ed25519" />
                <Button onClick={() => void pickKey()}>Browse…</Button>
              </div>
            )}
          </Field>
          <Field label={server?.credentials.passphrase ? 'Replace key passphrase (optional)' : 'Key passphrase (optional)'}>
            {(id) => <Input id={id} type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} />}
          </Field>
          {server?.credentials.passphrase && <div className="mb-3"><Button variant="danger" onClick={() => wipe('passphrase')}>Remove stored passphrase</Button></div>}
        </>
      )}

      <label className="mb-1 flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-1" checked={f.mcpAccessEnabled} onChange={(e) => set('mcpAccessEnabled', e.target.checked)} data-testid="f-mcp" />
        <span>
          Allow Claude (MCP) to access this server
          <span className="block text-xs text-muted">MCP can never open/close sessions or bypass native approval dialogs. Off by default.</span>
        </span>
      </label>

      {err && <p role="alert" className="mt-2 text-sm text-bad">{err}</p>}
      <div className="mt-4 flex justify-end gap-2">
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" data-testid="f-save" disabled={busy || !f.name || !f.host || !f.username} onClick={() => void save()}>Save</Button>
      </div>
    </Modal>
  )
}
