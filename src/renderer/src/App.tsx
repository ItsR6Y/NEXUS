import {
  History as HistoryIcon, KeyRound, LayoutDashboard, Lock, Plug, ScrollText, Server,
  Settings as SettingsIcon, Shield, ShieldAlert, ShieldCheck, SquareTerminal
} from 'lucide-react'
import { lazy, Suspense, useCallback, useEffect, useState, type ReactNode } from 'react'
import { Modal } from './components/ui'
import { SUBS, useLive } from './lib/live'
import { TerminalPage } from './pages/Terminal'

// Route-level code splitting. The terminal stays eager because it is kept mounted
// across navigation so tabs and sessions survive page changes.
const Dashboard = lazy(() => import('./pages/Dashboard').then((m) => ({ default: m.Dashboard })))
const Servers = lazy(() => import('./pages/Servers').then((m) => ({ default: m.Servers })))
const Approvals = lazy(() => import('./pages/Approvals').then((m) => ({ default: m.Approvals })))
const KnownHosts = lazy(() => import('./pages/KnownHosts').then((m) => ({ default: m.KnownHosts })))
const History = lazy(() => import('./pages/History').then((m) => ({ default: m.History })))
const Security = lazy(() => import('./pages/Security').then((m) => ({ default: m.Security })))
const Audit = lazy(() => import('./pages/Audit').then((m) => ({ default: m.Audit })))
const McpPage = lazy(() => import('./pages/Mcp').then((m) => ({ default: m.McpPage })))
const SettingsPage = lazy(() => import('./pages/Settings').then((m) => ({ default: m.SettingsPage })))

export type PageId =
  | 'dashboard' | 'servers' | 'terminal' | 'approvals' | 'knownHosts'
  | 'history' | 'security' | 'audit' | 'mcp' | 'settings'

type NavItem = { id: PageId; label: string; icon: ReactNode }

const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: 'CORE',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
      { id: 'servers', label: 'Servers', icon: <Server size={16} /> },
      { id: 'terminal', label: 'Terminal', icon: <SquareTerminal size={16} /> }
    ]
  },
  {
    title: 'CONTROL & AUDIT',
    items: [
      { id: 'approvals', label: 'Approvals', icon: <ShieldCheck size={16} /> },
      { id: 'knownHosts', label: 'Known Hosts', icon: <KeyRound size={16} /> },
      { id: 'history', label: 'History', icon: <HistoryIcon size={16} /> },
      { id: 'audit', label: 'Audit log', icon: <ScrollText size={16} /> }
    ]
  },
  {
    title: 'CONFIGURATION',
    items: [
      { id: 'mcp', label: 'Claude / MCP', icon: <Plug size={16} /> },
      { id: 'security', label: 'Security', icon: <ShieldAlert size={16} /> },
      { id: 'settings', label: 'Settings', icon: <SettingsIcon size={16} /> }
    ]
  }
]

const ALL_NAV: NavItem[] = NAV_GROUPS.flatMap((g) => g.items)

const loadSettings = (): ReturnType<typeof window.nexus.settings.get> => window.nexus.settings.get()
const loadApprovals = (): ReturnType<typeof window.nexus.approvals.list> => window.nexus.approvals.list()
const loadDashboard = (): ReturnType<typeof window.nexus.dashboard.get> => window.nexus.dashboard.get()

export function App(): ReactNode {
  const [page, setPage] = useState<PageId>('dashboard')
  const [openSession, setOpenSession] = useState<string | null>(null)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const settings = useLive(loadSettings, SUBS.mcp)
  const approvals = useLive(loadApprovals, SUBS.approvals)
  const dash = useLive(loadDashboard, SUBS.dashboard)
  const pending = approvals.data?.filter((a) => a.status === 'pending').length ?? 0

  useEffect(() => {
    document.documentElement.dataset.theme = settings.data?.theme ?? 'nexus-dark'
  }, [settings.data?.theme])

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.ctrlKey && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteOpen((v) => !v) }
      else if (e.ctrlKey && e.key === ',') { e.preventDefault(); setPage('settings') }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const go = useCallback((p: PageId, session?: string) => {
    setPage(p)
    if (session) setOpenSession(session)
  }, [])

  const refreshAll = useCallback(() => {
    settings.reload()
    approvals.reload()
    dash.reload()
  }, [settings, approvals, dash])

  return (
    <div className="flex h-full flex-col">
      <div className="flex min-h-0 flex-1">
        <nav
          aria-label="Main"
          className="flex w-60 shrink-0 flex-col justify-between border-r border-line backdrop-blur-2xl"
          style={{ backgroundColor: 'var(--sidebar-bg)' }}
        >
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="flex items-center gap-2.5 border-b border-line px-4 py-4">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-accent/30 bg-accent/15 text-accent">
                <Shield size={15} />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[13px] font-semibold tracking-tight text-fg">NEXUS</span>
                  <span className="h-1.5 w-1.5 rounded-full bg-ok shadow-[0_0_8px_var(--ok)]" aria-hidden />
                </div>
                <div className="truncate font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-muted">
                  Hardened SSH · MCP
                </div>
              </div>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto px-2.5 py-3">
              {NAV_GROUPS.map((group) => (
                <div key={group.title}>
                  <div className="px-2.5 pb-1 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-muted/80">
                    {group.title}
                  </div>
                  <ul className="space-y-0.5">
                    {group.items.map((n) => {
                      const active = page === n.id
                      return (
                        <li key={n.id}>
                          <button
                            type="button"
                            data-testid={`nav-${n.id}`}
                            aria-current={active ? 'page' : undefined}
                            onClick={() => setPage(n.id)}
                            style={active ? { backgroundColor: 'var(--accent-pill)' } : undefined}
                            className={`flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-[13px] font-medium transition-colors ${
                              active
                                ? 'text-white shadow-sm'
                                : 'text-muted hover:bg-white/[0.06] hover:text-fg'
                            }`}
                          >
                            <span aria-hidden className="flex w-4 justify-center">{n.icon}</span>
                            <span className="flex-1 truncate">{n.label}</span>
                            {n.id === 'approvals' && pending > 0 && (
                              <span
                                className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${
                                  active ? 'bg-white/20 text-white' : 'bg-crit text-white'
                                }`}
                                aria-label={`${pending} pending approvals`}
                              >
                                {pending}
                              </span>
                            )}
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-2 border-t border-line bg-black/20 p-3">
            <div className="flex items-center justify-between rounded-lg border border-line bg-panel px-2.5 py-1.5">
              <div className="flex min-w-0 items-center gap-2">
                <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-ok shadow-[0_0_6px_var(--ok)]" aria-hidden />
                <div className="min-w-0">
                  <div className="truncate font-mono text-[10px] font-semibold uppercase tracking-wider text-ok">
                    Enclave Secure
                  </div>
                  <div className="truncate font-mono text-[10px] text-muted">nexus-app://</div>
                </div>
              </div>
              <Lock size={13} className="shrink-0 text-ok" aria-hidden />
            </div>
            <div className="flex items-center justify-between px-1 text-[10px] text-muted">
              <span className="font-mono uppercase tracking-wider opacity-80" data-testid="developer-mark">
                NEXUS · by Ray
              </span>
              <kbd className="rounded border border-line bg-panel2 px-1.5 py-0.5 font-mono text-[9px] text-muted">
                Ctrl+K
              </kbd>
            </div>
          </div>
        </nav>

        <main className="min-w-0 flex-1 bg-bg" id="main">
          <Suspense fallback={<div className="p-6 text-sm text-muted">Loading…</div>}>
            {page === 'dashboard' && <Dashboard go={go} />}
            {page === 'servers' && <Servers go={go} />}
            {page === 'approvals' && <Approvals />}
            {page === 'knownHosts' && <KnownHosts />}
            {page === 'history' && <History />}
            {page === 'security' && <Security />}
            {page === 'audit' && <Audit />}
            {page === 'mcp' && <McpPage />}
            {page === 'settings' && <SettingsPage onChanged={refreshAll} />}
          </Suspense>
          <div className={page === 'terminal' ? 'h-full' : 'hidden'}>
            <TerminalPage active={page === 'terminal'} focusSession={openSession} go={go} />
          </div>
        </main>
      </div>

      <footer
        className="flex h-7 items-center gap-4 border-t border-line px-4 font-mono text-[11px] text-muted backdrop-blur-xl"
        style={{ backgroundColor: 'var(--footer-bg)' }}
        aria-live="polite"
      >
        <span>Sessions: <b className="text-fg">{dash.data?.activeSessions ?? 0}</b></span>
        <span>Pending approvals: <b className={pending > 0 ? 'text-crit' : 'text-fg'}>{pending}</b></span>
        <span>MCP bridge: <b className={dash.data?.mcpListening ? 'text-ok' : 'text-muted'}>{dash.data?.mcpListening ? 'listening' : 'off'}</b></span>
        <span>Claude: <b className={dash.data?.mcpClients ? 'text-ok' : 'text-muted'} data-testid="claude-status">{dash.data?.mcpClients ? `connected (${dash.data.mcpClients})` : 'not connected'}</b></span>
        <span className="ml-auto opacity-80">Origin: nexus-app:// · Native OS Dialog Authority</span>
      </footer>

      {paletteOpen && (
        <Modal title="Quick navigation (Ctrl+K)" onClose={() => setPaletteOpen(false)}>
          <div className="grid grid-cols-2 gap-2">
            {ALL_NAV.map((n) => (
              <button
                key={n.id}
                type="button"
                onClick={() => { setPage(n.id); setPaletteOpen(false) }}
                className="flex items-center gap-2.5 rounded-lg border border-line bg-panel px-3 py-2 text-left text-[13px] font-medium text-fg transition-colors hover:border-accent hover:bg-[var(--panel3)]"
              >
                <span className="text-accent">{n.icon}</span>
                <span>{n.label}</span>
              </button>
            ))}
          </div>
        </Modal>
      )}
    </div>
  )
}