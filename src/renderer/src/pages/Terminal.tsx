import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { Terminal } from '@xterm/xterm'
import { Play, Square, Terminal as TerminalIcon } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import type { ExecutionResult, SessionDTO } from '../../../shared/types'
import type { PageId } from '../App'
import { Button, Empty, Input, Mono } from '../components/ui'
import { SUBS, unwrap, useLive } from '../lib/live'

const loadSessions = (): ReturnType<typeof window.nexus.sessions.list> => window.nexus.sessions.list()
const loadSettings = (): ReturnType<typeof window.nexus.settings.get> => window.nexus.settings.get()
const THEME = { background: '#0b0e14', foreground: '#d7dce6', cursor: '#6aa8ff', selectionBackground: '#264369' }

function TerminalView({ session, active }: { session: SessionDTO; active: boolean }): ReactNode {
  const host = useRef<HTMLDivElement>(null)
  const term = useRef<Terminal | null>(null)
  const fit = useRef<FitAddon | null>(null)
  const search = useRef<SearchAddon | null>(null)
  const settings = useLive(loadSettings)
  const [find, setFind] = useState(false)
  const [closed, setClosed] = useState<string | null>(null)
  const sid = session.id

  useEffect(() => {
    const t = new Terminal({
      fontFamily: '"JetBrains Mono Variable", Consolas, monospace',
      fontSize: 13,
      scrollback: 10000,
      cursorBlink: true,
      theme: THEME,
      allowProposedApi: false,
      convertEol: false
    })
    const f = new FitAddon()
    const s = new SearchAddon()
    t.loadAddon(f)
    t.loadAddon(s)
    t.open(host.current!)
    term.current = t
    fit.current = f
    search.current = s

    t.attachCustomKeyEventHandler((e) => {
      if (e.type === 'keydown' && e.ctrlKey && e.key.toLowerCase() === 'f') { setFind((v) => !v); return false }
      if (e.type === 'keydown' && e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'v') {
        void navigator.clipboard.readText().then((x) => {
          if (x.includes('\n') && !window.confirm(`Paste ${x.split('\n').length} lines into terminal?`)) return
          t.paste(x)
        })
        return false
      }
      if (e.type === 'keydown' && e.ctrlKey && (e.key === 'Tab' || (e.shiftKey && e.key.toLowerCase() === 'w'))) return false
      if (e.type === 'keydown' && e.ctrlKey && (e.shiftKey || t.hasSelection()) && e.key.toLowerCase() === 'c' && t.hasSelection()) {
        void navigator.clipboard.writeText(t.getSelection())
        return false
      }
      return true
    })

    let ready = false
    let queued = ''
    const d = t.onData((data) => {
      if (!ready) { queued += data; return }
      void window.nexus.terminal.input(sid, data)
    })
    const r = t.onResize(({ cols, rows }) => { void window.nexus.terminal.resize(sid, cols, rows) })
    const offData = window.nexus.on.terminalData((e) => { if (e.sessionId === sid) t.write(e.data) })
    const offClosed = window.nexus.on.terminalClosed((e) => { if (e.sessionId === sid) setClosed(e.reason) })
    f.fit()
    void window.nexus.terminal.open(sid, t.cols, t.rows).then(() => {
      ready = true
      if (queued) { void window.nexus.terminal.input(sid, queued); queued = '' }
    })

    let roTimer: number | null = null
    const ro = new ResizeObserver(() => {
      if (roTimer) window.clearTimeout(roTimer)
      roTimer = window.setTimeout(() => { try { f.fit() } catch { /* hidden */ } }, 40)
    })
    ro.observe(host.current!)
    return () => {
      if (roTimer) window.clearTimeout(roTimer)
      ro.disconnect(); offData(); offClosed(); d.dispose(); r.dispose(); t.dispose()
    }
  }, [sid])

  useEffect(() => {
    const t = term.current
    const st = settings.data
    if (t && st) {
      t.options.fontSize = st.fontSize
      t.options.scrollback = st.scrollback
      t.options.cursorBlink = st.cursorBlink
      try { fit.current?.fit() } catch { /* ignore */ }
    }
  }, [settings.data])

  useEffect(() => {
    if (active) {
      try { fit.current?.fit() } catch { /* ignore */ }
      term.current?.focus()
    }
  }, [active])

  return (
    <div className={`relative h-full flex-col ${active ? 'flex' : 'hidden'}`}>
      <div ref={host} data-testid="xterm-host" className="min-h-0 flex-1" style={{ background: 'var(--term-bg)' }} />
      {find && (
        <div className="absolute right-4 top-2 flex gap-1 rounded-lg border border-line bg-panel p-1.5">
          <input
            aria-label="Search terminal"
            autoFocus
            className="w-48 rounded border border-line bg-bg px-2 py-1 text-sm"
            onChange={(e) => search.current?.findNext(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') search.current?.findNext((e.target as HTMLInputElement).value)
              if (e.key === 'Escape') { setFind(false); term.current?.focus() }
            }}
          />
          <Button onClick={() => { setFind(false); term.current?.focus() }} aria-label="Close search">✕</Button>
        </div>
      )}
      {closed && (
        <div role="status" className="absolute inset-x-0 top-0 border-b border-warn bg-warn/10 px-4 py-2 text-sm text-warn">
          Session ended ({closed}). Open a fresh session from the Servers page.
        </div>
      )}
    </div>
  )
}

export function TerminalPage({ active, focusSession, go }: { active: boolean; focusSession: string | null; go: (p: PageId) => void }): ReactNode {
  const sessions = useLive(loadSessions, SUBS.sessions)
  const [current, setCurrent] = useState<string | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(true)
  const [cmd, setCmd] = useState('')
  const [running, setRunning] = useState(false)
  const [activeCmdId, setActiveCmdId] = useState<string | null>(null)
  const [result, setResult] = useState<ExecutionResult | null>(null)
  const [runErr, setRunErr] = useState<string | null>(null)

  const live = useMemo(() => sessions.data?.filter((s) => s.state === 'connected') ?? [], [sessions.data])
  const sel = current && live.some((s) => s.id === current) ? current : focusSession && live.some((s) => s.id === focusSession) ? focusSession : (live[0]?.id ?? null)
  const selSession = live.find((s) => s.id === sel) ?? null

  const closeTab = useCallback((id: string): void => {
    void unwrap(window.nexus.sessions.disconnect(id))
    setCurrent(null)
  }, [])

  useEffect(() => {
    if (!active) return
    const h = (e: KeyboardEvent): void => {
      if (e.ctrlKey && e.key.toLowerCase() === 'j') { e.preventDefault(); setDrawerOpen((v) => !v); return }
      if (live.length === 0) return
      const idx = live.findIndex((x) => x.id === sel)
      if (e.ctrlKey && e.key === 'Tab') { e.preventDefault(); setCurrent(live[(idx + (e.shiftKey ? live.length - 1 : 1)) % live.length].id) }
      else if (e.altKey && /^[1-9]$/.test(e.key) && live[Number(e.key) - 1]) { e.preventDefault(); setCurrent(live[Number(e.key) - 1].id) }
      else if (e.ctrlKey && e.key.toLowerCase() === 'w' && sel) { e.preventDefault(); closeTab(sel) }
    }
    window.addEventListener('keydown', h, true)
    return () => window.removeEventListener('keydown', h, true)
  }, [active, live, sel, closeTab])

  const runProgrammatic = async (): Promise<void> => {
    if (!selSession || !cmd.trim() || running) return
    // Generate the id up front so Cancel is available while the command is still in flight.
    const commandId = crypto.randomUUID()
    setRunning(true)
    setActiveCmdId(commandId)
    setRunErr(null)
    setResult(null)
    try {
      const res = await unwrap(window.nexus.commands.execute({
        serverId: selSession.serverId,
        sessionId: selSession.id,
        command: cmd.trim(),
        clientCommandId: commandId
      }))
      setResult(res)
    } catch (e) {
      setRunErr((e as Error).message)
    } finally {
      setRunning(false)
      setActiveCmdId(null)
    }
  }

  const cancelRunning = async (): Promise<void> => {
    if (activeCmdId) await window.nexus.commands.cancel(activeCmdId)
  }

  if (live.length === 0) {
    return (
      <div className="p-6">
        <Empty>
          No connected SSH sessions. Connect to a server from the{' '}
          <button className="text-accent underline" onClick={() => go('servers')}>Servers</button> page.
        </Empty>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div role="tablist" aria-label="Terminal sessions" className="flex items-center gap-1 border-b border-line bg-panel px-2 pt-2">
        {live.map((s) => (
          <div key={s.id} role="tab" aria-selected={sel === s.id} className={`flex items-center gap-2 rounded-t-lg border border-b-0 px-3 py-1.5 text-sm ${sel === s.id ? 'border-line bg-bg text-fg' : 'border-transparent text-muted'}`}>
            <span aria-hidden className="h-2 w-2 rounded-full bg-ok" title={`connected · epoch ${s.epoch}`} />
            <button type="button" onClick={() => setCurrent(s.id)} data-testid="term-tab">{s.title}</button>
            <button type="button" aria-label={`Close ${s.title}`} onClick={() => closeTab(s.id)} className="text-muted hover:text-bad">✕</button>
          </div>
        ))}
        <div className="ml-auto mb-1 flex items-center gap-2 pr-2">
          <Button variant="ghost" onClick={() => setDrawerOpen((v) => !v)} title="Toggle gated command bar (Ctrl+J)">
            <span className="inline-flex items-center gap-1.5 text-xs"><TerminalIcon size={13} /> Run Command (Ctrl+J)</span>
          </Button>
          <span className="text-xs text-muted">Ctrl+F search · Ctrl+Tab tabs</span>
        </div>
      </div>

      <div className="min-h-0 flex-1">
        {live.map((s) => <TerminalView key={s.id} session={s} active={active && sel === s.id} />)}
      </div>

      {drawerOpen && selSession && (
        <div className="border-t border-line bg-panel p-3" data-testid="run-command-drawer">
          <div className="flex items-center gap-2">
            <Input
              aria-label="Run gated command"
              data-testid="run-cmd-input"
              placeholder={`Run programmatic command on ${selSession.serverName} (routed through CommandAuthorizer + native approval)…`}
              value={cmd}
              onChange={(e) => setCmd(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void runProgrammatic() }}
            />
            <Button variant="primary" data-testid="run-cmd-btn" disabled={running || !cmd.trim()} onClick={() => void runProgrammatic()}>
              <span className="inline-flex items-center gap-1"><Play size={13} /> {running ? 'Running…' : 'Run'}</span>
            </Button>
            {running && activeCmdId && (
              <Button variant="danger" onClick={() => void cancelRunning()}>
                <span className="inline-flex items-center gap-1"><Square size={13} /> Cancel</span>
              </Button>
            )}
          </div>
          {runErr && <p role="alert" className="mt-2 text-xs text-bad">{runErr}</p>}
          {result && (
            <div className="mt-2">
              <div className="mb-1 text-xs text-muted">
                Status: <b className={result.status === 'completed' ? 'text-ok' : result.status === 'denied' ? 'text-crit' : 'text-warn'}>{result.status}</b>
                {'exitCode' in result && result.exitCode !== null ? ` · exit ${result.exitCode}` : ''}
                {'reason' in result ? ` · ${result.reason}` : ''}
                {'truncated' in result && result.truncated ? ' · truncated' : ''}
              </div>
              {'stdout' in result && (result.stdout || result.stderr) && (
                <Mono className="max-h-36 text-xs">{[result.stdout, result.stderr].filter(Boolean).join('\n')}</Mono>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
