import { useEffect, useId, useRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from 'react'
import type { RiskLevel } from '../../../shared/policy-types'

const LEVEL: Record<RiskLevel, string> = {
  LOW: 'text-ok border-ok/25 bg-ok/10',
  MEDIUM: 'text-warn border-warn/25 bg-warn/10',
  HIGH: 'text-bad border-bad/30 bg-bad/10',
  CRITICAL: 'text-[#ec4899] border-[#ec4899]/30 bg-[#ec4899]/10',
  DESTRUCTIVE: 'text-crit border-crit/40 bg-crit/15 font-bold'
}
const ICON: Record<RiskLevel, string> = { LOW: '●', MEDIUM: '▲', HIGH: '◆', CRITICAL: '⬣', DESTRUCTIVE: '✖' }

export function LevelBadge({ level }: { level: RiskLevel }): ReactNode {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] ${LEVEL[level]}`}
      data-testid={`level-${level}`}
    >
      <span aria-hidden>{ICON[level]}</span>
      {level}
    </span>
  )
}

export function Button({
  variant = 'default',
  className = '',
  ...p
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'default' | 'primary' | 'danger' | 'ghost' }): ReactNode {
  const v = {
    default: 'bg-panel2 border-line text-fg hover:border-white/20 hover:bg-[var(--panel3)]',
    primary: 'bg-accent text-accentfg border-accent hover:brightness-110 shadow-[inset_0_1px_0_rgba(255,255,255,0.2)]',
    danger: 'bg-crit/15 text-crit border-crit/35 hover:bg-crit/25',
    ghost: 'border-transparent text-muted hover:bg-panel2 hover:text-fg'
  }[variant]
  return (
    <button
      type="button"
      {...p}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-1.5 text-[13px] font-medium transition-all duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40 ${v} ${className}`}
    />
  )
}

export function Card({ title, actions, children, className = '' }: { title?: string; actions?: ReactNode; children: ReactNode; className?: string }): ReactNode {
  return (
    <section className={`obsidian-card rounded-xl p-4 ${className}`}>
      {(title || actions) && (
        <header className="mb-3 flex items-center justify-between gap-2 border-b border-line pb-2.5">
          <h2 className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-muted">{title}</h2>
          <div className="flex gap-2">{actions}</div>
        </header>
      )}
      {children}
    </section>
  )
}

export function Field({ label, children, hint }: { label: string; children: (id: string) => ReactNode; hint?: string }): ReactNode {
  const id = useId()
  return (
    <div className="mb-3.5">
      <label htmlFor={id} className="mb-1.5 block text-xs font-medium text-fg/90">{label}</label>
      {children(id)}
      {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
    </div>
  )
}

export const inputCls =
  'w-full rounded-lg border border-line bg-[var(--lowest)] px-3 py-2 font-mono text-[12px] text-fg placeholder:text-muted/60 shadow-inner transition-colors focus:border-accent focus:ring-1 focus:ring-accent'

export function Input(p: InputHTMLAttributes<HTMLInputElement>): ReactNode {
  return <input {...p} className={`${inputCls} ${p.className ?? ''}`} />
}

export function Page({ title, subtitle, actions, children }: { title: string; subtitle?: string; actions?: ReactNode; children: ReactNode }): ReactNode {
  return (
    <div className="flex h-full flex-col">
      <header className="flex items-end justify-between gap-4 border-b border-line bg-[var(--bg)]/80 px-6 py-4 backdrop-blur-xl">
        <div>
          <h1 className="text-[22px] font-semibold leading-7 tracking-[-0.015em] text-fg">{title}</h1>
          {subtitle && <p className="mt-0.5 text-[13px] text-muted">{subtitle}</p>}
        </div>
        <div className="flex items-center gap-2">{actions}</div>
      </header>
      <div className="min-h-0 flex-1 overflow-auto p-6">{children}</div>
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }): ReactNode {
  return <div className="obsidian-card rounded-xl border-dashed p-8 text-center text-muted">{children}</div>
}

export function Modal({ title, onClose, children, wide, tone }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean; tone?: 'danger' }): ReactNode {
  const ref = useRef<HTMLDivElement>(null)
  const tid = useId()
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null
    ref.current?.querySelector<HTMLElement>('input,textarea,select,button')?.focus()
    const h = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') { onClose(); return }
      if (e.key !== 'Tab' || !ref.current) return
      const items = [...ref.current.querySelectorAll<HTMLElement>(
        'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'
      )]
      if (items.length === 0) { e.preventDefault(); return }
      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement
      if (e.shiftKey && (active === first || !ref.current.contains(active))) { e.preventDefault(); last.focus() }
      else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus() }
    }
    window.addEventListener('keydown', h)
    return () => { window.removeEventListener('keydown', h); prev?.focus() }
  }, [onClose])
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#0a0e16]/80 p-4 backdrop-blur-md"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={tid}
        className={`obsidian-modal max-h-[90vh] w-full overflow-auto rounded-2xl p-5 ${wide ? 'max-w-3xl' : 'max-w-lg'} ${tone === 'danger' ? 'border-crit/70' : ''}`}
      >
        <h2 id={tid} className="mb-3.5 text-base font-semibold tracking-tight text-fg">{title}</h2>
        {children}
      </div>
    </div>
  )
}

export function Mono({ children, className = '' }: { children: ReactNode; className?: string }): ReactNode {
  return (
    <pre className={`overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-[var(--lowest)] p-3 font-mono text-[12px] leading-relaxed text-fg/95 ${className}`}>
      {children}
    </pre>
  )
}

export function StatusDot({ on, label }: { on: boolean; label: string }): ReactNode {
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[11px]">
      <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${on ? 'bg-ok shadow-[0_0_6px_var(--ok)]' : 'bg-muted/60'}`} />
      {label}
    </span>
  )
}