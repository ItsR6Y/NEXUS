import { BrowserWindow, dialog } from 'electron'
import type { CommandSource } from '../../shared/types'
import type { RiskLevel } from '../../shared/policy-types'

export interface ApprovalPresentation {
  approvalId: string
  source: CommandSource
  requester: string
  serverName: string
  sessionTitle: string
  level: RiskLevel
  reasons: string[]
  flags: string[]
  /** Already redacted via redactText before reaching the presenter. */
  commandRedacted: string
  timeoutRemainingSec: number
}

export interface ApprovalPresenter {
  present(req: ApprovalPresentation, signal?: AbortSignal): Promise<'approve' | 'deny'>
}

const MAX_DISPLAY_CHARS = 800

function truncateCommand(cmd: string): string {
  if (cmd.length <= MAX_DISPLAY_CHARS) return cmd
  return cmd.slice(0, MAX_DISPLAY_CHARS) + '…(truncated)'
}

/**
 * Native OS dialog approval presenter running strictly inside the trusted Electron main process.
 * Default button and cancel button are ALWAYS Deny (button index 0).
 * A compromised renderer or MCP client cannot interact with or bypass this native dialog.
 */
export class NativeApprovalPresenter implements ApprovalPresenter {
  constructor(private readonly getParentWindow: () => BrowserWindow | null) {}

  async present(req: ApprovalPresentation, signal?: AbortSignal): Promise<'approve' | 'deny'> {
    if (signal?.aborted) return 'deny'
    const parent = this.getParentWindow()
    // Fail closed if no main window exists to display the native prompt.
    if (!parent || parent.isDestroyed()) return 'deny'

    const badge = req.source === 'claude' ? `Claude (MCP: ${req.requester})` : 'GUI Programmatic Command'
    const detailLines = [
      `Source:   ${badge}`,
      `Server:   ${req.serverName}`,
      `Session:  ${req.sessionTitle}`,
      `Risk:     ${req.level}`,
      `Expires:  ${req.timeoutRemainingSec}s`,
      '',
      'Command (redacted):',
      truncateCommand(req.commandRedacted),
      '',
      'Reasons:',
      ...req.reasons.map((r) => `• ${r}`)
    ]
    if (req.flags.length > 0) {
      detailLines.push('', `Flags: ${req.flags.join(', ')}`)
    }

    try {
      const first = await dialog.showMessageBox(parent, {
        type: req.level === 'DESTRUCTIVE' || req.level === 'CRITICAL' ? 'error' : 'warning',
        title: `NEXUS Approval Required [${req.level}]`,
        message: `Approve remote command on ${req.serverName}?`,
        detail: detailLines.join('\n'),
        buttons: ['Deny', 'Approve once'],
        defaultId: 0,
        cancelId: 0,
        noLink: true
      })

      if (signal?.aborted || first.response !== 1) return 'deny'

      // Authoritative requirement: DESTRUCTIVE commands require a second explicit confirmation dialog.
      if (req.level === 'DESTRUCTIVE') {
        const second = await dialog.showMessageBox(parent, {
          type: 'error',
          title: 'NEXUS DESTRUCTIVE Command Confirmation',
          message: `FINAL CONFIRMATION: Run DESTRUCTIVE command on ${req.serverName}?`,
          detail: `This command was classified as DESTRUCTIVE.\n\n${truncateCommand(req.commandRedacted)}\n\nClick "Confirm DESTRUCTIVE Execution" only if you are certain.`,
          buttons: ['Deny (Cancel)', 'Confirm DESTRUCTIVE Execution'],
          defaultId: 0,
          cancelId: 0,
          noLink: true
        })
        if (signal?.aborted || second.response !== 1) return 'deny'
      }

      return 'approve'
    } catch {
      return 'deny'
    }
  }
}
