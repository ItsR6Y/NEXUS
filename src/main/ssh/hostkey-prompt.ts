import { BrowserWindow, dialog } from 'electron'

export interface UnknownHostKeyInfo {
  serverName: string
  host: string
  port: number
  keyType: string
  fingerprintSha256: string
}

export interface HostKeyMismatchInfo {
  serverName: string
  host: string
  port: number
  keyType: string
  expectedFingerprint: string
  actualFingerprint: string
}

export interface HostKeyTypeMismatchInfo {
  serverName: string
  host: string
  port: number
  pinnedKeyType: string
  presentedKeyType: string
  pinnedFingerprint: string
  presentedFingerprint: string
}

export interface HostKeyPresenter {
  /** Unknown (first-use) key prompt. Must default to Reject (false). */
  presentUnknown(info: UnknownHostKeyInfo, signal?: AbortSignal): Promise<boolean>
  /**
   * The endpoint is already pinned, but the server presented a different key *type*.
   * Distinct from first use so a silent algorithm downgrade cannot look like a new host.
   * Must default to Reject (false).
   */
  presentTypeMismatch(info: HostKeyTypeMismatchInfo): Promise<boolean>
  /** Informational hard-block alert on host-key mismatch (no "continue anyway" button). */
  presentMismatch(info: HostKeyMismatchInfo): Promise<void>
  /** Native confirmation before removing a known host entry or clearing history. */
  confirmAction(title: string, message: string, detail: string, confirmLabel: string): Promise<boolean>
}

export class NativeHostKeyPresenter implements HostKeyPresenter {
  constructor(private readonly getParentWindow: () => BrowserWindow | null) {}

  async presentUnknown(info: UnknownHostKeyInfo, signal?: AbortSignal): Promise<boolean> {
    if (signal?.aborted) return false
    const parent = this.getParentWindow()
    if (!parent || parent.isDestroyed()) return false
    try {
      const res = await dialog.showMessageBox(parent, {
        type: 'warning',
        title: 'Unknown SSH Host Key',
        message: `Trust SSH host key for ${info.serverName} (${info.host}:${info.port})?`,
        detail: [
          `Host:        ${info.host}:${info.port}`,
          `Key type:    ${info.keyType}`,
          `Fingerprint: ${info.fingerprintSha256}`,
          '',
          'Verify this fingerprint out-of-band before trusting. Default is Reject.'
        ].join('\n'),
        buttons: ['Reject', 'Trust & Save Host Key'],
        defaultId: 0,
        cancelId: 0,
        noLink: true
      })
      return !signal?.aborted && res.response === 1
    } catch {
      return false
    }
  }

  async presentTypeMismatch(info: HostKeyTypeMismatchInfo): Promise<boolean> {
    const parent = this.getParentWindow()
    if (!parent || parent.isDestroyed()) return false
    try {
      const res = await dialog.showMessageBox(parent, {
        type: 'warning',
        title: 'SSH HOST KEY TYPE CHANGED',
        message: `A different host key type was offered for ${info.serverName} (${info.host}:${info.port})`,
        detail: [
          'This endpoint is already pinned with a different key type.',
          'This can be legitimate after a server reconfiguration, or an attempt to weaken',
          'the algorithm that is verified.',
          '',
          `Pinned:    ${info.pinnedKeyType}  ${info.pinnedFingerprint}`,
          `Presented: ${info.presentedKeyType}  ${info.presentedFingerprint}`,
          '',
          'The connection has been rejected. Default is Reject.'
        ].join('\n'),
        buttons: ['Reject', 'Trust This Key Type'],
        defaultId: 0,
        cancelId: 0,
        noLink: true
      })
      return res.response === 1
    } catch {
      return false
    }
  }

  async presentMismatch(info: HostKeyMismatchInfo): Promise<void> {
    const parent = this.getParentWindow()
    if (!parent || parent.isDestroyed()) return
    try {
      await dialog.showMessageBox(parent, {
        type: 'error',
        title: 'SSH HOST KEY CHANGED — CONNECTION BLOCKED',
        message: `Host key mismatch for ${info.serverName} (${info.host}:${info.port})`,
        detail: [
          'WARNING: The remote host key does NOT match the stored fingerprint.',
          'This may indicate a Man-in-the-Middle attack or a rebuilt server.',
          '',
          `Key type: ${info.keyType}`,
          `Expected: ${info.expectedFingerprint}`,
          `Received: ${info.actualFingerprint}`,
          '',
          'The connection has been rejected. If this change is expected, remove the stored key in Known Hosts and reconnect.'
        ].join('\n'),
        buttons: ['OK (Close)'],
        defaultId: 0,
        cancelId: 0,
        noLink: true
      })
    } catch {
      /* ignore dialog failure */
    }
  }

  async confirmAction(title: string, message: string, detail: string, confirmLabel: string): Promise<boolean> {
    const parent = this.getParentWindow()
    if (!parent || parent.isDestroyed()) return false
    try {
      const res = await dialog.showMessageBox(parent, {
        type: 'warning',
        title,
        message,
        detail,
        buttons: ['Cancel', confirmLabel],
        defaultId: 0,
        cancelId: 0,
        noLink: true
      })
      return res.response === 1
    } catch {
      return false
    }
  }
}
