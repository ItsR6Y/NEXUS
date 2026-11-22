import { app, BrowserWindow, dialog, ipcMain, safeStorage, shell } from 'electron'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { createDefaultCredentialStore, type SecretCipher } from './core/credentials/credential-store'
import { openDatabase } from './core/db/database'
import { CredentialRefRepo } from './core/db/repositories'
import { registerIpc, wireEvents, type IpcMainLike } from './ipc/registry'
import { resolveAppPaths } from './paths'
import { installAppProtocol, registerAppScheme } from './protocol'
import { NativeApprovalPresenter } from './security/approvals-ui'
import { Services } from './services'
import { resolveE2EPlaintext } from './security/e2e-mode'
import { NativeHostKeyPresenter } from './ssh/hostkey-prompt'
import { createMainWindow, hardenWebContents, installSessionSecurity, rendererTarget } from './window'

app.setName('NEXUS')

// Register custom privileged scheme `nexus-app://` BEFORE app.whenReady().
registerAppScheme()

// Test-only affordance for headless CI without OS keyring: never active in packaged builds and
// requires `--e2e`, NEXUS_E2E=1 and an explicit userData directory (NEXUS-018).
const e2ePlainText = resolveE2EPlaintext({ isPackaged: app.isPackaged, argv: process.argv, env: process.env })
if (e2ePlainText && process.platform === 'linux') app.commandLine.appendSwitch('password-store', 'basic')
if (!app.isPackaged && process.env['NEXUS_E2E_USERDATA']) app.setPath('userData', process.env['NEXUS_E2E_USERDATA'])

const cipher: SecretCipher = {
  isAvailable: () => safeStorage.isEncryptionAvailable(),
  encrypt: (p) => safeStorage.encryptString(p),
  decrypt: (b) => safeStorage.decryptString(b)
}

if (!app.requestSingleInstanceLock()) {
  app.quit()
} else {
  let win: BrowserWindow | null = null
  let services: Services | null = null

  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore()
      win.focus()
    }
  })

  // Deny all TLS certificate errors unconditionally.
  app.on('certificate-error', (event, _webContents, _url, _error, _certificate, callback) => {
    event.preventDefault()
    callback(false)
  })

  app.on('web-contents-created', (_e, wc) => {
    const target = rendererTarget()
    hardenWebContents(wc, target.trustedOrigin)
  })

  void app.whenReady().then(async () => {
    if (e2ePlainText) safeStorage.setUsePlainTextEncryption(true)
    const userData = app.getPath('userData')
    const paths = resolveAppPaths(userData)
    mkdirSync(paths.userData, { recursive: true })
    mkdirSync(paths.logsDir, { recursive: true })

    const target = rendererTarget()
    if (!target.dev) {
      installAppProtocol(join(__dirname, '../renderer'))
    }
    installSessionSecurity(target.dev)

    const db = openDatabase(paths.dbFile)
    const credentialStore = await createDefaultCredentialStore(new CredentialRefRepo(db), cipher, !e2ePlainText)

    const mcpServerPath = app.isPackaged
      ? join(process.resourcesPath, 'mcp', 'nexus-mcp.mjs')
      : join(app.getAppPath(), 'out', 'mcp', 'nexus-mcp.mjs')

    const approvalPresenter = new NativeApprovalPresenter(() => win)
    const hostKeyPresenter = new NativeHostKeyPresenter(() => win)

    services = new Services({
      db,
      credentialStore,
      approvalPresenter,
      hostKeyPresenter,
      userDataDir: paths.userData,
      mcpServerPath
    })
    await services.init()
    if (e2ePlainText) {
      services.logger.warn('credential_backend_plaintext', { userData: paths.userData })
      services.audit.securityEvent('credential_backend_plaintext', 'warning', { userData: paths.userData })
    }

    const send = (event: string, payload: unknown): void => {
      if (win && !win.isDestroyed()) win.webContents.send(event, payload)
    }
    wireEvents(services, send)

    registerIpc(ipcMain as unknown as IpcMainLike, {
      services,
      trustedOrigin: target.trustedOrigin,
      getExpectedWebContentsId: () => (win && !win.isDestroyed() ? win.webContents.id : null),
      send,
      appInfo: { version: app.getVersion(), platform: process.platform },
      pickKeyPath: async () => {
        if (!win || win.isDestroyed()) return null
        const r = await dialog.showOpenDialog(win, {
          title: 'Select SSH Private Key File',
          properties: ['openFile'],
          filters: [{ name: 'SSH Keys', extensions: ['*'] }]
        })
        // Return ONLY the path on disk; private key contents are NEVER sent across IPC.
        return r.canceled || !r.filePaths[0] ? null : r.filePaths[0]
      },
      openLogsFolder: async () => {
        await shell.openPath(paths.logsDir)
      },
      confirmClearHistory: () =>
        hostKeyPresenter.confirmAction(
          'Clear Command History',
          'Clear all recorded command history?',
          'This removes command execution history from the local database. The append-only audit log is not affected.',
          'Clear History'
        )
    })

    win = createMainWindow(target)
    win.on('closed', () => { win = null })
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        win = createMainWindow(target)
        win.on('closed', () => { win = null })
      }
    })
  })

  let quitting = false
  app.on('before-quit', (e) => {
    if (quitting || !services) return
    e.preventDefault()
    quitting = true
    void services.shutdown().finally(() => app.quit())
  })
  app.on('window-all-closed', () => { app.quit() })
}
