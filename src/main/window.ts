import { BrowserWindow, app, session, type WebContents, type WebPreferences } from 'electron'
import { join } from 'node:path'
import { buildCsp } from './csp'
import { APP_ORIGIN, isTrustedRendererUrl } from './protocol'

export interface RendererTarget {
  url: string
  trustedOrigin: string
  dev: boolean
}

/** Pure helper exported so unit tests assert every required BrowserWindow security flag. */
export function buildWebPreferences(preloadPath: string): WebPreferences {
  return {
    preload: preloadPath,
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    webSecurity: true,
    allowRunningInsecureContent: false,
    webviewTag: false,
    experimentalFeatures: false,
    spellcheck: false
  }
}

export function rendererTarget(devUrl = process.env['ELECTRON_RENDERER_URL'], isPackaged = app.isPackaged): RendererTarget {
  if (!isPackaged && devUrl) {
    const origin = new URL(devUrl).origin
    return { url: devUrl, trustedOrigin: origin, dev: true }
  }
  return { url: `${APP_ORIGIN}/index.html`, trustedOrigin: APP_ORIGIN, dev: false }
}

export function isAllowedOrigin(url: string, trustedOrigin: string): boolean {
  return isTrustedRendererUrl(url, trustedOrigin)
}

/** Lock down a WebContents: no external navigation, no redirects, no new windows, no webviews. */
export function hardenWebContents(wc: WebContents, allowedOrigin: string): void {
  wc.setWindowOpenHandler(() => ({ action: 'deny' }))
  wc.on('will-navigate', (e, url) => {
    if (!isAllowedOrigin(url, allowedOrigin)) e.preventDefault()
  })
  wc.on('will-redirect', (e, url) => {
    if (!isAllowedOrigin(url, allowedOrigin)) e.preventDefault()
  })
  wc.on('will-attach-webview', (e) => e.preventDefault())
}

export function installSessionSecurity(dev: boolean): void {
  const ses = session.defaultSession
  const csp = buildCsp(dev)
  ses.webRequest.onHeadersReceived((details, cb) => {
    const headers = { ...(details.responseHeaders ?? {}) }
    delete headers['content-security-policy']
    headers['Content-Security-Policy'] = [csp]
    cb({ responseHeaders: headers })
  })
  ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false))
  ses.setPermissionCheckHandler(() => false)
  ses.setDevicePermissionHandler(() => false)
}

export function createMainWindow(target: RendererTarget): BrowserWindow {
  const preload = join(__dirname, '../preload/index.js')
  const win = new BrowserWindow({
    width: 1380,
    height: 860,
    minWidth: 980,
    minHeight: 640,
    backgroundColor: '#0b0e14',
    title: 'NEXUS Terminal',
    show: false,
    autoHideMenuBar: true,
    webPreferences: buildWebPreferences(preload)
  })
  hardenWebContents(win.webContents, target.trustedOrigin)
  win.once('ready-to-show', () => win.show())
  void win.loadURL(target.url)
  return win
}
