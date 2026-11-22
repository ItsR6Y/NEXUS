import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { BRIDGE_VERSION, EndpointFile, type EndpointFileT } from '../../../shared/bridge'

/**
 * Derive a unique local pipe path.
 * On Windows: \\.\pipe\nexus-bridge-<first16hex(sha256(userData))>-<random8hex>
 * On POSIX:   <socketDir>/nexus-bridge-<random16hex>.sock
 */
export function newPipePath(platform: NodeJS.Platform, socketDir: string): string {
  const dirHash = createHash('sha256').update(socketDir).digest('hex').slice(0, 16)
  const rand = randomBytes(4).toString('hex')
  return platform === 'win32'
    ? `\\\\.\\pipe\\nexus-bridge-${dirHash}-${rand}`
    : join(socketDir, `nexus-bridge-${dirHash}-${rand}.sock`)
}

export function newEndpoint(pipeName: string, pid = process.pid): EndpointFileT {
  return { version: BRIDGE_VERSION, pipeName, secret: randomBytes(32).toString('hex'), pid }
}

/**
 * Write bridge.json to the per-user userData directory.
 * SECURITY NOTE (per NEXUS-BUILD-PLAN.md §7):
 * - We deliberately do NOT shell out to `icacls` on Windows. The per-user %APPDATA%\NEXUS directory is user-private
 *   by default, and every connection authenticates with a per-launch 256-bit HMAC-SHA256 challenge-response secret.
 * - On POSIX, enforce 0o600 permissions on the endpoint file.
 */
export function writeEndpointFile(file: string, ep: EndpointFileT, platform: NodeJS.Platform = process.platform): void {
  EndpointFile.parse(ep)
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, JSON.stringify(ep), { encoding: 'utf8', mode: 0o600 })
  if (platform !== 'win32') {
    chmodSync(file, 0o600)
    if ((statSync(file).mode & 0o077) !== 0) {
      throw new Error('bridge endpoint file permissions could not be restricted to current user')
    }
  }
}
