import { join } from 'node:path'

export interface AppPaths {
  userData: string
  dbFile: string
  logsDir: string
  logFile: string
  bridgeFile: string
}

export function resolveAppPaths(userData: string): AppPaths {
  const logsDir = join(userData, 'logs')
  return {
    userData,
    dbFile: join(userData, 'nexus.db'),
    logsDir,
    logFile: join(logsDir, 'nexus.log'),
    bridgeFile: join(userData, 'bridge.json')
  }
}
