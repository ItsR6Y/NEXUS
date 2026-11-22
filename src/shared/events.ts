/** Events pushed from main to renderer. Dependency-free so the sandboxed preload can import it. */
export const EVENTS = {
  terminalData: 'evt:terminal:data',
  terminalClosed: 'evt:terminal:closed',
  sessionsChanged: 'evt:sessions:changed',
  approvalsChanged: 'evt:approvals:changed',
  knownHostsChanged: 'evt:knownhosts:changed',
  mcpChanged: 'evt:mcp:changed',
  executionsChanged: 'evt:executions:changed',
  securityChanged: 'evt:security:changed'
} as const

export type EventName = keyof typeof EVENTS
