export const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'DESTRUCTIVE'] as const
export type RiskLevel = (typeof RISK_LEVELS)[number]

export const APPROVAL_POLICIES = ['sensitive', 'ask', 'always'] as const
export type ApprovalPolicy = (typeof APPROVAL_POLICIES)[number]

/** Bump whenever classification rules change: invalidates every outstanding approval. */
export const POLICY_VERSION = '2026.11.2'

export function levelRank(l: RiskLevel): number {
  return RISK_LEVELS.indexOf(l)
}

export function maxLevel(a: RiskLevel, b: RiskLevel): RiskLevel {
  return levelRank(a) >= levelRank(b) ? a : b
}

export interface PolicyDecision {
  level: RiskLevel
  reasons: string[]
  flags: string[]
  requiresApproval: boolean
  /** 1 = clean parse of a fully understood command, 0 = unparseable. */
  parseConfidence: number
  policyVersion: string
}
