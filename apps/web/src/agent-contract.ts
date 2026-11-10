import type { DetectionFinding, ThreatCategory } from '@sieve/contracts'

export type ProtectedAgent = {
  id: string
  workspaceId: string
  name: string
  policy: Record<string, unknown>
  policyVersion: number
}

export type AgentProvisionResponse = {
  agent: ProtectedAgent
  credential: { secret: string; prefix: string }
}

export type ThreatMemoryReviewAction = 'validate' | 'promote' | 'reject'
export type ThreatMemoryReviewResponse = { id: string; status: string; walrusExpiresAt: string | null }

export type AgentInspectionResponse = {
  id: string
  contentHash: string
  assessment: {
    outcome: 'signals_detected' | 'no_signals_detected' | 'uncertain'
    findings: DetectionFinding[]
  }
  decision: { action: 'allow' | 'review' | 'block'; policyVersion: number }
  memoryEvidence: Array<{ id: string; role: 'supporting_context' }>
  memoryLearning: Array<{ id: string; status: string; storageStatus?: string }>
  createdAt: string
  expiresAt: string
}

export type AgentAssessmentSummary = {
  id: string
  contentHash: string
  sourceType: string
  action: AgentInspectionResponse['decision']['action']
  outcome: AgentInspectionResponse['assessment']['outcome']
  findingCount: number
  memoryCount: number
  createdAt: string
  categories: ThreatCategory[]
}
