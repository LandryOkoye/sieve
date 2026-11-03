import type { InspectionCase, SuiNetwork } from '@sieve/contracts'

const API_BASE = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''

export type CasePage = {
  cases: InspectionCase[]
  limit: number
  nextCursor: string | null
}

export type Health = {
  status: 'ready' | 'not_ready'
  integrations: Record<string, 'available' | 'unavailable' | 'unverified' | 'not_configured'>
}

export class ApiError extends Error {
  status: number
  code: string

  constructor(status: number, code: string) {
    super(code)
    this.status = status
    this.code = code
  }
}

async function request<T>(path: string, token?: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set('Accept', 'application/json')
  if (init?.body) headers.set('Content-Type', 'application/json')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers })
  const payload = await response.json().catch(() => ({})) as unknown
  if (!response.ok) {
    const code = payload && typeof payload === 'object' && 'error' in payload && typeof payload.error === 'string'
      ? payload.error
      : 'request_failed'
    throw new ApiError(response.status, code)
  }
  return payload as T
}

export const api = {
  me: (token: string) => request<{ userId: string }>('/api/v1/me', token),
  health: async () => {
    const response = await fetch(`${API_BASE}/api/v1/health/ready`, { headers: { Accept: 'application/json' } })
    const payload = await response.json().catch(() => null) as Health | null
    if (!payload || (!response.ok && response.status !== 503)) throw new ApiError(response.status, 'health_unavailable')
    return payload
  },
  cases: (token: string, cursor?: string) => {
    const query = new URLSearchParams({ limit: '20' })
    if (cursor) query.set('cursor', cursor)
    return request<CasePage>(`/api/v1/cases?${query}`, token)
  },
  case: (token: string, caseId: string) => request<InspectionCase>(`/api/v1/cases/${caseId}`, token),
  createCase: (token: string, network: SuiNetwork, target: { digest: string } | { objectId: string }) =>
    request<InspectionCase>('/api/v1/cases', token, {
      method: 'POST',
      headers: { 'Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify({ network, ...target }),
    }),
  retryCase: (token: string, caseId: string) =>
    request<{ id: string; status: string }>(`/api/v1/cases/${caseId}/retry`, token, { method: 'POST' }),
}

export function readableApiError(error: unknown): string {
  if (!(error instanceof ApiError)) return 'The API could not be reached. Check that the service is running and try again.'
  if (error.status === 401) return 'Your session has expired. Connect again with a valid access token.'
  if (error.status === 503 && error.code === 'authentication_not_configured') return 'Authentication is not configured on this API.'
  if (error.status === 503) return 'A required service is unavailable. Your case is saved and can be retried.'
  if (error.code === 'invalid_sui_identifier') return 'That Sui identifier is not valid. Check the value and try again.'
  if (error.code === 'idempotency_key_conflict') return 'This request key was already used for a different inspection.'
  return `Request failed (${error.code}). Please try again.`
}
