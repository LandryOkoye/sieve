import type { AgentAssessmentSummary } from './agent-contract'
import type { Health } from './api'
import './AgentOverview.css'

export function AgentOverview({ health, assessments, onProtect, onSuiEvidence }: {
  health: Health | null
  assessments: readonly AgentAssessmentSummary[]
  onProtect: () => void
  onSuiEvidence: () => void
}) {
  return <>
    <section className="page-heading agent-home-heading">
      <div><p className="eyebrow">SIEVE WORKSPACE <span>•</span> AGENT DEFENSE</p><h1>Protect the agent’s context.</h1><p className="page-subtitle">Inspect untrusted content before your agent relies on it. Current evidence leads; validated threat memory adds context.</p></div>
      <button className="button button-primary" onClick={onProtect}>Protect content <span aria-hidden="true">→</span></button>
    </section>
    <section className="agent-home-status" aria-label="SIEVE service status">
      <article><span className={`agent-home-status-dot ${health?.status === 'ready' ? 'is-ready' : ''}`} /><div><small>DEFENSE API</small><strong>{health?.status === 'ready' ? 'Operational' : health ? 'Needs attention' : 'Checking status'}</strong></div></article>
      <article><span className="agent-home-status-index">{assessments.length.toString().padStart(2, '0')}</span><div><small>AGENT CHECKS</small><strong>This browser session</strong></div></article>
      <article><span className="agent-home-status-tag">OPTIONAL</span><div><small>FIRST CHAIN CONNECTOR</small><strong>Sui evidence</strong></div><button className="agent-home-link" onClick={onSuiEvidence} aria-label="Open Sui evidence">↗</button></article>
    </section>
    <section className="agent-home-grid">
      <article className="panel agent-home-start">
        <div className="agent-home-card-kicker"><span>01</span> / PRIMARY WORKFLOW</div>
        <div className="agent-home-start-mark" aria-hidden="true">S/</div>
        <h2>Check before trust.</h2>
        <p>Connect a protected agent, submit the content it is about to use, and enforce SIEVE’s allow, review, or block decision.</p>
        <button className="button button-primary" onClick={onProtect}>Open agent protection <span aria-hidden="true">→</span></button>
        <div className="agent-home-safe-note"><span /> Raw inspected content is not persisted by SIEVE.</div>
      </article>
      <article className="panel agent-home-flow">
        <div className="agent-home-card-kicker"><span>02</span> / TRUST BOUNDARY</div>
        <h2>Evidence → context → policy</h2>
        <div className="agent-home-flow-row"><span className="flow-index">A</span><div><strong>Inspect current content</strong><small>Direct text works without a chain provider.</small></div></div>
        <div className="agent-home-flow-row"><span className="flow-index">B</span><div><strong>Recall only validated memory</strong><small>Scope, status, policy, and expiry are checked.</small></div></div>
        <div className="agent-home-flow-row"><span className="flow-index">C</span><div><strong>Enforce before trusted context</strong><small>Memory cannot override current evidence.</small></div></div>
        <button className="agent-home-text-link" onClick={onSuiEvidence}>Sui is an optional evidence source <span aria-hidden="true">↗</span></button>
      </article>
    </section>
    <section className="panel agent-home-recent">
      <div className="panel-heading"><div><h2>Recent agent assessments</h2><p>Only checks from this browser session are shown here.</p></div><span className="panel-count">{assessments.length} this session</span></div>
      {assessments.length ? <div className="agent-home-assessment-list">{assessments.slice(0, 5).map((assessment) => <article key={assessment.id}><span className={`agent-home-action action-${assessment.action}`}>{assessment.action}</span><div><strong>{assessment.categories.length ? assessment.categories.map((category) => category.replaceAll('_', ' ')).join(', ') : 'No manipulation signals found'}</strong><small>{assessment.sourceType} · {new Date(assessment.createdAt).toLocaleTimeString()}</small></div><code>{assessment.contentHash.slice(0, 12)}…</code></article>)}</div> : <div className="agent-home-empty"><span className="agent-home-empty-icon">⌁</span><div><strong>No direct-content assessments yet</strong><p>Start with a protected agent to check its first input.</p></div><button className="button button-secondary button-small" onClick={onProtect}>Start inspection</button></div>}
    </section>
  </>
}
