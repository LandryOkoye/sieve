import { useState, type FormEvent } from 'react'
import { api, readableApiError } from './api'
import type { AgentAssessmentSummary, AgentInspectionResponse, ProtectedAgent, ThreatMemoryReviewAction } from './agent-contract'
import './AgentProtection.css'

export function AgentProtectionPage({ idToken, onAssessment }: {
  idToken: string
  onAssessment: (summary: AgentAssessmentSummary) => void
}) {
  const [agentName, setAgentName] = useState('Protected agent')
  const [agent, setAgent] = useState<ProtectedAgent | null>(null)
  const [credential, setCredential] = useState('')
  const [showCredential, setShowCredential] = useState(false)
  const [copied, setCopied] = useState(false)
  const [content, setContent] = useState('')
  const [sourceType, setSourceType] = useState('direct_content')
  const [sourceRef, setSourceRef] = useState('')
  const [result, setResult] = useState<AgentInspectionResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function createAgent(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const provisioned = await api.createProtectedAgent(idToken, agentName.trim())
      setAgent(provisioned.agent)
      setCredential(provisioned.credential.secret)
      setShowCredential(false)
      setCopied(false)
      setResult(null)
    } catch (cause) { setError(readableApiError(cause)) } finally { setBusy(false) }
  }

  async function inspect(event: FormEvent) {
    event.preventDefault()
    if (!credential.trim()) { setError('Connect an agent credential before inspecting content.'); return }
    setBusy(true)
    setError('')
    try {
      const assessment = await api.inspectAgentContent(credential.trim(), content, sourceType, sourceRef.trim() || undefined)
      setResult(assessment)
      onAssessment({
        id: assessment.id,
        contentHash: assessment.contentHash,
        sourceType,
        action: assessment.decision.action,
        outcome: assessment.assessment.outcome,
        findingCount: assessment.assessment.findings.length,
        memoryCount: assessment.memoryEvidence.length,
        createdAt: assessment.createdAt,
        categories: [...new Set(assessment.assessment.findings.map(({ category }) => category))],
      })
    } catch (cause) { setError(readableApiError(cause)) } finally { setBusy(false) }
  }

  async function copyCredential() {
    try {
      await navigator.clipboard.writeText(credential)
      setCopied(true)
    } catch { setError('Clipboard access failed. Reveal the credential and copy it manually.') }
  }

  return <>
    <section className="page-heading"><p className="eyebrow">AGENT DEFENSE <span>•</span> DIRECT CONTENT</p><h1>Protect agent context</h1><p className="page-subtitle">Create a protected agent or connect an existing one, then inspect content before it enters trusted context.</p></section>
    <div className="agent-protection-grid">
      <div className="agent-protection-main">
        <section className="panel agent-connect-panel">
          <div className="panel-heading"><div><h2>Connect an agent</h2><p>Credentials authorize inspection for one protected agent.</p></div><span className="agent-step">01</span></div>
          <form className="agent-provision-form" onSubmit={createAgent}>
            <label className="field-label" htmlFor="agent-name">Agent name</label>
            <div className="agent-provision-row"><input id="agent-name" value={agentName} onChange={(event) => setAgentName(event.target.value)} minLength={1} maxLength={120} required /><button className="button button-secondary" disabled={busy}>Create protected agent</button></div>
          </form>
          {agent && <div className="agent-created-note"><span className="agent-created-dot" /><span><strong>{agent.name}</strong><small>Protected agent created · policy version {agent.policyVersion}</small></span></div>}
          <div className="agent-credential-area">
            <label className="field-label" htmlFor="agent-credential">Agent API credential</label>
            <input id="agent-credential" className="agent-credential-input" type={showCredential ? 'text' : 'password'} autoComplete="off" spellCheck={false} value={credential} onChange={(event) => { setCredential(event.target.value); setAgent(null) }} placeholder="Paste a sieve_live_ credential" />
            {agent && <div className="one-time-credential"><div><strong>Copy this credential now</strong><p>It is shown once and held only in this page’s memory. It is not saved in browser storage.</p></div><div className="credential-actions"><button type="button" className="button button-secondary button-small" onClick={() => setShowCredential(!showCredential)}>{showCredential ? 'Hide' : 'Reveal'}</button><button type="button" className="button button-primary button-small" onClick={() => void copyCredential()}>{copied ? 'Copied' : 'Copy credential'}</button></div></div>}
            <p className="field-hint">Use a dedicated agent key here. Never paste a Google sign-in token or provider secret.</p>
          </div>
        </section>

        <form className="panel agent-inspect-form" onSubmit={inspect}>
          <div className="panel-heading"><div><h2>Inspect before trust</h2><p>SIEVE assesses the current content, then checks authorized threat memory before deciding.</p></div><span className="agent-step">02</span></div>
          <div className="agent-form-body">
            <label className="field-label" htmlFor="source-type">Content source</label>
            <select id="source-type" value={sourceType} onChange={(event) => setSourceType(event.target.value)}><option value="direct_content">Direct content</option><option value="webpage">Web page</option><option value="email">Email</option><option value="document">Document</option><option value="tool_output">Tool output</option></select>
            <label className="field-label agent-content-label" htmlFor="untrusted-content">Untrusted content</label>
            <textarea id="untrusted-content" value={content} onChange={(event) => setContent(event.target.value)} maxLength={65_536} required placeholder="Paste content your agent is about to read or rely on…" />
            <div className="agent-input-footer"><span>{new TextEncoder().encode(content).length.toLocaleString()} / 65,536 bytes</span><span>Raw content is not stored by SIEVE</span></div>
            <label className="field-label agent-source-ref-label" htmlFor="source-ref">Source reference <span>OPTIONAL · HASHED BEFORE STORAGE</span></label>
            <input id="source-ref" value={sourceRef} onChange={(event) => setSourceRef(event.target.value)} maxLength={2_048} placeholder="URL, document ID, or source pointer" />
            {error && <div className="form-error" role="alert"><Icon name="alert" size={14} />{error}</div>}
            <button className="button button-primary agent-submit" type="submit" disabled={busy || !credential.trim() || !content.trim()}><Icon name="scan" size={16} />{busy ? 'Inspecting…' : 'Inspect content'}</button>
            <p className="agent-privacy-note"><Icon name="lock" size={13} /> A configured semantic provider may receive bounded content. SIEVE persists the content hash, assessment, and policy decision.</p>
          </div>
        </form>
        {result && <AgentAssessment key={result.id} result={result} idToken={idToken} />}
      </div>

      <aside className="agent-boundary-panel">
        <p className="eyebrow">ENFORCEMENT ORDER</p><h2>Memory can support.<br />Evidence decides.</h2>
        <div className="agent-boundary-flow"><span>Current content</span><i>↓</i><span>Deterministic detection</span><i>↓</i><span>Authorized memory recall</span><i>↓</i><span>Policy decision</span><i>↓</i><b>ALLOW · REVIEW · BLOCK</b></div>
        <div className="agent-boundary-rule"><Icon name="shield" size={15} /><p>Retrieved memory cannot override current evidence or policy. Review and block results stay outside trusted context.</p></div>
        <div className="agent-boundary-scope"><span className="signal-dot" /><span>Direct inspection works independently of Tatum or Sui.</span></div>
      </aside>
    </div>
  </>
}

function Icon({ name, size }: { name: string; size: number }) {
  if (name === 'alert') return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="m10.3 4.3-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-2.7l-8-14a2 2 0 0 0-3.4 0Z" /><path d="M12 9v4m0 4h.01" /></svg>
  if (name === 'scan') return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3" /><path d="M7 12h10M12 7v10" /></svg>
  if (name === 'lock') return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 1 1 8 0v3M12 14v3" /></svg>
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></svg>
}

function AgentAssessment({ result, idToken }: { result: AgentInspectionResponse; idToken: string }) {
  const [memories, setMemories] = useState(result.memoryLearning)
  const [rationale, setRationale] = useState('')
  const [reviewing, setReviewing] = useState('')
  const [reviewError, setReviewError] = useState('')
  const action = result.decision.action

  async function review(memoryId: string, action: ThreatMemoryReviewAction) {
    if (!rationale.trim()) { setReviewError('Add a rationale for this review decision.'); return }
    setReviewing(`${memoryId}:${action}`)
    setReviewError('')
    try {
      const updated = await api.reviewThreatMemory(idToken, memoryId, action, rationale.trim())
      setMemories((previous) => previous.map((memory) => memory.id === updated.id ? { ...memory, status: updated.status, storageStatus: updated.status === 'active' ? 'stored' : memory.storageStatus } : memory))
      setRationale('')
    } catch (cause) { setReviewError(readableApiError(cause)) } finally { setReviewing('') }
  }

  return <section className={`panel agent-assessment action-${action}`} aria-live="polite">
    <div className="panel-heading"><div><p className="eyebrow">EVIDENCE-BACKED RESULT</p><h2>Assessment complete</h2></div><span className={`agent-action-badge action-badge-${action}`}>{action.toUpperCase()}</span></div>
    <div className="agent-result-summary"><span>{result.assessment.outcome.replaceAll('_', ' ')}</span><span>Policy v{result.decision.policyVersion}</span><span>{new Date(result.createdAt).toLocaleString()}</span></div>
    {result.assessment.findings.length ? <div className="agent-findings">{result.assessment.findings.map((finding, index) => <article key={`${finding.signal}-${index}`}><div><span className="category-pill">{finding.category.replaceAll('_', ' ')}</span><span className={`strength strength-${finding.strength}`}>{finding.strength}</span></div><h3>{finding.signal.replaceAll('_', ' ')}</h3><p>{finding.rationale}</p>{finding.evidence.startChar !== undefined && finding.evidence.endChar !== undefined && <code>Current content · chars {finding.evidence.startChar}–{finding.evidence.endChar}</code>}</article>)}</div> : <p className="agent-no-findings">No manipulation signal was found in this inspection. This is an assessment of the submitted content, not a guarantee of safety.</p>}
    <div className="agent-memory-evidence"><Icon name="shield" size={15} /><span>{result.memoryEvidence.length ? `${result.memoryEvidence.length} validated memory record${result.memoryEvidence.length === 1 ? '' : 's'} used as supporting context` : 'No validated threat memory contributed to this assessment'}</span></div>
    {memories.length > 0 && <div className="agent-candidates"><strong>Threat-memory review</strong><p>Candidate observations are not trusted or retrievable until an authorized workspace reviewer validates and promotes them.</p><label htmlFor="memory-review-rationale">Review rationale</label><textarea id="memory-review-rationale" value={rationale} onChange={(event) => setRationale(event.target.value)} maxLength={1000} placeholder="Explain the evidence and reason for this review decision" />{memories.map((memory) => <div className="agent-candidate-row" key={memory.id}><span><b>{memory.status}</b> · Walrus {memory.storageStatus ?? 'pending'} · <code>{memory.id.slice(0, 8)}</code></span><div>{memory.status === 'candidate' && <><button type="button" disabled={Boolean(reviewing)} onClick={() => void review(memory.id, 'validate')}>{reviewing === `${memory.id}:validate` ? 'Validating…' : 'Validate'}</button><button type="button" className="candidate-reject" disabled={Boolean(reviewing)} onClick={() => void review(memory.id, 'reject')}>{reviewing === `${memory.id}:reject` ? 'Rejecting…' : 'Reject'}</button></>}{memory.status === 'validated' && <button type="button" disabled={Boolean(reviewing) || memory.storageStatus !== 'stored'} onClick={() => void review(memory.id, 'promote')}>{reviewing === `${memory.id}:promote` ? 'Promoting…' : 'Promote active'}</button>}</div></div>)}{reviewError && <span className="candidate-review-error" role="alert">{reviewError}</span>}<small>Promotion requires a stored candidate and creates a fresh, expiry-verified Walrus record.</small></div>}
    <div className="agent-result-hash"><span>Content SHA-256</span><code>{result.contentHash}</code></div>
  </section>
}
