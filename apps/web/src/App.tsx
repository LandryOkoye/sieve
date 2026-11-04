import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react'
import type { DetectorVerdict, EvaluationRun, InspectionCase, SuiNetwork, ThreatMemoryWrite } from '@sieve/contracts'
import { api, readableApiError, type Health } from './api'
import './App.css'

type Page = { name: 'overview' | 'inspect' | 'memory' | 'evaluations' | 'settings' | 'case'; caseId?: string }
type NavName = Exclude<Page['name'], 'case'>

const navItems: { name: NavName; label: string; icon: string }[] = [
  { name: 'overview', label: 'Overview', icon: 'grid' },
  { name: 'inspect', label: 'Inspect', icon: 'scan' },
  { name: 'memory', label: 'Threat memory', icon: 'memory' },
  { name: 'evaluations', label: 'Evaluations', icon: 'chart' },
]

function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
    scan: <><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3" /><path d="M7 12h10M12 7v10" /></>,
    memory: <><path d="M12 3a7 7 0 0 0-4 12.74V19a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2v-3.26A7 7 0 0 0 12 3Z" /><path d="M9 19h6M9 10l2 2 4-4" /></>,
    chart: <><path d="M4 19V5M4 19h17" /><path d="m7 15 4-4 3 2 6-7" /><path d="M17 6h3v3" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="m19.4 15 .1.1a1.7 1.7 0 0 1-2.4 2.4l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a1.7 1.7 0 0 1-3.4 0v-.2a1.7 1.7 0 0 0-2.9-1.2l-.1.1a1.7 1.7 0 0 1-2.4-2.4l.1-.1a1.7 1.7 0 0 0-1.2-2.9H4a1.7 1.7 0 0 1 0-3.4h.2a1.7 1.7 0 0 0 1.2-2.9l-.1-.1a1.7 1.7 0 0 1 2.4-2.4l.1.1a1.7 1.7 0 0 0 2.9-1.2V4a1.7 1.7 0 0 1 3.4 0v.2a1.7 1.7 0 0 0 2.9 1.2l.1-.1a1.7 1.7 0 0 1 2.4 2.4l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.2a1.7 1.7 0 0 1 0 3.4h-.2a1.7 1.7 0 0 0-1.2.9Z" /></>,
    arrow: <><path d="M5 12h14M13 6l6 6-6 6" /></>,
    back: <><path d="M19 12H5m6 6-6-6 6-6" /></>,
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M5.6 9A7 7 0 0 1 18 6l2 2M4 16l2 2a7 7 0 0 0 12.4-3" /></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 1 1 8 0v3M12 14v3" /></>,
    alert: <><path d="m10.3 4.3-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-2.7l-8-14a2 2 0 0 0-3.4 0Z" /><path d="M12 9v4m0 4h.01" /></>,
  }
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">{paths[name] ?? paths.grid}</svg>
}

function pageFromHash(): Page {
  const [route, caseId] = window.location.hash.replace(/^#\/?/, '').split('/')
  if (route === 'case' && caseId) return { name: 'case', caseId }
  if (route === 'inspect' || route === 'memory' || route === 'evaluations' || route === 'settings') return { name: route }
  return { name: 'overview' }
}

function targetText(inspectionCase: InspectionCase): string {
  return inspectionCase.target.kind === 'transaction' ? inspectionCase.target.digest : inspectionCase.target.objectId
}

function shortTarget(inspectionCase: InspectionCase): string {
  const target = targetText(inspectionCase)
  return target.length > 22 ? `${target.slice(0, 10)}…${target.slice(-8)}` : target
}

function relativeTime(value: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000))
  if (seconds < 60) return 'Just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function verdictLabel(assessment: DetectorVerdict | null): string {
  if (!assessment) return 'In progress'
  if (assessment.outcome === 'signals_detected') return `${assessment.findings.length} signal${assessment.findings.length === 1 ? '' : 's'}`
  if (assessment.outcome === 'uncertain') return 'Needs review'
  return 'No signals'
}

function StatusBadge({ status }: { status: string }) {
  const label: Record<string, string> = {
    queued: 'Queued', fetching_evidence: 'Fetching evidence', assessing: 'Assessing', completed: 'Complete', failed: 'Failed',
  }
  return <span className={`status-badge status-${status}`}><i />{label[status] ?? status}</span>
}

function OutcomeBadge({ assessment }: { assessment: DetectorVerdict | null }) {
  const outcome = assessment?.outcome ?? 'processing'
  return <span className={`outcome-badge outcome-${outcome}`}><i />{verdictLabel(assessment)}</span>
}

function LoadingScreen() {
  return <main className="auth-screen"><div className="auth-mark"><span className="brand-mark">S</span><span>SIEVE</span></div><div className="auth-card auth-loading"><span className="spinner" /><p>Checking your session…</p></div></main>
}

function ConnectScreen({ onConnect, message }: { onConnect: (value: string) => Promise<void>; message: string }) {
  const [accessToken, setAccessToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try { await onConnect(accessToken.trim()) } catch (cause) { setError(readableApiError(cause)) } finally { setBusy(false) }
  }
  return <main className="auth-screen">
    <div className="auth-orbit orbit-one" /><div className="auth-orbit orbit-two" />
    <div className="auth-mark"><span className="brand-mark">S</span><span>SIEVE</span><span className="brand-caption">EVIDENCE INTELLIGENCE</span></div>
    <section className="auth-card">
      <div className="auth-icon"><Icon name="lock" size={21} /></div>
      <p className="eyebrow">SECURE WORKSPACE</p>
      <h1>Connect to SIEVE</h1>
      <p className="auth-copy">Use an access token issued by your SIEVE identity provider to view your inspection workspace.</p>
      <form onSubmit={submit} className="connect-form">
        <label htmlFor="access-token">Access token</label>
        <input id="access-token" type="password" autoComplete="current-password" spellCheck={false} value={accessToken} onChange={(event) => setAccessToken(event.target.value)} placeholder="Paste your bearer token" required />
        {error && <div className="inline-error" role="alert">{error}</div>}
        {message && <div className="inline-error" role="status">{message}</div>}
        <button className="button button-primary button-wide" disabled={busy || !accessToken.trim()}>{busy ? <><span className="spinner spinner-small" /> Connecting…</> : <>Connect securely <Icon name="arrow" size={16} /></>}</button>
      </form>
      <p className="auth-footnote"><Icon name="lock" size={13} /> Token stays in this browser tab and is cleared when you disconnect.</p>
    </section>
    <p className="auth-bottom">Read-only access · Sui mainnet and testnet</p>
  </main>
}

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('sieve_access_token') ?? '')
  const [authState, setAuthState] = useState<'checking' | 'connected' | 'disconnected'>(() => sessionStorage.getItem('sieve_access_token') ? 'checking' : 'disconnected')
  const [userId, setUserId] = useState('')
  const [page, setPage] = useState<Page>(pageFromHash)
  const [cases, setCases] = useState<InspectionCase[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loadingCases, setLoadingCases] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [globalError, setGlobalError] = useState('')
  const [health, setHealth] = useState<Health | null>(null)
  const [currentCase, setCurrentCase] = useState<InspectionCase | null>(null)
  const [caseError, setCaseError] = useState('')
  const loadedOlderCases = useRef(false)

  useEffect(() => {
    const update = () => setPage(pageFromHash())
    window.addEventListener('hashchange', update)
    return () => window.removeEventListener('hashchange', update)
  }, [])

  useEffect(() => {
    let alive = true
    if (!token) return
    api.me(token).then((identity) => {
      if (!alive) return
      setUserId(identity.userId)
      setAuthState('connected')
      setGlobalError('')
    }).catch((error: unknown) => {
      if (!alive) return
      if (error instanceof Error && 'status' in error && error.status === 401) {
        sessionStorage.removeItem('sieve_access_token')
        setToken('')
      } else setGlobalError(readableApiError(error))
      setAuthState('disconnected')
    })
    return () => { alive = false }
  }, [token])

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null))
  }, [])

  useEffect(() => {
    if (!token || authState !== 'connected') return
    let alive = true
    const refresh = async () => {
      try {
        const result = await api.cases(token)
        if (!alive) return
        setCases((previous) => {
          const combined = new Map<string, InspectionCase>()
          for (const item of [...previous, ...result.cases]) combined.set(item.id, item)
          return [...combined.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 100)
        })
        if (!loadedOlderCases.current) setNextCursor(result.nextCursor)
        setGlobalError('')
      } catch (error) {
        if (alive) setGlobalError(readableApiError(error))
      } finally { if (alive) setLoadingCases(false) }
    }
    void refresh()
    const interval = window.setInterval(() => { void refresh() }, 5000)
    return () => { alive = false; window.clearInterval(interval) }
  }, [token, authState])

  useEffect(() => {
    if (page.name !== 'case' || !page.caseId || !token || authState !== 'connected') return
    let alive = true
    const load = async () => {
      try {
        const record = await api.case(token, page.caseId!)
        if (alive) { setCurrentCase(record); setCaseError('') }
      } catch (error) { if (alive) setCaseError(readableApiError(error)) }
    }
    void load()
    const interval = window.setInterval(() => { void load() }, 3000)
    return () => { alive = false; window.clearInterval(interval) }
  }, [page.name, page.caseId, token, authState])

  const stats = useMemo(() => ({
    total: cases.length,
    flagged: cases.filter((item) => item.assessment?.outcome === 'signals_detected').length,
    uncertain: cases.filter((item) => item.assessment?.outcome === 'uncertain' || item.status === 'failed').length,
    processing: cases.filter((item) => ['queued', 'fetching_evidence', 'assessing'].includes(item.status)).length,
  }), [cases])

  function navigate(destination: Page) {
    setCaseError('')
    const hash = destination.name === 'case' ? `#/case/${destination.caseId}` : destination.name === 'overview' ? '#/' : `#/${destination.name}`
    if (window.location.hash === hash) setPage(destination)
    else window.location.hash = hash
  }

  async function connect(accessToken: string) {
    const identity = await api.me(accessToken)
    sessionStorage.setItem('sieve_access_token', accessToken)
    setUserId(identity.userId)
    setGlobalError('')
    setToken(accessToken)
    setAuthState('connected')
    setLoadingCases(true)
  }

  function disconnect() {
    sessionStorage.removeItem('sieve_access_token')
    setToken('')
    setUserId('')
    setCases([])
    setAuthState('disconnected')
  }

  async function loadMore() {
    if (!nextCursor || loadingMore) return
    setLoadingMore(true)
    try {
      const result = await api.cases(token, nextCursor)
      loadedOlderCases.current = true
      setCases((previous) => {
        const combined = new Map(previous.map((item) => [item.id, item]))
        for (const item of result.cases) combined.set(item.id, item)
        return [...combined.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      })
      setNextCursor(result.nextCursor)
    } catch (error) { setGlobalError(readableApiError(error)) } finally { setLoadingMore(false) }
  }

  async function retry(caseId: string) {
    try {
      await api.retryCase(token, caseId)
      const updated = await api.case(token, caseId)
      setCurrentCase(updated)
      setCases((previous) => previous.map((item) => item.id === caseId ? updated : item))
    } catch (error) { setCaseError(readableApiError(error)) }
  }

  if (authState === 'checking') return <LoadingScreen />
  if (authState === 'disconnected') return <ConnectScreen onConnect={connect} message={globalError} />

  const pageTitle = page.name === 'case' ? 'Inspection detail' : ({ overview: 'Overview', inspect: 'Inspect evidence', memory: 'Threat memory', evaluations: 'Evaluations', settings: 'Settings' } as Record<string, string>)[page.name]
  return <div className="app-shell">
    <aside className="sidebar">
      <button className="brand-lockup" onClick={() => navigate({ name: 'overview' })} aria-label="SIEVE overview"><span className="brand-mark">S</span><span className="brand-word">SIEVE<span className="brand-period">.</span></span></button>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="main-nav" aria-label="Main navigation">
        {navItems.map((item) => <button key={item.name} className={`nav-link ${page.name === item.name || (item.name === 'overview' && page.name === 'case') ? 'active' : ''}`} onClick={() => navigate({ name: item.name })}><Icon name={item.icon} /><span>{item.label}</span>{item.name === 'memory' && <span className="nav-soon">SOON</span>}</button>)}
      </nav>
      <div className="sidebar-spacer" />
      <div className="sidebar-note"><div className="sidebar-note-icon"><Icon name="shield" size={17} /></div><div><strong>Built for trust</strong><p>On-chain text stays untrusted by design.</p></div></div>
      <button className={`nav-link sidebar-settings ${page.name === 'settings' ? 'active' : ''}`} onClick={() => navigate({ name: 'settings' })}><Icon name="settings" /><span>Settings</span><span className={`health-dot ${health?.status === 'ready' ? 'dot-good' : 'dot-muted'}`} /></button>
      <div className="sidebar-profile"><span className="avatar">{userId.slice(0, 2).toUpperCase() || 'SI'}</span><div className="profile-info"><strong>Connected user</strong><span>{userId ? `${userId.slice(0, 8)}…${userId.slice(-4)}` : 'SIEVE workspace'}</span></div><button className="icon-button profile-menu" onClick={disconnect} title="Disconnect" aria-label="Disconnect"><Icon name="back" size={16} /></button></div>
    </aside>
    <main className="main-panel">
      <header className="topbar"><div className="breadcrumbs"><span>Workspace</span><span className="crumb-sep">/</span><strong>{pageTitle}</strong></div><div className="topbar-actions"><span className={`connection-pill ${health?.status === 'ready' ? 'connection-ready' : ''}`}><i />{health?.status === 'ready' ? 'Systems operational' : 'Systems unavailable'}</span><button className="button button-primary button-small" onClick={() => navigate({ name: 'inspect' })}><Icon name="scan" size={15} /> New inspection</button></div></header>
      <div className="content-wrap">
        {globalError && <div className="global-alert" role="alert"><Icon name="alert" size={17} /><span>{globalError}</span><button onClick={() => setGlobalError('')} aria-label="Dismiss error">×</button></div>}
        {page.name === 'overview' && <Overview cases={cases} stats={stats} loading={loadingCases} onOpen={navigate} onLoadMore={loadMore} nextCursor={nextCursor} loadingMore={loadingMore} />}
        {page.name === 'inspect' && <InspectPage onCreated={(record) => { setCases((previous) => [record, ...previous.filter((item) => item.id !== record.id)]); navigate({ name: 'case', caseId: record.id }) }} />}
        {page.name === 'case' && <CaseDetail inspectionCase={currentCase?.id === page.caseId ? currentCase : null} loading={!caseError && currentCase?.id !== page.caseId} error={caseError} onBack={() => navigate({ name: 'overview' })} onRetry={retry} />}
        {page.name === 'settings' && <SettingsPage health={health} />}
        {page.name === 'memory' && <ThreatMemoryPage token={token} onOpenCase={(caseId) => navigate({ name: 'case', caseId })} />}
        {page.name === 'evaluations' && <EvaluationsPage token={token} />}
        {page.name === 'memory' && <ComingSoonPage type="memory" />}
        {page.name === 'evaluations' && <ComingSoonPage type="evaluations" />}
        <footer className="page-footer"><span>SIEVE <span className="footer-dot">·</span> Read-only evidence analysis</span><span>Chain text is always treated as untrusted input</span></footer>
      </div>
    </main>
  </div>
}

function Overview({ cases, stats, loading, onOpen, onLoadMore, nextCursor, loadingMore }: {
  cases: InspectionCase[]; stats: { total: number; flagged: number; uncertain: number; processing: number }; loading: boolean;
  onOpen: (destination: Page) => void; onLoadMore: () => void; nextCursor: string | null; loadingMore: boolean
}) {
  return <>
    <section className="page-heading heading-row"><div><p className="eyebrow">SECURITY OBSERVABILITY <span>•</span> SUI NETWORK</p><h1>Evidence intelligence</h1><p className="page-subtitle">A clear view of what your agent reads, what it should distrust, and why.</p></div><button className="button button-primary" onClick={() => onOpen({ name: 'inspect' })}><Icon name="scan" /> Inspect evidence</button></section>
    <section className="metrics-grid" aria-label="Inspection summary">
      <Metric label="Inspections" value={loading ? '—' : stats.total.toLocaleString()} detail="Cases in this workspace" icon="scan" tone="mint" />
      <Metric label="Signals detected" value={loading ? '—' : stats.flagged.toString()} detail="Evidence with manipulation signals" icon="alert" tone="coral" />
      <Metric label="Needs review" value={loading ? '—' : stats.uncertain.toString()} detail="Partial evidence or failed cases" icon="clock" tone="amber" />
      <Metric label="Processing" value={loading ? '—' : stats.processing.toString()} detail="Cases still being analyzed" icon="refresh" tone="blue" />
    </section>
    <div className="dashboard-grid">
        <section className="panel cases-panel">
        <div className="panel-heading"><div><h2>Inspection history</h2><p>Evidence and assessments from your workspace</p></div><span className="panel-count">{stats.total} loaded</span></div>
        {loading ? <div className="table-loading"><span className="spinner" /> Loading inspection history…</div> : cases.length === 0 ? <div className="empty-state"><div className="empty-icon"><Icon name="scan" size={22} /></div><h3>No inspections yet</h3><p>Start with a Sui object ID or transaction digest. SIEVE will fetch the evidence and process it in a case you can revisit.</p><button className="button button-secondary" onClick={() => onOpen({ name: 'inspect' })}>Create first inspection <Icon name="arrow" size={15} /></button></div> : <CaseTable cases={cases} onOpen={(id) => onOpen({ name: 'case', caseId: id })} />}
        {nextCursor && <div className="panel-bottom"><button className="text-button" onClick={onLoadMore} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load older cases'} <Icon name="arrow" size={14} /></button></div>}
      </section>
      <aside className="trust-panel">
        <div className="trust-panel-top"><div className="trust-icon"><Icon name="shield" size={20} /></div><span className="trust-label">TRUST BOUNDARY</span></div>
        <h2>Evidence stays evidence.</h2><p>Every assessment is grounded in fresh chain data. Descriptions and event text remain quarantined as untrusted content.</p>
        <div className="trust-steps"><div className="trust-step"><span className="step-check">1</span><div><strong>Fetch from chain</strong><span>Source and network recorded</span></div></div><div className="trust-step"><span className="step-check">2</span><div><strong>Separate text from facts</strong><span>Attacker controlled content stays inert</span></div></div><div className="trust-step"><span className="step-check">3</span><div><strong>Report uncertainty</strong><span>Missing evidence is never a clean result</span></div></div></div>
        <button className="text-button trust-link" onClick={() => onOpen({ name: 'settings' })}>View system status <Icon name="arrow" size={14} /></button>
      </aside>
    </div>
  </>
}

function Metric({ label, value, detail, icon, tone }: { label: string; value: string; detail: string; icon: string; tone: string }) {
  return <article className="metric-card"><div className={`metric-icon tone-${tone}`}><Icon name={icon} size={17} /></div><span className="metric-label">{label}</span><strong className="metric-value">{value}</strong><span className="metric-detail">{detail}</span></article>
}

function CaseTable({ cases, onOpen }: { cases: InspectionCase[]; onOpen: (id: string) => void }) {
  return <div className="table-scroll"><table className="case-table"><thead><tr><th>Target</th><th>Network</th><th>Assessment</th><th>Status</th><th>Updated</th><th><span className="sr-only">Open</span></th></tr></thead><tbody>{cases.map((item) => <tr key={item.id} onClick={() => onOpen(item.id)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') onOpen(item.id) }}><td><div className="target-cell"><span className="target-kind">{item.target.kind === 'transaction' ? 'TX' : 'OBJ'}</span><div><strong>{shortTarget(item)}</strong><span>{item.target.kind === 'transaction' ? 'Transaction digest' : 'Sui object'}</span></div></div></td><td><span className="network-tag"><i />{item.network}</span></td><td><OutcomeBadge assessment={item.assessment} /></td><td><StatusBadge status={item.status} /></td><td className="time-cell">{relativeTime(item.updatedAt)}</td><td><button className="row-arrow" onClick={(event) => { event.stopPropagation(); onOpen(item.id) }} aria-label={`Open case ${shortTarget(item)}`}><Icon name="arrow" size={16} /></button></td></tr>)}</tbody></table></div>
}

function InspectPage({ onCreated }: { onCreated: (record: InspectionCase) => void }) {
  const [network, setNetwork] = useState<SuiNetwork>('mainnet')
  const [targetType, setTargetType] = useState<'object' | 'transaction'>('object')
  const [identifier, setIdentifier] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const result = await api.createCase(sessionStorage.getItem('sieve_access_token') ?? '', network, targetType === 'object' ? { objectId: identifier.trim() } : { digest: identifier.trim() })
      onCreated(result)
    } catch (cause) { setError(readableApiError(cause)) } finally { setBusy(false) }
  }
  return <>
    <section className="page-heading"><p className="eyebrow">NEW CASE <span>•</span> READ-ONLY</p><h1>Inspect on-chain evidence</h1><p className="page-subtitle">Enter one Sui object ID or transaction digest. SIEVE fetches source data directly from the selected network.</p></section>
    <div className="inspect-layout">
      <form className="panel inspect-form" onSubmit={submit}>
        <div className="form-section-title"><span className="form-step">01</span><div><h2>Choose a target</h2><p>Only one identifier can be inspected at a time.</p></div></div>
        <div className="segmented-control" role="group" aria-label="Target type"><button type="button" className={targetType === 'object' ? 'selected' : ''} onClick={() => { setTargetType('object'); setIdentifier('') }}><Icon name="memory" size={16} /> Object ID</button><button type="button" className={targetType === 'transaction' ? 'selected' : ''} onClick={() => { setTargetType('transaction'); setIdentifier('') }}><Icon name="chart" size={16} /> Transaction digest</button></div>
        <label className="field-label" htmlFor="network">Sui network</label><select id="network" value={network} onChange={(event) => setNetwork(event.target.value as SuiNetwork)}><option value="mainnet">Mainnet <span>Live network</span></option><option value="testnet">Testnet</option></select>
        <label className="field-label identifier-label" htmlFor="identifier">{targetType === 'object' ? 'Object ID' : 'Transaction digest'}</label><div className="input-with-icon"><span>{targetType === 'object' ? '0x' : 'SUI'}</span><input id="identifier" value={identifier} onChange={(event) => setIdentifier(event.target.value)} placeholder={targetType === 'object' ? 'Paste a Sui object ID' : 'Paste a transaction digest'} required autoComplete="off" spellCheck={false} /></div>
        <p className="field-hint">{targetType === 'object' ? 'A Sui address beginning with 0x.' : 'A Base58 encoded Sui transaction digest.'} The API validates the identifier before querying the chain.</p>
        {error && <div className="form-error" role="alert"><Icon name="alert" size={16} />{error}</div>}
        <button className="button button-primary button-wide submit-inspection" disabled={busy || !identifier.trim()}>{busy ? <><span className="spinner spinner-small" /> Creating case…</> : <>Fetch evidence <Icon name="arrow" size={16} /></>}</button>
        <div className="form-security-note"><Icon name="lock" size={14} /><span>SIEVE only reads public chain data. No wallet or signing is involved.</span></div>
      </form>
      <aside className="inspect-aside"><div className="aside-illustration"><div className="orbit-ring ring-a" /><div className="orbit-ring ring-b" /><div className="orbit-core"><Icon name="scan" size={27} /></div><span className="orbit-node node-a" /><span className="orbit-node node-b" /><span className="orbit-node node-c" /></div><h2>Traceable by design</h2><p>Each case records its source network, retrieval time, provider method, and evidence pointers for every extracted text field.</p><div className="aside-rule" /><div className="aside-detail"><span className="aside-detail-icon"><Icon name="shield" size={16} /></span><div><strong>Fresh evidence</strong><span>Fetched by the API from Tatum Sui gRPC</span></div></div><div className="aside-detail"><span className="aside-detail-icon"><Icon name="alert" size={16} /></span><div><strong>Unknown stays unknown</strong><span>Incomplete evidence produces an uncertain assessment</span></div></div></aside>
    </div>
  </>
}

function CaseDetail({ inspectionCase, loading, error, onBack, onRetry }: { inspectionCase: InspectionCase | null; loading: boolean; error: string; onBack: () => void; onRetry: (id: string) => void }) {
  if (loading) return <div className="detail-loading"><span className="spinner" /><p>Loading case evidence…</p></div>
  if (error || !inspectionCase) return <div className="panel detail-error"><Icon name="alert" /><h2>Case unavailable</h2><p>{error || 'This case could not be loaded.'}</p><button className="button button-secondary" onClick={onBack}><Icon name="back" size={15} /> Back to overview</button></div>
  const evidence = inspectionCase.evidence
  const verdict = inspectionCase.assessment
  return <>
    <button className="back-link" onClick={onBack}><Icon name="back" size={15} /> All inspections</button>
    <section className="detail-heading"><div><p className="eyebrow">CASE <span>•</span> {inspectionCase.network.toUpperCase()}</p><div className="detail-title-line"><h1>{inspectionCase.target.kind === 'object' ? 'Object inspection' : 'Transaction inspection'}</h1><StatusBadge status={inspectionCase.status} /></div><div className="detail-target"><code>{targetText(inspectionCase)}</code><span className="target-kind-label">{inspectionCase.target.kind === 'object' ? 'OBJECT ID' : 'TRANSACTION DIGEST'}</span></div></div>{inspectionCase.status === 'failed' && <button className="button button-secondary" onClick={() => onRetry(inspectionCase.id)}><Icon name="refresh" size={15} /> Retry case</button>}</section>
    {inspectionCase.status === 'failed' && <div className="case-warning"><Icon name="alert" size={18} /><div><strong>Inspection did not complete</strong><p>{inspectionCase.failureCode === 'tatum_not_configured' ? 'Tatum is not configured on the API. Your case is saved and can be retried after setup.' : 'The evidence provider could not complete this lookup. You can retry this case.'}</p></div></div>}
    {['queued', 'fetching_evidence', 'assessing'].includes(inspectionCase.status) && <div className="case-progress"><span className="spinner spinner-small" /><div><strong>{inspectionCase.status === 'queued' ? 'Case queued' : inspectionCase.status === 'fetching_evidence' ? 'Fetching chain evidence' : 'Assessing extracted text'}</strong><p>This page updates automatically as processing continues.</p></div></div>}
    {verdict && <section className={`verdict-banner verdict-${verdict.outcome}`}><span className="verdict-symbol"><Icon name={verdict.outcome === 'signals_detected' ? 'alert' : verdict.outcome === 'uncertain' ? 'clock' : 'shield'} size={21} /></span><div><span className="eyebrow">ASSESSMENT</span><h2>{verdict.outcome === 'signals_detected' ? `${verdict.findings.length} manipulation signal${verdict.findings.length === 1 ? '' : 's'} detected` : verdict.outcome === 'uncertain' ? 'Evidence is incomplete' : 'No known signals detected'}</h2><p>{verdict.outcome === 'no_signals_detected' ? 'No pattern matched in the fetched evidence. This is not a certification that the asset or project is safe.' : verdict.outcome === 'uncertain' ? 'The available evidence is partial. SIEVE cannot rule out signals in data it could not decode or retrieve.' : 'On-chain text attempted to influence agent instructions, trust, recommendations, or memory.'}</p></div></section>}
    <div className="detail-grid">
      <div className="detail-main-column">
        {verdict?.findings.length ? <section className="panel findings-panel"><div className="panel-heading"><div><h2>Detected signals</h2><p>Rule-based indicators linked to source evidence</p></div><span className="finding-count">{verdict.findings.length}</span></div><div className="finding-list">{verdict.findings.map((finding, index) => <article className="finding-card" key={`${finding.signal}-${index}`}><div className="finding-top"><span className="category-pill">{finding.category.replaceAll('_', ' ')}</span><span className={`strength strength-${finding.strength}`}>{finding.strength} signal</span></div><h3>{finding.signal.replaceAll('_', ' ')}</h3><p>{finding.rationale}</p><span className="evidence-ref">Source {finding.evidence.eventIndex !== undefined ? `· event ${finding.evidence.eventIndex}` : finding.evidence.objectId ? `· object ${finding.evidence.objectId.slice(0, 12)}…` : `· ${inspectionCase.target.kind}`}</span></article>)}</div></section> : verdict && <section className="panel no-findings-panel"><div className="no-findings-icon"><Icon name={verdict.outcome === 'uncertain' ? 'clock' : 'shield'} size={19} /></div><div><h2>{verdict.outcome === 'uncertain' ? 'No signals matched in available text' : 'No signals matched'}</h2><p>{verdict.outcome === 'uncertain' ? 'This does not resolve the unknown portions of the evidence.' : 'The detector found no known manipulation patterns in the fetched text.'}</p></div></section>}
        <section className="panel evidence-text-panel"><div className="panel-heading"><div><h2>Quarantined text</h2><p>Chain-sourced text is displayed as inert content</p></div><span className="untrusted-tag"><Icon name="lock" size={12} /> UNTRUSTED</span></div>{verdict?.quarantinedText.length ? <div className="quarantine-list">{verdict.quarantinedText.map((item, index) => <article className="quarantine-item" key={`${item.field}-${index}`}><div className="quarantine-meta"><code>{item.field}</code><span>{item.evidence.eventIndex !== undefined ? `Event ${item.evidence.eventIndex}` : item.evidence.objectId ? `Object ${item.evidence.objectId.slice(0, 10)}…` : 'Chain text'}</span></div><pre>{item.value}</pre></article>)}</div> : <div className="muted-empty">{evidence ? 'No text fields were extracted from this evidence bundle.' : 'Text will appear here after evidence is fetched.'}</div>}</section>
      </div>
      <aside className="detail-side-column">
        <section className="panel provenance-panel"><div className="panel-heading"><div><h2>Evidence provenance</h2><p>Where this information came from</p></div></div><div className="provenance-list"><Provenance label="Network" value={evidence?.network ?? inspectionCase.network} /><Provenance label="Source" value={evidence?.provider ?? 'Tatum Sui gRPC'} /><Provenance label="Method" value={evidence?.providerMethod ?? 'Pending'} mono /><Provenance label="Retrieved" value={evidence ? new Date(evidence.retrievedAt).toLocaleString() : 'Pending'} /><Provenance label="Completeness" value={evidence?.completeness ?? 'Pending'} tone={evidence?.completeness === 'partial' ? 'warning' : undefined} /></div>{evidence?.warnings.map((warning, index) => <div className="evidence-warning" key={index}><Icon name="alert" size={14} />{warning}</div>)}</section>
        <section className="panel facts-panel"><div className="panel-heading"><div><h2>Chain facts</h2><p>Structured fields returned by the provider</p></div></div>{evidence?.facts.length ? <div className="facts-list">{evidence.facts.map((fact, index) => <div className="fact-row" key={`${fact.field}-${index}`}><span>{fact.field}</span><code>{String(fact.value)}</code></div>)}</div> : <div className="muted-empty">Chain facts will appear after evidence is fetched.</div>}</section>
      </aside>
    </div>
  </>
}

function Provenance({ label, value, mono = false, tone }: { label: string; value: string; mono?: boolean; tone?: string }) {
  return <div className="provenance-row"><span>{label}</span><strong className={`${mono ? 'mono' : ''} ${tone ?? ''}`}>{value}</strong></div>
}

function ThreatMemoryPage({ token, onOpenCase }: { token: string; onOpenCase: (caseId: string) => void }) {
  const [memories, setMemories] = useState<ThreatMemoryWrite[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [selected, setSelected] = useState<ThreatMemoryWrite | null>(null)
  const [detail, setDetail] = useState<ThreatMemoryWrite | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const loadedOlder = useRef(false)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const page = await api.threatMemories(token)
        if (!alive) return
        setMemories((previous) => {
          const combined = new Map(previous.map((item) => [item.id, item]))
          for (const item of page.memories) combined.set(item.id, item)
          return [...combined.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        })
        if (!loadedOlder.current) setNextCursor(page.nextCursor)
        setError('')
      } catch (cause) { if (alive) setError(readableApiError(cause)) } finally { if (alive) setLoading(false) }
    }
    void load()
    const interval = window.setInterval(() => { void load() }, 8000)
    return () => { alive = false; window.clearInterval(interval) }
  }, [token])

  const filtered = useMemo(() => memories.filter((memory) => {
    if (statusFilter !== 'all' && memory.status !== statusFilter) return false
    const query = search.trim().toLowerCase()
    if (!query) return true
    return `${memory.pattern} ${memory.caseId} ${JSON.stringify(memory.normalizedRecord)}`.toLowerCase().includes(query)
  }), [memories, search, statusFilter])

  async function loadMore() {
    if (!nextCursor || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await api.threatMemories(token, nextCursor)
      loadedOlder.current = true
      setMemories((previous) => {
        const combined = new Map(previous.map((item) => [item.id, item]))
        for (const item of page.memories) combined.set(item.id, item)
        return [...combined.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      })
      setNextCursor(page.nextCursor)
    } catch (cause) { setError(readableApiError(cause)) } finally { setLoadingMore(false) }
  }

  async function openMemory(memory: ThreatMemoryWrite) {
    setSelected(memory)
    setDetail(null)
    setDetailLoading(true)
    try { setDetail(await api.threatMemory(token, memory.id)) } catch (cause) { setError(readableApiError(cause)) } finally { setDetailLoading(false) }
  }

  return <>
    <section className="page-heading"><p className="eyebrow">CROSS-SESSION DEFENSE <span>•</span> EVIDENCE-BACKED RECORDS</p><h1>Threat memory</h1><p className="page-subtitle">Review normalized threat records and their write status. Memory can raise suspicion, but each case still needs fresh chain evidence.</p></section>
    {error && <div className="global-alert" role="alert"><Icon name="alert" size={17} /><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}
    <section className="memory-summary-grid"><Metric label="Records loaded" value={loading ? '—' : memories.length.toString()} detail="Current history pages" icon="memory" tone="mint" /><Metric label="Completed writes" value={loading ? '—' : memories.filter((memory) => memory.status === 'completed').length.toString()} detail="Status recorded by the API" icon="shield" tone="blue" /><Metric label="Needs attention" value={loading ? '—' : memories.filter((memory) => memory.status === 'failed').length.toString()} detail="Failed or incomplete writes" icon="alert" tone="amber" /></section>
    <section className="panel memory-panel">
      <div className="panel-heading memory-heading"><div><h2>Memory records</h2><p>Normalized records saved by the controlled assessment workflow</p></div><span className="panel-count">{memories.length} loaded</span></div>
      <div className="memory-toolbar"><label className="memory-search"><Icon name="grid" size={15} /><span className="sr-only">Search memory records</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search pattern, case, or record" /></label><label className="filter-label">Status<select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="all">All statuses</option><option value="pending">Pending</option><option value="accepted">Accepted</option><option value="uploaded">Uploaded</option><option value="completed">Completed</option><option value="failed">Failed</option></select></label></div>
      {loading ? <div className="table-loading"><span className="spinner" /> Loading memory history…</div> : memories.length === 0 ? <div className="empty-state"><div className="empty-icon"><Icon name="memory" size={22} /></div><h3>No threat memory records yet</h3><p>Records will appear here when an assessment is approved for memory storage. Raw chain text is not stored as trusted threat knowledge.</p></div> : filtered.length === 0 ? <div className="muted-empty memory-filter-empty">No records match these filters.</div> : <div className="table-scroll"><table className="memory-table"><thead><tr><th>Pattern</th><th>Source case</th><th>Write status</th><th>Created</th><th><span className="sr-only">Details</span></th></tr></thead><tbody>{filtered.map((memory) => <tr key={memory.id} onClick={() => void openMemory(memory)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') void openMemory(memory) }}><td><span className="memory-pattern">{memory.pattern.replaceAll('_', ' ')}</span><span className="memory-id">{memory.id.slice(0, 8)}</span></td><td><button className="case-link" onClick={(event) => { event.stopPropagation(); onOpenCase(memory.caseId) }}>{memory.caseId.slice(0, 8)}… <Icon name="arrow" size={12} /></button></td><td><span className={`memory-status memory-${memory.status}`}><i />{memory.status}</span></td><td className="time-cell">{relativeTime(memory.createdAt)}</td><td><button className="row-arrow" onClick={(event) => { event.stopPropagation(); void openMemory(memory) }} aria-label={`View memory record ${memory.id}`}><Icon name="arrow" size={16} /></button></td></tr>)}</tbody></table></div>}
      {nextCursor && !loading && <div className="panel-bottom"><button className="text-button" onClick={() => void loadMore()} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load older records'} <Icon name="arrow" size={14} /></button></div>}
    </section>
    {selected && <div className="dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) { setSelected(null); setDetail(null) } }}><section className="memory-dialog" role="dialog" aria-modal="true" aria-labelledby="memory-dialog-title"><div className="dialog-heading"><div><p className="eyebrow">STORED THREAT RECORD <span>•</span> UNTRUSTED DATA</p><h2 id="memory-dialog-title">{selected.pattern.replaceAll('_', ' ')}</h2></div><button className="dialog-close" onClick={() => { setSelected(null); setDetail(null) }} aria-label="Close record details">×</button></div>{detailLoading ? <div className="dialog-loading"><span className="spinner" /> Loading record…</div> : <><div className="dialog-meta"><div><span>Status</span><strong className={`memory-status memory-${(detail ?? selected).status}`}><i />{(detail ?? selected).status}</strong></div><div><span>Source case</span><button className="case-link" onClick={() => onOpenCase(selected.caseId)}>{selected.caseId.slice(0, 8)}… <Icon name="arrow" size={12} /></button></div><div><span>Created</span><strong>{new Date((detail ?? selected).createdAt).toLocaleString()}</strong></div>{(detail ?? selected).failureCode && <div><span>Failure code</span><strong>{(detail ?? selected).failureCode}</strong></div>}</div><div className="record-boundary"><Icon name="shield" size={16} /><span>Stored memory is untrusted data. It may inform risk handling but cannot replace evidence from this case.</span></div><h3 className="record-label">Normalized record <span className="untrusted-tag"><Icon name="lock" size={11} /> UNTRUSTED</span></h3><pre className="record-json">{JSON.stringify((detail ?? selected).normalizedRecord, null, 2)}</pre>{(detail ?? selected).blobId && <div className="dialog-meta"><div><span>Walrus blob</span><strong className="mono">{(detail ?? selected).blobId}</strong></div></div>}</>}</section></div>}
  </>
}

function SettingsPage({ health }: { health: Health | null }) {
  const names: Record<string, string> = { database: 'PostgreSQL database', authentication: 'Identity provider', tatum: 'Tatum Sui gRPC', walrusMemory: 'Walrus Memory' }
  return <>
    <section className="page-heading"><p className="eyebrow">WORKSPACE CONFIGURATION</p><h1>System status</h1><p className="page-subtitle">Integration availability reported by the SIEVE API. Secret values are never displayed here.</p></section>
    <section className="panel integration-panel"><div className="panel-heading"><div><h2>Connected services</h2><p>Health reflects server configuration and provider availability.</p></div><span className={`health-summary ${health?.status === 'ready' ? 'summary-good' : 'summary-bad'}`}><i />{health?.status === 'ready' ? 'All systems ready' : 'Not all systems ready'}</span></div>{health ? <div className="integration-list">{Object.entries(health.integrations).map(([key, status]) => <div className="integration-row" key={key}><span className="integration-icon"><Icon name={key === 'database' ? 'grid' : key === 'authentication' ? 'lock' : key === 'tatum' ? 'scan' : 'memory'} size={17} /></span><div className="integration-name"><strong>{names[key] ?? key}</strong><span>{status === 'available' ? 'Connection verified' : status === 'unverified' ? 'Configured, not yet verified' : status === 'not_configured' ? 'Not configured on the API' : 'Connection unavailable'}</span></div><span className={`integration-status integration-${status}`}><i />{status.replaceAll('_', ' ')}</span></div>)}</div> : <div className="inline-empty"><span className="spinner" /><span>Could not retrieve current integration health. Check that the API is reachable.</span></div>}</section>
    <section className="security-note"><div className="security-note-icon"><Icon name="lock" size={17} /></div><div><strong>Credentials stay server-side</strong><p>Tatum and Walrus credentials are managed by the API environment and are never sent to this browser.</p></div></section>
  </>
}

function EvaluationsPage({ token }: { token: string }) {
  const [fixtureSetVersion, setFixtureSetVersion] = useState('sieve-baseline-v1')
  const [runs, setRuns] = useState<EvaluationRun[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [selectedId, setSelectedId] = useState('')
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')
  const loadedOlder = useRef(false)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const page = await api.evaluations(token)
        if (!alive) return
        setRuns((previous) => {
          const merged = new Map(previous.map((run) => [run.id, run]))
          for (const run of page.evaluations) merged.set(run.id, run)
          return [...merged.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        })
        if (!loadedOlder.current) setNextCursor(page.nextCursor)
        setError('')
      } catch (cause) { if (alive) setError(readableApiError(cause)) } finally { if (alive) setLoading(false) }
    }
    void load()
    const interval = window.setInterval(() => { void load() }, 3000)
    return () => { alive = false; window.clearInterval(interval) }
  }, [token])

  const selected = runs.find((run) => run.id === selectedId) ?? runs[0] ?? null

  async function startEvaluation() {
    setStarting(true)
    setError('')
    try {
      const run = await api.createEvaluation(token, fixtureSetVersion)
      setRuns((previous) => [run, ...previous.filter((item) => item.id !== run.id)])
      setSelectedId(run.id)
    } catch (cause) { setError(readableApiError(cause)) } finally { setStarting(false) }
  }

  async function loadMore() {
    if (!nextCursor || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await api.evaluations(token, nextCursor)
      loadedOlder.current = true
      setRuns((previous) => {
        const merged = new Map(previous.map((run) => [run.id, run]))
        for (const run of page.evaluations) merged.set(run.id, run)
        return [...merged.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      })
      setNextCursor(page.nextCursor)
    } catch (cause) { setError(readableApiError(cause)) } finally { setLoadingMore(false) }
  }

  return <>
    <section className="page-heading heading-row"><div><p className="eyebrow">QUALITY & COVERAGE <span>•</span> VERSIONED FIXTURES</p><h1>Evaluations</h1><p className="page-subtitle">Run the detector against versioned fixture sets and inspect measured results.</p></div><div className="evaluation-actions"><label className="sr-only" htmlFor="fixture-set">Fixture set</label><select id="fixture-set" value={fixtureSetVersion} onChange={(event) => setFixtureSetVersion(event.target.value)} disabled={starting}><option value="sieve-baseline-v1">Baseline regression</option><option value="sieve-variants-v1">Variant challenge</option><option value="sieve-dev-v1">Development set</option><option value="sieve-validation-v1">Frozen validation set</option></select><button className="button button-primary" onClick={() => void startEvaluation()} disabled={starting}><Icon name="chart" size={16} />{starting ? 'Starting…' : 'Run evaluation'}</button></div></section>
    <div className="evaluation-caveat"><Icon name="alert" size={16} /><span>Both sets are small, manually authored development fixtures. The held-out variants are separate from the baseline examples, but are not independent external validation, calibrated confidence, or a safety certification.</span></div>
    {error && <div className="global-alert" role="alert"><Icon name="alert" size={17} /><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}
    <div className="evaluation-layout">
      <section className="panel evaluation-history"><div className="panel-heading"><div><h2>Evaluation runs</h2><p>Persisted results for your workspace</p></div><span className="panel-count">{runs.length} loaded</span></div>
        {loading ? <div className="table-loading"><span className="spinner" /> Loading evaluation history…</div> : runs.length === 0 ? <div className="empty-state evaluation-empty"><div className="empty-icon"><Icon name="chart" size={22} /></div><h3>No evaluation runs yet</h3><p>Choose a fixture set and run it to see detector coverage and false positives.</p><button className="button button-secondary" onClick={() => void startEvaluation()} disabled={starting}>{starting ? 'Starting…' : 'Run evaluation'} <Icon name="arrow" size={14} /></button></div> : <div className="run-list">{runs.map((run) => <button key={run.id} className={`evaluation-run ${selected?.id === run.id ? 'selected-run' : ''}`} onClick={() => setSelectedId(run.id)}><span className={`run-icon run-${run.status}`}><Icon name={run.status === 'failed' ? 'alert' : run.status === 'completed' ? 'chart' : 'clock'} size={15} /></span><span className="run-main"><strong>{run.fixtureSetVersion}</strong><span>{relativeTime(run.createdAt)} · {run.id.slice(0, 8)}</span></span><EvaluationStatus status={run.status} /></button>)}</div>}
        {nextCursor && !loading && <div className="panel-bottom"><button className="text-button" onClick={() => void loadMore()} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load older runs'} <Icon name="arrow" size={14} /></button></div>}
      </section>
      <EvaluationResult run={selected} />
    </div>
  </>
}

function EvaluationStatus({ status }: { status: EvaluationRun['status'] }) {
  const labels = { queued: 'Queued', running: 'Running', completed: 'Complete', failed: 'Failed' }
  return <span className={`evaluation-status evaluation-${status}`}><i />{labels[status]}</span>
}

function formatRate(value: number | null): string {
  return value === null ? '—' : `${(value * 100).toFixed(1)}%`
}

function EvaluationResult({ run }: { run: EvaluationRun | null }) {
  if (!run) return <section className="panel evaluation-result evaluation-result-empty"><div className="empty-icon"><Icon name="chart" size={22} /></div><h2>Select an evaluation run</h2><p>Results will appear here when a run is selected.</p></section>
  return <section className="panel evaluation-result"><div className="panel-heading"><div><h2>Run results</h2><p>{run.fixtureSetVersion} <span className="footer-dot">·</span> {new Date(run.createdAt).toLocaleString()}</p></div><EvaluationStatus status={run.status} /></div>
    {run.status === 'queued' || run.status === 'running' ? <div className="run-progress"><span className="spinner" /><div><strong>{run.status === 'queued' ? 'Evaluation queued' : 'Evaluating fixtures'}</strong><p>This panel refreshes while the API processes the run.</p></div></div> : run.status === 'failed' ? <div className="evaluation-failure"><Icon name="alert" size={17} /><div><strong>Evaluation failed</strong><p>{run.failureCode ?? 'The API could not complete this fixture run.'}</p></div></div> : run.metrics ? <>
      <div className="evaluation-metrics"><Metric label="Precision" value={formatRate(run.metrics.precision)} detail="Among predicted attacks" icon="shield" tone="mint" /><Metric label="Recall" value={formatRate(run.metrics.recall)} detail="Known attacks detected" icon="scan" tone="blue" /><Metric label="False positive rate" value={formatRate(run.metrics.falsePositiveRate)} detail="Benign fixtures flagged" icon="alert" tone="amber" /></div>
      <div className={`acceptance-panel ${run.metrics.acceptance.passed ? 'acceptance-pass' : 'acceptance-fail'}`} role="status"><div className="acceptance-heading"><Icon name={run.metrics.acceptance.passed ? 'shield' : 'alert'} size={17} /><div><strong>{run.metrics.acceptance.passed ? 'Acceptance targets met' : 'Acceptance targets not met'}</strong><span>Overall recall ≥ {formatRate(run.metrics.thresholds.minimumOverallRecall)} · Each category ≥ {formatRate(run.metrics.thresholds.minimumCategoryRecall)} · False positives ≤ {formatRate(run.metrics.thresholds.maximumFalsePositiveRate)}</span></div></div><div className="acceptance-checks"><span className={run.metrics.acceptance.overallRecall ? 'check-passed' : 'check-failed'}>Overall recall</span>{Object.entries(run.metrics.acceptance.categoryRecall).map(([category, passed]) => <span key={category} className={passed ? 'check-passed' : 'check-failed'}>{category.replaceAll('_', ' ')}</span>)}<span className={run.metrics.acceptance.falsePositiveRate ? 'check-passed' : 'check-failed'}>False positive rate</span></div></div>
      <div className="fixture-summary"><div><strong>{run.metrics.fixtureCount}</strong><span>fixtures</span></div><div><strong>{run.metrics.attackCount}</strong><span>attack examples</span></div><div><strong>{run.metrics.benignCount}</strong><span>benign examples</span></div></div>
      <div className="confusion-grid"><ConfusionCell label="True positives" value={run.metrics.truePositives} tone="positive" /><ConfusionCell label="False positives" value={run.metrics.falsePositives} tone="negative" /><ConfusionCell label="True negatives" value={run.metrics.trueNegatives} tone="positive" /><ConfusionCell label="False negatives" value={run.metrics.falseNegatives} tone="negative" /></div>
      <div className="category-results"><div className="category-heading"><h3>Category coverage</h3><span>Expected attacks detected</span></div>{Object.entries(run.metrics.categories).map(([category, metrics]) => <div className="category-row" key={category}><span>{category.replaceAll('_', ' ')}</span><div className="category-track"><i style={{ width: `${metrics.support ? Math.min(100, metrics.detected / metrics.support * 100) : 0}%` }} /></div><strong>{metrics.detected}/{metrics.support}</strong><em>{metrics.falsePositives ? `${metrics.falsePositives} benign match${metrics.falsePositives === 1 ? '' : 'es'}` : '0 benign matches'}</em></div>)}</div>
      <p className="evaluation-footnote">Small deterministic fixtures help catch regressions. They do not measure paraphrase coverage or production accuracy.</p>
    </> : <div className="muted-empty">Metrics are not available for this run.</div>}
  </section>
}

function ConfusionCell({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className={`confusion-cell confusion-${tone}`}><span>{label}</span><strong>{value}</strong></div>
}
function ComingSoonPage({ type }: { type: 'memory' | 'evaluations' }) {
  const memory = type === 'memory'
  return <section className="coming-page"><div className="coming-icon"><Icon name={memory ? 'memory' : 'chart'} size={24} /></div><p className="eyebrow">{memory ? 'CROSS-SESSION DEFENSE' : 'QUALITY & COVERAGE'}</p><h1>{memory ? 'Threat memory' : 'Evaluations'}</h1><p className="coming-copy">{memory ? 'Review normalized, evidence-backed threat records and see when previous patterns influence a fresh assessment.' : 'Measure detector coverage against versioned attack and benign fixtures, with transparent category-level results.'}</p><div className="coming-status"><span className="status-indicator" /> API capability is not available yet</div><div className="coming-boundary"><Icon name="shield" size={16} /><span>This view will show live API data when the corresponding backend workflow is implemented. No sample records are shown.</span></div></section>
}

export default App
}
