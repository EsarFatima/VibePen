import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from 'react'

type CheckStatus = 'passed' | 'low' | 'medium' | 'high' | 'critical' | 'na' | 'skipped'
type FindingState = 'open' | 'false_positive' | 'resolved'

interface Check { id: string; label: string; category: string; status: CheckStatus; detail: string }
interface Finding {
  id: string
  label: string
  severity: Exclude<CheckStatus, 'passed' | 'na' | 'skipped'>
  summary: string
  evidence: string
  recommendation: string
  location: string
  confidence: number
  state?: FindingState
}
interface ScanReportFinding {
  id?: string; type: string; severity: string; title?: string; description?: string
  evidence?: string; remediation?: string; location?: string; confidence?: number
}
export interface ScanReport {
  id?: string
  target: string
  target_type?: string
  scanned_at?: string
  risk_score: number
  findings: ScanReportFinding[]
  network_info?: {
    scanner?: string; hostname?: string; ip_address?: string; is_local?: boolean
    open_ports?: Array<{ port: number; protocol?: string; service?: string }>
    duration_seconds?: number
  }
}
export interface HistoryEntry {
  id: string; scanned_at: string; target: string; target_type?: string
  risk_score: number; total_findings: number; severity_counts?: Record<string, number>
  report?: ScanReport
}

const fallbackChecks: Check[] = [
  ['auth_login_brute', 'Brute-force protection', 'Authentication & access control', 'passed', 'Login attempts are rate limited.'],
  ['cross_account_basket', 'Cross-account basket access', 'Authentication & access control', 'critical', 'One account can access another account’s private basket data.'],
  ['auth_user_area', 'Authenticated user area', 'Authentication & access control', 'passed', 'Authenticated routes require a valid session.'],
  ['priv_escalation', 'Privilege escalation', 'Authentication & access control', 'skipped', 'Two authorized test accounts were not provided.'],
  ['sql_injection', 'SQL injection', 'Injection & input handling', 'high', 'The login endpoint accepts unsanitized input in the email field.'],
  ['xss_reflected', 'Reflected XSS', 'Injection & input handling', 'medium', 'Search terms are reflected without HTML encoding.'],
  ['cmd_injection', 'Command injection', 'Injection & input handling', 'passed', 'No command injection was detected.'],
  ['xxe', 'XXE / XML injection', 'Injection & input handling', 'na', 'The target does not expose an XML processing surface.'],
  ['csp', 'Content Security Policy', 'Browser safety', 'passed', 'A content security policy is present.'],
  ['cors', 'CORS configuration', 'Browser safety', 'critical', 'Authenticated endpoints allow wildcard origins.'],
  ['clickjacking', 'Clickjacking (X-Frame-Options)', 'Browser safety', 'passed', 'Frame embedding is restricted.'],
  ['stack_trace', 'Stack trace disclosure', 'Error handling', 'passed', 'No stack traces were exposed in error responses.'],
  ['verbose_errors', 'Verbose error messages', 'Error handling', 'na', 'No applicable error surface was found.'],
  ['https_redirect', 'HTTPS redirect', 'Configuration & transport', 'passed', 'HTTP requests redirect to HTTPS.'],
  ['hsts', 'HSTS header', 'Configuration & transport', 'skipped', 'Could not verify HSTS because HTTPS-only access may be required.'],
  ['tls_version', 'TLS version check', 'Configuration & transport', 'na', 'TLS could not be evaluated for this local target.'],
].map(([id, label, category, status, detail]) => ({ id, label, category, status: status as CheckStatus, detail }))

const statusOrder: Record<CheckStatus, number> = { passed: 0, critical: 1, high: 2, medium: 3, low: 4, skipped: 5, na: 6 }

function normalizeSeverity(value: string): Finding['severity'] {
  const severity = value.toLowerCase()
  return severity === 'critical' || severity === 'high' || severity === 'medium' ? severity : 'low'
}

export function mapReport(report: ScanReport) {
  const reportFindings = (report.findings ?? []).map((item, index) => ({
    id: item.id ?? `${item.type}-${item.location ?? index}`,
    label: item.title ?? item.type ?? 'Security finding',
    severity: normalizeSeverity(item.severity),
    summary: item.description ?? 'A potential security issue was detected.',
    evidence: item.evidence ?? 'No evidence supplied.',
    recommendation: item.remediation ?? 'Review this result manually.',
    location: item.location ?? 'Unknown location',
    confidence: Math.round((item.confidence ?? 0) * 100),
    state: 'open' as FindingState,
  }))
  const dynamicChecks: Check[] = reportFindings.map(finding => ({
    id: `backend-${finding.id}`, label: finding.label, category: 'Backend scan result',
    status: finding.severity, detail: finding.summary,
  }))
  return { findings: reportFindings, checks: [...fallbackChecks.filter(check => !['critical', 'high', 'medium', 'low'].includes(check.status)), ...dynamicChecks] }
}

function navigate(path: string) {
  window.history.pushState({}, '', path)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

function isSandboxDomain(value: string) {
  try {
    const hostname = new URL(value).hostname.toLowerCase()
    return ['localhost', '127.0.0.1', '::1'].includes(hostname) || hostname.endsWith('.local')
  } catch { return false }
}

function isVerifiedDomain(value: string) {
  const domains: string[] = JSON.parse(localStorage.getItem('vibepen-domains') ?? '[]')
  try {
    const hostname = new URL(value).hostname.toLowerCase()
    return domains.some(domain => hostname === domain.toLowerCase() || hostname.endsWith(`.${domain.toLowerCase()}`))
  } catch { return false }
}

function downloadReport(report: ScanReport, format: string) {
  const findings = report.findings ?? []
  let content = ''
  let mime = 'text/plain'
  let extension = format
  if (format === 'json') { content = JSON.stringify(report, null, 2); mime = 'application/json' }
  if (format === 'md') {
    content = `# VibePen scan report\n\nTarget: ${report.target}\n\n## Findings\n\n${findings.map(item => `### ${item.title ?? item.type} (${item.severity})\n\n${item.description ?? ''}\n\nEvidence: ${item.evidence ?? 'None'}\n`).join('\n')}`
    mime = 'text/markdown'
  }
  if (format === 'csv') {
    content = ['title,severity,location,evidence', ...findings.map(item => [item.title ?? item.type, item.severity, item.location ?? '', item.evidence ?? ''].map(value => `"${String(value).replaceAll('"', '""')}"`).join(','))].join('\n')
    mime = 'text/csv'
  }
  if (format === 'pdf') {
    const lines = [`VibePen scan report`, `Target: ${report.target}`, `Risk score: ${report.risk_score}`, '', ...findings.map(item => `${item.severity.toUpperCase()}: ${item.title ?? item.type}`)]
    const escapePdf = (value: string) => value.replaceAll('\\', '\\\\').replaceAll('(', '\\(').replaceAll(')', '\\)')
    const stream = `BT /F1 12 Tf 50 760 Td ${lines.map(line => `(${escapePdf(line)}) Tj 0 -18 Td`).join(' ')} ET`
    const objects = [`<< /Type /Catalog /Pages 2 0 R >>`, `<< /Type /Pages /Kids [3 0 R] /Count 1 >>`, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>`, `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`, `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`]
    let pdf = '%PDF-1.4\n'
    const offsets = [0]
    objects.forEach((object, index) => { offsets.push(pdf.length); pdf += `${index + 1} 0 obj\n${object}\nendobj\n` })
    const xref = pdf.length
    pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.slice(1).map(offset => `${String(offset).padStart(10, '0')} 00000 n `).join('\n')}\ntrailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`
    content = pdf
    mime = 'application/pdf'
  }
  const link = document.createElement('a')
  link.href = URL.createObjectURL(new Blob([content], { type: mime }))
  link.download = `vibepen-${report.id ?? 'scan'}.${extension}`
  link.click()
  URL.revokeObjectURL(link.href)
}

function DownloadMenu({ report }: { report: ScanReport }) {
  const [format, setFormat] = useState('')
  useEffect(() => { if (format) { downloadReport(report, format); setFormat('') } }, [format, report])
  return <select className="template-download" value={format} onChange={event => setFormat(event.target.value)} aria-label="Download report">
    <option value="">Download report…</option><option value="pdf">PDF</option><option value="json">JSON</option><option value="md">Markdown</option><option value="csv">CSV</option>
  </select>
}

function ReportView({ report, findingStates, onFindingState }: { report: ScanReport; findingStates?: Record<string, FindingState>; onFindingState?: (id: string, state: FindingState) => void }) {
  const mapped = mapReport(report)
  const [expanded, setExpanded] = useState<string[]>([])
  const [expandedChecks, setExpandedChecks] = useState<string[]>([])
  const [openSections, setOpenSections] = useState<Array<'passed' | 'skipped'>>([])
  const findings = mapped.findings.map(finding => ({ ...finding, state: findingStates?.[finding.id] ?? finding.state }))
  const checks = mapped.checks
  const sortedChecks = [...checks].sort((a, b) => statusOrder[a.status] - statusOrder[b.status])
  const sortedFindings = [...findings].sort((a, b) => statusOrder[a.severity] - statusOrder[b.severity])
  const passed = checks.filter(check => check.status === 'passed')
  const skipped = checks.filter(check => check.status === 'skipped')
  const applicable = checks.filter(check => !['skipped', 'na'].includes(check.status))
  const toggle = (id: string) => setExpanded(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id])
  return <section className="template-report">
    <section className="template-summary">
      <div className="template-summary-heading"><span className="template-summary-icon">✦</span><div><h2>Scan complete</h2><p>{applicable.length} of {applicable.length} applicable checks completed · {skipped.length} skipped.</p></div><DownloadMenu report={report} /></div>
      <div className="template-summary-cards"><div className="critical"><b>⚠ Things to fix</b><strong>{findings.length} Findings</strong><small>Risk score {report.risk_score}</small></div><div className="passed"><b>✓ Passed cleanly</b><strong>{passed.length} Checks</strong><small>No issues detected in completed checks.</small></div><div className="skipped"><b>› Skipped checks</b><strong>{skipped.length} Skipped</strong><small>Requires credentials or setup.</small></div></div>
    </section>
    {report.network_info && <section className="template-network"><div><div className="template-section-label">HOST DISCOVERY</div><h2>Host and port discovery</h2><p>{report.network_info.scanner ?? 'Network scanner'}</p></div><strong>{report.network_info.ip_address ?? 'IP unresolved'}</strong><div className="template-network-stats"><span><b>Host</b>{report.network_info.hostname ?? 'Unknown'}</span><span><b>Scope</b>{report.network_info.is_local ? 'Local sandbox' : 'External host'}</span><span><b>Open ports</b>{report.network_info.open_ports?.length ?? 0}</span></div></section>}
    <section className="template-coverage template-coverage-card"><div className="template-section-label">SECURITY CHECK COVERAGE</div><h2>Security check coverage</h2><p>Click each box to expand its detail.</p><div className="template-check-bar">{sortedChecks.map(check => <button key={check.id} className={check.status} title={check.label} aria-label={`Open ${check.label}`} onClick={() => setExpandedChecks(current => current.includes(check.id) ? current.filter(id => id !== check.id) : [...current, check.id])} />)}</div><div className="template-check-legend">{(['passed', 'critical', 'high', 'medium', 'low', 'skipped', 'na'] as CheckStatus[]).map(name => <span key={name}><i className={name} /><label>{name} <b>{checks.filter(check => check.status === name).length}</b></label></span>)}</div>{expandedChecks.map(id => { const check = checks.find(item => item.id === id); return check && <div className="template-check-detail" key={id}><strong>↓ {check.label}</strong><span>{check.detail}</span></div> })}</section>
    <section className="template-original-section"><h2>⚑ Security findings ({findings.length})</h2><div className="template-original-list">{sortedFindings.map(finding => { const open = expanded.includes(finding.id); return <div key={finding.id}><button className="template-original-row" aria-expanded={open} onClick={() => toggle(finding.id)}><span className={open ? 'is-expanded' : ''}>›</span><strong>{finding.label}</strong>{finding.state && finding.state !== 'open' && <em className="finding-state">{finding.state.replace('_', ' ')}</em>}<i className={finding.severity} /></button>{open && <div className="template-finding-detail"><p>{finding.summary}</p><small>EVIDENCE</small><pre>{finding.evidence}</pre><small>RECOMMENDED ACTION</small><p>{finding.recommendation}</p><footer><span>LOCATION <code>{finding.location}</code></span><span>CONFIDENCE <code>{finding.confidence}%</code></span></footer><div className="finding-actions"><button onClick={() => onFindingState?.(finding.id, 'false_positive')}>Mark false positive</button><button onClick={() => onFindingState?.(finding.id, 'resolved')}>Mark resolved</button></div></div>}</div> })}</div></section>
    <section className="template-original-section template-validations"><h2>✓ Passed &amp; skipped validations <small>Automated checks</small></h2>{(['passed', 'skipped'] as const).map(section => <div key={section}><button className="template-collapse" aria-expanded={openSections.includes(section)} onClick={() => setOpenSections(current => current.includes(section) ? current.filter(item => item !== section) : [...current, section])}><span><i className={openSections.includes(section) ? 'is-expanded' : ''}>›</i> {section[0].toUpperCase() + section.slice(1)} checks</span><b>{section === 'passed' ? passed.length : skipped.length}</b></button>{openSections.includes(section) && (section === 'passed' ? passed : skipped).map(check => <div className="template-skipped-row" key={check.id}><strong>{check.label}</strong><span>{check.detail}</span></div>)}</div>)}</section>
  </section>
}

function AuthPage() {
  const [signup, setSignup] = useState(false)
  const [email, setEmail] = useState(''); const [password, setPassword] = useState('')
  function submit(event: FormEvent) { event.preventDefault(); localStorage.setItem('vibepen-user', JSON.stringify({ email })); navigate('/') }
  return <main className="template-home"><TopNav /><section className="template-auth"><div className="template-auth-card"><h1>{signup ? 'Create your account' : 'Welcome back'}</h1><p>{signup ? 'Start keeping your scans and verified domains in one place.' : 'Sign in to access your scan history and verified domains.'}</p><form onSubmit={submit}><input required type="email" placeholder="Email address" value={email} onChange={event => setEmail(event.target.value)} /><input required minLength={8} type="password" placeholder="Password" value={password} onChange={event => setPassword(event.target.value)} /><button>{signup ? 'Create account' : 'Sign in'}</button></form><button className="template-text-button" onClick={() => setSignup(current => !current)}>{signup ? 'Already have an account? Sign in' : 'Need an account? Sign up'}</button></div></section></main>
}

function HistoryPage({ entries, onReload }: { entries: HistoryEntry[]; onReload: () => void }) {
  const [query, setQuery] = useState(''); const [type, setType] = useState('all'); const [severity, setSeverity] = useState('all')
  const [target, setTarget] = useState('http://localhost:3000'); const [scanning, setScanning] = useState(false); const [message, setMessage] = useState('')
  const filtered = entries.filter(entry => `${entry.target} ${entry.target_type ?? ''}`.toLowerCase().includes(query.toLowerCase()) && (type === 'all' || (entry.target_type ?? 'URL').toUpperCase().includes(type)) && (severity === 'all' || (entry.severity_counts?.[severity] ?? 0) > 0))
  async function remove(id: string) {
    const response = await fetch(`/api/history/${id}`, { method: 'DELETE' })
    if (!response.ok) { setMessage('The scan could not be deleted.'); return }
    onReload()
  }
  async function scanTarget(event: FormEvent) {
    event.preventDefault()
    const normalized = target.trim().replace(/\/$/, '')
    if (!/^https?:\/\//i.test(normalized)) { setMessage('Enter a URL beginning with http:// or https://.'); return }
    setScanning(true); setMessage(`Scanning ${normalized}…`)
    try {
      const response = await fetch(`/api/scan?target=${encodeURIComponent(normalized)}`)
      if (!response.ok) throw new Error('The scan could not complete.')
      await response.json()
      setMessage(`Scan saved for ${normalized}.`)
      onReload()
    } catch (error) { setMessage(error instanceof Error ? error.message : 'The scan failed.') } finally { setScanning(false) }
  }
  function reportFor(entry: HistoryEntry): ScanReport {
    return entry.report ?? { id: entry.id, target: entry.target, target_type: entry.target_type, scanned_at: entry.scanned_at, risk_score: entry.risk_score, findings: [] }
  }
  return <main className="template-home"><TopNav /><section className="template-body template-page"><div className="template-page-heading"><div className="template-section-label">ARCHIVE</div><h1>Full scan history</h1><p>Run a target repeatedly, then compare every saved report from this table.</p></div><form className="history-scan-form" onSubmit={scanTarget}><input required type="url" value={target} onChange={event => setTarget(event.target.value)} placeholder="https://your-target.example" disabled={scanning} /><button disabled={scanning}>{scanning ? 'Scanning…' : 'Run scan'}</button></form>{message && <p className="history-message">{message}</p>}<div className="history-filters"><input placeholder="Search target…" value={query} onChange={event => setQuery(event.target.value)} /><select value={type} onChange={event => setType(event.target.value)}><option value="all">All types</option><option value="URL">URL</option><option value="ZIP">ZIP</option></select><select value={severity} onChange={event => setSeverity(event.target.value)}><option value="all">All severity</option>{['critical', 'high', 'medium', 'low'].map(item => <option key={item} value={item}>{item}</option>)}</select></div><div className="template-history full-history"><table className="history-table"><thead><tr><th>Run time</th><th>Target</th><th>Type</th><th>Findings</th><th>Actions</th></tr></thead><tbody>{filtered.map(entry => <tr key={entry.id} onClick={() => navigate(`/scans/${entry.id}`)}><td>{new Date(entry.scanned_at).toLocaleString()}</td><td>{entry.target}</td><td>{entry.target_type ?? 'URL'}</td><td>{entry.total_findings ? Object.entries(entry.severity_counts ?? {}).map(([key, value]) => `${value} ${key}`).join(' · ') : 'No findings'}</td><td className="history-actions"><select aria-label={`Download report for ${entry.target}`} title="Download report" defaultValue="" onClick={event => event.stopPropagation()} onChange={event => { event.stopPropagation(); if (event.target.value) downloadReport(reportFor(entry), event.target.value); event.target.value = '' }}>  <option value="">download</option><option value="pdf">PDF</option><option value="json">JSON</option><option value="md">MD</option><option value="csv">CSV</option></select><button aria-label={`Delete ${entry.target}`} title="Delete scan" onClick={event => { event.stopPropagation(); void remove(entry.id) }}>×</button></td></tr>)}</tbody></table></div>{filtered.length === 0 && <p className="template-empty-history">No scans match these filters.</p>}</section></main>
}

function TopNav() {
  const [menuOpen, setMenuOpen] = useState(false)
  const menuItems = [
    ['Scanner', '/'],
    ['Scan history', '/history'],
    ['Verified domains', '/domains'],
    ['Settings', '/settings'],
    ['Sign in', '/login'],
  ]
  return <header className="template-nav"><a href="/" className="template-brand"><span>V</span> vibepen</a><span className="template-live"><i /> SCANNER ONLINE</span><div className="template-menu"><button className="template-menu-button" aria-label="Open navigation menu" aria-expanded={menuOpen} onClick={() => setMenuOpen(current => !current)}><span /><span /><span /></button>{menuOpen && <div className="template-menu-dialog" role="menu">{menuItems.map(([label, path]) => <a key={path} href={path} role="menuitem" onClick={event => { event.preventDefault(); setMenuOpen(false); navigate(path) }}>{label}</a>)}</div>}</div></header>
}

function SettingsPage() {
  return <main className="template-home"><TopNav /><section className="template-body template-page"><div className="template-section-label">ACCOUNT</div><h1>Settings</h1><div className="settings-grid"><section><h2>Profile</h2><p>Signed in as {JSON.parse(localStorage.getItem('vibepen-user') ?? '{"email":"guest"}').email}</p><button onClick={() => { localStorage.removeItem('vibepen-user'); navigate('/login') }}>Sign out</button></section><section><h2>Scan preferences</h2><p>Default scan options and account preferences will appear here.</p></section></div></section></main>
}

function DomainsPage() {
  const [domains, setDomains] = useState<string[]>(JSON.parse(localStorage.getItem('vibepen-domains') ?? '[]'))
  const [domain, setDomain] = useState('')
  function verify(event: FormEvent) { event.preventDefault(); if (!domain) return; const normalized = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase(); const next = [...new Set([...domains, normalized])]; setDomains(next); localStorage.setItem('vibepen-domains', JSON.stringify(next)); setDomain('') }
  function remove(item: string) { const next = domains.filter(value => value !== item); setDomains(next); localStorage.setItem('vibepen-domains', JSON.stringify(next)) }
  return <main className="template-home"><TopNav /><section className="template-body template-page"><div className="template-section-label">SCAN ACCESS</div><h1>Verified domains</h1><p className="template-page-intro">Approve domains before scanning them. Local sandbox targets are trusted automatically.</p><section className="domain-manager"><form className="domain-add" onSubmit={verify}><input required placeholder="example.com" value={domain} onChange={event => setDomain(event.target.value)} /><button>Add verified domain</button></form>{domains.length === 0 && <p className="template-empty-history">No verified domains yet.</p>}{domains.map(item => <div className="verified-domain" key={item}><span className="domain-status">✓</span><strong>{item}</strong><span>Manual verification · active</span><button onClick={() => remove(item)}>Remove</button></div>)}</section></section></main>
}

export default function TemplateHome() {
  const [path, setPath] = useState(window.location.pathname)
  const [target, setTarget] = useState(new URLSearchParams(window.location.search).get('rescan') ?? 'http://localhost:3000')
  const [status, setStatus] = useState('Ready to scan'); const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(0); const [currentCheck, setCurrentCheck] = useState('')
  const [report, setReport] = useState<ScanReport>({ target, risk_score: 0, findings: [] })
  const [history, setHistory] = useState<HistoryEntry[]>([]); const [uploadedFile, setUploadedFile] = useState('')
  const [verified, setVerified] = useState(false); const [findingStates, setFindingStates] = useState<Record<string, FindingState>>({})
  const sandbox = isSandboxDomain(target)
  useEffect(() => { const listener = () => setPath(window.location.pathname); window.addEventListener('popstate', listener); return () => window.removeEventListener('popstate', listener) }, [])
  async function loadHistory() {
    const response = await fetch('/api/history/all')
    if (response.ok) {
      const data = await response.json() as { history?: HistoryEntry[] }
      setHistory(data.history ?? [])
      return
    }
    const fallback = await fetch(`/api/history?target=${encodeURIComponent(target)}`)
    if (fallback.ok) {
      const data = await fallback.json() as { history?: HistoryEntry[] }
      setHistory(data.history ?? [])
    }
  }
  useEffect(() => { void loadHistory() }, [])
  useEffect(() => { if (path.startsWith('/scans/')) { void fetch(`/api/history/${path.split('/')[2]}`).then(response => response.ok ? response.json() : null).then(data => data && setReport(data)) } }, [path])
  useEffect(() => { setVerified(isSandboxDomain(target) || isVerifiedDomain(target)) }, [target])
  async function runScan(event: FormEvent) { event.preventDefault(); if (scanning || !target.trim() || !verified) return; setScanning(true); setProgress(5); setStatus('Scanning target…'); const checks = ['Resolving target', 'Checking headers', 'Testing authentication', 'Reviewing injection points', 'Building report']; let timer = 0; const interval = window.setInterval(() => { timer = Math.min(timer + 1, checks.length - 1); setProgress(Math.min(90, (timer + 1) * 18)); setCurrentCheck(checks[timer]) }, 500); try { const response = await fetch(`/api/scan?target=${encodeURIComponent(target.trim().replace(/\/$/, ''))}`); if (!response.ok) throw new Error('The scan could not complete.'); const data = await response.json() as ScanReport; setReport(data); setProgress(100); setStatus('Scan complete'); await loadHistory() } catch (error) { setStatus(error instanceof Error ? error.message : 'Scan failed') } finally { window.clearInterval(interval); setScanning(false) } }
  async function chooseArchive(event: ChangeEvent<HTMLInputElement>) { const file = event.target.files?.[0]; if (!file) return; setUploadedFile(file.name); setScanning(true); setStatus(`Analyzing ${file.name}…`); const formData = new FormData(); formData.append('file', file); try { const response = await fetch('/api/scan/upload', { method: 'POST', body: formData }); if (!response.ok) throw new Error('The source scan could not complete.'); setReport(await response.json() as ScanReport); setStatus('Scan complete'); await loadHistory() } catch (error) { setStatus(error instanceof Error ? error.message : 'Source scan failed') } finally { setScanning(false); event.target.value = '' } }
  if (path === '/login' || path === '/signup') return <AuthPage />
  if (path === '/history') return <HistoryPage entries={history} onReload={() => void loadHistory()} />
  if (path === '/domains') return <DomainsPage />
  if (path === '/settings') return <SettingsPage />
  if (path.startsWith('/scans/')) return <main className="template-home"><TopNav /><section className="template-body template-page"><div className="template-section-label">PAST SCAN REPORT</div><h1>{report.target}</h1><p>{report.scanned_at ? new Date(report.scanned_at).toLocaleString() : 'Archived run'}</p><ReportView report={report} findingStates={findingStates} /></section></main>
  return <main className="template-home"><TopNav /><section className="template-hero"><div className="template-hero-shade" /><div className="template-hero-copy"><p>WEB SECURITY / CONTINUOUS VISIBILITY</p><h1>VibePen</h1><span>Your web security scanner</span><p className="template-hero-description">Discover exposed endpoints, weak configurations, and application vulnerabilities before they become incidents.</p><a className="template-down-arrow" href="#template-scanner">↓</a></div></section><section className="template-body" id="template-scanner"><form onSubmit={runScan}><div className="template-input"><span>↗</span><input value={target} onChange={event => setTarget(event.target.value)} disabled={scanning} /><button disabled={scanning || !verified}>{scanning ? 'Scanning…' : 'Run New Scan'}</button></div><div className={`domain-verification ${verified ? 'verified' : ''}`}><strong>{verified ? '✓ Domain verified' : 'Domain verification required'}</strong><span>{verified ? (sandbox ? 'Local sandbox target is trusted automatically.' : 'This target is approved for scanning.') : 'Verify this domain from the Verified domains page before starting a scan.'}</span>{!verified && <button type="button" onClick={() => navigate('/domains')}>Verify domain</button>}</div><div className="template-meta"><span>● {status}{scanning && ` · ${currentCheck} · ${progress}%`}</span></div><div className="template-progress" aria-label="Scan progress"><span style={{ width: `${progress}%` }} /></div><label className="template-upload"><span>↥</span><strong>Scan source code ZIP</strong><small>Upload a .zip for static analysis</small><input type="file" accept=".zip,application/zip" onChange={chooseArchive} /></label>{uploadedFile && <small className="template-uploaded">{uploadedFile}</small>}</form>{scanning && <div className="live-scan"><strong>Live scan in progress</strong><span>{currentCheck || 'Preparing checks'} · {progress}%</span></div>}<ReportView report={report} findingStates={findingStates} onFindingState={(id, state) => setFindingStates(current => ({ ...current, [id]: state }))} /><section className="template-original-section template-history" id="template-history"><h2>▦ Scan run history <button onClick={() => navigate('/history')}>View all history →</button></h2><div className="template-history-head"><span>Timestamp</span><span>Scan type</span><span>Findings</span><span>Status</span></div>{history.slice(0, 10).map(entry => <div className="template-history-row history-clickable" key={entry.id} onClick={() => navigate(`/scans/${entry.id}`)}><span>{new Date(entry.scanned_at).toLocaleString()}<small>{entry.target}</small></span><span>{entry.target_type ?? 'URL'}</span><span>{entry.total_findings ? Object.entries(entry.severity_counts ?? {}).map(([severity, count]) => `${count} ${severity}`).join(' · ') : 'No findings'}</span><b>Complete</b></div>)}</section></section></main>
}
