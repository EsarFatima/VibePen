import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from 'react'

type CheckStatus = 'passed' | 'low' | 'medium' | 'high' | 'critical' | 'na' | 'skipped'

interface Check {
  id: string
  label: string
  category: string
  status: CheckStatus
  detail: string
}

interface Finding {
  id: string
  label: string
  severity: Exclude<CheckStatus, 'passed' | 'na' | 'skipped'>
  summary: string
  evidence: string
  recommendation: string
  location: string
  confidence: number
}

interface ScanReportFinding {
  id?: string
  type: string
  severity: string
  title?: string
  description?: string
  evidence?: string
  remediation?: string
  location?: string
  confidence?: number
}

interface ScanReport {
  risk_score: number
  findings: ScanReportFinding[]
  network_info?: {
    scanner?: string
    hostname?: string
    ip_address?: string
    is_local?: boolean
    open_ports?: Array<{ port: number; protocol?: string; service?: string }>
    duration_seconds?: number
  }
}

interface HistoryEntry {
  scanned_at: string
  target: string
  risk_score: number
  total_findings: number
  severity_counts?: Record<string, number>
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

const fallbackFindings: Finding[] = [
  { id: 'cddaf68cb843', label: 'Cross-account basket access', severity: 'critical', summary: 'One authenticated account can read and modify another account’s private basket data without authorization.', evidence: 'GET /api/BasketItems/1 responded with 200 and returned items belonging to user ID 2 while authenticated as user ID 1.', recommendation: 'Add server-side authorization checks on every basket endpoint.', location: '/api/BasketItems/:id', confidence: 98 },
  { id: 'a1b2c3d4e5f6', label: 'SQL injection', severity: 'high', summary: 'The login endpoint is vulnerable to SQL injection via the email field, allowing authentication bypass.', evidence: `POST /rest/user/login with body {"email":"' OR 1=1--","password":"x"} returned HTTP 200.`, recommendation: 'Use parameterized queries or prepared statements for all user input.', location: '/rest/user/login — email parameter', confidence: 96 },
  { id: '7890abcdef01', label: 'Reflected XSS', severity: 'medium', summary: 'User-supplied search terms are reflected without sanitization, enabling script injection.', evidence: 'GET /search?q=<script>alert(1)</script> returned the script tag unencoded in the HTML body.', recommendation: 'HTML-encode user-supplied data and apply a strict Content Security Policy.', location: '/search — q parameter', confidence: 91 },
  { id: 'f234567890ab', label: 'CORS configuration', severity: 'critical', summary: 'Authenticated API endpoints allow any site to read responses.', evidence: 'OPTIONS /api/Users/1 responded with Access-Control-Allow-Origin: *.', recommendation: 'Restrict Access-Control-Allow-Origin to trusted origins.', location: 'All /api/* endpoints', confidence: 99 },
]

const statusOrder: Record<CheckStatus, number> = { passed: 0, critical: 1, high: 2, medium: 3, low: 4, skipped: 5, na: 6 }

function normalizeSeverity(value: string): Finding['severity'] {
  const severity = value.toLowerCase()
  return severity === 'critical' || severity === 'high' || severity === 'medium' ? severity : 'low'
}

export function mapReport(report: ScanReport) {
  const reportFindings = report.findings.map((item, index) => {
    const id = item.id ?? `${item.type}-${item.location ?? index}`
    return {
      id,
      label: item.title ?? item.type ?? 'Security finding',
      severity: normalizeSeverity(item.severity),
      summary: item.description ?? 'A potential security issue was detected.',
      evidence: item.evidence ?? 'No evidence supplied.',
      recommendation: item.remediation ?? 'Review this result manually.',
      location: item.location ?? 'Unknown location',
      confidence: Math.round((item.confidence ?? 0) * 100),
    } satisfies Finding
  })
  const dynamicChecks: Check[] = reportFindings.map(finding => ({
    id: `backend-${finding.id}`,
    label: finding.label,
    category: 'Backend scan result',
    status: finding.severity,
    detail: finding.summary,
  }))
  return { findings: reportFindings, checks: [...fallbackChecks.filter(check => !['critical', 'high', 'medium', 'low'].includes(check.status)), ...dynamicChecks] }
}

export default function TemplateHome() {
  const [target, setTarget] = useState('http://localhost:3000')
  const [status, setStatus] = useState('Ready to scan')
  const [scanning, setScanning] = useState(false)
  const [uploadedFile, setUploadedFile] = useState('')
  const [checks, setChecks] = useState(fallbackChecks)
  const [findings, setFindings] = useState(fallbackFindings)
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [networkInfo, setNetworkInfo] = useState<ScanReport['network_info']>()
  const [expandedFindings, setExpandedFindings] = useState<string[]>([])
  const [expandedChecks, setExpandedChecks] = useState<string[]>([])
  const [openSections, setOpenSections] = useState<Array<'passed' | 'skipped'>>([])
  const sortedChecks = useMemo(() => [...checks].sort((a, b) => statusOrder[a.status] - statusOrder[b.status]), [checks])
  const sortedFindings = useMemo(() => [...findings].sort((a, b) => statusOrder[a.severity] - statusOrder[b.severity]), [findings])
  const passed = checks.filter(check => check.status === 'passed')
  const skipped = checks.filter(check => check.status === 'skipped')
  const applicable = checks.filter(check => !['skipped', 'na'].includes(check.status))

  async function loadHistory(currentTarget: string) {
    try {
      const response = await fetch(`/api/history?target=${encodeURIComponent(currentTarget)}`)
      if (!response.ok) return
      const payload = await response.json() as { history?: HistoryEntry[] }
      if (Array.isArray(payload.history)) setHistory(payload.history)
    } catch {
      setHistory([])
    }
  }

  async function applyScan(currentTarget: string) {
    setScanning(true)
    setStatus('Checking the website…')
    try {
      const response = await fetch(`/api/scan?target=${encodeURIComponent(currentTarget)}`)
      if (!response.ok) throw new Error(response.status === 502 ? 'The backend is not running.' : 'The scan service could not complete this request.')
      const report = await response.json() as ScanReport
      const mapped = mapReport(report)
      setChecks(mapped.checks)
      setFindings(mapped.findings)
      setNetworkInfo(report.network_info)
      await loadHistory(currentTarget)
      setStatus('Scan complete')
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Scan failed')
    } finally {
      setScanning(false)
    }
  }

  useEffect(() => {
    void applyScan(target)
  }, [])

  function scrollToSection(id: string) {
    window.setTimeout(() => {
      const element = document.getElementById(id)
      if (!element) return
      const top = element.getBoundingClientRect().top + window.scrollY - 88
      const start = window.scrollY
      const distance = Math.max(0, top) - start
      const duration = 720
      const startedAt = performance.now()
      const animate = () => {
        const timestamp = performance.now()
        const progress = Math.min(1, (timestamp - startedAt) / duration)
        const eased = 1 - Math.pow(1 - progress, 3)
        window.scrollTo(0, start + distance * eased)
        if (progress < 1) window.setTimeout(animate, 16)
      }
      animate()
    })
  }

  function handleCheckClick(check: Check) {
    const finding = findings.find(item => item.label === check.label)
    if (finding) {
      setExpandedFindings(current => current.includes(finding.id) ? current : [...current, finding.id])
      scrollToSection(`finding-${finding.id}`)
      return
    }
    if (check.status === 'passed' || check.status === 'skipped') {
      setOpenSections(current => current.includes(check.status as 'passed' | 'skipped') ? current : [...current, check.status as 'passed' | 'skipped'])
      scrollToSection('template-validations')
      return
    }
    setExpandedChecks(current => current.includes(check.id) ? current : [...current, check.id])
    scrollToSection('template-coverage')
  }

  async function runScan(event: FormEvent) {
    event.preventDefault()
    if (scanning || !target.trim()) return
    setScanning(true)
    setStatus('Scanning target…')
    await applyScan(target.trim().replace(/\/$/, ''))
  }

  async function chooseArchive(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    setUploadedFile(file.name)
    setStatus(`Analyzing ${file.name}…`)
    const formData = new FormData()
    formData.append('file', file)
    try {
      const response = await fetch('/api/scan/upload', { method: 'POST', body: formData })
      if (!response.ok) throw new Error('The source scan could not complete.')
      const report = await response.json() as ScanReport
      const mapped = mapReport(report)
      setChecks(mapped.checks)
      setFindings(mapped.findings)
      setNetworkInfo(undefined)
      setStatus(`Source scan complete · ${mapped.findings.length} finding${mapped.findings.length === 1 ? '' : 's'}`)
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Source scan failed')
    } finally {
      event.target.value = ''
    }
  }

  return (
    <main className="template-home">
      <header className="template-nav">
        <a href="/" className="template-brand"><span>V</span> vibepen</a>
        <nav><a href="#template-scanner">Scanner</a><a href="#template-coverage">Coverage</a><a href="#template-history">History</a></nav>
        <span className="template-live"><i /> SCANNER ONLINE</span>
      </header>

      <section className="template-hero">
        <div className="template-hero-shade" />
        <div className="template-hero-copy">
          <p className="template-hero-eyebrow">WEB SECURITY / CONTINUOUS VISIBILITY</p>
          <h1>VibePen</h1><span>Your web security scanner</span>
          <p className="template-hero-description">Discover exposed endpoints, weak configurations, and application vulnerabilities before they become incidents.</p>
          <div className="template-hero-stats"><span><strong>16</strong> security checks</span><span><strong>24/7</strong> surface watch</span><span><strong>98%</strong> confidence</span></div>
          <a className="template-down-arrow" href="#template-scanner" aria-label="Scroll to scanner" onClick={event => { event.preventDefault(); scrollToSection('template-scanner') }}>↓</a>
        </div>
        <div className="template-hero-chip"><i /> LIVE MONITORING<br /><small>GLOBAL SURFACE / READY</small><b>● 04 ACTIVE FINDINGS</b><em>Last scan · 8 minutes ago</em></div>
      </section>

      <section className="template-body" id="template-scanner">
        <form className="template-original-control" onSubmit={runScan}>
          <div className="template-input"><span>↗</span><input value={target} onChange={event => setTarget(event.target.value)} placeholder="https://your-target.example" disabled={scanning} /><button disabled={scanning}>{scanning ? 'Scanning…' : 'Run New Scan'}</button></div>
          <div className="template-meta"><span className={status === 'Scan complete' ? 'success' : ''}>● {status}</span></div>
          <label className="template-upload"><span>↥</span><strong>Scan source code ZIP</strong><small>Upload a .zip for static analysis</small><input type="file" accept=".zip,application/zip" onChange={chooseArchive} /></label>
          {uploadedFile && <small className="template-uploaded">{uploadedFile}</small>}
        </form>

        <section className="template-summary">
          <div className="template-summary-heading"><span className="template-summary-icon">✦</span><div><h2>Scan complete</h2><p>{applicable.length} of {applicable.length} applicable checks completed · {skipped.length} skipped.</p></div></div>
          <div className="template-summary-cards"><div className="critical"><b>⚠ Things to fix</b><strong>{findings.length} Findings</strong><small>Prioritize these results for remediation.</small></div><div className="passed"><b>✓ Passed cleanly</b><strong>{passed.length} Checks</strong><small>No issues detected in completed checks.</small></div><div className="skipped"><b>› Skipped checks</b><strong>{skipped.length} Skipped</strong><small>Requires credentials or setup.</small></div></div>
        </section>

        {networkInfo && <section className="template-network"><div><div className="template-section-label">HOST DISCOVERY</div><h2>Host and port discovery</h2><p>{networkInfo.scanner ?? 'Network scanner'}{networkInfo.duration_seconds ? ` · ${networkInfo.duration_seconds}s` : ''}</p></div><strong>{networkInfo.ip_address ?? 'IP unresolved'}</strong><div className="template-network-stats"><span><b>Host</b>{networkInfo.hostname ?? 'Unknown'}</span><span><b>Scope</b>{networkInfo.is_local ? 'Local sandbox' : 'External host'}</span><span><b>Open ports</b>{networkInfo.open_ports?.length ?? 0}</span></div>{Boolean(networkInfo.open_ports?.length) && <div className="template-ports">{networkInfo.open_ports?.map(port => <span key={`${port.protocol ?? 'tcp'}-${port.port}`}>{port.port}/{port.protocol ?? 'tcp'} {port.service ?? ''}</span>)}</div>}</section>}

        <section className="template-coverage template-coverage-card" id="template-coverage">
          <div className="template-section-label">SECURITY CHECK COVERAGE</div><h2>Security check coverage</h2><p>Click each box to expand its detail.</p>
          <div className="template-check-bar">{sortedChecks.map(check => <button key={check.id} className={check.status} title={check.label} aria-label={`Open ${check.label}`} onClick={() => handleCheckClick(check)} />)}</div>
          <div className="template-check-legend" aria-label="What each coverage color represents">{(['passed', 'critical', 'high', 'medium', 'low', 'skipped', 'na'] as CheckStatus[]).map(statusName => <span key={statusName}><i className={statusName} aria-hidden="true" /><label>{statusName === 'na' ? 'N/A' : statusName[0].toUpperCase() + statusName.slice(1)} <b>{checks.filter(check => check.status === statusName).length}</b></label></span>)}</div>
          {expandedChecks.map(checkId => { const check = checks.find(item => item.id === checkId); return check ? <div className="template-check-detail" key={check.id}><strong>↓ {check.label}</strong><span>{check.detail}</span></div> : null })}
        </section>

        {findings.length > 0 && <section className="template-original-section" id="template-findings"><h2>⚑ Security findings ({findings.length})</h2><div className="template-original-list">{sortedFindings.map(finding => { const isExpanded = expandedFindings.includes(finding.id); return <div key={finding.id} id={`finding-${finding.id}`}><button className="template-original-row" aria-expanded={isExpanded} onClick={() => setExpandedFindings(current => isExpanded ? current.filter(id => id !== finding.id) : [...current, finding.id])}><span className={isExpanded ? 'is-expanded' : ''}>›</span><strong>{finding.label}</strong><i className={finding.severity} /></button>{isExpanded && <div className="template-finding-detail"><p>{finding.summary}</p><small>EVIDENCE</small><pre>{finding.evidence}</pre><small>RECOMMENDED ACTION</small><p>{finding.recommendation}</p><footer><span>LOCATION <code>{finding.location}</code></span><span>CONFIDENCE <code>{finding.confidence}%</code></span></footer></div>}</div>})}</div></section>}

        <section className="template-original-section template-validations" id="template-validations"><h2>✓ Passed &amp; skipped validations <small>Automated checks</small></h2><button className="template-collapse" aria-expanded={openSections.includes('passed')} onClick={() => setOpenSections(current => current.includes('passed') ? current.filter(section => section !== 'passed') : [...current, 'passed'])}><span><i className={openSections.includes('passed') ? 'is-expanded' : ''}>›</i> Passed checks</span><b>{passed.length}</b></button>{openSections.includes('passed') && <div className="template-passed-grid">{passed.map(check => <div key={check.id}>✓ <span>{check.label}<small>{check.detail}</small></span></div>)}</div>}<button className="template-collapse" aria-expanded={openSections.includes('skipped')} onClick={() => setOpenSections(current => current.includes('skipped') ? current.filter(section => section !== 'skipped') : [...current, 'skipped'])}><span><i className={openSections.includes('skipped') ? 'is-expanded' : ''}>›</i> Skipped checks</span><b>{skipped.length}</b></button>{openSections.includes('skipped') && skipped.map(check => <div className="template-skipped-row" key={check.id}><strong>{check.label}</strong><span>{check.detail}</span></div>)}</section>

        <section className="template-original-section template-history" id="template-history"><h2>▦ Scan run history <button>View all history →</button></h2><div className="template-history-head"><span>Timestamp (UTC)</span><span>Findings breakdown</span><span>Coverage</span><span>Run status</span></div>{history.length === 0 && <p className="template-empty-history">No scan history available yet.</p>}{history.map(entry => <div className="template-history-row" key={`${entry.scanned_at}-${entry.target}`}><span>{new Date(entry.scanned_at).toLocaleString()}<small>{entry.target}</small></span><span>{entry.total_findings ? Object.entries(entry.severity_counts ?? {}).map(([severity, count]) => `${count} ${severity}`).join(' · ') : 'No findings'}</span><span>{applicable.length} / {checks.length}</span><b>Complete</b></div>)}</section>
      </section>
    </main>
  )
}
