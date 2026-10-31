import { ChangeEvent, FormEvent, useMemo, useState } from 'react'

type Severity = 'critical' | 'high' | 'medium'
type MonitorStyle = 'radar' | 'pulse' | 'matrix'
type CheckStatus = 'passed' | 'low' | 'medium' | 'high' | 'critical' | 'na' | 'skipped'

interface MockFinding {
  title: string
  detail: string
  location: string
  severity: Severity
}

const findings: MockFinding[] = [
  { title: 'Cross-account basket access', detail: 'Private basket data is accessible without an owner check.', location: '/api/BasketItems/:id', severity: 'critical' },
  { title: 'SQL injection', detail: 'The login endpoint accepts unsanitized input in the email field.', location: '/rest/user/login', severity: 'high' },
  { title: 'Reflected XSS', detail: 'Search terms are reflected without HTML encoding.', location: '/search — q parameter', severity: 'medium' },
]

interface MockCheck {
  id: string
  label: string
  category: string
  status: CheckStatus
  detail: string
}

const checks: MockCheck[] = [
  { id: 'brute-force', label: 'Brute-force protection', category: 'Authentication & access control', status: 'passed', detail: 'Login attempts are rate limited.' },
  { id: 'basket-access', label: 'Cross-account basket access', category: 'Authentication & access control', status: 'critical', detail: 'One account can access another account’s private basket data.' },
  { id: 'user-area', label: 'Authenticated user area', category: 'Authentication & access control', status: 'passed', detail: 'Authenticated routes require a valid session.' },
  { id: 'privilege', label: 'Privilege escalation', category: 'Authentication & access control', status: 'skipped', detail: 'Two authorized test accounts were not provided.' },
  { id: 'sql', label: 'SQL injection', category: 'Injection & input handling', status: 'high', detail: 'The login endpoint accepts unsanitized input in the email field.' },
  { id: 'xss', label: 'Reflected XSS', category: 'Injection & input handling', status: 'medium', detail: 'Search terms are reflected without HTML encoding.' },
  { id: 'command', label: 'Command injection', category: 'Injection & input handling', status: 'passed', detail: 'No command injection was detected.' },
  { id: 'xxe', label: 'XXE / XML injection', category: 'Injection & input handling', status: 'na', detail: 'The target does not expose an XML processing surface.' },
  { id: 'csp', label: 'Content Security Policy', category: 'Browser safety', status: 'passed', detail: 'A content security policy is present.' },
  { id: 'cors', label: 'CORS configuration', category: 'Browser safety', status: 'critical', detail: 'Authenticated endpoints allow wildcard origins.' },
  { id: 'clickjacking', label: 'Clickjacking protection', category: 'Browser safety', status: 'passed', detail: 'Frame embedding is restricted.' },
  { id: 'stack-trace', label: 'Stack trace disclosure', category: 'Error handling', status: 'passed', detail: 'No stack traces were exposed in error responses.' },
  { id: 'verbose-errors', label: 'Verbose error messages', category: 'Error handling', status: 'na', detail: 'No applicable error surface was found.' },
  { id: 'https', label: 'HTTPS redirect', category: 'Configuration & transport', status: 'passed', detail: 'HTTP requests redirect to HTTPS.' },
  { id: 'hsts', label: 'HSTS header', category: 'Configuration & transport', status: 'skipped', detail: 'Could not verify HSTS because HTTPS-only access may be required.' },
  { id: 'tls', label: 'TLS version check', category: 'Configuration & transport', status: 'na', detail: 'TLS could not be evaluated for this local target.' },
]

const navItems = ['Overview', 'Findings', 'Scan history']
const statusColors: Record<CheckStatus, string> = {
  passed: '#63d19a',
  low: '#7fc9e7',
  medium: '#e6d37d',
  high: '#f0ad6c',
  critical: '#ff887b',
  na: '#6e8588',
  skipped: '#6e8588',
}
const statusOrder: Record<CheckStatus, number> = {
  passed: 0,
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  skipped: 5,
  na: 6,
}

export default function MockApp() {
  const [activeNav, setActiveNav] = useState('Overview')
  const [target, setTarget] = useState('http://localhost:3000')
  const [status, setStatus] = useState('Ready to scan')
  const [isScanning, setIsScanning] = useState(false)
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)
  const [uploadedFile, setUploadedFile] = useState('')
  const [monitorStyle, setMonitorStyle] = useState<MonitorStyle>('radar')
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null)
  const [openResultSection, setOpenResultSection] = useState<'findings' | 'passed' | 'skipped' | null>(null)

  const totalChecks = 16
  const completedChecks = 11
  const progress = useMemo(() => (completedChecks / totalChecks) * 100, [])
  const sortedChecks = useMemo(() => [...checks].sort((a, b) => statusOrder[a.status] - statusOrder[b.status]), [])
  const resultCounts = useMemo(() => ({
    findings: checks.filter(check => ['critical', 'high', 'medium', 'low'].includes(check.status)).length,
    passed: checks.filter(check => check.status === 'passed').length,
    skipped: checks.filter(check => check.status === 'skipped').length,
  }), [])

  async function runScan(event: FormEvent) {
    event.preventDefault()
    if (!target.trim() || isScanning) return
    setIsScanning(true)
    setStatus('Scanning target…')
    try {
      const response = await fetch(`/api/scan?target=${encodeURIComponent(target.trim())}`)
      if (!response.ok) throw new Error('Scan service returned an error')
      setStatus('Scan complete')
    } catch {
      setStatus('Preview complete · API unavailable')
    } finally {
      setIsScanning(false)
    }
  }

  async function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    setUploadedFile(file.name)
    setStatus(`Analyzing ${file.name}…`)
    const formData = new FormData()
    formData.append('file', file)
    try {
      const response = await fetch('/api/scan/upload', { method: 'POST', body: formData })
      if (!response.ok) throw new Error('Source scan returned an error')
      const report = await response.json() as { total_findings?: number }
      setStatus(`Source scan complete · ${report.total_findings ?? 0} findings`)
    } catch {
      setStatus(`${file.name} ready · API unavailable in preview`)
    }
  }

  return (
    <main className="mock-shell">
      <header className="mock-nav">
        <a className="mock-brand" href="?mock=1" aria-label="VibePen home">
          <span className="brand-mark">V</span>
          <span>vibepen</span>
        </a>
        <nav className="mock-nav-links" aria-label="Main navigation">
          {navItems.map(item => (
            <button className={activeNav === item ? 'active' : ''} key={item} onClick={() => setActiveNav(item)}>
              {item}
            </button>
          ))}
        </nav>
        <div className="mock-nav-actions">
          <span className="live-dot" /> <span>Scanner online</span>
          <button className="icon-button" aria-label="Open settings">⌘</button>
        </div>
      </header>

      <section className="mock-hero landing-art">
        <div className="landing-overlay" />
        <div className="hero-copy">
          <h1>VibePen</h1>
          <p>Your web security scanner</p>
          <button className="hero-cta" onClick={() => document.getElementById('scanner-panel')?.scrollIntoView({ behavior: 'smooth' })}>Start scanning ↘</button>
        </div>
        <div className="hero-status"><span className="live-dot" /> LIVE SCANNER / READY</div>
      </section>

      <section className="mock-content" id="scanner-panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">01 / CONTROL PANEL</p>
            <h2>Start a new scan</h2>
          </div>
          <span className="section-note">Last scan · 8 minutes ago</span>
        </div>

        <form className="scan-form" onSubmit={runScan}>
          <label htmlFor="mock-target">Target URL</label>
          <div className="scan-input-wrap">
            <span className="input-prefix">↗</span>
            <input id="mock-target" value={target} onChange={event => setTarget(event.target.value)} />
            <button type="submit" className="scan-button" disabled={isScanning}>{isScanning ? 'Scanning…' : 'Run scan ↗'}</button>
          </div>
          <div className="form-meta"><span className={status.includes('complete') ? 'status-success' : ''}>● {status}</span><span>Checks run against public endpoints only</span></div>
        </form>

        <div className="monitor-options">
          <div><p className="eyebrow">LIVE MONITORING</p><h3>Choose a visual signal</h3></div>
          <div className="monitor-tabs">
            {([
              ['radar', 'Radar sweep'],
              ['pulse', 'Pulse line'],
              ['matrix', 'Signal matrix'],
            ] as const).map(([style, label]) => <button key={style} className={monitorStyle === style ? 'selected' : ''} onClick={() => setMonitorStyle(style)}>{label}</button>)}
          </div>
          <div className={`monitor-preview ${monitorStyle}`} aria-label={`${monitorStyle} live monitoring preview`}>
            {monitorStyle === 'radar' && <><div className="preview-radar"><span /><span /><i /></div><strong>SCANNING SURFACE</strong></>}
            {monitorStyle === 'pulse' && <><div className="pulse-line"><i /><i /><i /><i /><i /></div><strong>REQUEST STREAM / 124 RPM</strong></>}
            {monitorStyle === 'matrix' && <><div className="matrix-grid">{Array.from({ length: 24 }, (_, index) => <i key={index} />)}</div><strong>ENDPOINTS MAPPED / 16</strong></>}
          </div>
        </div>

        <section className="result-overview" aria-labelledby="result-overview-heading">
          <div className="result-title"><p className="eyebrow">SCAN RESULTS</p><h2 id="result-overview-heading">Security check coverage</h2><p>Click a segment or result group to expand its details.</p></div>
          <div className="result-bar" role="list" aria-label="Security check statuses">
            {sortedChecks.map(check => <button key={check.id} className={`result-segment status-${check.status}`} title={`${check.label}: ${check.status}`} aria-label={`${check.label}: ${check.status}`} onClick={() => setExpandedCheck(expandedCheck === check.id ? null : check.id)} />)}
          </div>
          <div className="result-legend">
            {([
              ['passed', 'Passed'],
              ['critical', 'Critical'],
              ['high', 'High'],
              ['medium', 'Medium'],
              ['skipped', 'Skipped'],
              ['na', 'N/A'],
            ] as const).map(([status, label]) => <span key={status}><i className={`legend-swatch status-${status}`} />{label} <strong>{checks.filter(check => check.status === status).length}</strong></span>)}
          </div>
          {expandedCheck && <div className="check-detail"><span className={`severity ${checks.find(check => check.id === expandedCheck)?.status}`}>{checks.find(check => check.id === expandedCheck)?.status}</span><strong>{checks.find(check => check.id === expandedCheck)?.label}</strong><span>{checks.find(check => check.id === expandedCheck)?.detail}</span></div>}
          <div className="result-cards">
            <button className={`result-card result-card-findings ${openResultSection === 'findings' ? 'open' : ''}`} onClick={() => setOpenResultSection(openResultSection === 'findings' ? null : 'findings')}><span>⚠</span><small>THINGS TO FIX</small><strong>{resultCounts.findings} Findings</strong><em>Prioritize these results for remediation. ↘</em></button>
            <button className={`result-card result-card-passed ${openResultSection === 'passed' ? 'open' : ''}`} onClick={() => setOpenResultSection(openResultSection === 'passed' ? null : 'passed')}><span>✓</span><small>PASSED CLEANLY</small><strong>{resultCounts.passed} Checks</strong><em>No issues detected in completed checks. ↘</em></button>
            <button className={`result-card result-card-skipped ${openResultSection === 'skipped' ? 'open' : ''}`} onClick={() => setOpenResultSection(openResultSection === 'skipped' ? null : 'skipped')}><span>→</span><small>SKIPPED CHECKS</small><strong>{resultCounts.skipped} Skipped</strong><em>Requires credentials or setup. ↘</em></button>
          </div>
          {openResultSection && <div className="result-list">{checks.filter(check => openResultSection === 'findings' ? ['critical', 'high', 'medium', 'low'].includes(check.status) : check.status === openResultSection).map(check => <button key={check.id} onClick={() => setExpandedCheck(check.id)}><i className={`legend-swatch status-${check.status}`} /><span>{check.label}</span><small>{check.category}</small><b>↗</b></button>)}</div>}
        </section>

        <div className="upload-row">
          <div><strong>Scan a source archive</strong><span>Upload a .zip to inspect your codebase with static analysis.</span></div>
          <label className="upload-button">+ {uploadedFile || 'Choose .zip file'}<input type="file" accept=".zip" onChange={chooseFile} /></label>
        </div>

        <div className="section-heading findings-heading">
          <div><p className="eyebrow">02 / THREAT SURFACE</p><h2>Latest findings</h2></div>
          <button className="text-button" onClick={() => setActiveNav('Findings')}>View all findings ↗</button>
        </div>
        <div className="findings-grid">
          {findings.map((finding, index) => {
            const isOpen = expandedFinding === finding.title
            return (
              <article className={`finding-card ${isOpen ? 'expanded' : ''}`} key={finding.title}>
                <button className="finding-toggle" onClick={() => setExpandedFinding(isOpen ? null : finding.title)} aria-expanded={isOpen}>
                  <div className="finding-number">0{index + 1}</div>
                  <div className="finding-main"><span className={`severity ${finding.severity}`}>{finding.severity}</span><h3>{finding.title}</h3><span className="finding-location">{finding.location}</span></div>
                  <span className="finding-arrow">{isOpen ? '↘' : '↗'}</span>
                </button>
                {isOpen && <div className="finding-detail"><p>{finding.detail}</p><button className="detail-link">Open remediation guide ↗</button></div>}
              </article>
            )
          })}
        </div>
      </section>

      <section className="coverage-strip">
        <div><p className="eyebrow">03 / COVERAGE</p><h2>Every endpoint tells a story.</h2><p>VibePen checks authentication, injection, browser safety, error handling, and transport configuration in one focused pass.</p></div>
        <div className="coverage-meter"><div className="meter-top"><span>CHECKS COMPLETED</span><strong>{completedChecks}/{totalChecks}</strong></div><div className="meter-track"><span style={{ width: `${progress}%` }} /></div><div className="meter-labels"><span>0</span><span>Security health · 72%</span><span>{totalChecks}</span></div></div>
      </section>

      <footer className="mock-footer"><span>VIBEPEN / WEB SECURITY SCANNER</span><span>Built for the curious · 2026</span><a href="?">Return to existing dashboard ↗</a></footer>
    </main>
  )
}
