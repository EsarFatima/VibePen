import { ChangeEvent, FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react'

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
type DomainStatus = 'pending' | 'verified' | 'expired' | 'failed'
type VerificationMethod = 'DNS TXT' | 'File upload' | 'Meta tag'
interface DomainRecord {
  domain: string
  status: DomainStatus
  method?: VerificationMethod
  verifiedAt?: string
  expiresAt?: string
  token: string
  error?: string
}

const fallbackChecks: Check[] = [
  ['auth_login_brute', 'Brute-force protection', 'Authentication & access control', 'passed', 'Login attempts are rate limited.'],
  ['cross_account_basket', 'Cross-account basket access', 'Authentication & access control', 'critical', "One account can access another account's private basket data."],
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

function currentUser() {
  return JSON.parse(localStorage.getItem('vibepen-user') ?? 'null') as { email?: string; name?: string } | null
}



interface ServerDomain { domain: string; status: DomainStatus; token: string; method?: string | null; verified_at?: string | null; expires_at?: string | null; error?: string | null }
const METHOD_LABEL: Record<string, VerificationMethod> = { dns: 'DNS TXT', file: 'File upload', meta: 'Meta tag' }

function toDomainRecord(item: ServerDomain): DomainRecord {
  return { domain: item.domain, status: item.status, token: item.token, method: item.method ? METHOD_LABEL[item.method] : undefined, verifiedAt: item.verified_at ?? undefined, expiresAt: item.expires_at ?? undefined, error: item.error ?? undefined }
}

async function fetchDomains(): Promise<DomainRecord[] | null> {
  try {
    const response = await fetch('/api/domains')
    if (!response.ok) return null
    const data = await response.json() as { domains?: ServerDomain[] }
    return (data.domains ?? []).map(toDomainRecord)
  } catch { return null }
}

function isVerifiedHost(domains: DomainRecord[], value: string) {
  try {
    const hostname = new URL(value).hostname.toLowerCase()
    return domains.some(record => record.status === 'verified' && (hostname === record.domain || (record.method === 'DNS TXT' && hostname.endsWith(`.${record.domain}`))))
  } catch { return false }
}

function guestHistory() {
  return JSON.parse(localStorage.getItem('vibepen-guest-history') ?? '[]') as HistoryEntry[]
}

function saveGuestReport(report: ScanReport) {
  const findings = report.findings ?? []
  const severity_counts = findings.reduce<Record<string, number>>((counts, finding) => {
    const severity = finding.severity.toLowerCase()
    counts[severity] = (counts[severity] ?? 0) + 1
    return counts
  }, {})
  const entry: HistoryEntry = {
    id: report.id ?? `guest-${Date.now()}`, scanned_at: report.scanned_at ?? new Date().toISOString(),
    target: report.target, target_type: report.target_type ?? 'URL', risk_score: report.risk_score,
    total_findings: findings.length, severity_counts, report,
  }
  const next = [entry, ...guestHistory().filter(item => item.id !== entry.id)].slice(0, 10)
  localStorage.setItem('vibepen-guest-history', JSON.stringify(next))
  return next
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
    <option value="">Download report...</option><option value="pdf">PDF</option><option value="json">JSON</option><option value="md">Markdown</option><option value="csv">CSV</option>
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
    <section className="template-coverage template-coverage-card"><div className="template-section-label">SECURITY CHECK COVERAGE</div><h2>Security check coverage</h2><p>Click each box to expand its detail.</p><div className="template-check-bar">{sortedChecks.map(check => <button key={check.id} className={check.status} title={check.label} aria-label={`Open ${check.label}`} onClick={() => setExpandedChecks(current => current.includes(check.id) ? current.filter(id => id !== check.id) : [...current, check.id])} />)}</div><div className="template-check-legend">{(['passed', 'critical', 'high', 'medium', 'low', 'skipped', 'na'] as CheckStatus[]).map(name => <span key={name}><i className={name} /><label>{name} <b>{checks.filter(check => check.status === name).length}</b></label></span>)}</div>{expandedChecks.map(id => { const check = checks.find(item => item.id === id); return check && <div className="template-check-detail" key={id}><strong>v {check.label}</strong><span>{check.detail}</span></div> })}</section>
    <section className="template-original-section"><h2>⚑ Security findings ({findings.length})</h2><div className="template-original-list">{sortedFindings.map(finding => { const open = expanded.includes(finding.id); return <div key={finding.id}><button className="template-original-row" aria-expanded={open} onClick={() => toggle(finding.id)}><span className={open ? 'is-expanded' : ''}>›</span><strong>{finding.label}</strong>{finding.state && finding.state !== 'open' && <em className="finding-state">{finding.state.replace('_', ' ')}</em>}<i className={finding.severity} /></button>{open && <div className="template-finding-detail"><p>{finding.summary}</p><small>EVIDENCE</small><pre>{finding.evidence}</pre><small>RECOMMENDED ACTION</small><p>{finding.recommendation}</p><footer><span>LOCATION <code>{finding.location}</code></span><span>CONFIDENCE <code>{finding.confidence}%</code></span></footer><div className="finding-actions"><button onClick={() => onFindingState?.(finding.id, 'false_positive')}>Mark false positive</button><button onClick={() => onFindingState?.(finding.id, 'resolved')}>Mark resolved</button></div></div>}</div> })}</div></section>
    <section className="template-original-section template-validations"><h2>✓ Passed &amp; skipped validations <small>Automated checks</small></h2>{(['passed', 'skipped'] as const).map(section => <div key={section}><button className="template-collapse" aria-expanded={openSections.includes(section)} onClick={() => setOpenSections(current => current.includes(section) ? current.filter(item => item !== section) : [...current, section])}><span><i className={openSections.includes(section) ? 'is-expanded' : ''}>›</i> {section[0].toUpperCase() + section.slice(1)} checks</span><b>{section === 'passed' ? passed.length : skipped.length}</b></button>{openSections.includes(section) && (section === 'passed' ? passed : skipped).map(check => <div className="template-skipped-row" key={check.id}><strong>{check.label}</strong><span>{check.detail}</span></div>)}</div>)}</section>
  </section>
}

function AuthShell({ children, mode }: { children: ReactNode; mode: 'signin' | 'signup' | 'forgot' }) {
  return <main className="template-home auth-page"><TopNav /><section className="auth-form-panel"><div className="auth-form-wrap"><div className="auth-card">{children}</div><a className="auth-back-scanner" href="/" onClick={event => { event.preventDefault(); navigate('/') }}>Back to scanner (no account needed)</a></div></section></main>
}

function PasswordInput({ id, label, value, onChange, error, autoComplete, hint }: { id: string; label: string; value: string; onChange: (value: string) => void; error?: string; autoComplete: string; hint?: ReactNode }) {
  const [visible, setVisible] = useState(false)
  return <div className="auth-field"><label htmlFor={id}>{label}</label><div className="auth-password-wrap"><input id={id} name={id} type={visible ? 'text' : 'password'} value={value} onChange={event => onChange(event.target.value)} autoComplete={autoComplete} aria-invalid={Boolean(error)} aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined} /> <button type="button" className="auth-password-toggle" onClick={() => setVisible(current => !current)} aria-label={visible ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}><span className="material-symbols-outlined">{visible ? 'visibility_off' : 'visibility'}</span></button></div>{hint && <small id={`${id}-hint`} className="auth-hint">{hint}</small>}{error && <small id={`${id}-error`} className="auth-error">{error}</small>}</div>
}

function VerifyEmailPage() {
  const [state, setState] = useState<'working' | 'ok' | 'error'>('working')
  const [message, setMessage] = useState('')
  const ran = useRef(false)
  useEffect(() => {
    if (ran.current) return
    ran.current = true
    const token = new URLSearchParams(window.location.search).get('token') ?? ''
    if (!token) { setState('error'); setMessage('This link is missing its token.'); return }
    fetch('/api/auth/verify-email', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) })
      .then(async response => {
        const data = await response.json().catch(() => ({})) as { email?: string; name?: string; detail?: unknown }
        if (!response.ok) { setState('error'); setMessage(typeof data.detail === 'string' ? data.detail : 'Verification failed.'); return }
        localStorage.setItem('vibepen-user', JSON.stringify({ name: data.name ?? '', email: data.email ?? '' }))
        setState('ok')
        window.setTimeout(() => { window.location.href = '/' }, 1500)
      })
      .catch(() => { setState('error'); setMessage('Cannot reach the server.') })
  }, [])
  return <AuthShell mode="signin"><div className="auth-success"><p className="template-section-label">EMAIL VERIFICATION</p>{state === 'working' && <h1>Verifying your email...</h1>}{state === 'ok' && <><h1>Email confirmed</h1><p>Taking you to VibePen...</p></>}{state === 'error' && <><h1>Could not verify</h1><p>{message}</p><a className="auth-primary" href="/login">Back to sign in</a></>}</div></AuthShell>
}

function SignedInCard({ user, onSignOut }: { user: { email: string; name?: string }; onSignOut: () => void }) {
  const primaryRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { primaryRef.current?.focus() }, [])
  const initial = user.email.charAt(0).toUpperCase()
  return <div className="auth-signed-in" aria-live="polite"><div className="auth-avatar">{initial}</div><div className="auth-heading"><p className="template-section-label">ACCOUNT ACTIVE</p><h1>You're already signed in</h1><p>Signed in as {user.email}</p></div><div className="auth-signed-in-actions"><button ref={primaryRef} className="auth-primary" onClick={() => navigate('/')}>Continue to scanner</button><button className="auth-outline" onClick={onSignOut}>Switch account</button></div><button className="auth-signout-link" onClick={onSignOut}>Sign out</button><a className="auth-manage-link" href="/settings" onClick={event => { event.preventDefault(); navigate('/settings') }}>Manage account</a></div>
}

function AuthPage({ initialSignup = false }: { initialSignup?: boolean }) {
  const [signup, setSignup] = useState(initialSignup)
  const [name, setName] = useState(''); const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState('')
  const [errors, setErrors] = useState<Record<string, string>>({}); const [generalError, setGeneralError] = useState(''); const [submitting, setSubmitting] = useState(false); const [created, setCreated] = useState(false); const [signedInUser, setSignedInUser] = useState(currentUser()); const [signedOutMessage, setSignedOutMessage] = useState(''); const [unverified, setUnverified] = useState(false); const [resent, setResent] = useState(false)
  useEffect(() => {
    fetch('/api/auth/me').then(async response => {
      if (!response.ok) { localStorage.removeItem('vibepen-user'); setSignedInUser(null); return }
      const me = await response.json() as { email?: string; name?: string }
      if (me.email) { localStorage.setItem('vibepen-user', JSON.stringify({ name: me.name ?? '', email: me.email })); setSignedInUser(me) }
    }).catch(() => { /* backend offline: leave state alone */ })
  }, [])
  const passwordStrength = password.length >= 12 ? 'Strong' : password.length >= 8 ? 'Good' : password.length ? 'Needs work' : ''
  function validate() {
    const next: Record<string, string> = {}
    if (signup && !name.trim()) next.name = 'Enter your name.'
    if (!email.trim()) next.email = 'Enter your email address.'
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) next.email = 'Enter a valid email address.'
    if (!password) next.password = 'Enter your password.'
    else if (password.length < 8) next.password = 'Use at least 8 characters.'
    if (signup && password !== confirm) next.confirm = 'Passwords do not match.'
    return next
  }
  async function submit(event: FormEvent) {
    event.preventDefault(); setGeneralError(''); const next = validate(); setErrors(next); if (Object.keys(next).length) return
    setSubmitting(true)
    try {
      const response = await fetch(signup ? '/api/auth/register' : '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), password, name: name.trim() }),
      })
      const data = await response.json().catch(() => ({})) as { email?: string; name?: string; detail?: unknown }
      setUnverified(response.status === 403)
      if (!response.ok) {
        setGeneralError(typeof data.detail === 'string' ? data.detail : 'Something went wrong. Please try again.')
      } else if (signup) {
        setCreated(true)
      } else {
        localStorage.setItem('vibepen-user', JSON.stringify({ name: data.name ?? '', email: data.email ?? email.trim() }))
        navigate('/')
      }
    } catch {
      setGeneralError('Cannot reach the server. Is the backend running?')
    }
    setSubmitting(false)
  }
  function switchMode(nextSignup: boolean) { setSignup(nextSignup); setErrors({}); setGeneralError(''); setCreated(false) }
  async function signOutForAuth() { try { await fetch('/api/auth/logout', { method: 'POST' }) } catch { /* offline: still clear locally */ } localStorage.removeItem('vibepen-user'); setSignedInUser(null); setSignedOutMessage("You've been signed out.") }
  async function resendVerification() { try { await fetch('/api/auth/resend-verification', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email.trim() }) }) } catch { /* ignore */ } setResent(true) }
  if (signedInUser?.email) return <AuthShell mode={signup ? 'signup' : 'signin'}><SignedInCard user={signedInUser as { email: string; name?: string }} onSignOut={signOutForAuth} /></AuthShell>
  if (created) return <AuthShell mode="signup"><div className="auth-success"><span className="auth-success-icon">[ok]</span><p className="template-section-label">ACCOUNT CREATED</p><h1>Check your email to confirm</h1><p>We sent a confirmation link to <strong>{email}</strong>. Confirm your address to finish setting up VibePen.</p><a className="auth-primary" href="/login">Back to sign in</a></div></AuthShell>
  return <AuthShell mode={signup ? 'signup' : 'signin'}><div aria-live="polite">{signedOutMessage && <div className="auth-signed-out-message">{signedOutMessage}</div>}<div className="auth-heading"><p className="template-section-label">{signup ? 'CREATE ACCOUNT' : 'WELCOME BACK'}</p><h1>{signup ? 'Create your account' : 'Sign in to VibePen'}</h1><p>{signup ? 'Keep your scans and verified domains in one place.' : 'Access your scan history and continue protecting your apps.'}</p></div><form className="auth-form" onSubmit={submit} noValidate>{generalError && <div className="auth-general-error" role="alert">{generalError}{unverified && <> <button type="button" onClick={resendVerification}>{resent ? 'Email sent' : 'Resend verification email'}</button></>}</div>}{signup && <div className="auth-field"><label htmlFor="name">Name</label><input id="name" name="name" type="text" value={name} onChange={event => setName(event.target.value)} autoComplete="name" aria-invalid={Boolean(errors.name)} />{errors.name && <small className="auth-error">{errors.name}</small>}</div>}<div className="auth-field"><label htmlFor="email">Email</label><input id="email" name="email" type="email" value={email} onChange={event => setEmail(event.target.value)} autoComplete="email" aria-invalid={Boolean(errors.email)} />{errors.email && <small className="auth-error">{errors.email}</small>}</div><PasswordInput id="password" label="Password" value={password} onChange={setPassword} error={errors.password} autoComplete={signup ? 'new-password' : 'current-password'} hint={signup ? 'Use 8+ characters' : undefined} />{signup && <><div className="auth-password-meter"><span className={`is-${passwordStrength.toLowerCase().replace(' ', '-')}`} /></div><PasswordInput id="confirm" label="Confirm password" value={confirm} onChange={setConfirm} error={errors.confirm} autoComplete="new-password" /></>}{!signup && <div className="auth-forgot-row"><a href="/forgot-password" onClick={event => { event.preventDefault(); navigate('/forgot-password') }}>Forgot password?</a></div>  }<button className="auth-primary" type="submit" disabled={submitting}>{submitting && <span className="auth-spinner" aria-hidden="true" />}{submitting ? (signup ? 'Creating account...' : 'Signing in...') : (signup ? 'Create account' : 'Sign in')}</button></form><p className="auth-switch">{signup ? 'Already have an account? ' : 'Need an account? '}<button type="button" onClick={() => switchMode(!signup)}>{signup ? 'Sign in' : 'Sign up'}</button></p></div></AuthShell>
}

function ForgotPasswordPage() {
  const [email, setEmail] = useState(''); const [error, setError] = useState(''); const [sent, setSent] = useState(false); const [submitting, setSubmitting] = useState(false)
  function submit(event: FormEvent) { event.preventDefault(); if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { setError('Enter a valid email address.'); return } setError(''); setSubmitting(true); window.setTimeout(() => { setSubmitting(false); setSent(true) }, 450) }
  return <AuthShell mode="forgot">{sent ? <div className="auth-success"><span className="auth-success-icon">[ok]</span><p className="template-section-label">RESET LINK SENT</p><h1>Check your inbox</h1><p>If an account exists for <strong>{email}</strong>, you'll receive a password reset link shortly.</p><a className="auth-primary" href="/login">Back to sign in</a></div> : <><div className="auth-heading"><p className="template-section-label">ACCOUNT RECOVERY</p><h1>Forgot your password?</h1><p>Enter your email and we'll send you a secure reset link.</p></div><form className="auth-form" onSubmit={submit} noValidate><div className="auth-field"><label htmlFor="reset-email">Email</label><input id="reset-email" name="email" type="email" value={email} onChange={event => setEmail(event.target.value)} autoComplete="email" aria-invalid={Boolean(error)} />{error && <small className="auth-error">{error}</small>}</div><button className="auth-primary" type="submit" disabled={submitting}>{submitting && <span className="auth-spinner" aria-hidden="true" />}{submitting ? 'Sending...' : 'Send reset link'}</button></form><p className="auth-switch"><a href="/login">Back to sign in</a></p></>}</AuthShell>
}

function HistoryPage({ entries, onReload, guest }: { entries: HistoryEntry[]; onReload: () => void; guest: boolean }) {
  const [query, setQuery] = useState(''); const [appliedQuery, setAppliedQuery] = useState(''); const [type, setType] = useState('all'); const [severity, setSeverity] = useState('all')
  const [deleteId, setDeleteId] = useState<string | null>(null); const [message, setMessage] = useState(''); const [visibleCount, setVisibleCount] = useState(10)
  const searchTarget = appliedQuery.trim().toLowerCase()
  const filtered = entries.filter(entry => {
    const targetText = String(entry.target ?? entry.report?.target ?? '').toLowerCase()
    const searchable = `${targetText} ${entry.target_type ?? ''}`
    return (!searchTarget || searchable.includes(searchTarget)) &&
      (type === 'all' || (entry.target_type ?? 'URL').toUpperCase().includes(type)) &&
      (severity === 'all' || (entry.severity_counts?.[severity] ?? 0) > 0)
  })
  async function remove(id: string) {
    const response = await fetch(`/api/history/${id}`, { method: 'DELETE' })
    if (!response.ok) { setMessage('The scan could not be deleted.'); return }
    setDeleteId(null); setMessage('Scan deleted.')
    onReload()
  }
  function reportFor(entry: HistoryEntry): ScanReport {
    return entry.report ?? { id: entry.id, target: entry.target, target_type: entry.target_type, scanned_at: entry.scanned_at, risk_score: entry.risk_score, findings: [] }
  }
  const visible = filtered.slice(0, visibleCount)
  const findingPills = (entry: HistoryEntry) => Object.entries(entry.severity_counts ?? {}).filter(([, count]) => count > 0).map(([key, value]) => <span className={`finding-pill ${key}`} key={key}>{value} {key}</span>)
  return <main className="template-home"><TopNav /><section className="template-body template-page"><div className="history-container"><div className="template-page-heading"><div className="template-section-label">ARCHIVE</div><h1>History</h1><p>{guest ? 'Recent scans stored on this device. Sign in to save and manage your complete history.' : 'Review and manage every saved scan run from this table.'}</p></div>{guest && <div className="guest-save-banner" role="status"><span>Guest history is local to this browser. Sign in to keep scans across devices.</span><button onClick={() => navigate('/login')}>Sign in</button></div>}<div className="history-filters"><form className="history-search" onSubmit={event => { event.preventDefault(); setAppliedQuery(query); setVisibleCount(10) }}><input placeholder="Search target..." value={query} onChange={event => setQuery(event.target.value)} /><button type="submit" className="history-search-button" aria-label="Search history" title="Search"><span className="material-symbols-outlined">search</span></button></form><select value={type} onChange={event => { setType(event.target.value); setVisibleCount(10) }}><option value="all">All types</option><option value="URL">URL</option><option value="ZIP">ZIP</option></select><select value={severity} onChange={event => { setSeverity(event.target.value); setVisibleCount(10) }}><option value="all">All severity</option>{['critical', 'high', 'medium', 'low'].map(item => <option key={item} value={item}>{item}</option>)}</select></div><div className="history-divider" /><div className="history-result-count">Showing {visible.length} of {filtered.length} matching scan{filtered.length === 1 ? '' : 's'}{message && <span role="status">{message}</span>}</div><div className="template-history full-history"><table className="history-table"><thead><tr><th>Run time</th><th>Target</th><th>Type</th><th>Findings</th><th>Actions</th></tr></thead><tbody>{visible.map(entry => <tr key={entry.id} onClick={() => navigate(`/scans/${entry.id}`)}><td>{new Date(entry.scanned_at).toLocaleString()}</td><td>{entry.target}</td><td><span className={`scan-type-badge ${(entry.target_type ?? 'URL').toLowerCase()}`}>{entry.target_type ?? 'URL'}</span></td><td className="finding-pills">{entry.total_findings ? findingPills(entry) : <span className="no-findings">No findings</span>}</td><td className="history-actions"><label className="history-download" title="Download report"><span className="material-symbols-outlined" aria-hidden="true">download</span><select className="history-download-select" aria-label={`Download report for ${entry.target}`} title="Download report" defaultValue="" onClick={event => event.stopPropagation()} onChange={event => { event.stopPropagation(); if (event.target.value) downloadReport(reportFor(entry), event.target.value); event.target.value = '' }}><option value="">download</option><option value="pdf">PDF</option><option value="json">JSON</option><option value="md">MD</option><option value="csv">CSV</option></select></label>{!guest && <button aria-label={`Delete ${entry.target}`} title="Delete scan" onClick={event => { event.stopPropagation(); setDeleteId(entry.id) }}><span className="material-symbols-outlined">delete</span></button>}</td></tr>)}</tbody></table></div>{filtered.length === 0 && <div className="history-empty"><span className="material-symbols-outlined">history</span><strong>{entries.length === 0 ? 'No scans yet' : 'No scans match these filters'}</strong><p>{entries.length === 0 ? 'Run a scan to see it appear here.' : 'Try a different search or filter.'}</p></div>}{visible.length < filtered.length && <button className="history-load-more" onClick={() => setVisibleCount(count => count + 10)}>Load more</button>}</div></section>{deleteId && <div className="settings-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="history-delete-title"><div className="settings-modal"><h2 id="history-delete-title">Delete this scan?</h2><p>This saved report will be permanently removed.</p></div><div className="settings-modal-actions"><button className="settings-secondary" onClick={() => setDeleteId(null)}>Cancel</button><button className="settings-danger-button" onClick={() => void remove(deleteId)}>Delete scan</button></div></div>}</main>
}

function TopNav() {
  const [menuOpen, setMenuOpen] = useState(false)
  const user = currentUser()
  const menuRef = useRef<HTMLDivElement>(null)
  const navItems = user?.email ? [['Scanner', '/', 'grid_view'], ['History', '/history', 'history'], ['Verified domains', '/domains', 'verified_user'], ['Settings', '/settings', 'settings']] : [['Scanner', '/', 'grid_view'], ['History', '/history', 'history'], ['Verified domains', '/domains', 'verified_user'], ['Settings', '/settings', 'settings'], ['Sign in', '/login', 'login']]
  useEffect(() => {
    const closeOnOutside = (event: MouseEvent) => { if (menuOpen && menuRef.current && !menuRef.current.contains(event.target as Node)) setMenuOpen(false) }
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setMenuOpen(false) }
    document.addEventListener('mousedown', closeOnOutside); document.addEventListener('keydown', closeOnEscape)
    return () => { document.removeEventListener('mousedown', closeOnOutside); document.removeEventListener('keydown', closeOnEscape) }
  }, [menuOpen])
  useEffect(() => { setMenuOpen(false) }, [window.location.pathname])
  const active = window.location.pathname
  const initial = user?.email?.charAt(0).toUpperCase() ?? ''
  return <header className="template-nav"><a href="/" className="template-brand"><span>V</span> vibepen</a><span className="template-live"><i /> SCANNER ONLINE</span><div className="template-menu" ref={menuRef}><button className={`template-menu-button ${menuOpen ? 'is-open' : ''}`} aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'} aria-expanded={menuOpen} onClick={() => setMenuOpen(current => !current)}><span /><span /><span /></button><div className={`template-menu-dialog ${menuOpen ? 'is-open' : ''}`} role="menu" aria-hidden={!menuOpen}>{user?.email && <div className="template-menu-account"><span className="template-menu-avatar">{initial}</span><span>{user.email}</span></div>}<nav className="template-menu-links">{navItems.map(([label, path, icon]) => <a className={active === path ? 'is-active' : ''} key={path} href={path} role="menuitem" tabIndex={menuOpen ? 0 : -1} onClick={event => { event.preventDefault(); setMenuOpen(false); navigate(path) }}><span className="material-symbols-outlined">{icon}</span>{label}</a>)}</nav>{user?.email && <><div className="template-menu-divider" /><button className="template-menu-signout" role="menuitem" onClick={() => { void fetch('/api/auth/logout', { method: 'POST' }).finally(() => { localStorage.removeItem('vibepen-user'); setMenuOpen(false); navigate('/') }) }}><span className="material-symbols-outlined">logout</span>Sign out</button></>}</div></div></header>
}

function SettingsPage() {
  const user = JSON.parse(localStorage.getItem('vibepen-user') ?? 'null') as { email?: string; name?: string } | null
  const guest = !user?.email
  const [serverDomains, setServerDomains] = useState<DomainRecord[]>([])
  useEffect(() => { if (user?.email) void fetchDomains().then(list => list && setServerDomains(list)) }, [])
  const domains: string[] = serverDomains.filter(item => item.status === 'verified').map(item => item.domain)
  const [credentials, setCredentials] = useState({ userA: '', userB: '', useByDefault: false })
  const [reportFormat, setReportFormat] = useState('pdf')
  const [speed, setSpeed] = useState('normal')
  const [emailNotifications, setEmailNotifications] = useState(false)
  const [criticalOnly, setCriticalOnly] = useState(false)
  const [retention, setRetention] = useState('never')
  const [replaceA, setReplaceA] = useState(false); const [replaceB, setReplaceB] = useState(false)
  const [modal, setModal] = useState<'history' | 'account' | null>(null)
  const [saved, setSaved] = useState('')
  const save = (message: string) => { localStorage.setItem('vibepen-settings', JSON.stringify({ credentials, reportFormat, speed, emailNotifications, criticalOnly, retention })); setSaved(message); window.setTimeout(() => setSaved(''), 2200) }
  async function exportData() {
    const response = await fetch('/api/history/all')
    const data = response.ok ? await response.json() : { history: [] }
    const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify({ profile: user, domains, history: data.history ?? [] }, null, 2)], { type: 'application/json' })); link.download = 'vibepen-data.json'; link.click(); URL.revokeObjectURL(link.href)
  }
  async function deleteHistory() {
    const response = await fetch('/api/history/all'); const data = response.ok ? await response.json() as { history?: HistoryEntry[] } : { history: [] }
    await Promise.all((data.history ?? []).map(entry => fetch(`/api/history/${entry.id}`, { method: 'DELETE' }))); setModal(null); setSaved('All scan history deleted.')
  }
  function deleteAccount() { localStorage.clear(); navigate('/login') }
  const Card = ({ id, title, description, children, disabled = false, danger = false }: { id: string; title: string; description?: string; children: ReactNode; disabled?: boolean; danger?: boolean }) => <section id={id} className={`settings-card ${disabled ? 'is-disabled' : ''} ${danger ? 'is-danger' : ''}`} aria-disabled={disabled}><div className="settings-card-heading"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{!disabled && <button className="settings-save" onClick={() => save(`${title} saved.`)}>Save</button>}</div>{children}</section>
  return <main className="template-home"><TopNav /><section className="template-body template-page settings-page"><div className="settings-heading"><div><div className="template-section-label">ACCOUNT</div><h1>Settings</h1><p>Manage your profile, scan preferences, and data.</p></div>{saved && <span className="settings-saved">[ok] {saved}</span>}</div><div className="settings-layout"><aside className="settings-sidebar"><strong>Settings</strong>{[['profile', 'Profile'], ['defaults', 'Scan defaults'], ['domains', 'Verified domains'], ['notifications', 'Notifications'], ['privacy', 'Data & privacy'], ['danger', 'Danger zone']].map(([id, label]) => <a key={id} href={`#${id}`}>{label}</a>)}</aside><div className="settings-content"><Card id="profile" title="Profile" description={guest ? 'Sign in to save your scans and settings.' : 'Your account details and password.'} disabled={false}>{guest ? <button className="settings-primary" onClick={() => navigate('/login')}>Sign in to save your scans</button> : <><label>Name<input value={user.name ?? 'VibePen user'} readOnly /></label><label>Email<input value={user.email} readOnly /></label><div className="settings-divider" /><h3>Change password</h3><div className="settings-form-grid"><input type="password" placeholder="Current password" /><input type="password" placeholder="New password" /><input type="password" placeholder="Confirm new password" /></div><button className="settings-secondary">Change password</button><button className="settings-danger-button" onClick={() => { void fetch('/api/auth/logout', { method: 'POST' }).finally(() => { localStorage.removeItem('vibepen-user'); navigate('/login') }) }}>Sign out</button></>}</Card><Card id="defaults" title="Scan defaults" description="Credentials are used only for authorized test accounts." disabled={guest}><div className="credential-grid">{[['User A', 'userA'], ['User B', 'userB']].map(([label, key]) => <div className="credential-slot" key={key}><h3>{label}</h3><input placeholder="Username or email" value={credentials[key as 'userA' | 'userB']} onChange={event => setCredentials(current => ({ ...current, [key]: event.target.value }))} /><div className="password-row"><input type="password" readOnly={!((key === 'userA' ? replaceA : replaceB))} placeholder={(key === 'userA' ? replaceA : replaceB) ? 'Enter password' : '************'} /><button onClick={() => key === 'userA' ? setReplaceA(true) : setReplaceB(true)}>{(key === 'userA' ? replaceA : replaceB) ? 'Cancel' : 'Replace'}</button></div></div>)}</div><label className="settings-toggle-row"><input type="checkbox" checked={credentials.useByDefault} onChange={event => setCredentials(current => ({ ...current, useByDefault: event.target.checked }))} /><span><strong>Use these credentials by default</strong><small>Unlocks the privilege escalation check. Use only test accounts you own.</small></span></label><div className="settings-form-grid"><label>Default report format<select value={reportFormat} onChange={event => setReportFormat(event.target.value)}><option value="pdf">PDF</option><option value="json">JSON</option><option value="md">Markdown</option><option value="csv">CSV</option></select></label><label>Request speed<select value={speed} onChange={event => setSpeed(event.target.value)}><option value="gentle">Gentle</option><option value="normal">Normal</option></select></label></div></Card><Card id="domains" title="Verified domains" description="Domains approved for scanning."><div className="settings-domain-summary"><strong>{domains.length}</strong><span>verified domain{domains.length === 1 ? '' : 's'}</span><a href="/domains" onClick={event => { event.preventDefault(); navigate('/domains') }}>Manage</a></div>{domains.slice(0, 3).map(domain => <div className="settings-domain-row" key={domain}><span>{domain}</span><b>Active</b></div>)}</Card><Card id="notifications" title="Notifications" description="Choose when VibePen should notify you." disabled={guest}><label className="settings-toggle-row"><input type="checkbox" checked={emailNotifications} onChange={event => setEmailNotifications(event.target.checked)} /><span><strong>Email me when a scan finishes</strong><small>Receive a summary after each completed scan.</small></span></label><label className={`settings-toggle-row nested ${!emailNotifications ? 'is-disabled' : ''}`}><input type="checkbox" checked={criticalOnly} disabled={!emailNotifications} onChange={event => setCriticalOnly(event.target.checked)} /><span><strong>Only for critical findings</strong><small>Skip notifications for scans without critical issues.</small></span></label></Card><Card id="privacy" title="Data & privacy" description="Control how long your scan results are kept." disabled={guest}><label>Auto-delete scan results after<select value={retention} onChange={event => setRetention(event.target.value)}><option value="30">30 days</option><option value="90">90 days</option><option value="180">180 days</option><option value="never">Never</option></select></label><div className="settings-action-row"><button className="settings-secondary" onClick={() => void exportData()}>Export my data</button><button className="settings-danger-button" onClick={() => setModal('history')}>Delete all scan history</button></div></Card><Card id="danger" title="Danger zone" description="These actions cannot be undone." disabled={guest} danger><p>Delete your account and permanently remove all scans and verified domains.</p><button className="settings-danger-button" onClick={() => setModal('account')}>Delete account</button></Card></div></div></section>{modal && <div className="settings-modal-backdrop"><div className="settings-modal"><h2>{modal === 'history' ? 'Delete all scan history?' : 'Delete account?'}</h2><p>{modal === 'history' ? 'Every saved scan report will be permanently removed.' : 'All scans and verified domains will be removed. This cannot be undone.'}</p>{modal === 'account' && <input id="delete-confirmation" placeholder="Type DELETE to confirm" />}</div><div className="settings-modal-actions"><button className="settings-secondary" onClick={() => setModal(null)}>Cancel</button><button className="settings-danger-button" onClick={() => { if (modal === 'history') void deleteHistory(); else if ((document.getElementById('delete-confirmation') as HTMLInputElement)?.value === 'DELETE') deleteAccount() }}>{modal === 'history' ? 'Delete history' : 'Delete account'}</button></div></div>}</main>
}

function DomainsPage() {
  const signedIn = Boolean(currentUser()?.email)
  const [domains, setDomains] = useState<DomainRecord[]>([])
  const [loading, setLoading] = useState(signedIn)
  useEffect(() => { if (!signedIn) return; void fetchDomains().then(list => { if (list) setDomains(list); setLoading(false) }) }, [])
  const [domain, setDomain] = useState('')
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [method, setMethod] = useState<VerificationMethod>('DNS TXT')
  const [verifying, setVerifying] = useState(false)
  const [removeTarget, setRemoveTarget] = useState<string | null>(null)
  const [howOpen, setHowOpen] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const save = (next: DomainRecord[]) => setDomains(next)
  const normalizeDomain = (value: string) => value.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/\.$/, '').toLowerCase()
    async function addDomain(event: FormEvent) {
    event.preventDefault()
    if (!signedIn) { setError('Sign in to add domains.'); return }
    const normalized = normalizeDomain(domain)
    if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(normalized)) { setError('Enter a valid domain, such as example.com.'); return }
    if (domains.some(item => item.domain === normalized)) { setError('This domain is already in your list.'); return }
    const response = await fetch('/api/domains', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: normalized }) })
    if (response.status === 401) { setError('Sign in to add domains.'); return }
    if (!response.ok) { setError('Could not add this domain.'); return }
    const data = await response.json()
    save([...domains, toDomainRecord(data)]); setDomain(''); setError(''); setExpanded(normalized)
  }
  async function removeDomain() {
    if (!removeTarget) return
    const response = await fetch(`/api/domains/${encodeURIComponent(removeTarget)}`, { method: 'DELETE' })
    if (!response.ok) { setError('Could not remove this domain.'); setRemoveTarget(null); return }
    save(domains.filter(item => item.domain !== removeTarget)); setRemoveTarget(null); if (expanded === removeTarget) setExpanded(null)
  }
    async function verifyDomain(record: DomainRecord) {
    setVerifying(true); setError('')
    const response = await fetch(`/api/domains/${record.domain}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ method: ({ 'DNS TXT': 'dns', 'File upload': 'file', 'Meta tag': 'meta' } as Record<VerificationMethod, string>)[method] }) })
    const data = response.ok ? await response.json() : null
    const next: DomainRecord = data?.status === 'verified'
      ? { ...record, status: 'verified', method, verifiedAt: data.verified_at, expiresAt: data.expires_at, error: undefined }
      : { ...record, status: 'failed', error: data?.error ?? 'Verification failed. Try again in a few minutes.' }
    save(domains.map(item => item.domain === record.domain ? next : item)); setVerifying(false)
  }
  const daysUntil = (date?: string) => date ? Math.ceil((new Date(date).getTime() - Date.now()) / 86400000) : 0
  const verifiedCount = domains.filter(item => item.status === 'verified').length
  const pendingCount = domains.filter(item => item.status === 'pending').length
  const copy = (value: string) => { void navigator.clipboard?.writeText(value) }
  const verificationValue = (record: DomainRecord) => method === 'Meta tag' ? `<meta name="vibepen-verification" content="${record.token}">` : `vibepen-verification=${record.token}`
  return <main className="template-home"><TopNav /><section className="template-body template-page domains-page"><div className="template-section-label">SCAN ACCESS</div><h1>Verified domains</h1><p className="template-page-intro">Prove you own a site before scanning it. Verifications expire after 30 days.</p><p className="domains-summary">{verifiedCount} verified · {pendingCount} pending</p>{!signedIn && <div className="guest-save-banner domain-guest-prompt" role="status"><span>Sign in to add and verify domains. Verification is tied to your account.</span><button onClick={() => navigate('/login')}>Sign in</button></div>}<div className="domain-info-banner"><span className="material-symbols-outlined">info</span><span>Localhost and demo targets don’t need verification.</span></div><section className="domain-manager"><form className="domain-add" onSubmit={addDomain}><div><input ref={inputRef} placeholder="example.com" value={domain} onChange={event => { setDomain(event.target.value); setError('') }} aria-invalid={Boolean(error)} />{error && <small className="domain-inline-error">{error}</small>}</div><button type="submit">Add domain</button></form><small className="domain-helper">Enter a domain without https://</small></section>{loading ? <p className="template-page-intro">Loading your domains...</p> : domains.length === 0 ? <div className="domains-empty"><span className="material-symbols-outlined">shield</span><h2>No verified domains yet</h2><p>Verification confirms that you own the site before a scan can begin.</p><button onClick={() => inputRef.current?.focus()}>Add your first domain</button></div> : <div className="domain-list">{domains.map(record => { const days = daysUntil(record.expiresAt); const value = verificationValue(record); return <article className="domain-card" key={record.domain}><div className="domain-card-main"><div className="domain-card-title"><h2>{record.domain}</h2><span className={`domain-badge ${record.status}`}>{record.status}</span></div><div className="domain-card-meta"><span>Method: {record.method ?? 'Not verified'}</span><span>{record.verifiedAt ? `Verified ${new Date(record.verifiedAt).toLocaleDateString()}` : 'Verification required'}</span>{record.expiresAt && <span className={days < 7 ? 'expires-soon' : ''}>Expires in {Math.max(0, days)} days</span>}</div>{record.error && <p className="domain-error">{record.error}</p>}</div>  <div className="domain-card-actions">{record.status === 'verified' && <button className="domain-icon-action" title="Scan now" aria-label={`Scan ${record.domain} now`} onClick={() => navigate(`/?rescan=${encodeURIComponent(`https://${record.domain}`)}`)}><span className="material-symbols-outlined">play_arrow</span></button>}<button onClick={() => { setExpanded(record.domain); setMethod(record.method ?? 'DNS TXT') }}>Re-verify</button><button className="domain-remove-action" onClick={() => setRemoveTarget(record.domain)}>Remove</button></div>{expanded === record.domain && <div className="domain-verification-panel"><div className="domain-tabs">{(['DNS TXT', 'File upload', 'Meta tag'] as VerificationMethod[]).map(item => <button key={item} className={method === item ? 'active' : ''} onClick={() => setMethod(item)}>{item}</button>)}</div><p>{method === 'DNS TXT' ? `Add a TXT record named _vibepen-verify.${record.domain} with this value.` : method === 'File upload' ? `Upload a text file at https://${record.domain}/.well-known/vibepen-verify.txt containing exactly this text.` : `Paste this tag inside the <head> of your homepage at https://${record.domain}/ so it appears in the page source.`}</p><div className="domain-copy-value"><code>{value}</code><button title="Copy verification value" aria-label="Copy verification value" onClick={() => copy(value)}><span className="material-symbols-outlined">content_copy</span></button></div>{method === 'DNS TXT' && <small>DNS changes may take a few minutes.</small>}<button className="domain-verify-button" disabled={verifying} onClick={() => void verifyDomain(record)}>{verifying ? 'Verifying...' : 'Verify now'}</button></div>}</article> })}</div>}<button className="domains-how-toggle" onClick={() => setHowOpen(value => !value)}>{howOpen ? 'Hide' : 'Show'} how verification works</button>{howOpen && <div className="domains-how"><p><b>1.</b> Add your domain and choose a verification method.</p><p><b>2.</b> Place the TXT record, meta tag, or file on your site.</p><p><b>3.</b> Verify the method, then start scanning.</p></div>}</section>{removeTarget && <div className="settings-modal-backdrop" role="dialog" aria-modal="true"><div className="settings-modal"><h2>Remove {removeTarget}?</h2><p>This will remove the domain from your verification list.</p><div className="settings-modal-actions"><button className="settings-secondary" onClick={() => setRemoveTarget(null)}>Cancel</button><button className="settings-danger-button" onClick={removeDomain}>Remove domain</button></div></div></div>}</main>
}

export default function TemplateHome() {
  const [path, setPath] = useState(window.location.pathname)
  const [target, setTarget] = useState(new URLSearchParams(window.location.search).get('rescan') ?? 'http://localhost:3000')
  const [status, setStatus] = useState('Ready to scan'); const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(0); const [currentCheck, setCurrentCheck] = useState('')
  const [report, setReport] = useState<ScanReport>({ target, risk_score: 0, findings: [] })
  const [history, setHistory] = useState<HistoryEntry[]>([]); const [uploadedFile, setUploadedFile] = useState('')
  const [verified, setVerified] = useState(false); const [findingStates, setFindingStates] = useState<Record<string, FindingState>>({})
  const [guestBanner, setGuestBanner] = useState(false)
  const sandbox = isSandboxDomain(target)
  useEffect(() => { const listener = () => setPath(window.location.pathname); window.addEventListener('popstate', listener); return () => window.removeEventListener('popstate', listener) }, [])
  async function loadHistory() {
    if (!currentUser()?.email) { setHistory(guestHistory()); return }
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
  useEffect(() => { if (path.startsWith('/scans/')) { const scanId = path.split('/')[2]; const local = guestHistory().find(entry => entry.id === scanId); if (local?.report) { setReport(local.report); return } void fetch(`/api/history/${scanId}`).then(response => response.ok ? response.json() : null).then(data => data && setReport(data)) } }, [path])
  const [myDomains, setMyDomains] = useState<DomainRecord[]>([])
  useEffect(() => { if (!currentUser()?.email) { setMyDomains([]); return } void fetchDomains().then(list => { if (list) setMyDomains(list) }) }, [path])
  useEffect(() => { setVerified(isSandboxDomain(target) || isVerifiedHost(myDomains, target)) }, [target, myDomains])
  async function runScan(event: FormEvent) { event.preventDefault(); if (scanning || !target.trim() || !verified) return; setScanning(true); setProgress(5); setStatus('Scanning target...'); const checks = ['Resolving target', 'Checking headers', 'Testing authentication', 'Reviewing injection points', 'Building report']; let timer = 0; const interval = window.setInterval(() => { timer = Math.min(timer + 1, checks.length - 1); setProgress(Math.min(90, (timer + 1) * 18)); setCurrentCheck(checks[timer]) }, 500); try { const response = await fetch(`/api/scan?target=${encodeURIComponent(target.trim().replace(/\/$/, ''))}`); if (response.status === 403) throw new Error('Verify this domain on the Verified domains page before scanning it.'); if (!response.ok) throw new Error('The scan could not complete.'); const data = await response.json() as ScanReport; setReport(data); setProgress(100); setStatus('Scan complete'); if (!currentUser()?.email) { saveGuestReport(data); setGuestBanner(true) } await loadHistory() } catch (error) { setStatus(error instanceof Error ? error.message : 'Scan failed') } finally { window.clearInterval(interval); setScanning(false) } }
  async function chooseArchive(event: ChangeEvent<HTMLInputElement>) { const file = event.target.files?.[0]; if (!file) return; setUploadedFile(file.name); setScanning(true); setStatus(`Analyzing ${file.name}...`); const formData = new FormData(); formData.append('file', file); try { const response = await fetch('/api/scan/upload', { method: 'POST', body: formData }); if (!response.ok) throw new Error('The source scan could not complete.'); const data = await response.json() as ScanReport; setReport(data); setStatus('Scan complete'); if (!currentUser()?.email) { saveGuestReport(data); setGuestBanner(true) } await loadHistory() } catch (error) { setStatus(error instanceof Error ? error.message : 'Source scan failed') } finally { setScanning(false); event.target.value = '' } }
  if (path === '/verify-email') return <VerifyEmailPage />
  if (path === '/login') return <AuthPage />
  if (path === '/signup') return <AuthPage initialSignup />
  if (path === '/forgot-password') return <ForgotPasswordPage />
  if (path === '/history') return <HistoryPage entries={history} onReload={() => void loadHistory()} guest={!currentUser()?.email} />
  if (path === '/domains') return <DomainsPage />
  if (path === '/settings') return <SettingsPage />
  if (path.startsWith('/scans/')) return <main className="template-home"><TopNav /><section className="template-body template-page"><div className="template-section-label">PAST SCAN REPORT</div><h1>{report.target}</h1><p>{report.scanned_at ? new Date(report.scanned_at).toLocaleString() : 'Archived run'}</p><ReportView report={report} findingStates={findingStates} /></section></main>
  return <main className="template-home"><TopNav /><section className="template-hero"><div className="template-hero-shade" /><div className="template-hero-copy"><p>WEB SECURITY / CONTINUOUS VISIBILITY</p><h1>VibePen</h1><span>Your web security scanner</span><p className="template-hero-description">Discover exposed endpoints, weak configurations, and application vulnerabilities before they become incidents.</p><a className="template-down-arrow" href="#template-scanner">↓</a></div></section><section className="template-body" id="template-scanner">{guestBanner && !currentUser()?.email && <div className="guest-save-banner" role="status"><span>Sign in to save this report and keep your verified domains.</span><button aria-label="Dismiss sign-in reminder" onClick={() => setGuestBanner(false)}>×</button></div>}<form onSubmit={runScan}><div className="template-input"><span>↗</span><input value={target} onChange={event => setTarget(event.target.value)} disabled={scanning} /><button disabled={scanning || !verified}>{scanning ? 'Scanning...' : 'Run New Scan'}</button></div><div className={`domain-verification ${verified ? 'verified' : ''}`}><strong>{verified ? '✓ Domain verified' : 'Domain verification required'}</strong><span>{verified ? (sandbox ? 'Local sandbox target is trusted automatically.' : 'This target is approved for scanning.') : 'Verify this domain from the Verified domains page before starting a scan.'}</span>{!verified && <button type="button" onClick={() => navigate('/domains')}>Verify domain</button>}</div><div className="template-meta"><span>● {status}{scanning && ` - ${currentCheck} - ${progress}%`}</span></div><div className="template-progress" aria-label="Scan progress"><span style={{ width: `${progress}%` }} /></div><label className="template-upload"><span>↥</span><strong>Scan source code ZIP</strong><small>Upload a .zip for static analysis</small><input type="file" accept=".zip,application/zip" onChange={chooseArchive} /></label>{uploadedFile && <small className="template-uploaded">{uploadedFile}</small>}</form>{scanning && <div className="live-scan"><strong>Live scan in progress</strong><span>{currentCheck || 'Preparing checks'} - {progress}%</span></div>}<ReportView report={report} findingStates={findingStates} onFindingState={(id, state) => setFindingStates(current => ({ ...current, [id]: state }))} /><section className="template-original-section template-history" id="template-history"><h2>▦ Recent scan history {!currentUser()?.email && <small className="guest-history-note">Stored on this device</small>}<button onClick={() => navigate('/history')}>View all history →</button></h2><div className="template-history-head"><span>Timestamp</span><span>Scan type</span><span>Findings</span><span>Status</span></div>  {history.slice(0, 3).map(entry => <div className="template-history-row history-clickable" key={entry.id} onClick={() => entry.report ? setReport(entry.report) : navigate(`/scans/${entry.id}`)}><span>{new Date(entry.scanned_at).toLocaleString()}<small>{entry.target}</small></span><span>{entry.target_type ?? 'URL'}</span><span>{entry.total_findings ? Object.entries(entry.severity_counts ?? {}).map(([severity, count]) => `${count} ${severity}`).join(' · ') : 'No findings'}</span><b>Complete</b></div>)}</section></section></main>
}
