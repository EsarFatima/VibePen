import { useEffect, useState } from 'react'

// ─── Tokens ───────────────────────────────────────────────────────────────────

const C = {
  bg: '#F2F3F4',
  panel: '#FFFFFF',
  text: '#1C1B17',
  muted: '#6B6A62',
  border: '#DDE2E7',
  critical: '#A13D3D',
  high: '#BC5A3A',
  medium: '#B08A2E',
  low: '#4A7A8C',
  passed: '#3F7D5C',
  na: '#C6CBD1',
  accent: '#2B4C7E',
  bodyText: '#3D3B35',
} as const

// ─── Data ────────────────────────────────────────────────────────────────────

type CheckStatus = 'passed' | 'low' | 'medium' | 'high' | 'critical' | 'na' | 'skipped'

interface Check {
  id: string
  label: string
  category: string
  status: CheckStatus
  findingId?: string
  reason?: string
}

interface Finding {
  id: string
  checkId: string
  checkLabel: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  summary: string
  evidence: string
  recommendation: string
  location?: string
  confidence?: number
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
  target: string
  risk_score: number
  findings: ScanReportFinding[]
  network_info?: NetworkInfo
}

interface NetworkInfo {
  scanner?: string
  hostname?: string
  ip_address?: string
  is_local?: boolean
  open_ports?: Array<{ port: number; protocol?: string; service?: string; product?: string }>
  duration_seconds?: number
}

interface ScanHistoryEntry {
  scannedAt: string
  target: string
  riskScore: number
  totalFindings: number
  severityCounts?: Record<string, number>
}

const TARGET_URL = 'http://localhost:3000'

const SCAN_HISTORY: ScanHistoryEntry[] = [
  { scannedAt: '2026-09-16T18:39:43.002340Z', target: TARGET_URL, riskScore: 18.7, totalFindings: 5, severityCounts: { critical: 2, high: 1, medium: 1, low: 1 } },
  { scannedAt: '2026-09-16T18:38:25.621480Z', target: TARGET_URL, riskScore: 18.7, totalFindings: 5, severityCounts: { critical: 2, high: 1, medium: 1, low: 1 } },
  { scannedAt: '2026-09-14T12:29:44.029168Z', target: TARGET_URL, riskScore: 0, totalFindings: 0 },
]

export const CHECKS: Check[] = [
  { id: 'auth_login_brute', label: 'Brute-force protection', category: 'Authentication & access control', status: 'passed' },
  { id: 'cross_account_basket', label: 'Cross-account basket access', category: 'Authentication & access control', status: 'critical', findingId: 'cddaf68cb843' },
  { id: 'auth_user_area', label: 'Authenticated user area', category: 'Authentication & access control', status: 'passed' },
  { id: 'priv_escalation', label: 'Privilege escalation', category: 'Authentication & access control', status: 'skipped', reason: 'Two authorized test accounts were not provided.' },
  { id: 'sql_injection', label: 'SQL injection', category: 'Injection & input handling', status: 'high', findingId: 'a1b2c3d4e5f6' },
  { id: 'xss_reflected', label: 'Reflected XSS', category: 'Injection & input handling', status: 'medium', findingId: '7890abcdef01' },
  { id: 'cmd_injection', label: 'Command injection', category: 'Injection & input handling', status: 'passed' },
  { id: 'xxe', label: 'XXE / XML injection', category: 'Injection & input handling', status: 'na' },
  { id: 'csp', label: 'Content Security Policy', category: 'Browser safety', status: 'passed' },
  { id: 'cors', label: 'CORS configuration', category: 'Browser safety', status: 'critical', findingId: 'f234567890ab' },
  { id: 'clickjacking', label: 'Clickjacking (X-Frame-Options)', category: 'Browser safety', status: 'passed' },
  { id: 'stack_trace', label: 'Stack trace disclosure', category: 'Error handling', status: 'passed' },
  { id: 'verbose_errors', label: 'Verbose error messages', category: 'Error handling', status: 'na' },
  { id: 'https_redirect', label: 'HTTPS redirect', category: 'Configuration & transport', status: 'passed' },
  { id: 'hsts', label: 'HSTS header', category: 'Configuration & transport', status: 'skipped', reason: 'Could not verify HSTS — target may require HTTPS-only access.' },
  { id: 'tls_version', label: 'TLS version check', category: 'Configuration & transport', status: 'na' },
]

export const FINDINGS: Finding[] = [
  {
    id: 'cddaf68cb843',
    checkId: 'cross_account_basket',
    checkLabel: 'Cross-account basket access',
    severity: 'critical',
    summary: "One authenticated account can read and modify another account's private basket data without authorization.",
    evidence: 'GET /api/BasketItems/1 responded with 200 and returned items belonging to user ID 2 while authenticated as user ID 1. The API does not validate that the basket belongs to the requesting user.',
    recommendation: 'Add server-side authorization checks on every basket endpoint. Verify the authenticated user\'s ID matches the basket owner before returning or modifying data.',
    location: '/api/BasketItems/:id',
    confidence: 0.98,
  },
  {
    id: 'a1b2c3d4e5f6',
    checkId: 'sql_injection',
    checkLabel: 'SQL injection',
    severity: 'high',
    summary: 'The login endpoint is vulnerable to SQL injection via the email field, allowing authentication bypass.',
    evidence: `POST /rest/user/login with body {"email":"' OR 1=1--","password":"x"} returned HTTP 200 with a valid authentication token.`,
    recommendation: 'Use parameterized queries or a prepared statement library. Never concatenate user input into SQL strings.',
    location: '/rest/user/login — email parameter',
    confidence: 0.96,
  },
  {
    id: '7890abcdef01',
    checkId: 'xss_reflected',
    checkLabel: 'Reflected XSS',
    severity: 'medium',
    summary: 'User-supplied search terms are reflected in the page response without sanitization, enabling script injection.',
    evidence: 'GET /search?q=<script>alert(1)</script> returned the script tag unencoded in the HTML body.',
    recommendation: 'HTML-encode all user-supplied data before inserting it into the DOM. Apply a strict Content Security Policy.',
    location: '/search — q parameter',
    confidence: 0.91,
  },
  {
    id: 'f234567890ab',
    checkId: 'cors',
    checkLabel: 'CORS configuration',
    severity: 'critical',
    summary: 'The application returns Access-Control-Allow-Origin: * on authenticated API endpoints, allowing any site to read responses.',
    evidence: 'OPTIONS /api/Users/1 responded with Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.',
    recommendation: 'Restrict Access-Control-Allow-Origin to specific trusted origins. Do not combine wildcard origin with Allow-Credentials: true.',
    location: 'All /api/* endpoints',
    confidence: 0.99,
  },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────

const STATUS_FILL: Record<CheckStatus, string> = {
  passed: C.passed,
  low: C.low,
  medium: C.medium,
  high: C.high,
  critical: C.critical,
  na: C.na,
  skipped: 'skipped',
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: C.critical,
  high: C.high,
  medium: C.medium,
  low: C.low,
}

function severityPoints(s: string) {
  return ({ critical: 10, high: 7, medium: 4, low: 2, info: 1 } as Record<string, number>)[s] ?? 0
}

function normalizeSeverity(severity: string): Finding['severity'] {
  const normalized = severity.toLowerCase()
  if (normalized === 'critical' || normalized === 'high' || normalized === 'medium') return normalized
  return 'low'
}

function computeRiskScore(findings: Finding[]) {
  return findings.reduce((acc, f) => acc + severityPoints(f.severity) * (f.confidence ?? 1), 0)
}

const RISK_SCORE_MAX = 50

const SEVERITY_ORDER: Record<CheckStatus, number> = {
  passed: 0,
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  skipped: 5,
  na: 6,
}

export function sortFindings(findings: Finding[]) {
  return [...findings].sort((a, b) => severityPoints(b.severity) - severityPoints(a.severity))
}

function sortChecksForDisplay(checks: Check[]) {
  return [...checks].sort((a, b) => SEVERITY_ORDER[a.status] - SEVERITY_ORDER[b.status])
}

export function countByStatus(checks: Check[], status: CheckStatus) {
  return checks.filter(c => c.status === status).length
}

function riskResultText(findings: Finding[]) {
  if (findings.length === 0) return 'No findings were detected in the completed checks.'
  const criticalCount = findings.filter(finding => finding.severity === 'critical').length
  const highCount = findings.filter(finding => finding.severity === 'high').length
  if (criticalCount > 0) return `${findings.length} finding${findings.length === 1 ? '' : 's'} detected, including ${criticalCount} critical.`
  if (highCount > 0) return `${findings.length} finding${findings.length === 1 ? '' : 's'} detected, including ${highCount} high severity.`
  return `${findings.length} finding${findings.length === 1 ? '' : 's'} detected for review.`
}

function mapScanReport(report: ScanReport) {
  const dynamicFindings: Finding[] = report.findings.map(finding => {
    const id = finding.id ?? `${finding.type}-${finding.location ?? finding.message ?? 'finding'}`
    const severity = normalizeSeverity(finding.severity)
    return {
      id,
      checkId: `backend-${id}`,
      checkLabel: finding.title ?? finding.type ?? 'Static analysis finding',
      severity,
      summary: finding.description ?? finding.message ?? 'A potential security issue was detected.',
      evidence: finding.evidence ?? 'No evidence supplied.',
      recommendation: finding.remediation ?? 'Review this result manually.',
      location: finding.location,
      confidence: finding.confidence,
    }
  })
  const dynamicChecks: Check[] = report.findings.map((finding, index) => ({
    id: `backend-${dynamicFindings[index].id}`,
    label: finding.title ?? finding.type ?? 'Static analysis finding',
    category: 'Backend scan result',
    status: dynamicFindings[index].severity,
    findingId: dynamicFindings[index].id,
  }))

  return {
    findings: dynamicFindings,
    checks: [...CHECKS.filter(check => !check.findingId), ...dynamicChecks],
  }
}

// ─── Segmented Grid Bar ───────────────────────────────────────────────────────

function SegmentedBar({ checks, expandedFinding, onSegmentClick }: {
  checks: Check[]
  expandedFinding: string | null
  onSegmentClick: (c: Check) => void
}) {
  const sorted = sortChecksForDisplay(checks)

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: `repeat(${sorted.length}, 1fr)`,
        border: `1px solid ${C.border}`,
        height: 40,
      }}
    >
      {sorted.map((c, i) => {
        const isClickable = true
        const isHighlighted = !!c.findingId && expandedFinding === c.findingId
        const fill = STATUS_FILL[c.status]
        const isSkipped = c.status === 'skipped'

        return (
          <div
            key={c.id}
            role="button"
            tabIndex={0}
            aria-label={`${c.label}: ${c.status}`}
            title={`${c.label} — ${c.status}`}
            onClick={() => onSegmentClick(c)}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onSegmentClick(c) }}
            style={{
              borderLeft: i > 0 ? `1px solid ${C.border}` : undefined,
              backgroundColor: isSkipped ? undefined : fill,
              backgroundImage: isSkipped
                ? `repeating-linear-gradient(-45deg, transparent, transparent 3px, rgba(0,0,0,0.12) 3px, rgba(0,0,0,0.12) 5px)`
                : undefined,
              backgroundSize: isSkipped ? '8px 8px' : undefined,
              backgroundRepeat: isSkipped ? 'repeat' : undefined,
              cursor: isClickable ? 'pointer' : 'default',
              outline: isHighlighted ? `2px solid ${C.text}` : undefined,
              outlineOffset: isHighlighted ? -2 : undefined,
              opacity: isHighlighted ? 0.85 : 1,
              animation: 'segmentScaleIn 240ms cubic-bezier(0.2, 0.85, 0.3, 1) both',
              animationDelay: `${i * 130}ms`,
              transition: 'opacity 0.15s',
            }}
          />
        )
      })}
    </div>
  )
}

// ─── Legend ───────────────────────────────────────────────────────────────────

function LegendRow({ checks }: { checks: Check[] }) {
  const items: { label: string; color: string; status: CheckStatus }[] = [
    { label: 'Passed', color: C.passed, status: 'passed' },
    { label: 'Critical', color: C.critical, status: 'critical' },
    { label: 'High', color: C.high, status: 'high' },
    { label: 'Medium', color: C.medium, status: 'medium' },
    { label: 'Low', color: C.low, status: 'low' },
    { label: 'Skipped', color: 'skipped', status: 'skipped' },
    { label: 'N/A', color: C.na, status: 'na' },
  ]

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '18px 28px', marginTop: 12 }}>
      {items.map(it => {
        const n = countByStatus(checks, it.status)
        return (
          <div key={it.label} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span
              style={{
                display: 'inline-block',
                width: 14,
                height: 14,
                flexShrink: 0,
                backgroundColor: it.color === 'skipped' ? undefined : it.color,
                backgroundImage: it.color === 'skipped'
                  ? `repeating-linear-gradient(-45deg, ${C.na}, ${C.na} 3px, rgba(0,0,0,0.15) 3px, rgba(0,0,0,0.15) 5px)`
                  : undefined,
                backgroundSize: '8px 8px',
              }}
            />
            <span style={{ fontFamily: 'Arial, sans-serif', fontSize: 12, color: C.muted }}>{it.label}</span>
            <span style={{ fontFamily: 'Arial, sans-serif', fontSize: 12, fontWeight: 700, color: C.text }}>{n}</span>
          </div>
        )
      })}
    </div>
  )
}

// ─── Semicircle Meter ─────────────────────────────────────────────────────────

function SemicircleMeter({ score, details, maxScore = RISK_SCORE_MAX }: { score: number; details: string; maxScore?: number }) {
  const [showInfo, setShowInfo] = useState(false)
  const pct = Math.min(score / maxScore, 1)
  const R = 58
  const cx = 80, cy = 66
  const semiCirc = Math.PI * R
  const offset = semiCirc * (1 - pct)
  const arcColor = C.accent

  return (
    <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width="160" height="76" viewBox="0 0 160 76" aria-label={`Risk score ${score.toFixed(1)}`} style={{ overflow: 'visible' }}>
        {/* Track */}
        <path
          d={`M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`}
          fill="none"
          stroke={C.border}
          strokeWidth="9"
          strokeLinecap="round"
        />
        {/* Fill */}
        <path
          d={`M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`}
          fill="none"
          stroke={arcColor}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={semiCirc}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        <text
          x={cx} y={cy - 10}
          textAnchor="middle"
          fill={C.text}
          fontSize="24"
          fontFamily="Georgia, 'Times New Roman', serif"
          fontWeight="700"
        >
          {score.toFixed(1)}
        </text>
      </svg>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span
          style={{ position: 'relative', display: 'inline-flex' }}
          onMouseEnter={() => setShowInfo(true)}
          onMouseLeave={() => setShowInfo(false)}
        >
          <button
            type="button"
            aria-label="Explain risk score"
            aria-expanded={showInfo}
            onFocus={() => setShowInfo(true)}
            onBlur={() => setShowInfo(false)}
            style={{ width: 18, height: 18, padding: 0, border: `1px solid ${C.accent}`, borderRadius: '50%', background: C.panel, color: C.accent, fontFamily: 'Arial, sans-serif', fontSize: 11, fontWeight: 700, lineHeight: '16px', cursor: 'help' }}
          >
            i
          </button>
          {showInfo && (
            <div role="tooltip" style={{ position: 'absolute', zIndex: 2, top: 26, left: 0, width: 250, padding: '10px 12px', border: `1px solid ${C.border}`, background: C.panel, boxShadow: '0 4px 12px rgba(28, 27, 23, 0.12)', color: C.bodyText, fontFamily: 'Arial, sans-serif', fontSize: 11, lineHeight: 1.45, textAlign: 'left' }}>
              {details}
            </div>
          )}
        </span>
        <span style={{ fontFamily: 'Arial, sans-serif', fontSize: 11, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Risk score
        </span>
      </div>
    </div>
  )
}

// ─── Collapsible Section ──────────────────────────────────────────────────────

function CollapsibleSection({ title, count, description, children, open, onToggle }: { title: string; count: number; description?: string; children: React.ReactNode; open: boolean; onToggle: () => void }) {
  return (
    <div style={{ border: `1px solid ${C.border}` }}>
      <button
        onClick={onToggle}
        aria-expanded={open}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 10,
          padding: '10px 16px', textAlign: 'left', background: C.panel,
          border: 'none', cursor: 'pointer', borderBottom: open ? `1px solid ${C.border}` : 'none',
        }}
      >
        <MaterialIcon name={open ? 'keyboard_arrow_down' : 'chevron_right'} label={open ? 'Collapse section' : 'Expand section'} color={C.accent} size={14} />
        <span style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <span style={{ fontFamily: 'Arial, sans-serif', fontSize: 13, fontWeight: 700, color: C.text }}>{title}</span>
          {description && <span style={{ fontFamily: 'Inter, Arial, sans-serif', fontSize: 11, fontWeight: 400, color: C.muted }}>{description}</span>}
        </span>
        <span style={{ marginLeft: 'auto', fontFamily: 'Consolas, monospace', fontSize: 12, color: C.muted }}>{count}</span>
      </button>
      {open && <div style={{ background: C.bg }}>{children}</div>}
    </div>
  )
}

function SummaryBox({ icon, label, value, detail, color }: { icon: string; label: string; value: string; detail: string; color: string }) {
  return (
    <div style={{ minHeight: 104, padding: '13px 14px', background: C.bg, border: `1px solid ${C.border}`, boxShadow: '0 2px 7px rgba(28, 27, 23, 0.04)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
        <MaterialIcon name={icon} label={label} color={color} size={16} />
        <span style={{ fontFamily: 'Arial, sans-serif', fontSize: 10, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>{label}</span>
      </div>
      <div style={{ fontFamily: 'Georgia, serif', fontSize: 20, color, fontWeight: 700 }}>{value}</div>
      <p style={{ fontFamily: 'Arial, sans-serif', fontSize: 11, lineHeight: 1.4, color: C.muted, margin: '5px 0 0' }}>{detail}</p>
    </div>
  )
}

function LogoMark({ tone = C.text }: { tone?: string }) {
  return (
    <span aria-hidden="true" style={{ width: 34, height: 34, flexShrink: 0, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', borderRadius: 8, background: tone, color: C.panel, fontFamily: 'Inter, Arial, sans-serif', fontSize: 17, fontWeight: 700, boxShadow: `0 3px 8px ${tone}33` }}>
      <span className="material-symbols-outlined" style={{ fontSize: 18 }}>shield</span>
    </span>
  )
}

function ScanStatusMark() {
  return (
    <span aria-hidden="true" style={{ width: 44, height: 44, flexShrink: 0, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: C.passed }}>
      <span className="material-symbols-outlined" style={{ fontSize: 36, fontVariationSettings: "'FILL' 1" }}>shield_with_heart</span>
    </span>
  )
}

function MaterialIcon({ name, label, color = C.muted, size = 15 }: { name: string; label: string; color?: string; size?: number }) {
  return <span className="material-symbols-outlined" aria-label={label} style={{ color, fontSize: size }}>{name}</span>
}

function FindingsBreakdown({ entry }: { entry: ScanHistoryEntry }) {
  const severityItems = [
    { key: 'critical', label: 'Critical', color: C.critical },
    { key: 'high', label: 'High', color: C.high },
    { key: 'medium', label: 'Medium', color: C.medium },
    { key: 'low', label: 'Low', color: C.low },
    { key: 'info', label: 'Info', color: C.muted },
  ].filter(item => (entry.severityCounts?.[item.key] ?? 0) > 0)

  if (severityItems.length === 0) {
    return <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: entry.totalFindings > 0 ? C.critical : C.passed, whiteSpace: 'nowrap' }}>{entry.totalFindings === 0 ? '0 findings' : `${entry.totalFindings} finding${entry.totalFindings === 1 ? '' : 's'}`}</span>
  }

  return (
    <span style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 5, fontFamily: 'Consolas, monospace', fontSize: 11, whiteSpace: 'nowrap' }}>
      {severityItems.map((item, index) => (
        <span key={item.key} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          {index > 0 && <span style={{ color: C.muted }}>•</span>}
          <span style={{ color: item.color, fontWeight: 600 }}>{entry.severityCounts?.[item.key]} {item.label}</span>
        </span>
      ))}
    </span>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function App() {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)
  const [openSection, setOpenSection] = useState<'passed' | 'skipped' | 'na' | null>(null)
  const [targetUrl, setTargetUrl] = useState(TARGET_URL)
  const [isScanning, setIsScanning] = useState(false)
  const [scanMessage, setScanMessage] = useState('')
  const [history, setHistory] = useState<ScanHistoryEntry[]>([])
  const [checks, setChecks] = useState<Check[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [riskScore, setRiskScore] = useState(0)
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo | null>(null)
  const [uploadMessage, setUploadMessage] = useState('')
  const [barRevision, setBarRevision] = useState(0)
  const [highlightedDetailId, setHighlightedDetailId] = useState<string | null>(null)

  async function loadHistory(target: string) {
    try {
      const response = await fetch(`/api/history?target=${encodeURIComponent(target)}`)
      if (!response.ok) return
      const payload = await response.json()
      if (!Array.isArray(payload.history)) return
      setHistory(payload.history.map((entry: { scanned_at: string; target: string; risk_score: number; total_findings: number; severity_counts?: Record<string, number> }) => ({
        scannedAt: entry.scanned_at,
        target: entry.target,
        riskScore: entry.risk_score,
        totalFindings: entry.total_findings,
        severityCounts: entry.severity_counts,
      })))
    } catch {
      // Keep the local preview history when the API is unavailable.
    }
  }

  useEffect(() => {
    loadHistory(targetUrl)
  }, [targetUrl])

  useEffect(() => {
    runScanForTarget(TARGET_URL)
  }, [])

  const applicable = checks.filter(c => c.status !== 'na')
  const completed = applicable.filter(c => c.status !== 'skipped')
  const skipped = applicable.filter(c => c.status === 'skipped')
  const passed = checks.filter(c => c.status === 'passed')
  const naChecks = checks.filter(c => c.status === 'na')
  const orderedFindings = sortFindings(findings)

  function handleSegmentClick(check: Check) {
    if (check.findingId) {
      const id = check.findingId
      setOpenSection(null)
      setExpandedFinding(prev => prev === id ? null : id)
      brieflyHighlight(id)
      setTimeout(() => {
        document.getElementById(`finding-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }, 50)
      return
    }

    const section = check.status === 'passed' ? 'passed' : check.status === 'skipped' ? 'skipped' : 'na'
    setExpandedFinding(null)
    setOpenSection(section)
    brieflyHighlight(`check-${check.id}`)
    setTimeout(() => {
      document.getElementById(`check-${check.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }, 50)
  }

  function brieflyHighlight(id: string) {
    setHighlightedDetailId(null)
    setTimeout(() => setHighlightedDetailId(id), 20)
    setTimeout(() => setHighlightedDetailId(null), 520)
  }

  function toggleSection(section: 'passed' | 'skipped' | 'na') {
    setOpenSection(current => current === section ? null : section)
    setExpandedFinding(null)
  }

  async function runScanForTarget(normalizedTarget: string) {
    setIsScanning(true)
    setScanMessage('Checking the website...')
    try {
      const response = await fetch(`/api/scan?target=${encodeURIComponent(normalizedTarget)}`)
      if (!response.ok) {
        throw new Error(response.status === 502
          ? 'The backend is not running. Start FastAPI on port 8000.'
          : 'The scan service could not complete this request.')
      }
      const report = await response.json() as ScanReport
      const mappedReport = mapScanReport(report)
      setChecks(mappedReport.checks)
      setFindings(mappedReport.findings)
      setRiskScore(report.risk_score)
      setNetworkInfo(report.network_info ?? null)
      setBarRevision(revision => revision + 1)
      await loadHistory(normalizedTarget)
      setScanMessage('Scan complete')
    } catch (error) {
      setScanMessage(error instanceof Error ? error.message : 'Scan failed')
    } finally {
      setIsScanning(false)
    }
  }

  async function uploadSource(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    setUploadMessage('Scanning source archive...')
    const formData = new FormData()
    formData.append('file', file)
    try {
      const response = await fetch('/api/scan/upload', { method: 'POST', body: formData })
      if (!response.ok) throw new Error('The source scan could not complete.')
      const report = await response.json() as ScanReport
      const mappedReport = mapScanReport(report)
      setChecks(mappedReport.checks)
      setFindings(mappedReport.findings)
      setRiskScore(report.risk_score)
      setNetworkInfo(null)
      setUploadMessage(`Source scan complete: ${mappedReport.findings.length} finding${mappedReport.findings.length === 1 ? '' : 's'}.`)
    } catch (error) {
      setUploadMessage(error instanceof Error ? error.message : 'Source scan failed')
    } finally {
      event.target.value = ''
    }
  }

  async function runScan(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const normalizedTarget = targetUrl.trim().replace(/\/$/, '')
    if (!/^https?:\/\//i.test(normalizedTarget)) {
      setScanMessage('Enter a website address starting with http:// or https://.')
      return
    }
    if (/\/api\/(scan|history)(?:[/?]|$)/i.test(normalizedTarget)) {
      setScanMessage('Enter the target website URL, not the backend API URL. Try http://localhost:3000.')
      return
    }

    setTargetUrl(normalizedTarget)
    await runScanForTarget(normalizedTarget)
  }

  return (
    <div className="vibepen-app" style={{ minHeight: '100vh', background: C.bg, fontFamily: 'Inter, Arial, sans-serif', color: C.text }}>
      <div style={{ maxWidth: 860, margin: '0 auto', padding: '40px 20px', display: 'flex', flexDirection: 'column', gap: 24 }}>

        {/* Product context */}
        <div style={{ display: 'flex', alignItems: 'center', width: '100vw', marginTop: -40, marginLeft: 'calc(50% - 50vw)', padding: '12px max(20px, calc((100vw - 860px) / 2 + 16px))', background: '#0F172A', borderTop: '5px solid #0F172A', borderBottom: '1px solid #0F172A', boxShadow: '0 3px 10px rgba(28, 27, 23, 0.05)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
            <LogoMark />
            <div className="vibepen-wordmark" style={{ fontSize: 24, color: C.panel }}>VibePen</div>
          </div>
        </div>

        {/* Target control */}
        <form onSubmit={runScan} style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: '16px', background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, boxShadow: '0 3px 10px rgba(28, 27, 23, 0.08)' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
            <input
              id="target-url"
              type="url"
              value={targetUrl}
              onChange={event => setTargetUrl(event.target.value)}
              placeholder="https://your-target.example"
              disabled={isScanning}
              style={{ flex: '1 1 360px', minWidth: 0, border: `1px solid ${C.accent}`, background: '#F7F8F9', color: C.text, padding: '13px 14px', fontFamily: 'Consolas, monospace', fontSize: 14, outline: 'none' }}
            />
            <button
              type="submit"
              disabled={isScanning}
              aria-busy={isScanning}
              style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 8, border: '1px solid #0F172A', background: isScanning ? C.muted : '#0F172A', color: C.panel, padding: '13px 22px', minWidth: 148, fontFamily: 'Arial, sans-serif', fontSize: 13, fontWeight: 700, cursor: isScanning ? 'wait' : 'pointer' }}
            >
              {isScanning && <span aria-hidden="true" style={{ width: 12, height: 12, border: '2px solid rgba(255,255,255,0.45)', borderTopColor: C.panel, borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />}
              {!isScanning && <MaterialIcon name="play_arrow" label="Run scan" color={C.panel} size={14} />}
              {isScanning ? 'Scanning...' : 'Run New Scan'}
            </button>
          </div>
          {scanMessage && <div role="status" style={{ fontFamily: 'Arial, sans-serif', fontSize: 11, color: scanMessage === 'Scan complete' ? C.passed : C.muted }}>{scanMessage}</div>}
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, width: 'fit-content', fontFamily: 'Arial, sans-serif', fontSize: 12, color: C.accent, cursor: 'pointer' }}>
            <MaterialIcon name="upload_file" label="Upload source archive" color={C.accent} size={16} />
            Scan source ZIP
            <input type="file" accept=".zip,application/zip" onChange={uploadSource} style={{ position: 'absolute', width: 1, height: 1, opacity: 0 }} />
          </label>
          {uploadMessage && <div role="status" style={{ fontFamily: 'Arial, sans-serif', fontSize: 11, color: C.muted }}>{uploadMessage}</div>}
        </form>

        {/* Scan summary */}
        <section style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, boxShadow: '0 3px 10px rgba(28, 27, 23, 0.06)', overflow: 'hidden' }} aria-labelledby="scan-summary-heading">
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '18px 20px', borderBottom: `1px solid ${C.border}` }}>
            <ScanStatusMark />
            <div>
              <h1 id="scan-summary-heading" style={{ fontFamily: 'Georgia, serif', fontSize: 24, lineHeight: 1.2, margin: 0, color: C.text }}>Scan complete</h1>
              <p style={{ fontFamily: 'Arial, sans-serif', fontSize: 12, lineHeight: 1.5, color: C.muted, margin: '5px 0 0' }}>{completed.length} of {applicable.length} applicable checks completed{skipped.length > 0 ? ` - ${skipped.length} skipped` : ''}.</p>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 10, padding: 10 }}>
            <SummaryBox icon="warning" label="Things to fix" value={`${findings.length} Finding${findings.length === 1 ? '' : 's'}`} detail="Prioritize these results for remediation." color={C.critical} />
            <SummaryBox icon="check_circle" label="Passed cleanly" value={`${passed.length} Checks`} detail="No issues detected in completed checks." color={C.passed} />
            <SummaryBox icon="fast_forward" label="Skipped checks" value={`${skipped.length} Skipped`} detail={skipped.length ? 'Requires credentials or setup.' : 'No checks were skipped.'} color={C.muted} />
          </div>
        </section>

        {networkInfo && (
          <section style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16 }} aria-labelledby="network-heading">
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', borderBottom: `1px solid ${C.border}`, paddingBottom: 10, marginBottom: 12 }}>
              <div>
                <h2 id="network-heading" style={{ fontFamily: 'Newsreader, Georgia, serif', fontSize: 20, margin: 0 }}>Host and port discovery</h2>
                <div style={{ fontFamily: 'Arial, sans-serif', fontSize: 11, color: C.muted }}>{networkInfo.scanner ?? 'Network scanner'}{networkInfo.duration_seconds ? ` · ${networkInfo.duration_seconds}s` : ''}</div>
              </div>
              <strong style={{ fontFamily: 'Consolas, monospace', fontSize: 12, color: C.accent }}>{networkInfo.ip_address ?? 'IP unresolved'}</strong>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 8, fontFamily: 'Arial, sans-serif', fontSize: 12 }}>
              <div><strong>Host</strong><br />{networkInfo.hostname ?? 'Unknown'}</div>
              <div><strong>Scope</strong><br />{networkInfo.is_local ? 'Local sandbox' : 'External host'}</div>
              <div><strong>Open ports</strong><br />{networkInfo.open_ports?.length ?? 0}</div>
            </div>
            {!!networkInfo.open_ports?.length && <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12 }}>
              {networkInfo.open_ports.map(port => <span key={`${port.protocol ?? 'tcp'}-${port.port}`} style={{ border: `1px solid ${C.border}`, padding: '6px 8px', fontFamily: 'Consolas, monospace', fontSize: 11 }}>{port.port}/{port.protocol ?? 'tcp'} {port.service ?? ''}</span>)}
            </div>}
          </section>
        )}

        {/* Grid Bar */}
        <div style={{ background: C.panel, border: `1px solid ${C.border}`, padding: '18px 18px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 14, paddingBottom: 10, borderBottom: `1px solid ${C.border}` }}>
            <MaterialIcon name="troubleshoot" label="Security check coverage" color={C.accent} size={22} />
            <div style={{ marginTop: 1 }}>
              <h2 style={{ fontFamily: 'Newsreader, Georgia, serif', fontSize: 19, lineHeight: 1.2, color: C.text, margin: 0 }}>Security check coverage</h2>
              <p style={{ fontFamily: 'Inter, Arial, sans-serif', fontSize: 11, color: C.muted, margin: '3px 0 0' }}>Click each box to expand its detail.</p>
            </div>
          </div>
          <SegmentedBar key={barRevision} checks={checks} expandedFinding={expandedFinding} onSegmentClick={handleSegmentClick} />
          <LegendRow checks={checks} />
        </div>

        {/* Findings */}
        {findings.length > 0 && (
          <section style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 16, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, boxShadow: '0 3px 10px rgba(28, 27, 23, 0.05)' }} aria-labelledby="findings-heading">
            <div id="findings-heading" style={{ display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'Newsreader, Georgia, serif', fontSize: 20, color: C.text }}>
              <MaterialIcon name="flag" label="Finding" color={C.critical} size={18} />
              <span>Security findings ({findings.length})</span>
            </div>
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, background: C.panel, overflow: 'hidden' }}>
              {orderedFindings.map((f, i) => {
                const isOpen = expandedFinding === f.id
                const color = SEVERITY_COLOR[f.severity]
                return (
                  <div key={f.id} id={`finding-${f.id}`} style={{ borderBottom: i < findings.length - 1 ? `1px solid ${C.border}` : 'none', boxShadow: highlightedDetailId === f.id ? `0 0 0 3px ${C.accent}55, 0 5px 18px ${C.accent}35` : undefined, transition: 'box-shadow 0.15s ease' }}>
                    {/* Row header — same pattern as CollapsibleSection */}
                    <button
                      onClick={() => setExpandedFinding(isOpen ? null : f.id)}
                      aria-expanded={isOpen}
                      style={{
                        width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                        padding: '11px 16px', textAlign: 'left', background: C.panel,
                        border: 'none', cursor: 'pointer',
                        borderBottom: isOpen ? `1px solid ${C.border}` : 'none',
                      }}
                      onMouseEnter={e => (e.currentTarget.style.background = C.bg)}
                      onMouseLeave={e => (e.currentTarget.style.background = C.panel)}
                    >
                      <MaterialIcon name={isOpen ? 'keyboard_arrow_down' : 'chevron_right'} label={isOpen ? 'Collapse finding' : 'Expand finding'} color={C.accent} size={14} />
                      <span style={{ fontFamily: 'Georgia, serif', fontSize: 13, fontWeight: 700, color: C.text }}>{f.checkLabel}</span>
                      <span style={{ marginLeft: 'auto', width: 14, height: 14, flexShrink: 0, backgroundColor: color, display: 'inline-block' }} aria-label={f.severity} />
                    </button>
                    {/* Expanded body */}
                    {isOpen && (
                      <div style={{ background: C.bg, padding: '14px 16px 14px 36px', display: 'flex', flexDirection: 'column', gap: 12 }}>
                        <p style={{ fontFamily: 'Georgia, serif', fontSize: 13, color: C.bodyText, lineHeight: 1.6, margin: 0 }}>{f.summary}</p>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}><MaterialIcon name="code" label="Technical evidence" /><div style={{ fontFamily: 'Inter, Arial, sans-serif', fontSize: 10, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Evidence</div></div>
                          <pre style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: C.bodyText, background: C.panel, border: `1px solid ${C.border}`, padding: '8px 10px', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                            {f.evidence}
                          </pre>
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}><MaterialIcon name="auto_awesome" label="Remediation" color={C.accent} /><div style={{ fontFamily: 'Inter, Arial, sans-serif', fontSize: 10, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Recommended action</div></div>
                          <p style={{ fontFamily: 'Georgia, serif', fontSize: 13, color: C.bodyText, lineHeight: 1.6, margin: 0 }}>{f.recommendation}</p>
                        </div>
                        {(f.location || f.confidence !== undefined) && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 24px', borderTop: `1px solid ${C.border}`, paddingTop: 10 }}>
                            {f.location && (
                              <div>
                                <div style={{ fontFamily: 'Arial, sans-serif', fontSize: 10, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>Location</div>
                                <code style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: C.muted }}>{f.location}</code>
                              </div>
                            )}
                            {f.confidence !== undefined && (
                              <div>
                                <div style={{ fontFamily: 'Arial, sans-serif', fontSize: 10, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>Confidence</div>
                                <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: C.muted }}>{(f.confidence * 100).toFixed(0)}%</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </section>
        )}

        {/* Passed and skipped validations */}
        <section style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: 16, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, boxShadow: '0 3px 10px rgba(28, 27, 23, 0.05)' }} aria-labelledby="validation-heading">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <div id="validation-heading" style={{ display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'Newsreader, Georgia, serif', fontSize: 18, fontWeight: 600, color: C.text }}>
              <MaterialIcon name="verified" label="Validations passed" color={C.passed} size={18} />
              <span>Passed &amp; skipped validations</span>
            </div>
            <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: C.muted }}>Automated checks</span>
          </div>

          <CollapsibleSection title="Passed checks" count={passed.length} open={openSection === 'passed'} onToggle={() => toggleSection('passed')}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 8, padding: 12 }}>
              {passed.map(c => (
                <div key={c.id} id={`check-${c.id}`} style={{ display: 'flex', alignItems: 'flex-start', gap: 9, padding: '10px', background: C.panel, border: `1px solid ${C.border}`, boxShadow: highlightedDetailId === `check-${c.id}` ? `0 0 0 3px ${C.passed}55, 0 5px 18px ${C.passed}35` : undefined, transition: 'box-shadow 0.15s ease' }}>
                  <MaterialIcon name="check_circle" label="Passed check" color={C.passed} size={14} />
                  <div>
                    <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, fontWeight: 700, color: C.bodyText }}>{c.label}</span>
                    <p style={{ fontFamily: 'Arial, sans-serif', fontSize: 11, lineHeight: 1.4, color: C.muted, margin: '3px 0 0' }}>No issue detected.</p>
                  </div>
                </div>
              ))}
            </div>
          </CollapsibleSection>

          {skipped.length > 0 && (
            <CollapsibleSection title="Skipped checks" count={skipped.length} open={openSection === 'skipped'} onToggle={() => toggleSection('skipped')}>
              {skipped.map((c, i) => (
                <div key={c.id} id={`check-${c.id}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '11px 16px', borderBottom: i < skipped.length - 1 ? `1px solid ${C.border}` : 'none', boxShadow: highlightedDetailId === `check-${c.id}` ? `0 0 0 3px ${C.muted}55, 0 5px 18px ${C.muted}35` : undefined, transition: 'box-shadow 0.15s ease' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span aria-hidden="true" className="seg-skipped" style={{ width: 9, height: 9, flexShrink: 0, display: 'inline-block' }} />
                      <span style={{ fontFamily: 'Georgia, serif', fontSize: 13, color: C.bodyText }}>{c.label}</span>
                    </div>
                    {c.reason && <p style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: C.muted, margin: '4px 0 0 17px' }}>{c.reason}</p>}
                  </div>
                  <span style={{ flexShrink: 0, fontFamily: 'Consolas, monospace', fontSize: 10, color: C.muted, background: C.bg, padding: '4px 6px' }}>Requires setup</span>
                </div>
              ))}
            </CollapsibleSection>
          )}
        </section>

        {/* N/A */}
        {naChecks.length > 0 && (
          <CollapsibleSection title="Not applicable checks" count={naChecks.length} description="These checks do not apply to this target and do not affect the risk score." open={openSection === 'na'} onToggle={() => toggleSection('na')}>
            {naChecks.map((c, i) => (
              <div key={c.id} id={`check-${c.id}`} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 16px', borderBottom: i < naChecks.length - 1 ? `1px solid ${C.border}` : 'none', boxShadow: highlightedDetailId === `check-${c.id}` ? `0 0 0 3px ${C.na}99, 0 5px 18px ${C.na}66` : undefined, transition: 'box-shadow 0.15s ease' }}>
                <span style={{ width: 8, height: 8, flexShrink: 0, backgroundColor: C.na, display: 'inline-block' }} />
                <span style={{ fontFamily: 'Georgia, serif', fontSize: 13, color: C.muted }}>{c.label}</span>
              </div>
            ))}
          </CollapsibleSection>
        )}

        {/* History */}
        <section style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: 16, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, boxShadow: '0 3px 10px rgba(28, 27, 23, 0.05)' }} aria-labelledby="scan-history-heading">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <div id="scan-history-heading" style={{ display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'Newsreader, Georgia, serif', fontSize: 18, fontWeight: 600, color: C.text }}>
              <MaterialIcon name="table_rows" label="Scan history" color={C.accent} />
              <span>Scan run history</span>
            </div>
            <button type="button" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, border: 'none', background: 'transparent', color: C.text, padding: 0, fontFamily: 'JetBrains Mono, monospace', fontSize: 11, cursor: 'pointer' }}>
              View all history <span aria-hidden="true">→</span>
            </button>
          </div>
          <div style={{ border: `1px solid ${C.border}`, background: C.panel, overflow: 'hidden' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 1.2fr) minmax(130px, 1fr) minmax(150px, 1fr) minmax(90px, auto)', gap: 16, padding: '10px 16px', background: C.bg, color: C.muted, fontFamily: 'JetBrains Mono, monospace', fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              <span>Timestamp (UTC)</span>
              <span>Findings breakdown</span>
              <span>Coverage</span>
              <span style={{ textAlign: 'right' }}>Run status</span>
            </div>
            {history.map((entry, index) => (
              <div key={`${entry.scannedAt}-${entry.target}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 1.2fr) minmax(130px, 1fr) minmax(150px, 1fr) minmax(90px, auto)', alignItems: 'center', gap: 16, padding: '11px 16px', borderBottom: index < history.length - 1 ? `1px solid ${C.border}` : 'none' }}>
                <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: C.muted }}>{new Date(entry.scannedAt).toLocaleString()}</span>
                <FindingsBreakdown entry={entry} />
                <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: C.muted, whiteSpace: 'nowrap' }}>{completed.length} of {applicable.length} ran ({skipped.length} skipped)</span>
                <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: C.passed, textAlign: 'right', whiteSpace: 'nowrap' }}>Completed</span>
              </div>
            ))}
          </div>
        </section>

      </div>
    </div>
  )
}
