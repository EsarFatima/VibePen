import { describe, expect, it } from 'vitest'
import { mapReport } from './TemplateHome'

describe('production scan report mapping', () => {
  it('keeps backend findings ordered by severity data', () => {
    const mapped = mapReport({
      risk_score: 10,
      findings: [
        { type: 'xss', severity: 'medium', title: 'Reflected XSS' },
        { type: 'idor', severity: 'critical', title: 'Broken access control' },
      ],
    })

    expect(mapped.findings.map(finding => finding.severity)).toEqual(['medium', 'critical'])
    expect(mapped.checks.filter(check => check.status === 'critical')).toHaveLength(1)
  })
})
