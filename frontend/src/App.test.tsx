import { describe, expect, it } from 'vitest'
import { CHECKS, FINDINGS, countByStatus, sortFindings } from './App'

describe('scan health data contract', () => {
  it('keeps header, bar, and legend counts mathematically consistent', () => {
    const na = countByStatus(CHECKS, 'na')
    const skipped = countByStatus(CHECKS, 'skipped')
    const applicable = CHECKS.length - na
    const completed = applicable - skipped
    const statusTotal = countByStatus(CHECKS, 'passed') + countByStatus(CHECKS, 'low') + countByStatus(CHECKS, 'medium') + countByStatus(CHECKS, 'high') + countByStatus(CHECKS, 'critical') + skipped + na

    expect({ applicable, completed, skipped, na, statusTotal }).toEqual({ applicable: 13, completed: 11, skipped: 2, na: 3, statusTotal: 16 })
  })

  it('keeps findings ordered from most to least severe', () => {
    expect(sortFindings(FINDINGS).map(finding => finding.severity)).toEqual(['critical', 'critical', 'high', 'medium'])
  })
})
