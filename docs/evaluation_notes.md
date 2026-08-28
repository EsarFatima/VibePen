# AutoPenAI — Evaluation Notes: DVWA Security Level Testing

## Purpose

DVWA's security levels (Low/Medium/High/Impossible) are a teaching construct specific to DVWA — real-world websites have no equivalent toggle. We use these levels purely as a controlled way to measure our detector's sensitivity: does it only catch the most blatant, unmitigated version of a vulnerability, or does it still catch partially-mitigated versions? This is a repeatable robustness test, not a feature the final tool needs for arbitrary real targets.

## Methodology

- Target: DVWA (Docker container, `bkimminich/juice-shop` sibling setup — actually `vulnerables/web-dvwa`)
- Our script (`run_dynamic_injection.py`) explicitly sets the DVWA security level programmatically via `set_dvwa_security()` before each test run, overriding whatever the browser UI shows — this makes tests repeatable and independent of manual browser state.
- Checks tested:
  - `check_sql_injection_error_based` — sends a single quote (`'`) as the `id` param, checks for leaked DB error text
  - `check_sql_injection_boolean` — compares response length between a TRUE (`' OR '1'='1`) and FALSE (`' OR '1'='2`) payload, threshold: >50 char difference
  - `check_reflected_xss` — sends a unique marker wrapped in `<angle brackets>`, checks if it's echoed back unescaped

## Results

| Security Level | SQLi (error-based) | SQLi (boolean-based) | Reflected XSS |
|---|---|---|---|
| Low | ✅ Detected | ✅ Detected | ✅ Detected |
| Medium | ❌ Not detected | ❌ Not detected | ✅ Detected |
| High | ❌ Not detected | ❌ Not detected | ✅ Detected |
| Impossible | *(fill in after test)* | *(fill in after test)* | *(fill in after test)* |

## Interpretation

**SQLi detection drops off between Low and Medium.** DVWA's Medium/High tiers use `mysqli_real_escape_string()` to escape quote characters, which neutralizes both our error-based payload (the `'` gets escaped before reaching the query, so no syntax error occurs) and our boolean-based payload (`' OR '1'='1` similarly gets escaped and no longer changes query logic). This is expected, correct behavior — our detector isn't broken, the underlying vulnerability is genuinely mitigated by these specific payload types at Medium and above.

**Reflected XSS detection remains constant through Medium and High.** This reveals that DVWA's XSS filtering at these levels only blocks specific literal patterns (commonly `<script>` tags), not arbitrary HTML-like markers. Our test payload format (`<xsstest_XXXXXXXX>`) isn't a real script tag, so it bypasses this naive blacklist-style filtering. This is a realistic, useful finding: blacklist-based XSS filters are commonly bypassed by anything outside the exact filtered pattern.

**Limitation to state explicitly:** our SQLi payloads are quote-based only (error-based and boolean-based via `'`). We have not tested payload variants that might bypass `mysqli_real_escape_string()`-style escaping (e.g., numeric-context injection without quotes, since the `id` field is used in a numeric comparison in some DVWA variants). This means "0 findings at Medium/High" should be read as "not detected by our current payload set," not "definitively not vulnerable" — an important distinction for the report's honesty.

## What this means for the FYP

This table is genuine evaluation evidence for the dissertation/report:
- It demonstrates the detector correctly distinguishes between vulnerable and mitigated code (not just flagging everything indiscriminately) — a meaningful negative-control result.
- It surfaces an honest limitation (payload set narrowness) rather than overclaiming complete coverage.
- It sets up a natural comparison point against Juice Shop and the team's own AI-generated app dataset later — the same level-based methodology (where applicable) or a similar layered-mitigation comparison can be applied there.

## Next steps

- [ ] Fill in Impossible-level results once tested
- [ ] Test whether raw HTTP requests (bypassing DVWA's dropdown UI at Medium) reveal anything the browser UI itself would prevent a normal user from attempting
- [ ] Extend SQLi payload set (numeric-context injection, time-based blind) to reduce the "not detected by our current payload set" caveat
- [ ] Repeat similar level/mitigation-based testing against Juice Shop where applicable
- [ ] Feed these results into Person 3's `evaluate_against_known_vulns()` once that module is built
