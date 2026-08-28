# AutoPenAI — Project Status Report

**Purpose of this document:** if you're a teammate picking this up, or pasting this into Claude to continue work, this tells you exactly what exists, what works, what's broken, and where to pick up. Read this before touching any code.

---

## 1. Project Overview (for context)

AutoPenAI is an FYP building an automated security scanner focused on vulnerabilities common in AI-generated ("vibe coded") web applications. The core (current focus) is a **detector**: code that finds security problems either by reading source code (static analysis) or by attacking a running app with real requests (dynamic testing). Findings get scored by severity/confidence and ranked. Later phases (not started) add an LLM report generator, a React dashboard, and broader tool integration (Nmap, SQLMap).

The team is divided into: **Person 1** (static analyzer), **Person 2A** (dynamic — access control/CORS/auth), **Person 2B** (dynamic — injection/XSS), **Person 3** (scoring + dataset).

---

## 2. Environment / Setup Status

✅ **Fully working and documented.**

- Repo cloned, Python 3.11 venv set up in `backend/`
- `requirements.txt` committed and working
- Docker running two sandbox targets:
  - `dvwa` container → `http://localhost:8080`
  - `juice-shop` container → `http://localhost:3000`
- **Known gotcha, already solved:** DVWA needs a one-time manual step after first container start — visit `http://localhost:8080/setup.php` and click "Create/Reset Database," or login will silently fail and bounce to setup.php. This is documented in `docs/AutoPenAI_Team_Onboarding.md`.
- DVWA admin password has been **changed from the default `password` to `iamesar`** on this dev machine. This is stored in `.env` (gitignored). If teammates use their own DVWA instance, the default `admin`/`password` still applies unless they've also changed it.
- Reference docs already in repo:
  - `docs/AutoPenAI_Team_Onboarding.md` — full setup instructions for new machines
  - `docs/evaluation_notes.md` — DVWA security-level test results (see section 5 below)

---

## 3. Person 2A — Access Control Checks

✅ **Done, working, committed.**

**Files (`backend/detector/dynamic/`):**
- `auth_session.py` — logs into DVWA, handles CSRF token, verifies session, also has `set_dvwa_security()` / `get_dvwa_security_level()` (see note below — these were added mid-session and are shared with 2B)
- `cors_checks.py` — checks for wildcard CORS headers
- `auth_bypass_checks.py` — checks if protected pages are reachable without login
- `rate_limit_checks.py` — checks if rapid requests ever get throttled
- `run_dynamic_access.py` — combines all of the above

**Verified result:** running `python -m detector.dynamic.run_dynamic_access` against DVWA correctly returns a `missing_rate_limit` finding (DVWA has no rate limiting, confirmed real). CORS and auth-bypass checks return empty against the specific tested paths — this is correct behavior, not a bug (those specific paths are properly protected in DVWA).

**Status: this module's Definition of Done is met. No known open issues.**

---

## 4. Person 2B — Injection & XSS Checks

⚠️ **Mostly done. One function still broken (stored XSS). Everything else works and has been tested extensively across DVWA's security levels.**

**Files (`backend/detector/dynamic/`):**
- `injection_checks.py` — `check_sql_injection_error_based()`, `check_sql_injection_boolean()` — **working**
- `xss_checks.py` — `check_reflected_xss()` **working**; `check_stored_xss()` **broken, see below**
- `run_dynamic_injection.py` — combines the above, takes a `security_level` parameter

### What works
- SQLi error-based and boolean-based detection both confirmed working against DVWA at Low security.
- Reflected XSS confirmed working at Low, Medium, and High (only blocked at Impossible, correctly).
- Full 4-level DVWA security sweep completed and documented in `docs/evaluation_notes.md` — see section 5.

### What's broken — Stored XSS (`check_stored_xss` in `xss_checks.py`)

**Symptom:** function returns `{"error": "Could not find CSRF token on stored XSS page"}` every time.

**What we know so far (debugged this session):**
- We ARE reaching the correct page (`http://localhost:8080/vulnerabilities/xss_s/`, status 200, confirmed via debug print of final URL).
- The string `user_token` does **not appear anywhere** in that page's HTML at all — confirmed via debug dump of the first 500 characters and a full-text search.
- This is different from the login/security.php CSRF issues we hit earlier (where the token existed but our regex initially didn't match it) — here the token may genuinely not exist on this specific form.

**Next step (not yet done):** dump the actual `<form>...</form>` HTML block from the stored XSS page (code for this is already written, just needs to be run — see below) to see the real field names and confirm whether a CSRF token field exists at all on this form. If it doesn't, the fix is simple: remove the `user_token` requirement from the POST payload entirely for this specific function. If it does exist under a different structure, adjust the regex like we did for login.php.

**Exact code to run to continue this debugging**, paste into `check_stored_xss` in place of the current token-search block:
```python
page = session.get(page_url, timeout=5)
print("=== PAGE STATUS ===", page.status_code)

form_start = page.text.find("<form")
form_end = page.text.find("</form>", form_start) + len("</form>")
print("=== FULL FORM HTML ===")
print(page.text[form_start:form_end])
```
Run `python -m detector.dynamic.xss_checks` and read the printed form HTML to determine the real fix.

---

## 5. Evaluation Data Collected This Session

Full writeup in `docs/evaluation_notes.md`. Summary table:

| Security Level | SQLi (error-based) | SQLi (boolean-based) | Reflected XSS |
|---|---|---|---|
| Low | ✅ Detected | ✅ Detected | ✅ Detected |
| Medium | ❌ Not detected | ❌ Not detected | ✅ Detected |
| High | ❌ Not detected | ❌ Not detected | ✅ Detected |
| Impossible | ❌ Not detected | ❌ Not detected | ❌ Not detected |

**Why this matters:** this shows the detector correctly tracks DVWA's actual mitigation strength — SQLi gets blocked once `mysqli_real_escape_string()` is introduced (Medium+), while reflected XSS stays exploitable until Impossible's proper `htmlspecialchars()` escaping. This is real, citable evaluation evidence, not just a smoke test. Known limitation already documented: our SQLi payloads are quote-based only; other payload types (numeric-context injection, time-based blind) haven't been tested and might behave differently.

---

## 6. Person 1 — Static Analyzer

❌ **Status unknown from this session — was assigned to a peer via `AutoPenAI_Peer_Task_Assignments.md`.**

Per the task doc, Person 1 should be building, in `backend/detector/static/`:
- `secret_rules.py` — hardcoded secrets detection
- `injection_rules.py` — unsafe eval + SQL string concatenation detection
- `xss_rules.py` — unsafe innerHTML detection
- `run_static.py` — combines all checks, meant to be tested against real cloned Juice Shop source code

**Action needed:** check in with whoever owns this — confirm progress against the Definition of Done in the task doc (all 4 files exist, `run_static.py` runs without errors, has been tested against real Juice Shop source).

---

## 7. Person 3 — Scoring + Dataset

❌ **Status unknown from this session — was assigned to a peer via `AutoPenAI_Peer_Task_Assignments.md`. Not built by the project owner in this session.**

Per the task doc, Person 3 should be building, in `backend/detector/scoring/` and `dataset/`:
- `weights.py` — severity/confidence lookup tables
- `scorer.py` — `score_finding()`, `score_all()`, `rank_findings()`
- `dataset/metadata.json` — dataset entry structure

**Action needed:** check in on progress. Note: this module can now be tested against REAL findings instead of fake sample data, since Person 2A and 2B both have genuine working output — recommend pointing `score_all()` at the actual output of `run_dynamic_access()` and `run_dynamic_injection()` combined, once Person 3 has `scorer.py` built.

---

## 8. Immediate Next Steps (in priority order)

1. **Fix `check_stored_xss`** — run the form-dump debug code above, adjust the CSRF handling (or remove it if the field doesn't exist), re-test.
2. **Check in with Person 1 and Person 3** — confirm their status against the task doc's Definition of Done for each.
3. **Once Person 1 and Person 3 have working code**, schedule the joint integration session to build `run_full_scan.py` combining static + dynamic + scoring — this needs all three/four people present together, not done solo, since schema mismatches surface here.
4. **Extend SQLi payload coverage** (noted as a limitation in evaluation_notes.md) — worth doing before final evaluation write-up, not urgent right now.
5. **Repeat the security-level sweep methodology against Juice Shop** where applicable, for a second data point beyond DVWA.

---

## 9. Known Gotchas To Remember (so nobody re-debugs these)

- DVWA needs `setup.php` → "Create/Reset Database" run once after a fresh container start, or login silently fails.
- DVWA's security level is **not** purely session-based — it appears to persist more globally than expected; but our code explicitly calls `set_dvwa_security()` every run anyway, so this is a non-issue in practice as long as that function is used.
- Always run detector scripts as modules from the `backend/` folder: `python -m detector.dynamic.xxx`, never `python detector\dynamic\xxx.py` directly, or imports break.
- If `ImportError: cannot import name X from Y` shows up, the file exists but is empty/wasn't saved after pasting — this has happened multiple times this session, always check the file isn't blank first.
- DVWA admin password on this dev machine is `iamesar`, not the default `password` — stored in `.env`, not hardcoded in committed code.
