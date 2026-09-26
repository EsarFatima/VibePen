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

✅ **Done, working, tested at all DVWA security levels.**

**Files (`backend/detector/dynamic/`):**
- `injection_checks.py` — `check_sql_injection_error_based()`, `check_sql_injection_boolean()` — **working**
- `xss_checks.py` — `check_reflected_xss()` **working**; `check_stored_xss()` **fixed** ✅
- `error_handling_checks.py` — `check_verbose_error_handling()` — **working** (NEW)
- `run_dynamic_injection.py` — combines all checks, takes a `security_level` parameter

### What's working
- ✅ SQLi error-based detection — detects leaked SQL errors at Low security
- ✅ SQLi boolean-based detection — detects response length differences at Low security
- ✅ Reflected XSS detection — detects unescaped input reflection at Low-High security
- ✅ Stored XSS detection — detects stored payloads persisting at Low-Medium security (fixed by making CSRF token optional)
- ✅ Verbose error handling detection — detects PHP/SQL error leaks and technical details across all security levels
- ✅ Full 4-level DVWA security sweep completed and documented in `docs/evaluation_notes.md`

### What changed this session
- **Fixed**: `check_stored_xss()` now handles forms without CSRF tokens
- **Added**: `check_verbose_error_handling()` to detect information disclosure via error messages
- **Result**: All findings tested and verified at Low/Medium/High/Impossible security levels

**Status: Person 2B's Definition of Done is MET. All checks working. No known open issues.**

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

1. ✅ **Fix `check_stored_xss`** — COMPLETE. Made CSRF token optional on form submissions.
2. ✅ **Build verbose error handling checks** — COMPLETE. Added `error_handling_checks.py` to detect information disclosure.
3. **Check in with Person 1 and Person 3** — confirm their status and build skeleton code for both.
4. **Once Person 1 and Person 3 have working code**, schedule the joint integration session to build `run_full_scan.py` combining static + dynamic + scoring — this needs all three/four people present together, not done solo, since schema mismatches surface here.
5. **Extend SQLi payload coverage** (noted as a limitation in evaluation_notes.md) — worth doing before final evaluation write-up, not urgent right now.
6. **Repeat the security-level sweep methodology against Juice Shop** where applicable, for a second data point beyond DVWA.

---

## 9. Known Gotchas To Remember (so nobody re-debugs these)

- DVWA needs `setup.php` → "Create/Reset Database" run once after a fresh container start, or login silently fails.
- DVWA's security level is **not** purely session-based — it appears to persist more globally than expected; but our code explicitly calls `set_dvwa_security()` every run anyway, so this is a non-issue in practice as long as that function is used.
- Always run detector scripts as modules from the `backend/` folder: `python -m detector.dynamic.xxx`, never `python detector\dynamic\xxx.py` directly, or imports break.
- If `ImportError: cannot import name X from Y` shows up, the file exists but is empty/wasn't saved after pasting — this has happened multiple times this session, always check the file isn't blank first.
- DVWA admin password on this dev machine is `iamesar`, not the default `password` — stored in `.env`, not hardcoded in committed code.

---

## 10. Current Status Update — September 2026

> This section is the current status and supersedes older unfinished items above where they conflict.

### Overall position

The project is now a working dynamic-scanning prototype with automatic target detection, shared scoring, scan history, and a simple dashboard. The user enters only a website URL; the system decides which checks to run.

### Supported targets

| Target | Automatic detection | Dashboard scan | Current coverage |
|---|---:|---:|---|
| OWASP Juice Shop | ✅ | ✅ | Application-specific API checks plus browser safety checks |
| DVWA | ✅ | ✅ | Public access checks plus authenticated SQLi, XSS, rate-limit, and error checks |
| Unknown live website | ✅ | ✅ | Safe generic HTTPS and security-header checks |

### Juice Shop verified result

Live target: `http://localhost:3000`

- Anonymous scan: 3 findings, risk score `15.5`
- Authenticated scan with two test accounts: 6 findings, risk score `28.2`
- 2 critical, 1 medium, 3 low in the authenticated scan
- Anonymous administrative configuration access
- Cross-account access to another user's basket
- Wildcard CORS
- Missing browser safety headers
- Detailed error pages on unauthenticated order-history and user-data requests

Relevant files:

- `backend/detector/dynamic/juice_shop_checks.py`
- `backend/detector/dynamic/run_dynamic_juice_shop.py`
- `backend/target_detection.py`

### DVWA verified result

Live target: `http://localhost:8080`

- 14 findings
- Risk score: `36.5`
- Authentication verified through the local server environment
- Finding categories include missing rate limiting, SQL injection, XSS, and verbose error handling

Relevant file:

- `backend/detector/dynamic/run_dynamic_dvwa.py`

The dashboard does not display or return passwords. Authenticated DVWA checks require server-side environment variables:

```powershell
$env:DVWA_USERNAME = "admin"
$env:DVWA_PASSWORD = "<local password>"
$env:DVWA_SECURITY_LEVEL = "low"
```

The current running DVWA container accepted the standard local `admin` / `password` credentials during verification. Teammates must use the credentials configured by their own DVWA instance.

### Generic live-site checks

Unknown reachable websites receive a baseline scan instead of an empty or misleading clean result:

- HTTPS usage
- Content Security Policy
- Referrer Policy
- Permissions Policy

Example verified target: `https://example.com` returned one low-severity missing-header finding.

The report explains that only general checks were performed because the application was not recognized.

### Scoring and reporting

Implemented in `backend/detector/scoring/scorer.py`:

- Deterministic finding IDs
- Severity and confidence
- Per-finding score
- Risk score total
- Severity counts
- Ranking by score
- Plain-language descriptions and remediation guidance

### Dashboard and history

Implemented in `backend/app.py`:

- URL-only user workflow
- Automatic target detection
- Risk score and severity summary
- Finding evidence and remediation
- Animated gear while a scan is running
- Clear completed and failed states
- Simple language for non-technical users
- Recent scan timeline
- Target-specific scan history
- `GET /api/scan`
- `GET /api/history`

History is stored locally in `backend/scan_history.json`. The current page is a functional prototype; it is intentionally simple and can later be replaced by the Figma-designed UI without changing the scan API.

### Team ownership of current work

- **Member 1 — Static analysis:** source-code checks for hardcoded secrets, unsafe SQL construction, `eval()`, unsafe HTML rendering, and insecure dependencies.
- **Member 2A — Dynamic access and authentication:** DVWA and Juice Shop access-control, authentication, CORS, rate-limit, and cross-account work.
- **Member 2B — Dynamic injection and behavior:** SQL injection, XSS, error disclosure, input reflection, and browser safety checks.
- **Member 3 — Scoring and reporting:** severity, confidence, risk ranking, history, and the shared report contract.
- **Network Reconnaissance & Host Discovery:** URL to IP tracking and automated port scanning via Nmap 7.991 and fallback socket scanning.

### Network Reconnaissance & Nmap Integration — September 2026

- **Module**: `backend/scanners/network_scanner.py`
- **Capabilities**:
  - Automatically parses URLs with or without scheme and port (`http://localhost:3000`, `scanme.nmap.org`).
  - Resolves domain names to IPv4 addresses via `socket.gethostbyname`.
  - Discovers open ports and services using `nmap.exe` (installed at `C:\Program Files (x86)\Nmap\nmap.exe`, Nmap 7.991).
  - Uses XML output parsing (`-oX -`) for fast, deterministic extraction of open ports and services.
  - Automatically includes URL-specific ports (e.g. 3000 for Juice Shop, 8080 for DVWA) alongside common web, database, and admin ports.
  - Resilient design: falls back to native Python socket scanning if Nmap times out or is uninstalled on another machine.
- **API & UI Integration**:
  - `/api/scan` returns `network_info` containing hostname, IP address, scanner name, and open ports list.
  - Interactive dashboard (`http://localhost:8000`) renders host & IP badges and an open ports grid in real time.
- **Verified Results**:
  - `http://localhost:3000` $\rightarrow$ IP `127.0.0.1`, detected open ports: 80, 3000, 3306, 8080 (0.7s - 1.5s scan time).
  - `https://example.com` $\rightarrow$ IP `172.66.147.243`, detected open ports: 80, 443, 8080, 8443.

### Next steps

1. Build Member 1's static analyzer and test it against cloned Juice Shop source.
2. Normalize static findings to the same format as dynamic findings.
3. Combine static and dynamic results into one full-scan report.
4. Add history comparisons for new, fixed, and unchanged findings.
5. Expand Juice Shop and DVWA endpoint coverage with regression tests. Juice Shop's anonymous and authenticated runner paths now have regression coverage.
6. Replace the prototype dashboard with the final Figma UI while keeping the existing API contract.

