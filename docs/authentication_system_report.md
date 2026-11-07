# VibePen FYP: Progress Report, 7 November 2026

**Project:** VibePen, a scanner for vibe-coded websites (FYP F26-077, FAST Lahore)
**Author:** Esar Fatima
**Deadline:** 4 December 2026

## 1. Summary

Today's work had three parts. First, I checked the domain ownership verification feature and fixed my local environment. Second, I replaced the simulated login with a real account system backed by PostgreSQL, including email verification. Third, I added a third domain verification method (a meta tag in the homepage) to the backend, with unit tests.

Before today, signing in only stored whatever email was typed into the browser's `localStorage`. There was no user table, no password check and no server-side session. Now accounts, passwords, sessions and email confirmation are handled by the backend, and the whole sign-up, confirm and sign-in flow was tested end to end in the browser.

## 2. Domain ownership verification

**Checks and corrections**

- Confirmed the DNS TXT record name is `_vibepen-verify.<domain>` (with the underscore) in both `backend/verification.py` and the UI text. An earlier handoff note said there was no underscore. That note was wrong, and the code and UI agree with each other.
- Confirmed that `localhost` and `127.0.0.1` are trusted automatically. The default scan target `http://localhost:3000` is Juice Shop (confirmed with `docker ps`), which is why it showed "Domain verified".
- Found that an earlier handoff note was wrong about the meta tag: `verification.py` only supported `dns` and `file`. The meta method did not exist in the backend, even though the UI's "how verification works" text mentioned it.

**Meta tag method (new, backend)**

The owner adds `<meta name="vibepen-verification" content="<token>">` to the `<head>` of the homepage. `_check_meta` in `backend/verification.py` verifies it with these safeguards:

- Refuses private and internal addresses before making any request (same protection as the file check).
- Follows only same-host redirects, up to 3. A redirect to another host (for example `example.com` to `www.example.com`, or anything external) is refused, so the owner must register the host they actually serve.
- Reads at most 512 KB of the page, and accepts the tag only if it appears before `<body>`, so a tag placed in page content does not count.
- Reads the HTML the server sends and does not run JavaScript, so on React or Vite sites the tag must be in `index.html`, not in a component. The failure message tells the user this.
- A meta tag proves control of one host only, so (like the file method) it does not authorize subdomains. A DNS record still covers the whole zone.
- `verify_domain` now accepts `dns`, `file` or `meta`, and the challenge response includes a ready-made `meta_tag` string.

**Meta tag method (UI)**

The UI tab, method mapping and instruction text are prepared as five small edits to `frontend/src/TemplateHome.tsx` (add `'Meta tag'` to the method type and tab list, map it to `meta`, show the tag as the copyable value). They need to be applied and checked in the browser (see section 9).

## 3. Environment fixes

- The backend virtual environment was created when the project folder was named `AutoPen`, so `pip.exe` points at a path that no longer exists. Fix: always use `python -m pip ...` inside this venv, or recreate the venv.
- Installed missing packages (`dnspython`, `pytest`).
- `http://0.0.0.0:8000` cannot be opened in a browser. Use `http://localhost:8000/docs`.
- A leftover uvicorn process kept `vibepen.db` locked. Stopped the stray Python processes. Port 8000 is now free.

## 4. Authentication system (backend)

New files in `backend/`: `db.py`, `auth.py`, `mailer.py`. `app.py` creates the tables on startup and includes the auth router.

**Endpoints (`/api/auth`)**

| Endpoint | Purpose |
|---|---|
| `POST /register` | Creates the account (unverified), emails a confirmation link. Does not sign the user in. |
| `POST /verify-email` | Consumes the emailed token, marks the email verified, starts a session. |
| `POST /resend-verification` | Issues a fresh link. Answers the same whether or not the email exists. |
| `POST /login` | Checks the password. Refuses unverified accounts with 403. |
| `POST /logout` | Deletes the server-side session. |
| `GET /me` | Returns the signed-in user, or 401. |

**Security design**

- **Passwords:** argon2id hashes only (`argon2-cffi`). Plain passwords are never stored. Verified in the database: hashes start with `$argon2id$v=19$m=65536,t=3,p=4`.
- **Tokens:** generated with `secrets.token_urlsafe(32)` (32 random bytes, 256 bits). The database stores only the SHA-256 hash of each token, so a leaked database cannot be used to build working links or cookies.
- **Email token:** valid for 24 hours and single-use. The row is deleted after use, so a second click fails with "invalid or has expired". Resending removes older tokens, so only the newest link works.
- **Session:** a separate random token, stored hashed with a 30-day expiry. The browser holds the raw value in an `httpOnly`, `SameSite=Lax` cookie, so scripts on the page cannot read it. Logout deletes the row, which ends the session immediately.
- **Email delivery:** `mailer.py` sends through SMTP when `SMTP_HOST` is set. Otherwise it prints the email in the uvicorn terminal (development mode). Mail failures are caught so they cannot crash a request.
- The Vite dev server proxies `/api` to port 8000, so the browser sees one origin and the cookie works without any CORS configuration.

## 5. Database: PostgreSQL

Decision: use PostgreSQL now rather than SQLite, so every table added from here on (verified domains, scan history) is built on the real database, and there is no risky migration close to the deadline.

- Runs in Docker: container `vibepen-db`, image `postgres:17`, volume `vibepen-pgdata`, port 5432.
- The backend reads `DATABASE_URL` (format `postgresql+psycopg://user:pass@localhost:5432/vibepen`). If it is not set, the code falls back to a local SQLite file, so a missing database does not block development.
- Tables created and verified with `\dt`: `users`, `auth_sessions`, `email_tokens`.
- The `devpassword` credential is for local development only and is never written in code. It is set through the environment variable.
- Note: `create_all` creates missing tables but does not add columns to existing ones. During development, reset with `docker rm -f vibepen-db` and `docker volume rm vibepen-pgdata`. Alembic migrations are planned once the schema settles.

**Dependencies**

| Package | Version | Note |
|---|---|---|
| SQLAlchemy | 2.0.53 | Pinned to the 2.0 line. SQLAlchemy 2.1 became the default install on 24 Sep 2026 and has breaking changes that were not tested here. |
| argon2-cffi | 25.1.0 | Latest release |
| psycopg[binary] | pin the version `pip show psycopg` reports | PostgreSQL driver |

Run `python -m pip show sqlalchemy argon2-cffi psycopg` and make sure `requirements.txt` matches before committing.

## 6. Frontend changes (`frontend/src/TemplateHome.tsx`)

- Sign-up and sign-in now call the backend and show its error messages (wrong password, account exists, email not confirmed).
- A Resend verification email button appears when sign-in is refused for an unconfirmed email.
- New `/verify-email` page opens from the emailed link, confirms the token and signs the user in.
- On load, the app asks `/api/auth/me` whether a real session exists and clears the old fake login if not. The copy of the user in `localStorage` is now only a display cache.
- All three sign-out buttons (sign-in page card, navigation menu, settings page) now end the server session as well as clearing the browser.
- Domain verification calls (`addDomain`, `verifyDomain`) from the earlier work remain in place.
- `pnpm run build` passes. `tsc --noEmit` reports only the three older errors (`TemplateHome.test.ts` missing `target`, and `replaceAll` on lines 169 and 174), which are unrelated to today's changes.

## 7. Testing performed

**Automated.** `python -m pytest test_verification.py test_verification_meta.py -q` gives **21 passed**: 9 existing verification tests plus 12 new tests for the meta method. The new tests use fake HTTP responses and cover attribute order and case, wrong token, tag inside `<body>` (ignored), private hosts (no request made), same-host redirects, off-host redirects, redirect loops, the 512 KB size limit, end-to-end verification with its scope, the failure message, and rejection of unknown methods.

**Manual, in the browser.** End-to-end account flow:

1. Sign up with a new email, which showed "Check your email to confirm".
2. Copied the confirmation link from the backend terminal (development mailer).
3. Signing in before confirming was refused with a Resend option.
4. Opening the link confirmed the email and signed in.
5. Signing out and signing in again worked, and a wrong password was rejected.

All steps behaved as expected. Direct API checks were also done at `/docs` (register, me, logout, login, duplicate email, short password), and the stored password hash was inspected in the database.

## 8. Known gaps (to state in the final report)

**Security**
- No rate limiting on login, register or resend, so password guessing and email spam are not blocked.
- Password rules are minimal (8 characters). Strength checks are planned for later, closer to the evaluation.
- The session cookie uses `secure=False`, which is correct for local HTTP only. It must be `True` behind HTTPS.
- Login responds slightly faster for unknown emails than for wrong passwords (a small timing difference), and registration reveals whether an email already has an account.
- Expired sessions and tokens are not cleaned up automatically.
- `APP_URL` defaults to `http://localhost:8443` and must be set to the real address when deployed.
- SMTP is not configured yet, so confirmation emails only print in the backend terminal.

**Not yet connected to accounts**
- `/api/domains`, `/api/history` and `/api/scan` do not require a login, and records have no `user_id`. Domain verification is still global, and verified domains are still stored in `verified_domains.json` rather than the database.
- Settings "Delete account" only clears the browser. It does not delete the account on the server.
- Forgot-password is still a simulated screen.

**Verification**
- The DNS, file and meta checks have only been tested with mocks. None has been run against a live domain yet.
- The meta tag UI tab still needs to be applied and checked in the browser.

## 9. Next steps

1. Apply and test the Meta tag tab in the UI, then try all three methods against a real test site (for example a small static page on Netlify or GitHub Pages).
2. Require login on `/api/domains` and `/api/history`, add `user_id` to those records and move verified domains into PostgreSQL.
3. Make account deletion real and finish the forgot-password flow.
4. Crawler and generic XSS/SQLi checks so unknown sites get real testing.
5. Semgrep rules and static-type mapping in `SCORING_RULES`.