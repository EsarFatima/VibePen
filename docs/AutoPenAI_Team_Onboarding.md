# AutoPenAI — Team Onboarding: What to Install Locally

The GitHub repo has our **code**, not the tools/programs that code depends on. Every teammate needs to install the same software locally before the cloned code will actually run. Follow this in order — do not skip steps.

---

## 1. Install these programs first (one-time, per machine)

| Tool | Version needed | Check with | Download |
|---|---|---|---|
| Python | 3.11.x | `python --version` | https://www.python.org/downloads/ |
| Node.js | 18.x or 20.x LTS | `node --version` | https://nodejs.org/ |
| Docker Desktop | Latest | `docker --version` | https://www.docker.com/products/docker-desktop/ |
| Git | Latest | `git --version` | https://git-scm.com/downloads |
| VS Code | Latest | — | https://code.visualstudio.com/ |

Run all four version checks in a terminal before moving on. If any command isn't recognized, that program isn't installed correctly — fix it before continuing.

**Do not use Python 3.12+.** Stick to 3.11.x — some of our packages (esprima) have had issues on newer Python versions.

---

## 2. VS Code Extensions (install inside VS Code, Extensions tab)

- Python (Microsoft)
- Pylance
- Docker (Microsoft)

---

## 3. Clone the repo

```powershell
git clone <our-repo-url>
cd AutoPen
```

---

## 4. Set up the Python environment

This step downloads and installs the actual Python packages our code imports (fastapi, requests, esprima, etc.) — these are NOT included in the GitHub repo, they get installed locally from `requirements.txt`.

```powershell
cd backend
python -m venv venv
```

**Activate it (Windows PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```

If you get an execution policy error, run this once (only needed the first time on a machine):
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
Then retry activation. Your terminal prompt should now start with `(venv)`.

**Install our exact dependencies:**
```powershell
pip install -r requirements.txt
```

**Set VS Code's interpreter:** `Ctrl+Shift+P` → "Python: Select Interpreter" → choose the one inside `backend\venv`. Everyone must do this or VS Code will show false "module not found" errors even though installation succeeded.

---

## 5. Set up the sandbox targets (Docker)

These are the deliberately-vulnerable test apps we scan against. Every teammate needs their own local copies running.

Make sure **Docker Desktop is open and running** first (check for the whale icon in your system tray), then:

```powershell
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

Check both are running:
```powershell
docker ps
```

Confirm in browser:
- Juice Shop: http://localhost:3000
- DVWA: http://localhost:8080

### Critical extra step for DVWA — do this once, or login will silently fail

DVWA starts with an empty database. Before you can log in (manually or through our scripts):

1. Go to `http://localhost:8080/setup.php` in your browser
2. Scroll down, click **"Create / Reset Database"**
3. Wait for the success message
4. Log in manually with `admin` / `password` to confirm it lands on the real DVWA dashboard (title says "Welcome"), not back on setup.php

**If you skip this step, our login script will connect fine but every request will bounce back to `setup.php` instead of authenticating — this looks like a code bug but isn't. Do the setup.php step first.**

### If a port is already in use

```
Error: port is already allocated
```
Something else on your machine is using 3000 or 8080. Map to a different port instead:
```powershell
docker run -d -p 3001:3000 --name juice-shop bkimminich/juice-shop
```
Then use `localhost:3001` and tell the team so nobody's confused during a call.

---

## 6. Verify everything works end-to-end

From `backend/`, with venv activated:

```powershell
python -m detector.dynamic.run_dynamic_access
```

Expected: it prints `Starting access checks...`, then a findings count, then a list of findings (at minimum you should see a `missing_rate_limit` finding, since DVWA has no rate limiting by default).

If you get `ImportError: cannot import name ... from ...`, one of the files in `detector/dynamic/` is empty or wasn't saved after pasting — open that file in VS Code, check it's not blank, re-paste the code from the repo/team doc, and `Ctrl+S` to save.

If you get `ModuleNotFoundError: No module named 'detector'`, you're either not running from the `backend/` folder, or you're running the file directly instead of as a module — always use:
```powershell
python -m detector.dynamic.run_dynamic_access
```
not
```powershell
python detector\dynamic\run_dynamic_access.py
```

---

## 7. Common errors & fixes (quick reference)

| Error | Fix |
|---|---|
| `venv\Scripts\Activate.ps1 cannot be loaded` | Run the `Set-ExecutionPolicy` command in step 4, once per machine |
| `ModuleNotFoundError` after `pip install` | You're not in the activated venv, or VS Code is using the wrong interpreter |
| Login script succeeds but findings are always empty / bounces to setup.php | You skipped the DVWA `setup.php` → "Create / Reset Database" step |
| `port is already allocated` (Docker) | Another process is using that port — map to a different port |
| `docker: command not found` / Docker errors | Docker Desktop isn't running — open the app, wait for the whale icon |
| `ImportError: cannot import name X from Y` | File Y exists but is empty or wasn't saved — reopen, check contents, re-save |
| Git shows huge diffs on `venv/` or `node_modules/` | Someone committed a folder that should be ignored — flag in group chat, don't fix solo |

---

## 8. Before every work session

```powershell
git pull origin main
```

Pull latest before starting, and again before pushing, to avoid merge conflicts — especially important now that multiple people are working in `detector/dynamic/` at once (Person 2A and 2B).

---

## 9. Stuck for more than 15–20 minutes?

Post the **exact, full terminal error output** in the team chat — not a screenshot description, not a paraphrase. Copy-paste the real text so it can actually be debugged.
