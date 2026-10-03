# AutoPenAI — Environment Setup Guide

Follow this exactly, in order. Do not skip version checks — most "it works on my machine" bugs on this project will come from mismatched versions here.

## 1. Required Software & Exact Versions

Install these first. Versions listed are what the project is built/tested against — small patch differences (e.g. 3.11.9 instead of 3.11.8) are fine, but stay on the same **major.minor** version as listed.

| Tool | Required Version | Check With | Download |
|---|---|---|---|
| Python | 3.11.x | `python --version` | https://www.python.org/downloads/ |
| Node.js | 18.x or 20.x LTS | `node --version` | https://nodejs.org/ |
| Docker Desktop | Latest | `docker --version` | https://www.docker.com/products/docker-desktop/ |
| Git | Latest | `git --version` | https://git-scm.com/downloads |
| VS Code | Latest | — | https://code.visualstudio.com/ |

**Important — Node version note:** if `node --version` shows v21+ (e.g. v23.x), that's fine for frontend work, but if you hit unexplained errors later with backend tooling, downgrade to Node 20 LTS using [nvm-windows](https://github.com/coreybutler/nvm-windows) — don't uninstall/reinstall manually.

**Important — Python version note:** Do NOT use Python 3.12+ yet. Some packages (esprima, certain LangGraph dependencies) have had compatibility issues on 3.12 at time of writing. Stick to 3.11.x across the whole team.

## 2. VS Code Extensions (install these)

- Python (Microsoft)
- Pylance
- Docker (Microsoft)
- ESLint
- Prettier

## 3. Clone the Repo

```powershell
git clone <repo-url>
cd AutoPen
```

## 4. Python Backend Setup

```powershell
cd backend
python -m venv venv
```

**Activate the virtual environment (Windows PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```

If you get an execution policy error, run this once (only needed the first time, per machine):
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**Activate the virtual environment (Mac/Linux):**
```bash
source venv/bin/activate
```

**Install exact pinned dependencies (do this, don't freehand `pip install`):**
```powershell
pip install -r requirements.txt
```

If `requirements.txt` doesn't exist yet or you added a new package, regenerate it and commit the update:
```powershell
pip freeze > requirements.txt
```

**Verify your interpreter in VS Code:** `Ctrl+Shift+P` → "Python: Select Interpreter" → choose the one inside `backend\venv`. Everyone must do this — VS Code sometimes defaults to a global Python install otherwise, which causes "module not found" errors even though `pip install` succeeded.

## 5. Docker Sandbox Setup

Make sure Docker Desktop is **running** (check the whale icon in your system tray) before running these:

```powershell
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

Verify both are up:
```powershell
docker ps
```

You should see both containers listed as `Up`. Then check in your browser:
- Juice Shop: http://localhost:3000
- DVWA: http://localhost:8080

**If a port is already in use** (common error: `port is already allocated`), something else on your machine is using 3000 or 8080. Either stop that process or map to a different port, e.g.:
```powershell
docker run -d -p 3001:3000 --name juice-shop bkimminich/juice-shop
```
(then use `localhost:3001` instead — just tell the team if you had to do this, so nobody's confused in a call)

## 6. Frontend Setup (once frontend work starts)

```powershell
cd frontend
npm install
npm run dev
```

**Do not commit `node_modules/` or `venv/`** — these are already in `.gitignore`. If you accidentally commit them, tell the team immediately so we can clean the git history before it grows huge.

## 7. Confirm Everything Works

Run this sanity check script from `backend/`:
```powershell
python detector\static_analyzer.py
```

You should see two findings printed (eval + innerHTML flags on the sample code). If this runs cleanly, your environment is correctly set up.

## 8. Common Errors & Fixes

| Error | Fix |
|---|---|
| `venv\Scripts\Activate.ps1 cannot be loaded` | Run the `Set-ExecutionPolicy` command above, once per machine |
| `ModuleNotFoundError` after `pip install` | You're not in the activated venv, or VS Code is using the wrong interpreter — recheck step 4 |
| `port is already allocated` (Docker) | Another process is using that port — map to a different port or stop the conflicting process |
| `docker: command not found` | Docker Desktop isn't running — open the app, wait for the whale icon to show it's ready |
| Node/npm errors on install | Confirm Node version matches table above; use nvm to switch if needed |
| Git shows huge diffs / merge conflicts on `venv/` or `node_modules/` | Someone committed a folder that should've been ignored — flag in group chat, don't try to fix solo |

## 9. Before You Start Coding Each Session

```powershell
git pull origin main
```

Always pull latest before starting work, and again before pushing, to minimize merge conflicts.

## 10. Team Contact for Setup Issues

If you're stuck for more than 15-20 minutes on setup, don't keep fighting it alone — post the exact error message in the team chat. Copy-paste the full terminal output, not a screenshot description.
