# VibePen Startup Guide

VibePen has a React/Vite dashboard and a FastAPI backend. During development they run on separate ports. The vulnerable apps used for dynamic checks run in Docker.

## Dashboard architecture

| Service | URL | Purpose |
|---|---|---|
| Vite frontend | http://localhost:8443 | Opens the VibePen dashboard |
| FastAPI backend | http://localhost:8000 | Runs scans and serves `/api/scan` and `/api/history` |
| Juice Shop target | http://localhost:3000 | Vulnerable target used by scans |
| DVWA target | http://localhost:8080 | Vulnerable target used by scans |

The frontend proxies `/api/*` requests to `http://localhost:8000`. Open the frontend URL in the browser, not the backend URL.

## 1) Open PowerShell and go to the backend folder

```powershell
cd "D:\FAST\VibePen\VibePen\backend"
```

## 2) Activate the virtual environment

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks the script, run this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Then retry:

```powershell
.\venv\Scripts\Activate.ps1
```

You should see a prompt like:

```powershell
(venv) PS D:\FAST\VibePen\VibePen\backend>
```

## 3) Check whether Docker is running

If Docker Desktop is not open, start it first. Then verify containers:

```powershell
docker ps
```

If the containers are already running, you should see both:
- `dvwa`
- `juice-shop`

If they are not running, start them:

```powershell
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
docker ps
```

## 4) Initialize DVWA once before login

Open the app in a browser:

- http://localhost:8080/setup.php

Then click:

- `Create / Reset Database`

Then log in with:

- username: `admin`
- password: `password`

This must be done once or the login flow may appear to fail even though the app is running.

## 5) Run the project scan

From the activated venv:

```powershell
python -m detector.dynamic.run_dynamic_access
```

Expected result:
- `Starting access checks...`
- a total findings count
- results such as missing rate limiting, CORS issues, or auth checks

## 6) Quick static check

If you only want to verify the project code is working without Docker:

```powershell
python -m detector.static_analyzer
```

This should print findings for unsafe `eval` and `innerHTML` usage.

## 7) Install and run the dashboard

Use a second PowerShell terminal for the frontend. Node.js 18 or 20 LTS is recommended.

### Install frontend packages

```powershell
cd "D:\FAST\VibePen\Design a Page"
npm install
```

The UI does not require an icon npm package. It loads Google Material Symbols from `src/index.css` and uses the icon names directly in the React components.

### Start the FastAPI backend

In the backend terminal:

```powershell
cd "D:\FAST\VibePen\VibePen\backend"
.\venv\Scripts\Activate.ps1
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

Keep this terminal running. You should see:

```text
Uvicorn running on http://0.0.0.0:8000
```

### Start the Vite frontend

In the second terminal:

```powershell
cd "D:\FAST\VibePen\Design a Page"
npm run dev -- --host 0.0.0.0
```

Open:

- http://localhost:8443/

The dashboard runs a scan on startup and again when `Run New Scan` is clicked. Findings, risk score, and scan history come from the FastAPI backend. If the backend is not running, the dashboard cannot load live findings.

### Verify the API directly

With the backend running, use a third terminal:

```powershell
Invoke-WebRequest "http://localhost:8000/api/scan?target=http%3A%2F%2Flocalhost%3A3000"
```

A successful response should include `findings`, `total_findings`, `severity_counts`, and `risk_score`.

### Build the frontend

```powershell
cd "D:\FAST\VibePen\Design a Page"
npm run build
```

The production build is written to `Design a Page/dist`.

## Edge cases and fixes

### `Set-ExecutionPolicy` is not recognized

This means you are in `cmd`, not PowerShell. Use PowerShell instead, or run the venv Python directly:

```powershell
cd "D:\FAST\VibePen\VibePen\backend"
.\venv\Scripts\python.exe -m detector.static_analyzer
```

### `ModuleNotFoundError: No module named 'detector'`

You are likely not in the backend folder, or you are using the wrong Python. Run:

```powershell
cd "D:\FAST\VibePen\VibePen\backend"
```

Then run the command again from there.

### `ModuleNotFoundError: No module named 'requests'`

This means the virtual environment is not active or dependencies were not installed. Fix it with:

```powershell
cd "D:\FAST\VibePen\VibePen\backend"
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Docker not running

Start Docker Desktop first, then run:

```powershell
docker ps
```

If containers are stopped:

```powershell
docker start dvwa juice-shop
```

### Port already in use

If `3000` or `8080` is already occupied, map to another port:

```powershell
docker run -d -p 3001:3000 --name juice-shop bkimminich/juice-shop
docker run -d -p 8081:80 --name dvwa vulnerables/web-dvwa
```

Then use the new ports in your browser and config.

## Recommended startup routine

Use three terminals every time you open VS Code:

Terminal 1, backend:

```powershell
cd "D:\FAST\VibePen\VibePen\backend"
.\venv\Scripts\Activate.ps1
docker ps
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

Terminal 2, frontend:

```powershell
cd "D:\FAST\VibePen\Design a Page"
npm run dev -- --host 0.0.0.0
```

Terminal 3, optional direct detector check:

```powershell
cd "D:\FAST\VibePen\VibePen\backend"
.\venv\Scripts\Activate.ps1
python -m detector.dynamic.run_dynamic_access
```

If Docker containers are not running, start them first:

```powershell
docker start dvwa juice-shop
```

or recreate them as needed:

```powershell
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

This is the standard local workflow for this project.
