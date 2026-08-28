# VibePen Startup Guide

This project runs from the backend folder using a Python virtual environment. The vulnerable apps used for dynamic checks run in Docker.

## 1) Open PowerShell and go to the backend folder

```powershell
cd "D:\VibePen\VibePen\backend"
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
(venv) PS D:\VibePen\VibePen\backend>
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

## Edge cases and fixes

### `Set-ExecutionPolicy` is not recognized

This means you are in `cmd`, not PowerShell. Use PowerShell instead, or run the venv Python directly:

```powershell
cd "D:\VibePen\VibePen\backend"
.\venv\Scripts\python.exe -m detector.static_analyzer
```

### `ModuleNotFoundError: No module named 'detector'`

You are likely not in the backend folder, or you are using the wrong Python. Run:

```powershell
cd "D:\VibePen\VibePen\backend"
```

Then run the command again from there.

### `ModuleNotFoundError: No module named 'requests'`

This means the virtual environment is not active or dependencies were not installed. Fix it with:

```powershell
cd "D:\VibePen\VibePen\backend"
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

Use this every time you open VS Code:

```powershell
cd "D:\VibePen\VibePen\backend"
.\venv\Scripts\Activate.ps1
docker ps
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
