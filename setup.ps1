$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  throw 'Python 3.11 is required. Install it from https://www.python.org/downloads/'
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw 'Node.js 18 or 20 LTS is required. Install it from https://nodejs.org/'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker Desktop is required. Install it from https://www.docker.com/products/docker-desktop/'
}

Set-Location (Join-Path $root 'backend')
if (-not (Test-Path 'venv\Scripts\python.exe')) {
  python -m venv venv
}
& '.\venv\Scripts\python.exe' -m pip install -r requirements.txt

Set-Location (Join-Path $root 'frontend')
npm install

Write-Host ''
Write-Host 'Setup complete. Run .\start.bat whenever you want to start VibePen.' -ForegroundColor Green
