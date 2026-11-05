$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker Desktop is required and must be installed.'
}
docker info *> $null
if ($LASTEXITCODE -ne 0) {
  throw 'Docker Desktop is not running. Start Docker Desktop and run start.bat again.'
}
if (-not (Test-Path (Join-Path $root 'backend\venv\Scripts\python.exe'))) {
  throw 'Dependencies are not installed. Run setup.ps1 once first.'
}
if (-not (Test-Path (Join-Path $root 'frontend\node_modules'))) {
  throw 'Frontend dependencies are not installed. Run setup.ps1 once first.'
}

function Start-TargetContainer([string] $name, [string] $image, [string] $portMapping) {
  $existing = docker ps -a --filter "name=^$name$" --format '{{.Names}}'
  if ($existing -eq $name) {
    docker start $name *> $null
  } else {
    docker run -d -p $portMapping --name $name $image *> $null
  }
  if ($LASTEXITCODE -ne 0) {
    throw "Could not start Docker container '$name'. Check whether its port is already in use."
  }
}

Start-TargetContainer 'juice-shop' 'bkimminich/juice-shop' '3000:3000'
Start-TargetContainer 'dvwa' 'vulnerables/web-dvwa' '8080:80'

$backendCommand = "Set-Location '$root\backend'; & '.\venv\Scripts\python.exe' -m uvicorn app:app --host 0.0.0.0 --port 8000"
$frontendCommand = "Set-Location '$root\frontend'; npm run dev -- --host 0.0.0.0"
Start-Process powershell.exe -WorkingDirectory (Join-Path $root 'backend') -ArgumentList '-NoExit', '-Command', $backendCommand
Start-Process powershell.exe -WorkingDirectory (Join-Path $root 'frontend') -ArgumentList '-NoExit', '-Command', $frontendCommand

Start-Process 'http://localhost:8443'
Write-Host 'VibePen is starting at http://localhost:8443' -ForegroundColor Green
