# Tally HTTPS Proxy bootstrapper
# ------------------------------
# Installs Caddy via Webi, configures a local HTTPS endpoint on https://localhost:8443,
# and reverse-proxies to Tally on http://127.0.0.1:9000.
#
# Usage:
# 1. Run PowerShell as Administrator.
# 2. powershell -ExecutionPolicy Bypass -File .\tally-proxy-bootstrap.ps1

$ErrorActionPreference = 'Stop'

# Quiet progress bars in legacy PowerShell
$ProgressPreference = 'SilentlyContinue'

# --- Elevation check ------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error 'Run this script from an elevated PowerShell session (Right-click -> "Run as administrator").'
    exit 1
}

# --- Compatibility helpers and TLS defaults -------------------------------
function Test-Command {
  param([Parameter(Mandatory=$true)][string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

try {
  $proto = 0
  foreach ($p in 'Tls13','Tls12','Tls11','Tls','Ssl3') {
    try { $proto = $proto -bor [Enum]::Parse([Net.SecurityProtocolType], $p) } catch {}
  }
  if ($proto -ne 0) { [Net.ServicePointManager]::SecurityProtocol = $proto }
} catch {
  Write-Warning "Could not set TLS protocol: $_"
}

function Invoke-WebRequestCompat {
  param(
    [Parameter(Mandatory=$true)][string]$Uri,
    [string]$OutFile,
    [int]$TimeoutSec = 30,
    [switch]$SkipCertificateCheck
  )
  $iwr = Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue
  $params = @{ Uri = $Uri }
  if ($OutFile) { $params.OutFile = $OutFile }
  if ($iwr.Parameters.ContainsKey('UseBasicParsing')) { $params.UseBasicParsing = $true }
  if ($iwr.Parameters.ContainsKey('TimeoutSec')) { $params.TimeoutSec = $TimeoutSec }

  $bypass = $false
  if ($SkipCertificateCheck) {
    if ($iwr.Parameters.ContainsKey('SkipCertificateCheck')) {
      $params.SkipCertificateCheck = $true
    } else {
      $bypass = $true
      $origCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
      [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
  }

  try {
    return Invoke-WebRequest @params
  } finally {
    if ($bypass) {
      [Net.ServicePointManager]::ServerCertificateValidationCallback = $origCallback
    }
  }
}

# Robust archive extraction across legacy systems
function Expand-ArchiveCompat {
  param(
    [Parameter(Mandatory=$true)][string]$ArchivePath,
    [Parameter(Mandatory=$true)][string]$DestinationPath
  )
  New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null

  # 1) Prefer tar (bsdtar on newer Windows can handle zip too)
  if (Test-Command -Name 'tar') {
    try {
      & tar -xf "$ArchivePath" -C "$DestinationPath"
      return
    } catch {}
  }

  # 2) Expand-Archive if available
  if (Test-Command -Name 'Expand-Archive') {
    try {
      Expand-Archive -Path "$ArchivePath" -DestinationPath "$DestinationPath" -Force
      return
    } catch {}
  }

  # 3) .NET ZipFile
  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $DestinationPath)
    return
  } catch {}

  # 4) Windows Shell (COM)
  try {
    $shell = New-Object -ComObject Shell.Application
    $zip = $shell.NameSpace($ArchivePath)
    if (-not $zip) { throw "Not a ZIP archive or not recognized: $ArchivePath" }
    $dest = $shell.NameSpace($DestinationPath)
    $dest.CopyHere($zip.Items(), 0x10)
    Start-Sleep -Milliseconds 500
    return
  } catch {}

  # 5) 7-Zip if installed
  $sevenZip = $null
  if (Test-Command -Name '7z') { $sevenZip = (Get-Command 7z -ErrorAction SilentlyContinue).Path }
  if (-not $sevenZip -and (Test-Path "$env:ProgramFiles\7-Zip\7z.exe")) { $sevenZip = "$env:ProgramFiles\7-Zip\7z.exe" }
  if (-not $sevenZip -and (Test-Path "$env:ProgramFiles(x86)\7-Zip\7z.exe")) { $sevenZip = "$env:ProgramFiles(x86)\7-Zip\7z.exe" }
  if ($sevenZip) {
    & "$sevenZip" x -y -o"$DestinationPath" "$ArchivePath" | Out-Null
    return
  }

  throw "Failed to extract archive using available methods."
}

# --- Configurable bits ----------------------------------------------------
$InstallRoot   = 'C:\ProgramData\TallyHttpsProxy'
$ServiceName   = 'TallyHttpsProxy'
$ListenPort    = 8443
$TallyPort     = 9000
$RuleName      = 'Tally HTTPS Proxy (Caddy)'
$WebiUrl       = 'https://webi.ms/caddy'

# Possible locations Webi or other installers may place caddy.exe
$CandidateCaddyPaths = @(
    "$env:USERPROFILE\.local\bin\caddy.exe",
    "$env:USERPROFILE\scoop\apps\caddy\current\caddy.exe",
    "$env:USERPROFILE\scoop\apps\caddy\current\bin\caddy.exe",
    "$env:ProgramFiles\Caddy\caddy.exe",
    "$env:ProgramFiles\Caddy\bin\caddy.exe",
    "$env:ProgramData\TallyHttpsProxy\caddy.exe"
)

$CaddyExePath  = Join-Path $InstallRoot 'caddy.exe'
$CaddyfilePath = Join-Path $InstallRoot 'Caddyfile'

# --- Prepare install directory -------------------------------------------
Write-Host "`n==> Preparing install directory at $InstallRoot" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null

# --- Install / Update Caddy via Webi (with fallback) ---------------------
Write-Host "==> Installing/Updating Caddy via Webi ($WebiUrl)" -ForegroundColor Cyan
$installedViaWebi = $false
try {
    $scriptContent = (Invoke-WebRequestCompat -Uri $WebiUrl).Content
    Invoke-Expression $scriptContent
    $installedViaWebi = $true
} catch {
    Write-Warning "Webi failed ($WebiUrl): $_"
    Write-Host "==> Falling back to direct download" -ForegroundColor Yellow

    $arch = if ($env:PROCESSOR_ARCHITECTURE -match '64') { 'amd64' } else { '386' }
    $zipUrl = "https://caddyserver.com/api/download?os=windows&arch=$arch"
    $zipPath = Join-Path $InstallRoot 'caddy.zip'

    try {
      Invoke-WebRequestCompat -Uri $zipUrl -OutFile $zipPath -TimeoutSec 120
    } catch {
      Write-Error "Failed to download Caddy from $zipUrl. Error: $_"
      exit 1
    }

    $extracted = $false
    try {
      Expand-ArchiveCompat -ArchivePath $zipPath -DestinationPath $InstallRoot
      $extracted = $true
    } catch {
      Write-Warning ("Primary extraction failed: {0}" -f $_)
    }

    if (-not $extracted) {
      # Try GitHub Releases fallback with a commonly named asset
      $ghUrl = "https://github.com/caddyserver/caddy/releases/latest/download/caddy_windows_${arch}.zip"
      Write-Host ("==> Retrying with GitHub asset: {0}" -f $ghUrl) -ForegroundColor Yellow
      try {
        Invoke-WebRequestCompat -Uri $ghUrl -OutFile $zipPath -TimeoutSec 120
      } catch {
        Write-Error ("Failed to download from GitHub: {0}" -f $_)
        exit 1
      }
      try {
        Expand-ArchiveCompat -ArchivePath $zipPath -DestinationPath $InstallRoot
      } catch {
        Write-Error ("Failed to extract fallback archive: {0}" -f $_)
        exit 1
      }
    }

    Remove-Item $zipPath -ErrorAction SilentlyContinue
}

# --- Locate an installed caddy.exe ---------------------------------------
$sourceCaddy = $CandidateCaddyPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $sourceCaddy) {
    # Search within InstallRoot recursively in case the archive created a subfolder
    try {
        $found = Get-ChildItem -Path $InstallRoot -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { -not $_.PSIsContainer -and $_.Name -ieq 'caddy.exe' } |
                 Select-Object -ExpandProperty FullName -First 1
        if ($found) { $sourceCaddy = $found }
    } catch {}
}
if (-not $sourceCaddy) {
    Write-Error "Could not locate caddy.exe after installation. Check $WebiUrl output for errors."
    exit 1
}

Write-Host "==> Using caddy executable at $sourceCaddy" -ForegroundColor Cyan

# --- Stop running service before copying binaries ------------------------
try {
    $running = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($running -and $running.Status -eq 'Running') {
        Write-Host "==> Stopping running service '$ServiceName' before updating binaries" -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & $sourceCaddy service stop --name $ServiceName 2>$null
    }
} catch {
    Write-Warning "Could not stop running service '$ServiceName': $_"
}

# --- Copy caddy.exe into InstallRoot -------------------------------------
Copy-Item -Path $sourceCaddy -Destination $CaddyExePath -Force
try { Unblock-File -Path $CaddyExePath } catch {}

function Test-CaddyServiceFeature {
  try {
    & $CaddyExePath service --help | Out-Null
    return $true
  } catch {
    return $false
  }
}

# --- Write Caddyfile ------------------------------------------------------
Write-Host "==> Writing Caddyfile (HTTPS -> HTTP proxy)" -ForegroundColor Cyan
@"
https://localhost:$ListenPort {
    tls internal
    reverse_proxy http://127.0.0.1:$TallyPort {
        transport http {
            versions h1 h2c
        }
    }
}
"@ | Set-Content -Path $CaddyfilePath -Encoding utf8

# --- (Re)Create Windows Service -------------------------------------------
# ----------------------------- (Re)Create Windows Service ---------------------------------------
Write-Host "==> Configuring Windows Service '$ServiceName'" -ForegroundColor Cyan

$hasCaddyService = Test-CaddyServiceFeature

if ($hasCaddyService) {
  # Stop/uninstall any existing service via Caddy
  try { & $CaddyExePath service stop --name $ServiceName 2>$null } catch {}
  try { & $CaddyExePath service uninstall --name $ServiceName 2>$null } catch {}
  Start-Sleep -Seconds 1

  # Install & start using Caddy's built-in service manager
  & $CaddyExePath service install `
    --name   $ServiceName `
    --config $CaddyfilePath `
    --watchdog-interval 0s
  & $CaddyExePath service start --name $ServiceName
} else {
  # Fallback: use sc.exe (Windows Service Controller)
  # Stop & delete any previous service
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc) {
    try { sc.exe stop  $ServiceName   | Out-Null } catch {}
    Start-Sleep -Seconds 1
    try { sc.exe delete $ServiceName   | Out-Null } catch {}
    Start-Sleep -Seconds 1
  }

  # Build a properly quoted binPath that includes the full command line
  $svcCmd = "`"$CaddyExePath`" run --config `"$CaddyfilePath`" --adapter caddyfile"
  # Important: sc.exe expects 'binPath= ' and 'start= ' with a space after '=' as part of the same token.
  $argCreate = @(
    'create', $ServiceName,
    ('binPath= ' + '"' + $svcCmd + '"'),
    'start= auto'
  )
  & sc.exe @argCreate | Out-Null
  & sc.exe start $ServiceName | Out-Null
}

# ----------------------------- Firewall Rule -----------------------------------------------
if (Test-Command -Name 'Get-NetFirewallRule' -and Test-Command -Name 'New-NetFirewallRule') {
  if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
      Write-Host "==> Creating Windows Firewall rule for port $ListenPort" -ForegroundColor Cyan
      New-NetFirewallRule `
          -DisplayName $RuleName `
          -Direction Inbound `
          -Action Allow `
          -Protocol TCP `
          -LocalPort $ListenPort `
          -Profile Domain,Private | Out-Null
  }
} else {
  Write-Host "==> Configuring Windows Firewall with netsh (legacy OS)" -ForegroundColor Cyan
  & netsh advfirewall firewall delete rule name="$RuleName" protocol=TCP localport=$ListenPort | Out-Null
  & netsh advfirewall firewall add rule name="$RuleName" dir=in action=allow protocol=TCP localport=$ListenPort profile=domain,private | Out-Null
}

# --- Final checks / output -----------------------------------------------
Write-Host "`nAll done! ✅" -ForegroundColor Green
Write-Host "Open https://localhost:$ListenPort in your browser to verify." -ForegroundColor Green
Write-Host "In Loupe, set the Tally host to https://localhost:$ListenPort before pushing vouchers." -ForegroundColor Green

try {
    $resp = Invoke-WebRequestCompat -Uri "https://localhost:$ListenPort" -TimeoutSec 5 -SkipCertificateCheck
    Write-Host "`nHealth check: Received HTTP $($resp.StatusCode) from https://localhost:$ListenPort" -ForegroundColor Green
} catch {
    Write-Warning "Could not fetch https://localhost:$ListenPort yet. If this is the first run, give it a moment or check 'services.msc' for '$ServiceName'."
}

# ----------------------------- Trust local CA (optional) -----------------------------------------
try {
  # Some builds may not have 'trust'. If it errors, we just warn.
  & $CaddyExePath trust --config $CaddyfilePath --adapter caddyfile | Out-Null
  Write-Host "==> Installed Caddy's local root CA into Windows trust store (if needed)." -ForegroundColor Green
} catch {
  Write-Warning "Could not install local root CA with 'caddy trust'. You may see a browser warning until trusted. $_"
}
