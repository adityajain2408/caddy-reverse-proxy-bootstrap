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

# --- TCP port probe helper ------------------------------------------------
function Test-TcpPortOpen {
  param(
    [Parameter(Mandatory=$true)][string]$TargetHost,
    [Parameter(Mandatory=$true)][int]$TargetPort,
    [int]$TimeoutSec = 10
  )
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      $iar = $client.BeginConnect($TargetHost, $TargetPort, $null, $null)
      $ok = $iar.AsyncWaitHandle.WaitOne(500)
      if ($ok -and $client.Connected) { $client.EndConnect($iar); $client.Close(); return $true }
      $client.Close()
    } catch {}
    Start-Sleep -Milliseconds 300
  }
  return $false
}

# Pick an admin port that's free (try a small list)
function Select-AdminPort {
  param([int[]]$Candidates = @(2019,2020,2021,2022))
  foreach ($p in $Candidates) {
    # If nothing is listening, prefer this port
    if (-not (Test-TcpPortOpen -TargetHost '127.0.0.1' -TargetPort $p -TimeoutSec 1)) { return $p }
  }
  return $Candidates[0]
}
# Polls Windows service state until it is running or a timeout is hit.
function Wait-ServiceRunning {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [int]$TimeoutSec = 30
  )
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    $svc = $null
    try {
      $svc = Get-Service -Name $Name -ErrorAction Stop
    } catch {
      Start-Sleep -Milliseconds 500
      continue
    }
    if ($svc.Status -eq 'Running') { return $true }
    if ($svc.Status -eq 'Stopped') {
      try { Start-Service -Name $Name -ErrorAction SilentlyContinue } catch {}
    }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Test-ServiceExists {
  param([Parameter(Mandatory=$true)][string]$Name)
  try {
    Get-Service -Name $Name -ErrorAction Stop | Out-Null
    return $true
  } catch {
    return $false
  }
}


function Test-CaddyStartFeature {
  param([Parameter(Mandatory=$true)][string]$ExePath)
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
  try { $null = (& $ExePath 'start' '--help' 2>&1 | Out-Null); return ($LASTEXITCODE -eq 0) } catch { return $false } finally { $ErrorActionPreference = $prev }
}

# --- Preflight: start Caddy, trust CA, stop --------------------------------
function Invoke-CaddyPreflightTrust {
  param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [int]$TimeoutSec = 25,
    [int]$AdminPort
  )
  Write-Host "==> Preflight: launching Caddy to install local CA" -ForegroundColor Cyan
  if (Test-CaddyStartFeature -ExePath $ExePath) {
    # Use native background mode
    & $ExePath start --config $ConfigPath --adapter caddyfile *> $null
    $started = Test-TcpPortOpen -TargetHost '127.0.0.1' -TargetPort $AdminPort -TimeoutSec $TimeoutSec
    $ok = $false
    if ($started) {
      try { & $ExePath trust --config $ConfigPath --adapter caddyfile | Out-Null; $ok = $true } catch { Write-Warning "Preflight: 'caddy trust' failed: $_" }
    } else {
      Write-Warning "Preflight: Caddy admin API did not become reachable; skipping trust."
    }
    try { & $ExePath stop *> $null } catch {}
    return $ok
  } else {
    # Fallback: run with redirected output and kill after
    $logPath = Join-Path (Split-Path $ConfigPath -Parent) 'preflight.log'
    $proc = Start-Process -FilePath $ExePath -ArgumentList @('run','--config', $ConfigPath, '--adapter', 'caddyfile') -RedirectStandardOutput $logPath -RedirectStandardError $logPath -WindowStyle Hidden -PassThru
    try {
      $started = Test-TcpPortOpen -TargetHost '127.0.0.1' -TargetPort $AdminPort -TimeoutSec $TimeoutSec
      if ($started) {
        try { & $ExePath trust --config $ConfigPath --adapter caddyfile | Out-Null; return $true } catch { Write-Warning "Preflight: 'caddy trust' failed: $_"; return $false }
      } else {
        Write-Warning ("Preflight: admin API not reachable; see log {0}" -f $logPath)
        return $false
      }
    } finally {
      try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue; Wait-Process -Id $proc.Id -Timeout 5 -ErrorAction SilentlyContinue } catch {}
    }
  }
}

# Reliable downloader with real timeouts and fallbacks
function Get-FileCompat {
  param(
    [Parameter(Mandatory=$true)][string]$Url,
    [Parameter(Mandatory=$true)][string]$OutFile,
    [int]$TimeoutSec = 180,
    [switch]$SkipCertificateCheck
  )
  Write-Host ("==> Downloading: {0}" -f $Url) -ForegroundColor Cyan

  # 1) Prefer curl.exe if available (has robust timeouts & redirects)
  if (Test-Command -Name 'curl.exe') {
    $curlArgs = @('-L','--fail','--max-time', $TimeoutSec.ToString(), '-o', $OutFile, $Url)
    if ($SkipCertificateCheck) { $curlArgs = @('-k') + $curlArgs }
    $p = Start-Process -FilePath 'curl.exe' -ArgumentList $curlArgs -NoNewWindow -PassThru -Wait
    if ($p.ExitCode -ne 0) { throw ("curl.exe failed with exit code {0}" -f $p.ExitCode) }
    if (-not (Test-Path $OutFile)) { throw "curl.exe reported success but file not found: $OutFile" }
    return
  }

  # 2) BITS transfer with manual timeout loop
  if (Test-Command -Name 'Start-BitsTransfer') {
    try {
      $job = Start-BitsTransfer -Source $Url -Destination $OutFile -Asynchronous -ErrorAction Stop
      $sw = [Diagnostics.Stopwatch]::StartNew()
      do {
        Start-Sleep -Milliseconds 500
        try { $job = Get-BitsTransfer -Id $job.Id -ErrorAction Stop } catch { break }
        if ($sw.Elapsed.TotalSeconds -ge $TimeoutSec) {
          try { Remove-BitsTransfer -BitsJob $job -ErrorAction SilentlyContinue } catch {}
          throw "BITS download timed out after $TimeoutSec seconds"
        }
      } while ($job.JobState -in @('Connecting','Transferring','Queued','TransientError'))
      if ($job -and $job.JobState -eq 'Transferred') { Complete-BitsTransfer -BitsJob $job; return }
      if ($job) { throw ("BITS download failed with state {0}" -f $job.JobState) }
    } catch {}
  }

  # 3) .NET HttpWebRequest with timeouts
  $origCallback = $null
  if ($SkipCertificateCheck) {
    $origCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  }
  try {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.UserAgent = 'TallyProxyBootstrap/1.0'
    $req.Timeout = $TimeoutSec * 1000
    $req.ReadWriteTimeout = $TimeoutSec * 1000
    $req.AllowAutoRedirect = $true
    $resp = $req.GetResponse()
    try {
      $stream = $resp.GetResponseStream()
      $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
      try {
        $buffer = New-Object byte[] 8192
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
          $fs.Write($buffer, 0, $read)
        }
      } finally { $fs.Dispose() }
    } finally { $resp.Close() }
    if (-not (Test-Path $OutFile)) { throw "Download completed but file not found: $OutFile" }
    return
  } finally {
    if ($origCallback) { [Net.ServicePointManager]::ServerCertificateValidationCallback = $origCallback }
  }

  throw "No available downloader could fetch the file."
}

# --- Caddyfile formatting and validation helpers -------------------------
function Invoke-CaddyFmt {
  param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$ConfigPath
  )
  try {
    & $ExePath fmt --overwrite $ConfigPath | Out-Null
    Write-Host "==> Formatted Caddyfile" -ForegroundColor Cyan
    return $true
  } catch {
    Write-Warning "Could not format Caddyfile: $_"
    return $false
  }
}

function Invoke-CaddyValidate {
  param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$ConfigPath
  )
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = & $ExePath validate --config $ConfigPath --adapter caddyfile 2>&1
    if ($LASTEXITCODE -ne 0) {
      $msg = ($output | Out-String).Trim()
      Write-Error ("Caddy config validation failed. Output:\n{0}" -f $msg)
      exit 1
    }
    Write-Host "==> Caddyfile validated successfully" -ForegroundColor Green
  } finally {
    $ErrorActionPreference = $prev
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
$didTrust      = $false

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

# --- SkipInstall mode detection -----------------------------------------
$SkipInstallMode = $false
if (Test-Path $CaddyExePath) {
  $SkipInstallMode = $true
  Write-Host "==> Found caddy.exe at $CaddyExePath; skipping installation." -ForegroundColor Yellow
}

# --- Install / Update Caddy via Webi (with fallback) ---------------------
if (-not $SkipInstallMode) {
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
        Get-FileCompat -Url $zipUrl -OutFile $zipPath -TimeoutSec 180
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
          Get-FileCompat -Url $ghUrl -OutFile $zipPath -TimeoutSec 180
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
} else {
  Write-Host "==> SkipInstall mode active: using existing caddy.exe" -ForegroundColor Yellow
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
if ($sourceCaddy -and ($sourceCaddy -ne $CaddyExePath)) {
  Copy-Item -Path $sourceCaddy -Destination $CaddyExePath -Force
} else {
  Write-Host "==> caddy.exe already in place at $CaddyExePath; skipping copy." -ForegroundColor Yellow
}
try { Unblock-File -Path $CaddyExePath } catch {}

function Test-CaddyServiceFeature {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $null = (& $CaddyExePath 'service' '--help' 2>&1 | Out-Null)
    return ($LASTEXITCODE -eq 0)
  } catch {
    return $false
  } finally {
    $ErrorActionPreference = $prev
  }
}

# --- Write Caddyfile ------------------------------------------------------
Write-Host "==> Writing Caddyfile (HTTPS -> HTTP proxy)" -ForegroundColor Cyan
$AdminPort = Select-AdminPort
Write-Host ("==> Admin API will listen on 127.0.0.1:{0}" -f $AdminPort) -ForegroundColor Cyan
@"
{
    admin 127.0.0.1:$AdminPort
}
https://localhost:$ListenPort {
    tls internal
    reverse_proxy http://127.0.0.1:$TallyPort {
        transport http {
            versions 1.1
        }
    }
}
"@ | Set-Content -Path $CaddyfilePath -Encoding utf8

# --- Auto-format and validate the generated Caddyfile --------------------
Invoke-CaddyFmt -ExePath $CaddyExePath -ConfigPath $CaddyfilePath | Out-Null
Invoke-CaddyValidate -ExePath $CaddyExePath -ConfigPath $CaddyfilePath

# --- Preflight trust before creating background runner --------------------
try {
  if (Invoke-CaddyPreflightTrust -ExePath $CaddyExePath -ConfigPath $CaddyfilePath -TimeoutSec 25 -AdminPort $AdminPort) {
    $didTrust = $true
  }
} catch {
  Write-Warning "Preflight step encountered an issue: $_"
}

# --- (Re)Create Windows Service -------------------------------------------
Write-Host "==> Configuring Windows Service '$ServiceName'" -ForegroundColor Cyan

$hasCaddyService = Test-CaddyServiceFeature
$serviceInstalled = $false

if ($hasCaddyService) {
  try { & $CaddyExePath service stop --name $ServiceName 2>$null } catch {}
  try { & $CaddyExePath service uninstall --name $ServiceName 2>$null } catch {}
  Start-Sleep -Seconds 1

  $installOutput = & $CaddyExePath service install `
    --name   $ServiceName `
    --config $CaddyfilePath `
    --watchdog-interval 0s 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Warning ("Caddy service install failed (exit {0}). Output: {1}" -f $LASTEXITCODE, ($installOutput -join ' '))
  } else {
    $serviceInstalled = Test-ServiceExists -Name $ServiceName
    if (-not $serviceInstalled) {
      Write-Warning "Caddy service install completed but service not found; falling back to sc.exe."
    } else {
      $startOutput = & $CaddyExePath service start --name $ServiceName 2>&1
      if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Caddy service start failed (exit {0}). Output: {1}" -f $LASTEXITCODE, ($startOutput -join ' '))
        $serviceInstalled = Test-ServiceExists -Name $ServiceName
      }
    }
  }
}

if (-not $serviceInstalled) {
  Write-Host "==> Provisioning Windows service via sc.exe" -ForegroundColor Cyan
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc) {
    try { sc.exe stop  $ServiceName   | Out-Null } catch {}
    Start-Sleep -Seconds 1
    try { sc.exe delete $ServiceName   | Out-Null } catch {}
    Start-Sleep -Seconds 1
  }

  $svcCmd = "`"$CaddyExePath`" run --config `"$CaddyfilePath`" --adapter caddyfile"
  $binPathArg = 'binPath="' + $svcCmd + '"'
  $argCreate = @(
    'create', $ServiceName,
    $binPathArg,
    'type=own',
    'start=auto'
  )
  $createOutput = & sc.exe @argCreate 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw ("Failed to create Windows service '{0}' (exit {1}). Output: {2}" -f $ServiceName, $LASTEXITCODE, ($createOutput -join ' '))
  }

  $serviceInstalled = Test-ServiceExists -Name $ServiceName
  if (-not $serviceInstalled) {
    throw ("Service '{0}' was not registered by sc.exe create." -f $ServiceName)
  }

  $startOutput = & sc.exe start $ServiceName 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Warning ("sc.exe start returned exit {0}. Output: {1}" -f $LASTEXITCODE, ($startOutput -join ' '))
  } else {
    $serviceInstalled = Test-ServiceExists -Name $ServiceName
  }
}

# ----------------------------- Firewall Rule -----------------------------------------------
if ((Test-Command -Name 'Get-NetFirewallRule') -and (Test-Command -Name 'New-NetFirewallRule')) {
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
Write-Host "`nAll done!" -ForegroundColor Green
Write-Host "Open https://localhost:$ListenPort in your browser to verify." -ForegroundColor Green
Write-Host "In Loupe Factory, set the Tally host to https://localhost:$ListenPort before pushing vouchers." -ForegroundColor Green

try {
    $resp = Invoke-WebRequestCompat -Uri "https://localhost:$ListenPort" -TimeoutSec 10 -SkipCertificateCheck
    Write-Host "`nHealth check: Received HTTP $($resp.StatusCode) from https://localhost:$ListenPort" -ForegroundColor Green
} catch {
    Write-Warning "Could not fetch https://localhost:$ListenPort yet. If this is the first run, give it a moment or check 'services.msc' for '$ServiceName'."
}

# ----------------------------- Trust local CA (optional) -----------------------------------------
if (-not $didTrust) {
  # Only attempt 'caddy trust' once the admin API is reachable
  $serviceReady = $false
  try {
    $serviceReady = Wait-ServiceRunning -Name $ServiceName -TimeoutSec 30
  } catch {
    Write-Warning ("Could not verify Windows service '{0}': {1}" -f $ServiceName, $_)
  }

  if (-not $serviceReady) {
    Write-Warning ("Service '{0}' is not running; skipping 'caddy trust' for now." -f $ServiceName)
  } else {
    Write-Host ("==> Waiting for Caddy admin API on 127.0.0.1:{0} before trusting CA" -f $AdminPort) -ForegroundColor Cyan
    if (Test-TcpPortOpen -TargetHost '127.0.0.1' -TargetPort $AdminPort -TimeoutSec 20) {
      try {
        & $CaddyExePath trust --config $CaddyfilePath --adapter caddyfile | Out-Null
        Write-Host "==> Installed Caddy's local root CA into Windows trust store (if needed)." -ForegroundColor Green
      } catch {
        Write-Warning "Could not install local root CA with 'caddy trust'. You may see a browser warning until trusted. $_"
      }
    } else {
      Write-Warning ("Caddy admin API is not reachable on 127.0.0.1:{0} yet; skipping 'caddy trust' for now." -f $AdminPort)
    }
  }
}

# Final summary: echo chosen admin port
Write-Host ("Admin API: http://127.0.0.1:{0}" -f $AdminPort) -ForegroundColor Cyan


