# pktforge installer for Windows (PowerShell 5.1+ / 7+).
#   irm https://raw.githubusercontent.com/OWNER/pktforge/main/install.ps1 | iex
# Options are environment variables, set before running:
#   $env:PKTFORGE_SKILL = "1"      also install the Claude skill (~\.claude\skills\pktforge)
#   $env:PKTFORGE_UNINSTALL = "1"  remove pktforge
#   $env:PKTFORGE_NO_PATH = "1"    do not touch your PATH
#   $env:PKTFORGE_REPO / PKTFORGE_REF / PKTFORGE_HOME
#   $env:PKTFORGE_SRC              local folder, .zip or URL to install from instead of GitHub
# Needs Python 3.10+. No pip, no admin rights. Adds %USERPROFILE%\.pktforge\bin to your *user* PATH.
$ErrorActionPreference = "Stop"

$Repo    = if ($env:PKTFORGE_REPO) { $env:PKTFORGE_REPO } else { "OWNER/pktforge" }
$Ref     = if ($env:PKTFORGE_REF)  { $env:PKTFORGE_REF }  else { "main" }
$Home_   = if ($env:PKTFORGE_HOME) { $env:PKTFORGE_HOME } else { Join-Path $env:USERPROFILE ".pktforge" }
$BinDir  = Join-Path $Home_ "bin"
$Skill   = Join-Path $env:USERPROFILE ".claude\skills\pktforge"

function Fail($m) { Write-Host "pktforge install: $m" -ForegroundColor Red; throw $m }

if ($env:PKTFORGE_UNINSTALL -eq "1") {
    Remove-Item -Recurse -Force $Home_, $Skill -ErrorAction SilentlyContinue
    $p = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($p) {
        $keep = ($p -split ";" | Where-Object { $_ -and ($_ -ne $BinDir) }) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $keep, "User")
    }
    Write-Host "pktforge removed."
    return
}

# ---- python >= 3.10 (skip the Microsoft Store stub, which prints nothing and exits non-zero)
$Py = $null
foreach ($cand in @("python", "python3", "py")) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    try {
        $args_ = if ($cand -eq "py") { @("-3", "-c") } else { @("-c") }
        $out = & $cmd.Source @args_ "import sys; print(int(sys.version_info >= (3, 10)))" 2>$null
        if ("$out".Trim() -eq "1") { $Py = $cmd.Source; $PyArgs = if ($cand -eq "py") { "-3 " } else { "" }; break }
    } catch { }
}
if (-not $Py) { Fail "Python 3.10+ not found. Install it with:  winget install Python.Python.3.12   then open a new terminal and re-run." }

# ---- fetch
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("pktforge-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    $stage = Join-Path $tmp "stage"
    New-Item -ItemType Directory -Force $stage | Out-Null
    $src = $env:PKTFORGE_SRC
    if ($src -and (Test-Path -LiteralPath $src -PathType Container)) {
        Write-Host "Installing from folder $src"
        Copy-Item -Recurse -Force (Join-Path $src "*") $stage
    } else {
        $url = if ($src) { $src } else { "https://github.com/$Repo/archive/refs/heads/$Ref.zip" }
        $zip = Join-Path $tmp "pktforge.zip"
        if ($url -match "^https?://") {
            Write-Host "Downloading $url"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
        } else { Copy-Item -LiteralPath $url $zip }
        $x = Join-Path $tmp "x"
        Expand-Archive -LiteralPath $zip -DestinationPath $x -Force
        $inner = Get-ChildItem $x -Directory | Select-Object -First 1
        $root = if ($inner -and (Test-Path (Join-Path $inner.FullName "pktforge\__init__.py"))) { $inner.FullName } else { $x }
        Copy-Item -Recurse -Force (Join-Path $root "*") $stage
    }
    if (-not (Test-Path (Join-Path $stage "pktforge\__init__.py"))) { Fail "archive does not contain the pktforge package" }

    # ---- install
    $dest = Join-Path $Home_ "src"
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    New-Item -ItemType Directory -Force $Home_, $BinDir | Out-Null
    Copy-Item -Recurse -Force $stage $dest
    Get-ChildItem $dest -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$shim = "@echo off`r`nset ""PYTHONPATH=$dest;%PYTHONPATH%""`r`n""$Py"" $($PyArgs)-m pktforge %*`r`n"
[IO.File]::WriteAllText((Join-Path $BinDir "pktforge.cmd"), $shim, (New-Object Text.UTF8Encoding($false)))

if ($env:PKTFORGE_SKILL -eq "1") {
    New-Item -ItemType Directory -Force $Skill | Out-Null
    Copy-Item -Force (Join-Path $dest "SKILL.md") (Join-Path $Skill "SKILL.md")
    Write-Host "Claude skill installed: $Skill"
}

# ---- PATH (user scope only; PKTFORGE_NO_PATH=1 skips it, e.g. for tests)
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($env:PKTFORGE_NO_PATH -ne "1" -and -not (($userPath -split ";") -contains $BinDir)) {
    [Environment]::SetEnvironmentVariable("Path", (($userPath, $BinDir) | Where-Object { $_ }) -join ";", "User")
    Write-Host "Added $BinDir to your user PATH (open a new terminal to use `pktforge`)."
}
$env:Path = "$BinDir;$env:Path"

& (Join-Path $BinDir "pktforge.cmd") doctor
if ($LASTEXITCODE -ne 0) { Fail "installed, but the self-test failed" }
Write-Host ""
Write-Host "Done. Try:  pktforge guide"
