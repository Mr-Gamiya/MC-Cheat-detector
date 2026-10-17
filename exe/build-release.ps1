[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipAgent,
    [switch]$SkipClippy
)

$ErrorActionPreference = 'Stop'
$workspace = $PSScriptRoot
$target = 'x86_64-pc-windows-msvc'
$dist = Join-Path $workspace 'dist'

function Require-Command([string]$Name, [string]$InstallHint) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) { throw "$Name is required. $InstallHint" }
    return $command
}

function Invoke-CargoStep([string]$Description, [string[]]$Arguments) {
    Write-Host "==> $Description"
    & $script:cargo.Source @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Description failed with exit code $LASTEXITCODE" }
}

function Test-PeX64([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return $false }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 6)) { return $false }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return $false }
        return ($reader.ReadUInt16() -eq 0x8664)
    }
    finally { $stream.Dispose() }
}

$cargo = Get-Command 'cargo.exe' -ErrorAction SilentlyContinue
if (-not $cargo) {
    $userCargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $userCargo) {
        $cargoBin = Split-Path -Parent $userCargo
        $env:PATH = "$cargoBin;$env:PATH"
        $cargo = Get-Command 'cargo.exe' -ErrorAction SilentlyContinue
    }
}
if (-not $cargo) { throw 'cargo.exe was not found on PATH or in the current user Rustup bin directory. Install Rustup and stable x86_64-pc-windows-msvc; see the README.' }
$rustc = Get-Command 'rustc.exe' -ErrorAction SilentlyContinue
if (-not $rustc) { $rustc = Get-Command (Join-Path (Split-Path -Parent $cargo.Source) 'rustc.exe') -ErrorAction SilentlyContinue }
if (-not $rustc) { throw 'rustc.exe was not found beside Cargo. Install the stable x86_64-pc-windows-msvc toolchain.' }
$rustcInfo = (& $rustc.Source --version --verbose | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'Could not query rustc version.' }
if ($rustcInfo -notmatch '(?m)^host:\s*x86_64-pc-windows-msvc\r?$') {
    throw "The active rustc host is not x86_64-pc-windows-msvc. Active compiler details:`n$rustcInfo"
}
if (-not $env:VCToolsInstallDir -or -not (Test-Path -LiteralPath $env:VCToolsInstallDir)) {
    throw 'MSVC C++ Build Tools are unavailable in this shell. Install Visual Studio Build Tools with the Desktop development with C++ workload, then use its x64 Native Tools/Developer PowerShell.'
}
if (-not $env:WindowsSdkDir -or -not (Test-Path -LiteralPath $env:WindowsSdkDir)) {
    throw 'Windows SDK environment is unavailable. Install a Windows 10/11 SDK with Visual Studio Build Tools and reopen the x64 Developer PowerShell.'
}

$rustup = Get-Command rustup.exe -ErrorAction SilentlyContinue
if ($rustup) {
    $installedTargets = @(& $rustup.Source target list --installed)
    if ($LASTEXITCODE -ne 0) { throw 'Could not query installed Rust targets.' }
    if ($installedTargets -notcontains $target) { throw "Rust target $target is missing. Install it with: rustup target add $target" }
}
elseif ($rustcInfo -notmatch '(?m)^host: x86_64-pc-windows-msvc$') {
    throw "rustup is required to install the $target target."
}

# Build the optional startup agent before Cargo. scanner-gui/build.rs embeds
# this exact x64 DLL into the native EXE when it is present.
$agentDll = Join-Path $workspace 'target\embedded-agent\mc-jvmti-agent.dll'
if (-not $SkipAgent) {
    $compiler = Get-Command 'cl.exe' -ErrorAction SilentlyContinue
    $jdkHeaders = @()
    if ($env:JAVA_HOME) { $jdkHeaders += Join-Path $env:JAVA_HOME 'include\jvmti.h' }
    if (${env:ProgramFiles}) {
        $javaRoot = Join-Path ${env:ProgramFiles} 'Java'
        if (Test-Path -LiteralPath $javaRoot) {
            $jdkHeaders += Get-ChildItem -LiteralPath $javaRoot -Directory -Filter 'jdk*' -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'include\jvmti.h' }
        }
    }
    $header = $jdkHeaders | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($compiler -and $header -and $env:VSCMD_ARG_TGT_ARCH -eq 'x64') {
        $jdkRoot = Split-Path -Parent (Split-Path -Parent $header)
        $agentOut = Split-Path -Parent $agentDll
        New-Item -ItemType Directory -Path $agentOut -Force | Out-Null
        $source = Join-Path $workspace 'agents\mc-jvmti-agent\agent.cpp'
        $agentImplib = Join-Path $agentOut 'mc-jvmti-agent.lib'
        $agentObject = Join-Path $agentOut 'agent.obj'
        & $compiler.Source /nologo /std:c++17 /EHsc /O2 /MT /LD "/I$jdkRoot\include" "/I$jdkRoot\include\win32" "/Fo$agentObject" $source /link /MACHINE:X64 "/OUT:$agentDll" "/IMPLIB:$agentImplib" Advapi32.lib Rpcrt4.lib
        if ($LASTEXITCODE -ne 0) { throw "JVMTI agent compilation failed with exit code $LASTEXITCODE" }
        if (-not (Test-Path -LiteralPath $agentDll -PathType Leaf) -or -not (Test-PeX64 $agentDll)) { throw 'JVMTI agent output is missing or is not a valid x64 PE DLL.' }
        Write-Host "Agent built for embedding: $agentDll"
    }
    elseif (Test-Path -LiteralPath $agentDll -PathType Leaf) {
        if (-not (Test-PeX64 $agentDll)) { throw "Existing optional agent is not a valid x64 PE DLL: $agentDll" }
        Write-Host "Using existing x64 agent for embedding: $agentDll"
    }
    elseif (Test-Path -LiteralPath (Join-Path $dist 'agent\mc-jvmti-agent.dll') -PathType Leaf) {
        $previousAgent = Join-Path $dist 'agent\mc-jvmti-agent.dll'
        if (-not (Test-PeX64 $previousAgent)) { throw "Existing optional agent is not a valid x64 PE DLL: $previousAgent" }
        $agentOut = Split-Path -Parent $agentDll
        New-Item -ItemType Directory -Path $agentOut -Force | Out-Null
        Copy-Item -LiteralPath $previousAgent -Destination $agentDll
        Write-Host "Using preserved x64 agent for embedding: $agentDll"
    }
    else {
        if ($env:MCS_REQUIRE_AGENT -eq '1') {
            throw 'The CI build requires the optional JVMTI agent to be built and embedded, but no compatible x64 agent compiler/JDK headers were available.'
        }
        Write-Warning 'Building without optional JVMTI class inspection: x64 MSVC, JDK JVMTI headers, or x64 Developer shell is unavailable.'
    }
}

New-Item -ItemType Directory -Path $dist -Force | Out-Null
Push-Location $workspace
try {
    Invoke-CargoStep 'Rust formatting check' @('fmt', '--all', '--', '--check')
    if (-not (Test-Path -LiteralPath (Join-Path $workspace 'Cargo.lock') -PathType Leaf)) {
        throw 'Cargo.lock is missing. Resolve dependencies first with cargo generate-lockfile; release builds use --locked.'
    }
    Invoke-CargoStep 'Workspace cargo check' @('check', '--locked', '--workspace', '--target', $target)
    if (-not $SkipClippy) { Invoke-CargoStep 'Workspace clippy' @('clippy', '--locked', '--workspace', '--all-targets', '--target', $target) }
    if (-not $SkipTests) { Invoke-CargoStep 'Workspace tests' @('test', '--locked', '--workspace', '--target', $target) }
    Invoke-CargoStep 'Workspace release build' @('build', '--locked', '--release', '--workspace', '--target', $target)

    $built = Join-Path $workspace "target\$target\release\scanner-gui.exe"
    if (-not (Test-Path -LiteralPath $built -PathType Leaf)) { throw "Cargo completed without producing expected executable: $built" }
    if (-not (Test-PeX64 $built)) { throw "Built executable is not a valid x64 Windows PE image: $built" }

    $exeOut = Join-Path $dist 'Minecraft-Cheat-Scanner.exe'
    Copy-Item -LiteralPath $built -Destination $exeOut -Force
    if (-not (Test-PeX64 $exeOut)) { throw "Packaged executable failed x64 PE verification: $exeOut" }
    Write-Host "Verified x64 EXE: $exeOut"
}
finally { Pop-Location }
