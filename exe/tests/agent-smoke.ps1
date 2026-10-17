[CmdletBinding()]
param(
    [string]$JdkRoot = $env:JAVA_HOME,
    [string]$AgentPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $AgentPath) { $AgentPath = Join-Path $PSScriptRoot '..\target\embedded-agent\mc-jvmti-agent.dll' }
if (-not $JdkRoot) { throw 'Set JAVA_HOME to a compatible x64 JDK before running the JVMTI smoke test.' }
$java = Join-Path $JdkRoot 'bin\java.exe'
$javac = Join-Path $JdkRoot 'bin\javac.exe'
if (-not (Test-Path -LiteralPath $java) -or -not (Test-Path -LiteralPath $javac)) { throw "JDK java.exe/javac.exe not found under $JdkRoot" }
if (-not (Test-Path -LiteralPath $AgentPath)) { throw "JVMTI agent DLL not found: $AgentPath" }

function Test-PeX64([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5a4d) { return $false }
        $stream.Position = 0x3c; $offset = $reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt ($stream.Length - 6)) { return $false }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550) { return $false }
        return ($reader.ReadUInt16() -eq 0x8664)
    } finally { $stream.Dispose() }
}
if (-not (Test-PeX64 $AgentPath)) { throw 'Agent is not a valid x64 PE DLL.' }

$temp = Join-Path ([IO.Path]::GetTempPath()) ('mc-jvmti-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
$markerPath = $null
$proc = $null
$pipe = $null
try {
    $source = @"
import java.util.ArrayList;
public final class AgentSmoke {
    public static void main(String[] args) throws Exception {
        ArrayList<String> loaded = new ArrayList<>();
        loaded.add("fixture");
        Class.forName("java.lang.Thread");
        System.out.println("READY");
        System.out.flush();
        System.in.read();
    }
}
"@
    $sourcePath = Join-Path $temp 'AgentSmoke.java'
    [IO.File]::WriteAllText($sourcePath, $source, [Text.UTF8Encoding]::new($false))
    & $javac -d $temp $sourcePath
    if ($LASTEXITCODE -ne 0) { throw "javac failed with exit code $LASTEXITCODE" }
    $fixtureLocalAppData = Join-Path $temp 'LocalAppData'
    New-Item -ItemType Directory -Path $fixtureLocalAppData -Force | Out-Null

    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $java
    $psi.Arguments = '-agentpath:"' + (Resolve-Path -LiteralPath $AgentPath).Path + '" -cp "' + $temp + '" AgentSmoke'
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['LOCALAPPDATA'] = $fixtureLocalAppData
    $proc = [Diagnostics.Process]::Start($psi)
    if (-not $proc) { throw 'Could not start the controlled Java fixture.' }
    $markerPath = Join-Path $fixtureLocalAppData ('MinecraftCheatScanner\Agent\agent-' + $proc.Id + '.json')
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $markerPath) -and [DateTime]::UtcNow -lt $deadline -and -not $proc.HasExited) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path -LiteralPath $markerPath)) {
        $proc.Refresh(); $stderr = if ($proc.HasExited) { $proc.StandardError.ReadToEnd() } else { 'agent marker timeout' }
        throw "Agent_OnLoad did not create its marker. $stderr"
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ([int]$marker.processId -ne $proc.Id) { throw 'Agent marker PID did not match the Java fixture.' }
    $pipeName = ([string]$marker.pipeName).Substring(([string]$marker.pipeName).LastIndexOf('\') + 1)
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $pipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None)
    $pipe.Connect(5000)
    $requestText = 'SCAN {0} {1} {2}' -f $marker.processId, $marker.processCreationFiletime, $marker.sessionId
    $payload = [Text.Encoding]::UTF8.GetBytes($requestText)
    $writer = [IO.BinaryWriter]::new($pipe, [Text.Encoding]::UTF8, $true)
    $writer.Write([uint32]$payload.Length); $writer.Write($payload); $writer.Flush()
    $reader = [IO.BinaryReader]::new($pipe, [Text.Encoding]::UTF8, $true)
    $length = $reader.ReadUInt32()
    if ($length -lt 1 -or $length -gt 16MB) { throw "Agent returned an invalid frame size: $length" }
    $responseBytes = $reader.ReadBytes([int]$length)
    if ($responseBytes.Length -ne $length) { throw 'Agent closed the pipe before returning the full response.' }
    $response = [Text.Encoding]::UTF8.GetString($responseBytes) | ConvertFrom-Json
    if ($response.protocol_version -ne 1 -or $response.process_id -ne $proc.Id -or $response.process_creation_filetime -ne $marker.processCreationFiletime -or $response.session_id -ne $marker.sessionId) { throw 'Agent response identity/session validation failed.' }
    if ($response.error) { throw "JVMTI snapshot failed: $($response.error)" }
    $classes = @($response.classes | ForEach-Object { $_.name })
    if ($classes -notcontains 'AgentSmoke' -or $classes -notcontains 'java.lang.String') { throw 'Expected loaded classes were absent from the JVMTI snapshot.' }
    [PSCustomObject]@{Status='PASS';Jdk=$JdkRoot;JavaPid=$proc.Id;AgentPath=(Resolve-Path -LiteralPath $AgentPath).Path;LoadedClassCount=$classes.Count;ClassNameConversion='AgentSmoke and java.lang.String observed';PipeSession='PID, process creation time, protocol, and session matched'} | Format-List
    $proc.StandardInput.WriteLine('exit'); $proc.StandardInput.Flush()
    if (-not $proc.WaitForExit(5000)) { throw 'Java fixture did not exit gracefully after stdin close.' }
    $proc.Refresh()
    if (Test-Path -LiteralPath $markerPath) { throw 'Agent_OnUnload did not remove its rendezvous marker.' }
}
finally {
    if ($pipe) { $pipe.Dispose() }
    if ($proc) { if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(3000) }; $proc.Dispose() }
    if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
