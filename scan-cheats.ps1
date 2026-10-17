[CmdletBinding()]
param(
[string]$OutputDirectory,
    [switch]$NoHtml,
    [ValidateRange(1,1000000)][int]$MaxFiles = 5000,
    [ValidateRange(1024,10737418240)][long]$MaxJarBytes = 536870912,
    [ValidateRange(0,8)][int]$MaxNestedDepth = 2,
    [ValidateRange(1,300)][int]$JcmdTimeoutSeconds = 8,
    [switch]$RuntimeDiagnostic
)

# Minecraft Cheat Scanner v7.2. Read-only, best-effort local diagnostics.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.
$script:ScannerVersion = '7.2'
$ErrorActionPreference = 'Stop'
$script:ScannerPath = $PSCommandPath
if ([string]::IsNullOrWhiteSpace($script:ScannerPath)) { $script:ScannerPath = $MyInvocation.MyCommand.Path }
$script:ScannerRoot = if (![string]::IsNullOrWhiteSpace($PSScriptRoot)) { [IO.Path]::GetFullPath($PSScriptRoot) } elseif (![string]::IsNullOrWhiteSpace($script:ScannerPath)) { Split-Path -Parent ([IO.Path]::GetFullPath($script:ScannerPath)) } else { (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $script:ScannerRoot 'Reports'
}
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:Coverage = New-Object 'System.Collections.Generic.List[object]'
$script:Diagnostics = New-Object 'System.Collections.Generic.List[object]'
$script:FileCache = @{}
$script:HashCache = @{}
$script:HashCount = 0
$script:DllCount = 0
$script:JarCount = 0
$script:ModArtifacts = New-Object 'System.Collections.Generic.List[object]'
$script:ProcessMethodResults = New-Object 'System.Collections.Generic.List[object]'
$script:KnownBrands = @('meteor-client','meteor client','meteorclient','liquidbounce','wurst','aristois','impact client','inertia client','bleachhack','thunderhack','rusherhack','future client','lambda client','kami blue','doomsday client','rise client','fdpclient','augustus client','tenacity client','flux client','sigma client','vape lite','vape','raven','drip client','entropy client','whiteout','dream client','slinky')
$script:SignatureCatalogPath = Join-Path $script:ScannerRoot 'signatures.json'
$script:ClientCatalog = @()
$script:TrustedSignatureHosts = @('github.com','meteorclient.com','liquidbounce.net','wurstclient.net','wurst.wiki','modrinth.com','api.modrinth.com')
try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop;Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { $script:CompressionAssemblyError=$_.Exception.Message }

$script:ProgressPhases = @(
    [pscustomobject]@{Name='Startup';Weight=3},
    [pscustomobject]@{Name='Process discovery';Weight=10},
    [pscustomobject]@{Name='Minecraft installation discovery';Weight=10},
    [pscustomobject]@{Name='Runtime diagnostics';Weight=22},
    [pscustomobject]@{Name='Logs and configuration inspection';Weight=10},
    [pscustomobject]@{Name='Mod file inventory';Weight=12},
    [pscustomobject]@{Name='JAR and nested archive analysis';Weight=20},
    [pscustomobject]@{Name='User artifact inspection';Weight=8},
    [pscustomobject]@{Name='Report generation';Weight=5}
)
$script:ProgressPercent=0;$script:ProgressPhasePercent=0;$script:ProgressPhaseName='';$script:ProgressFallback=$false
$script:ProgressLastText='';$script:ProgressLastTextPhase='';$script:ProgressLastTextTime=[datetime]::MinValue
$script:ScanStarted=Get-Date;$script:ScannedPaths=@{};$script:ScannedFileCount=0;$script:InstallationCount=0

function Get-CachedSha256 {
    param([string]$Path,[long]$MaximumBytes=536870912)
    if(!(Test-LocalScanPath $Path)){return [pscustomobject]@{Status='Skipped';Hash=$null;Detail='Non-local path excluded.'}}
    try {
        $before=Get-Item -LiteralPath $Path -ErrorAction Stop
        if($before.PSIsContainer){return [pscustomobject]@{Status='Skipped';Hash=$null;Detail='Path is a directory.'}}
        if($before.Length -gt $MaximumBytes){Add-Coverage "SHA-256: $Path" 'Skipped' "File exceeds the configured $MaximumBytes-byte hashing limit.";return [pscustomobject]@{Status='Skipped';Hash=$null;Detail='File exceeds configured hashing limit.'}}
        $key=('{0}|{1}|{2}' -f $Path.ToLowerInvariant(),$before.Length,$before.LastWriteTimeUtc.Ticks)
        if($script:HashCache.ContainsKey($key)){return [pscustomobject]@{Status='Completed';Hash=$script:HashCache[$key];Detail='Cached for unchanged file metadata.'}}
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $sha=[Security.Cryptography.SHA256]::Create()
        try{$digest=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose();$stream.Dispose()}
        $after=Get-Item -LiteralPath $Path -ErrorAction Stop
        if($before.Length -ne $after.Length -or $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks){Add-Coverage "SHA-256: $Path" 'Partial' 'File changed during hashing; digest was discarded.';return [pscustomobject]@{Status='ChangedDuringScan';Hash=$null;Detail='File size or modification time changed during hashing.'}}
        $script:HashCache[$key]=$digest;$script:HashCount++
        return [pscustomobject]@{Status='Completed';Hash=$digest;Detail='SHA-256 calculated locally.'}
    } catch { Add-Coverage "SHA-256: $Path" 'Failed' $_.Exception.Message;return [pscustomobject]@{Status='Failed';Hash=$null;Detail=$_.Exception.Message} }
}

function Get-UserFolderPath {
    param([string]$EnvironmentName,[Environment+SpecialFolder]$SpecialFolder)
    $value=[Environment]::GetEnvironmentVariable($EnvironmentName)
    if(![string]::IsNullOrWhiteSpace($value)){return $value}
    try{return [Environment]::GetFolderPath($SpecialFolder)}catch{return ''}
}
function Initialize-ScannerUserFolders {
    $profile=Get-UserFolderPath 'USERPROFILE' ([Environment+SpecialFolder]::UserProfile)
    $roaming=Get-UserFolderPath 'APPDATA' ([Environment+SpecialFolder]::ApplicationData)
    $local=Get-UserFolderPath 'LOCALAPPDATA' ([Environment+SpecialFolder]::LocalApplicationData)
    $documents=[Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
    $desktop=[Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
    if(!$documents -and $profile){$documents=Join-Path $profile 'Documents'}
    if(!$desktop -and $profile){$desktop=Join-Path $profile 'Desktop'}
    $downloads=''
    try{$shellFolders=Get-ItemProperty -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop;$downloadProperty=$shellFolders.PSObject.Properties['{374DE290-123F-4565-9164-39C4925E467B}'];if($downloadProperty){$downloads=[Environment]::ExpandEnvironmentVariables([string]$downloadProperty.Value)}}catch{}
    if(!$downloads -and $profile){$downloads=Join-Path $profile 'Downloads'}
    $temp=[Environment]::GetEnvironmentVariable('TEMP');if(!$temp){$temp=[IO.Path]::GetTempPath()}
    return @{UserProfile=$profile;AppData=$roaming;LocalAppData=$local;Roaming=$roaming;Downloads=$downloads;Desktop=$desktop;Documents=$documents;Temp=$temp}
}
$script:UserFolders=Initialize-ScannerUserFolders

function Update-ScanProgress {
    param([string]$Phase,[double]$PhasePercent,[string]$Operation='',[int]$Completed=0,[int]$Total=0)
    $index=-1
    for($i=0;$i -lt $script:ProgressPhases.Count;$i++){if($script:ProgressPhases[$i].Name -eq $Phase){$index=$i;break}}
    if($index -lt 0){return}
    $PhasePercent=[Math]::Max(0,[Math]::Min(100,$PhasePercent))
    if($script:ProgressPhaseName -eq $Phase){$PhasePercent=[Math]::Max($PhasePercent,$script:ProgressPhasePercent)}else{$script:ProgressPhasePercent=0;$script:ProgressPhaseName=$Phase}
    $before=0;for($i=0;$i -lt $index;$i++){$before += $script:ProgressPhases[$i].Weight}
    $weighted=$before+($script:ProgressPhases[$index].Weight*$PhasePercent/100)
    $script:ProgressPercent=[Math]::Max($script:ProgressPercent,[Math]::Min(100,[int][Math]::Floor($weighted)))
    $script:ProgressPhasePercent=$PhasePercent
    $done=@($script:ProgressPhases | Select-Object -First $index | ForEach-Object {$_.Name}) -join ', '
    $elapsed=[Math]::Round(((Get-Date)-$script:ScanStarted).TotalSeconds,1)
    $counts=if($Total -gt 0){" | $Completed / $Total items"}elseif($Completed -gt 0){" | $Completed items"}else{''}
    $findingCount=@(Get-PositiveCheatFindings $script:Findings.ToArray()).Count
    $status=('{0}% | {1}{2} | files {3} | elapsed {4}s | installations {5} | processes {6} | JARs {7} | DLLs {8} | hashes {9} | positive findings {10} | failed checks {11}' -f $script:ProgressPercent,$Operation,$counts,$script:ScannedFileCount,$elapsed,$script:InstallationCount,$script:ActiveProcessCount,$script:JarCount,$script:DllCount,$script:HashCount,$findingCount,$script:FailedCheckCount)
    if($done){$status += " | done: $done"}
    try { if([Console]::IsOutputRedirected){$script:ProgressFallback=$true};Write-Progress -Id 1 -Activity "Minecraft Cheat Scanner v$script:ScannerVersion" -Status $status -CurrentOperation $Phase -PercentComplete $script:ProgressPercent }
    catch { $script:ProgressFallback=$true }
    if($script:ProgressFallback -and ($script:ProgressPercent -ne $script:ProgressLastText -or $Phase -ne $script:ProgressLastTextPhase -or (Get-Date)-$script:ProgressLastTextTime -gt [TimeSpan]::FromSeconds(2))){Write-Host ("[{0,3}%] {1}: {2}" -f $script:ProgressPercent,$Phase,$status);$script:ProgressLastText=$script:ProgressPercent;$script:ProgressLastTextPhase=$Phase;$script:ProgressLastTextTime=Get-Date}
    if($Phase -eq 'Report generation' -and $PhasePercent -ge 100){try{Write-Progress -Id 1 -Activity "Minecraft Cheat Scanner v$script:ScannerVersion" -Completed}catch{}}
}
function Add-ScannedFile {
    param([string]$Path)
    if([string]::IsNullOrWhiteSpace($Path)){return}
    $key=$Path.ToLowerInvariant()
    if(!$script:ScannedPaths.ContainsKey($key)){$script:ScannedPaths[$key]=$true;$script:ScannedFileCount++}
}

function Add-Coverage {
    param([string]$Check,[ValidateSet('Completed','Partial','Skipped','Failed','Restricted')][string]$Status,[string]$Detail)
    $script:Coverage.Add([pscustomobject]@{ Check=$Check; Status=$Status; Detail=$Detail })
    if($Status -ne 'Completed'){$script:FailedCheckCount++}
    if($Status -ne 'Completed'){$script:Diagnostics.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('o');Level=$Status;Check=$Check;Detail=$Detail})}
}
function Add-ProcessMethodResult {
    param([Nullable[int]]$ProcessId,[string]$Method,[ValidateSet('Succeeded','Failed','Restricted','Unavailable','NoMatch','Partial','Skipped')][string]$Status,[string]$Detail)
    $script:ProcessMethodResults.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('o');ProcessId=$ProcessId;Method=$Method;Status=$Status;Detail=$Detail})
}
function Add-Finding {
    param([ValidateSet('Verified Artifact','Verified Runtime Association','Confirmed Indicator','High Suspicion','Needs Manual Review','Informational','Scan Incomplete')][string]$Category,[string]$Title,[string]$Detail,[string]$Path,[Nullable[int]]$ProcessId,[string]$ClientName,[string]$ClientCategory,[string]$MinecraftVersion,[string]$DetectionMethod,[string]$SignatureSource,[string]$EvidenceStrength,[string]$InstalledStatus,[string]$RuntimeAssociation,[string]$VerificationLimitations,[string]$FileHash)
    $script:Findings.Add([pscustomobject]@{ Category=$Category; Title=$Title; Detail=$Detail; Path=$Path; ProcessId=$ProcessId; ClientName=$ClientName; ClientCategory=$ClientCategory; MinecraftVersion=$MinecraftVersion; DetectionMethod=$DetectionMethod; SignatureSource=$SignatureSource; EvidenceStrength=$EvidenceStrength; InstalledStatus=$InstalledStatus; RuntimeAssociation=$RuntimeAssociation; VerificationLimitations=$VerificationLimitations; FileHash=$FileHash })
}
function Get-ScannerFindings { return $script:Findings.ToArray() }
function Get-PositiveCheatFindings {
    param([object[]]$Findings)
    $positiveCategories=@('Verified Artifact','Verified Runtime Association','Confirmed Indicator','High Suspicion')
    return @($Findings|Where-Object{$_.Category -in $positiveCategories})
}
function Get-CheatFindingDisplayLines {
    param([object[]]$Findings)
    $lines=New-Object 'System.Collections.Generic.List[string]'
    foreach($finding in (Get-PositiveCheatFindings $Findings)){
        $identity=if($finding.ClientName){$finding.ClientName}else{$finding.Title}
        $lines.Add("[DETECTED] $identity")
        if($finding.ClientCategory){$lines.Add("Type: $($finding.ClientCategory)")}
        if($finding.DetectionMethod){$lines.Add("Evidence: $($finding.DetectionMethod)")}
        if($finding.Detail){$lines.Add("Details: $($finding.Detail)")}
        if($finding.FileHash){$lines.Add("SHA-256: $($finding.FileHash)")}
        if($finding.Path){$lines.Add("Artifact: $($finding.Path)")}
        if($null -ne $finding.ProcessId){$lines.Add("Process: PID $($finding.ProcessId)")}
        if($finding.RuntimeAssociation){$lines.Add("Runtime association: $($finding.RuntimeAssociation)")}
        $lines.Add("Confidence: $($finding.Category) | $($finding.EvidenceStrength)")
        if($finding.SignatureSource){$lines.Add("Signature source: $($finding.SignatureSource)")}
        if($finding.VerificationLimitations){$lines.Add("Limitations: $($finding.VerificationLimitations)")}
        $lines.Add('')
    }
    return $lines.ToArray()
}
function Get-ScannerCoverage { return $script:Coverage.ToArray() }
function Get-ScannerDiagnostics { return $script:Diagnostics.ToArray() }
function Get-FirstCapture {
    param([string]$InputText,[string]$Pattern,[string]$Group='value')
    $m=[regex]::Match($InputText,$Pattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if($m.Success){ return $m.Groups[$Group].Value }; return $null
}
function Resolve-NormalPath {
    param([string]$Path)
    if([string]::IsNullOrWhiteSpace($Path)){ return $null }
    try { return [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path)).TrimEnd('\') + '\' } catch { return $null }
}
function Test-LocalScanPath {
    param([string]$Path)
    if([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('\\')){return $false}
    try{$full=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path));$root=[IO.Path]::GetPathRoot($full);$drive=New-Object IO.DriveInfo($root);return $drive.DriveType -in @([IO.DriveType]::Fixed,[IO.DriveType]::Removable,[IO.DriveType]::Ram)}catch{return $false}
}
function Test-PathWithin {
    param([string]$Path,[string[]]$Roots)
    $full=Resolve-NormalPath $Path
    if(!$full){ return $false }
    foreach($root in $Roots){ $base=Resolve-NormalPath $root; if($base -and $full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)){ return $true } }
    return $false
}
function Get-CommandResult {
    param([string]$File,[string[]]$Arguments,[int]$TimeoutSeconds=8)
    $p=$null
    try {
        $psi=New-Object Diagnostics.ProcessStartInfo
        $quoted=@($Arguments|ForEach-Object { $a=[string]$_; if($a -match '[\s"]'){'"'+($a -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1')+'"'}else{$a} })
        $psi.FileName=$File; $psi.Arguments=($quoted -join ' '); $psi.UseShellExecute=$false
        $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.CreateNoWindow=$true
        $p=New-Object Diagnostics.Process; $p.StartInfo=$psi
        if(!$p.Start()){ return [pscustomobject]@{Status='Failed';Output='';Error='Could not start process'} }
        $outTask=$p.StandardOutput.ReadToEndAsync(); $errTask=$p.StandardError.ReadToEndAsync()
        if(!$p.WaitForExit($TimeoutSeconds*1000)){ try{$p.Kill();[void]$p.WaitForExit(1000)}catch{}; return [pscustomobject]@{Status='Timeout';Output='';Error="Timed out after $TimeoutSeconds seconds"} }
        return [pscustomobject]@{Status='Completed';Output=$outTask.Result;Error=$errTask.Result;ExitCode=$p.ExitCode}
    } catch { return [pscustomobject]@{Status='Failed';Output='';Error=$_.Exception.Message} }
    finally {if($p){$p.Dispose()}}
}
function Get-JavaRuntimeInfo {
    param([string]$Executable,[int]$TimeoutSeconds=5)
    if(!$Executable){return [pscustomobject]@{Status='Unavailable';Version=$null;Vendor=$null;Path=$null;Detail='Process executable path unavailable'}}
    if(!(Test-LocalScanPath $Executable)){return [pscustomobject]@{Status='Unavailable';Version=$null;Vendor=$null;Path=$Executable;Detail='Executable is not on local fixed/removable storage'}}
    $javaPath=$Executable
    if([IO.Path]::GetFileName($javaPath) -ieq 'javaw.exe'){$javaPath=Join-Path (Split-Path -Parent $javaPath) 'java.exe'}
    if(!(Test-Path -LiteralPath $javaPath -PathType Leaf)){return [pscustomobject]@{Status='Unavailable';Version=$null;Vendor=$null;Path=$javaPath;Detail='Paired java.exe not found'}}
    $r=Get-CommandResult -File $javaPath -Arguments @('-version') -TimeoutSeconds $TimeoutSeconds
    $text=($r.Output+"`n"+$r.Error).Trim()
    if($r.Status -ne 'Completed'){return [pscustomobject]@{Status=$r.Status;Version=$null;Vendor=$null;Path=$javaPath;Detail=$r.Error}}
    $version=Get-FirstCapture $text '(?:version\s+"(?<value>[^"]+)"|openjdk\s+(?<value>\d+(?:\.\d+)?(?:\.\d+)?))'
    $vendor=if($text -match '(?i)openjdk|temurin|adoptium'){'OpenJDK-compatible'}elseif($text -match '(?i)java\(tm\)|oracle'){'Oracle Java'}else{'Unknown'}
    if(!$version){return [pscustomobject]@{Status='ParseFailed';Version=$null;Vendor=$vendor;Path=$javaPath;Detail=$text}}
    return [pscustomobject]@{Status='Completed';Version=$version;Vendor=$vendor;Path=$javaPath;Detail=$text}
}
function Get-PeArchitecture {
    param([string]$Path)
    try {
        if(!(Test-Path -LiteralPath $Path -PathType Leaf)){return [pscustomobject]@{Status='Unavailable';Architecture='Unknown';Machine=$null;Detail='Executable file is unavailable.'}}
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        try {
            $reader=New-Object IO.BinaryReader($stream)
            if($reader.ReadUInt16() -ne 0x5A4D){return [pscustomobject]@{Status='ParseFailed';Architecture='Unknown';Machine=$null;Detail='Executable has no DOS MZ header.'}}
            $stream.Position=0x3c;$peOffset=$reader.ReadInt32()
            if($peOffset -lt 64 -or $peOffset -gt ($stream.Length-6)){return [pscustomobject]@{Status='ParseFailed';Architecture='Unknown';Machine=$null;Detail='PE header offset is invalid.'}}
            $stream.Position=$peOffset;if($reader.ReadUInt32() -ne 0x00004550){return [pscustomobject]@{Status='ParseFailed';Architecture='Unknown';Machine=$null;Detail='PE signature is invalid.'}}
            $machine=$reader.ReadUInt16();$arch=switch($machine){0x8664{'x64'} 0x014c{'x86'} 0xAA64{'ARM64'} 0x01c4{'ARM'} default{'Unknown'}}
            return [pscustomobject]@{Status='Completed';Architecture=$arch;Machine=('0x{0:X4}' -f $machine);Detail='Architecture read from the PE machine field.'}
        } finally {$stream.Dispose()}
    } catch {return [pscustomobject]@{Status='Failed';Architecture='Unknown';Machine=$null;Detail=$_.Exception.Message}}
}
function Get-JcmdToolInfo {
    param([string]$Path)
    $bin=Split-Path -Parent $Path;$java=Join-Path $bin 'java.exe';if(!(Test-Path -LiteralPath $java -PathType Leaf)){$java=Join-Path $bin 'javaw.exe'}
    $version=Get-JavaRuntimeInfo $java 5;$arch=Get-PeArchitecture $Path;$javaArch=Get-PeArchitecture $java
    return [pscustomobject]@{Path=$Path;Version=$version.Version;VersionStatus=$version.Status;Architecture=$arch.Architecture;ArchitectureStatus=$arch.Status;JavaArchitecture=$javaArch.Architecture;Detail=$version.Detail}
}
function Get-OrderedJcmdPaths {
    param([string[]]$Jcmds,[string]$TargetVersion,[string]$TargetArchitecture,[int]$ProcessId)
    $targetMajor=Get-FirstCapture $TargetVersion '^(?<value>\d+)'
    $rows=New-Object 'System.Collections.Generic.List[object]'
    foreach($path in $Jcmds){$info=Get-JcmdToolInfo $path;$toolMajor=Get-FirstCapture $info.Version '^(?<value>\d+)';$sameArch=($TargetArchitecture -and $info.Architecture -and $TargetArchitecture -eq $info.Architecture);$sameMajor=($targetMajor -and $toolMajor -and $targetMajor -eq $toolMajor);$score=0;if($sameArch){$score+=2};if($sameMajor){$score+=4}
        $status=if($sameArch -and $sameMajor){'Succeeded'}elseif($info.Status -eq 'Unavailable'){'Unavailable'}else{'Partial'}
        $detail="jcmd=$path; tool Java=$($info.Version) ($($info.Architecture)); target Java=$TargetVersion ($TargetArchitecture)."
        Add-ProcessMethodResult $ProcessId 'jcmd runtime compatibility' $status $detail
        $rows.Add([pscustomobject]@{Path=$path;Score=$score;Info=$info})
    }
    $exact=@($rows|Where-Object{$_.Score -eq 6})
    Add-ProcessMethodResult $ProcessId 'Matching jcmd discovery' $(if($exact.Count){'Succeeded'}else{'Partial'}) $(if($exact.Count){"Found $($exact.Count) jcmd tool(s) matching Java feature $targetMajor and $TargetArchitecture architecture."}else{"No discovered jcmd matches Java feature $targetMajor and $TargetArchitecture architecture. Discovered tool(s): $(($rows|ForEach-Object{$_.Info.Path+' ('+$_.Info.Version+', '+$_.Info.Architecture+')'}) -join '; ')."})
    return @($rows|Sort-Object @{Expression='Score';Descending=$true},Path|ForEach-Object{$_.Path})
}
function Get-JcmdPaths {
    $found=New-Object 'System.Collections.Generic.List[string]'
    foreach($base in @($script:ScannerRoot,(Join-Path $script:ScannerRoot 'tools'))){
        if(Test-Path -LiteralPath $base -PathType Container){try{$jdkDirs=@(Get-ChildItem -LiteralPath $base -Directory -ErrorAction Stop | Where-Object Name -match '^(?i)jdk' | Select-Object -First 40);foreach($jdk in $jdkDirs){$candidate=Join-Path $jdk.FullName 'bin\jcmd.exe';if(Test-Path -LiteralPath $candidate -PathType Leaf){$found.Add($candidate)}}}catch{Add-Coverage "jcmd search: $base" 'Partial' $_.Exception.Message}}
    }
    $programRoots=@();foreach($programRoot in @($env:ProgramFiles,${env:ProgramFiles(x86)})){if($programRoot){$programRoots+=@((Join-Path $programRoot 'Java'),(Join-Path $programRoot 'Eclipse Adoptium'),(Join-Path $programRoot 'Zulu'))}}
    foreach($base in $programRoots){
        if(Test-Path -LiteralPath $base -PathType Container){
            try{$jdkDirs=@(Get-ChildItem -LiteralPath $base -Directory -ErrorAction Stop | Select-Object -First 80);foreach($jdk in $jdkDirs){$candidate=Join-Path $jdk.FullName 'bin\jcmd.exe';if(Test-Path -LiteralPath $candidate -PathType Leaf){$found.Add($candidate)}}}catch{Add-Coverage "jcmd search: $base" 'Partial' $_.Exception.Message}
        }
    }
    try {$cmd=Get-Command jcmd.exe -ErrorAction Stop; if($cmd){$found.Add($cmd.Source)}} catch { Add-Coverage 'jcmd on PATH' 'Skipped' 'jcmd.exe was not found on PATH.' }
    foreach($javaHome in @($env:JAVA_HOME,$env:JDK_HOME)){if($javaHome){$candidate=Join-Path $javaHome 'bin\jcmd.exe';if(Test-Path -LiteralPath $candidate -PathType Leaf){$found.Add($candidate)}}}
    # Bundled launcher JDKs often are not on PATH and are outside Program Files.
    # Check only each discovered Java executable's sibling bin directory.
    try{foreach($candidate in (Get-JavaProcessCandidates)){try{$javaExe=[string]$candidate.Path;if($javaExe){$sibling=Join-Path (Split-Path -Parent $javaExe) 'jcmd.exe';if(Test-Path -LiteralPath $sibling -PathType Leaf){$found.Add($sibling)}}}catch{}}}catch{Add-Coverage 'jcmd process-runtime discovery' 'Partial' $_.Exception.Message}
    return @($found | Select-Object -Unique)
}
function Invoke-JcmdCheck {
    param([string[]]$Jcmds,[int]$ProcessId,[string]$Command,[int]$TimeoutSeconds)
    # Deliberately do not execute jcmd against another process. On Windows the
    # attach provider can write a helper into the target and start a remote
    # thread. Keep this function as an explicit status boundary for callers.
    $why='Not attempted: target JVM attach may write a helper into the process and start a remote thread. Passive process, module, launcher-log, and file checks continue; JVM command line, classes, and classloaders remain unknown.'
    return [pscustomobject]@{Status='Skipped';Output='';Error=$why}
}
function Resolve-JvmMinecraftCandidates {
    param([object[]]$Processes,[string[]]$Jcmds,[int]$TimeoutSeconds=8)
    foreach($process in $Processes){
        if($process.ExecutablePath){
            $targetJava=Get-JavaRuntimeInfo $process.ExecutablePath 5
            $targetArch=Get-PeArchitecture $process.ExecutablePath
            if($targetJava.Status -eq 'Completed' -and $targetArch.Architecture -ne 'Unknown'){
                # Version and architecture inspection is local and read-only; only
                # the resulting jcmd version/PE metadata is compared. No target PID
                # is passed to a diagnostic executable.
                [void](Get-OrderedJcmdPaths $Jcmds $targetJava.Version $targetArch.Architecture $process.ProcessId)
            }else{
                Add-ProcessMethodResult $process.ProcessId 'Target JVM compatibility baseline' 'Partial' "Could not establish target Java version/architecture for passive tool comparison: java=$($targetJava.Status) ($($targetJava.Version)); architecture=$($targetArch.Architecture)."
            }
        }else{
            Add-ProcessMethodResult $process.ProcessId 'Target JVM compatibility baseline' 'Unavailable' 'Java executable path is unavailable; diagnostic tool compatibility cannot be compared.'
        }
        $skip=Invoke-JcmdCheck $Jcmds $process.ProcessId 'VM.command_line' $TimeoutSeconds
        Add-ProcessMethodResult $process.ProcessId 'JVM VM.command_line' $skip.Status $skip.Error
    }
    return $Processes
}function Get-ClassloaderRows {
    param([string]$Text)
    $rows=New-Object 'System.Collections.Generic.List[object]'
    foreach($line in ($Text -split "`r?`n")){
        # HotSpot versions use either spaced columns or tab-separated columns. Capture a
        # class count and a loader description without relying on global $Matches.
        $m=[regex]::Match($line,'^\s*(?:0x[0-9a-fA-F]+\s+){1,3}(?<tail>.+?)\s*$')
        if($m.Success){
            $fields=@($m.Groups['tail'].Value.Trim() -split '\s{2,}' | Where-Object {$_})
            if($fields.Count -ge 2 -and $fields[0] -match '^\d+$'){
                $loader=[string]$fields[$fields.Count-1]
                if($loader -notmatch '^\-+$'){$rows.Add([pscustomobject]@{Classes=[int]$fields[0];Loader=$loader.Trim();Raw=$line.Trim()})}
            }
        }
        # Newer JDK report variant: name, address, parent, classes.
        $m2=[regex]::Match($line,'^\s*(?<loader>[^\t]+)\t+0x[0-9a-fA-F]+\t+[^\t]*\t+(?<classes>\d+)\s*$')
        if($m2.Success){$rows.Add([pscustomobject]@{Classes=[int]$m2.Groups['classes'].Value;Loader=$m2.Groups['loader'].Value.Trim();Raw=$line.Trim()})}
    }
    return ,$rows.ToArray()
}
function Get-ClassHistogramNames {
    param([string]$Text)
    $names=New-Object 'System.Collections.Generic.HashSet[string]'
    foreach($line in ($Text -split "`r?`n")){$m=[regex]::Match($line,'^\s*\d+\s+\d+\s+(?<name>[A-Za-z0-9_.$/;\[<>-]+)\s*$');if($m.Success){[void]$names.Add($m.Groups['name'].Value.Replace('/','.'))}}
    return ,$names
}
function Get-LoadedClassOverlap {
    param([string[]]$ArtifactClasses,[System.Collections.Generic.HashSet[string]]$LoadedClasses)
    $overlap=New-Object 'System.Collections.Generic.List[string]'
    if(!$LoadedClasses){return $overlap.ToArray()}
    foreach($name in $ArtifactClasses){if($LoadedClasses.Contains($name)){$overlap.Add($name)}}
    return $overlap.ToArray()
}
function Get-LoaderKind {
    param([string]$Name)
    if($Name -match '(?i)bootstrap|platform|application|builtin|jdk\.internal\.loader|sun\.misc\.launcher|java\.net\.URLClassLoader'){return 'Standard'}
    if($Name -match '(?i)fabric|knot|forge|modlauncher|neoforge|quilt|launchwrapper|liteloader'){return 'Mod-loader'}
    if($Name -match '(?i)classloader\$|custom|plugin|transformer'){return 'Custom'}
    return 'Unknown'
}
function Read-ZipText {
    param($Archive,[string]$Name,[int]$MaxBytes=1048576,[hashtable]$Budget=$null)
    $entry=$Archive.Entries | Where-Object {$_.FullName -eq $Name} | Select-Object -First 1
    if(!$entry -or $entry.Length -gt $MaxBytes){return ''}
    if($Budget){if($entry.Length -gt $Budget.Remaining){return ''};$Budget.Remaining-=$entry.Length}
    $stream=$null;$reader=$null
    try{$stream=$entry.Open();$reader=New-Object IO.StreamReader($stream);$builder=New-Object Text.StringBuilder;$buf=New-Object char[] 16384;$total=0;while(($n=$reader.Read($buf,0,$buf.Length)) -gt 0){$total+=$n;if($total -gt $MaxBytes){return ''};[void]$builder.Append($buf,0,$n)};return $builder.ToString()}catch{return ''}finally{if($reader){$reader.Dispose()}elseif($stream){$stream.Dispose()}}
}
function Get-ZipRecursiveEvidence {
    param($Archive,[string]$Prefix,[int]$Depth,[int]$MaxDepth,[hashtable]$Budget,[object[]]$Catalog=@())
    $flags=New-Object 'System.Collections.Generic.List[string]';$nested=New-Object 'System.Collections.Generic.List[string]';$signatures=New-Object 'System.Collections.Generic.List[object]';$clientMatches=New-Object 'System.Collections.Generic.List[object]';$scanIncomplete=$false
    foreach($entry in $Archive.Entries){
        $entryPath=if($Prefix){"$Prefix!/$($entry.FullName)"}else{$entry.FullName}
        if($entry.FullName -match '(?i)^(fabric\.mod\.json|quilt\.mod\.json|META-INF/mods\.toml|META-INF/neoforge\.mods\.toml|mcmod\.info)$' -and $entry.Length -le 1048576){
            $text=Read-ZipText $Archive $entry.FullName 1048576 $Budget
            if($text){try{$nestedMetadata=$text|ConvertFrom-Json -ErrorAction Stop;$matches=Get-ModClientMatches ([string]$nestedMetadata.id) ([string]$nestedMetadata.name) @() $script:ClientCatalog;foreach($match in $matches){$clientMatches.Add([pscustomobject]@{Path=$entryPath;Client=$match})}}catch{}}
            foreach($brand in $script:KnownBrands){if([regex]::IsMatch($text.ToLowerInvariant(),'(?<![a-z0-9])'+[regex]::Escape($brand)+'(?![a-z0-9])')){$flags.Add("Known client identifier in nested metadata ($entryPath): $brand")}}
        }
        if($entry.FullName -notmatch '(?i)\.jar$'){continue}
        $nested.Add($entryPath)
        if($Depth -ge $MaxDepth){$scanIncomplete=$true;continue}
        if($entry.Length -gt 33554432 -or $entry.Length -gt $Budget.Remaining){$scanIncomplete=$true;continue}
        $inputStream=$null;$memory=$null;$zip=$null
        try{
            $inputStream=$entry.Open();$memory=New-Object IO.MemoryStream; $buffer=New-Object byte[] 81920; $copied=0L
            while(($read=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0){
                $copied += $read
                if($copied -gt 33554432 -or $copied -gt $Budget.Remaining){$scanIncomplete=$true;break}
                $memory.Write($buffer,0,$read)
            }
            if($scanIncomplete -and ($copied -gt 33554432 -or $copied -gt $Budget.Remaining)){continue}
            $Budget.Remaining -= $copied
            if($Catalog.Count){$sha=[Security.Cryptography.SHA256]::Create();try{$digest=[BitConverter]::ToString($sha.ComputeHash($memory.ToArray())).Replace('-','').ToLowerInvariant();$script:HashCount++}finally{$sha.Dispose()};$sig=Find-SignatureMatchByHash $digest $Catalog;if($sig){$signatures.Add([pscustomobject]@{Path=$entryPath;Signature=$sig})}}
            $memory.Position=0;$zip=New-Object IO.Compression.ZipArchive($memory,[IO.Compression.ZipArchiveMode]::Read,$false)
            $child=Get-ZipRecursiveEvidence $zip $entryPath ($Depth+1) $MaxDepth $Budget $Catalog
            foreach($f in $child.Flags){$flags.Add($f)};foreach($n in $child.Nested){$nested.Add($n)};foreach($s in $child.Signatures){$signatures.Add($s)};foreach($m in $child.ClientMatches){$clientMatches.Add($m)};if($child.Incomplete){$scanIncomplete=$true}
        }catch{$scanIncomplete=$true}finally{if($zip){$zip.Dispose()};if($memory){$memory.Dispose()};if($inputStream){$inputStream.Dispose()}}
    }
    return [pscustomobject]@{Flags=@($flags|Select-Object -Unique);Nested=@($nested|Select-Object -Unique);Signatures=$signatures.ToArray();ClientMatches=$clientMatches.ToArray();Incomplete=$scanIncomplete}
}
function Get-ModJarInfo {
    param([string]$Path,[long]$MaxBytes,[int]$Depth=0,[int]$MaxDepth=2,[object[]]$Catalog=@())
    $cacheKey="$Path|$((Get-Item -LiteralPath $Path -ErrorAction Stop).Length)|$((Get-Item -LiteralPath $Path).LastWriteTimeUtc.Ticks)|$Depth|$MaxDepth|$MaxBytes|$(@($Catalog|ForEach-Object{$_.sha256}) -join ',')"
    if($script:FileCache.ContainsKey($cacheKey)){return $script:FileCache[$cacheKey]}
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($file.Length -gt $MaxBytes){return [pscustomobject]@{Status='Skipped';File=$file.Name;Reason='Archive exceeds configured size limit';Id='';Name='';Authors='';ModLoader='Unknown';Flags=@();Nested=@()}}
    $zip=$null
    try{$zip=[IO.Compression.ZipFile]::OpenRead($Path)}catch{return [pscustomobject]@{Status='Corrupt';File=$file.Name;Reason=$_.Exception.Message;Id='';Name='';Authors='';ModLoader='Unknown';Flags=@();Nested=@()}}
    try{
        $flags=New-Object 'System.Collections.Generic.List[string]';$meta='';$id='';$name='';$authors='';$version='';$manifest='';$loader='Unknown';$budget=@{Remaining=268435456L}
        $fab=Read-ZipText $zip 'fabric.mod.json' 1048576 $budget
        if($fab){try{$j=$fab|ConvertFrom-Json -ErrorAction Stop;$id=[string]$j.id;$name=[string]$j.name;$version=[string]$j.version;$authors=(@($j.authors|ForEach-Object{if($_ -is [string]){$_}else{[string]$_.name}})-join ', ');$loader='Fabric'}catch{$flags.Add('Invalid Fabric metadata JSON')}}
        $q=Read-ZipText $zip 'quilt.mod.json' 1048576 $budget; if($q){$loader='Quilt';$meta+=$q;try{$qj=$q|ConvertFrom-Json -ErrorAction Stop;$id=[string]$qj.quilt_loader.id;$name=[string]$qj.quilt_loader.metadata.name;$version=[string]$qj.quilt_loader.version;$authors=(@($qj.quilt_loader.metadata.contributors.PSObject.Properties|ForEach-Object{$_.Name})-join ', ')}catch{$flags.Add('Invalid Quilt metadata JSON')}}
        foreach($n in @('META-INF/mods.toml','META-INF/neoforge.mods.toml','mcmod.info','META-INF/MANIFEST.MF')){$t=Read-ZipText $zip $n 1048576 $budget;if($t){$meta+="`n$t";if($n -match 'MANIFEST'){$manifest=$t};if($n -match 'neoforge'){$loader='NeoForge'}elseif($n -match 'mods.toml|mcmod.info'){$loader='Forge'}}}
        if(!$id){$id=Get-FirstCapture $meta 'modId\s*=\s*["\x27](?<value>[^"\x27]+)'}
        if(!$name){$name=Get-FirstCapture $meta '(?:displayName|name)\s*=\s*["\x27](?<value>[^"\x27]+)'}
        if(!$authors){$authors=Get-FirstCapture $meta 'authors\s*=\s*["\x27](?<value>[^"\x27]+)'}
        if(!$version){$version=Get-FirstCapture $meta 'version\s*=\s*["\x27](?<value>[^"\x27]+)'}
        if($id){$meta+="`n$id $name"}; $metaLower=$meta.ToLowerInvariant()
        foreach($brand in $script:KnownBrands){if([regex]::IsMatch($metaLower,'(?<![a-z0-9])'+[regex]::Escape($brand)+'(?![a-z0-9])')){$flags.Add("Known client identifier in metadata: $brand")}}
        $classCount=0;$classNames=New-Object 'System.Collections.Generic.List[string]';$nested=New-Object 'System.Collections.Generic.List[string]';$jarSignatureEntries=New-Object 'System.Collections.Generic.List[string]'
        foreach($entry in $zip.Entries){
            if($entry.FullName -match '(?i)^META-INF/[^/]+\.(SF|RSA|DSA|EC)$' -or $entry.FullName -match '(?i)^META-INF/SIG-[^/]+$'){$jarSignatureEntries.Add($entry.FullName)}
            if($entry.FullName.EndsWith('.class',[StringComparison]::OrdinalIgnoreCase)){$classCount++;if($classNames.Count -lt 10000){$classNames.Add(($entry.FullName.Substring(0,$entry.FullName.Length-6).Replace('/','.')))}}
        }
        $nestedScan=Get-ZipRecursiveEvidence $zip '' $Depth $MaxDepth $budget $Catalog
        foreach($nestedFlag in $nestedScan.Flags){$flags.Add($nestedFlag)}
        foreach($nestedPath in $nestedScan.Nested){$nested.Add($nestedPath)}
        $clientMatches=New-Object 'System.Collections.Generic.List[object]';foreach($match in (Get-ModClientMatches $id $name $classNames.ToArray())){$clientMatches.Add([pscustomobject]@{Path=$Path;Client=$match})};foreach($nestedMatch in $nestedScan.ClientMatches){$clientMatches.Add($nestedMatch)}
        $jarSignatureStatus=if($jarSignatureEntries.Count){'SignatureFilesPresentNotCryptographicallyVerified'}else{'NoJarsignerSignatureFilesFound'}
        $result=[pscustomobject]@{Status='Completed';File=$file.Name;Path=$Path;Id=$id;Name=$name;Authors=$authors;Version=$version;Manifest=$manifest;JarSignatureStatus=$jarSignatureStatus;JarSignatureEntries=$jarSignatureEntries.ToArray();ModLoader=$loader;ClassCount=$classCount;ClassNames=$classNames.ToArray();ClassNamesTruncated=($classCount -gt 10000);Flags=@($flags|Select-Object -Unique);ClientMatches=$clientMatches.ToArray();Nested=@($nested|Select-Object -Unique);NestedSignatures=$nestedScan.Signatures;NestedIncomplete=$nestedScan.Incomplete;ExpandedBytes=(268435456L-$budget.Remaining);Reason=''}
        $script:FileCache[$cacheKey]=$result;return $result
    }finally{$zip.Dispose()}
}
function Test-ZipArchiveCandidate {
    param([string]$Path,[long]$MaximumBytes=536870912)
    if([IO.Path]::GetExtension($Path) -ieq '.jar'){return $true}
    $stream=$null
    try {
        $item=Get-Item -LiteralPath $Path -ErrorAction Stop
        if($item.Length -lt 4 -or $item.Length -gt $MaximumBytes -or !(Test-LocalScanPath $Path)){return $false}
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $header=New-Object byte[] 4
        if($stream.Read($header,0,4) -ne 4){return $false}
        return ($header[0] -eq 0x50 -and $header[1] -eq 0x4b -and (($header[2] -eq 0x03 -and $header[3] -eq 0x04) -or ($header[2] -eq 0x05 -and $header[3] -eq 0x06) -or ($header[2] -eq 0x07 -and $header[3] -eq 0x08)))
    } catch { return $false } finally { if($stream){$stream.Dispose()} }
}
function Test-MinecraftModArchive {
    param([string]$Path,[long]$MaximumBytes=536870912)
    if([IO.Path]::GetExtension($Path) -ieq '.jar'){return $true}
    if(!(Test-ZipArchiveCandidate $Path $MaximumBytes)){return $false}
    $zip=$null
    try {
        $zip=[IO.Compression.ZipFile]::OpenRead($Path)
        foreach($entry in $zip.Entries){
            if($entry.FullName -match '^(?i)(fabric\.mod\.json|quilt\.mod\.json|META-INF/(mods\.toml|neoforge\.mods\.toml)|mcmod\.info)$'){return $true}
            if($entry.FullName -match '(?i)^(meteordevelopment/meteorclient/|net/ccbluex/liquidbounce/|net/wurstclient/)'){return $true}
        }
        return $false
    } catch { return $false } finally {if($zip){$zip.Dispose()}}
}
function Get-JavaProcessCandidates {
    return @(Get-Process -ErrorAction Stop | Where-Object {$_.ProcessName -match '^(javaw?|minecraft)$'})
}
function Get-CimMinecraftProcesses {
    # Keep the broad inventory query to low-sensitivity fields. Fetch command lines and
    # executable paths one Java PID at a time so a protected unrelated process cannot
    # abort the entire process inventory.
    $baseRows=@(Get-CimInstance -ClassName Win32_Process -Property Name,ProcessId,ParentProcessId -ErrorAction Stop)
    $rows=New-Object 'System.Collections.Generic.List[object]'
    foreach($row in $baseRows){
        $name=[string]$row.Name;$processId=[int]$row.ProcessId;$exe='';$command='';$commandStatus='Unavailable';$commandError='Not queried for non-Java processes.';$cimObject=$row
        if($name -match '(?i)^javaw?\.exe$'){
            try{$detail=Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -Property Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine -ErrorAction Stop | Select-Object -First 1
                if($detail){$exe=[string]$detail.ExecutablePath;$command=[string]$detail.CommandLine;$commandStatus=if($command){'Succeeded'}else{'Restricted'};$commandError=if($command){''}else{'CIM returned a blank command line for this PID.'};$cimObject=$detail}
            }catch{$commandError=$_.Exception.Message;$commandStatus=if($commandError -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'}}
            if(!$exe){try{$exe=[string](Get-Process -Id $processId -ErrorAction Stop).Path}catch{}}
        }
        $rows.Add([pscustomobject]@{Name=$name;ProcessId=$processId;ParentProcessId=$row.ParentProcessId;ExecutablePath=$exe;CommandLine=$command;CommandLineStatus=$commandStatus;CommandLineError=$commandError;CimObject=$cimObject})
    }
    return $rows.ToArray()
}
function Get-WmiMinecraftProcesses {
    $baseRows=@(Get-WmiObject -Class Win32_Process -Property Name,ProcessId,ParentProcessId -ErrorAction Stop)
    $rows=New-Object 'System.Collections.Generic.List[object]'
    foreach($row in $baseRows){$name=[string]$row.Name;$processId=[int]$row.ProcessId;$exe='';$command='';$commandStatus='Unavailable';$commandError='Not queried for non-Java processes.';$wmiObject=$row
        if($name -match '(?i)^javaw?\.exe$'){
            try{$detail=Get-WmiObject -Class Win32_Process -Filter "ProcessId = $processId" -Property Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine -ErrorAction Stop | Select-Object -First 1
                if($detail){$exe=[string]$detail.ExecutablePath;$command=[string]$detail.CommandLine;$commandStatus=if($command){'Succeeded'}else{'Restricted'};$commandError=if($command){''}else{'WMI returned a blank command line for this PID.'};$wmiObject=$detail}
            }catch{$commandError=$_.Exception.Message;$commandStatus=if($commandError -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'}}
            if(!$exe){try{$exe=[string](Get-Process -Id $processId -ErrorAction Stop).Path}catch{}}
        }
        $rows.Add([pscustomobject]@{Name=$name;ProcessId=$processId;ParentProcessId=$row.ParentProcessId;ExecutablePath=$exe;CommandLine=$command;CommandLineStatus=$commandStatus;CommandLineError=$commandError;CimObject=$wmiObject})
    }
    return $rows.ToArray()
}
function Test-ManagedMinecraftJavaPath {
    param([string]$Path)
    if([string]::IsNullOrWhiteSpace($Path)){return $false}
    return ($Path -match '(?i)\\\.minecraft\\runtime\\|\\Minecraft Launcher\\runtime\\|\\ModrinthApp\\meta\\java_versions\\|\\PrismLauncher\\runtimes\\|\\MultiMC\\runtime\\|\\CurseForge\\minecraft\\Install\\java\\')
}
function Get-MinecraftModuleIndicators {
    param([int]$ProcessId)
    try{$modules=@((Get-Process -Id $ProcessId -ErrorAction Stop).Modules);$known=@($modules|Where-Object{$_.ModuleName -match '(?i)^(lwjgl(?:_[a-z0-9]+)?|glfw|openal|openal32)\.dll$'});$nativePaths=@($known|Where-Object{$_.FileName -match '(?i)\\\.minecraft\\(?:versions|libraries|runtime)\\|\\ModrinthApp\\meta\\natives\\|\\PrismLauncher\\instances\\|\\MultiMC\\instances\\|\\CurseForge\\minecraft\\Instances\\|\\ATLauncher\\Instances\\|\\GDLauncher\\instances\\'}|ForEach-Object{[string]$_.FileName});$names=@($known|ForEach-Object{[string]$_.ModuleName});$confirmedSet=($names.Count -ge 3 -and $nativePaths.Count -ge 2);$detail="Accessible native indicators: $($names -join ', '); launcher-managed Minecraft native paths=$($nativePaths.Count).";return [pscustomobject]@{Status='Succeeded';IsMinecraftNativeSet=[bool]$confirmedSet;ModuleNames=$names;NativePaths=$nativePaths;Detail=$detail}}
    catch{$status=if($_.Exception.Message -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'};return [pscustomobject]@{Status=$status;IsMinecraftNativeSet=$false;ModuleNames=@();NativePaths=@();Detail=$_.Exception.Message}}
}
function Get-LauncherParentName {
    param([string]$Name)
    if($Name -match '(?i)^(MinecraftLauncher|Minecraft|PrismLauncher|MultiMC|ModrinthApp|CurseForge|Overwolf|ATLauncher|GDLauncher|LunarClient|Badlion|Feather)(?:\.exe)?$'){return $true}
    return $false
}
function Get-ToolhelpProcessInventory {
    if(-not ('McScanner.NativeProcessSnapshot' -as [type])){
        $nativeSource=@'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace McScanner {
  public sealed class ProcessRow { public int ProcessId { get; set; } public int ParentProcessId { get; set; } public string Name { get; set; } }
  public static class NativeProcessSnapshot {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct PROCESSENTRY32 {
      public uint dwSize; public uint cntUsage; public uint th32ProcessID; public IntPtr th32DefaultHeapID;
      public uint th32ModuleID; public uint cntThreads; public uint th32ParentProcessID; public int pcPriClassBase;
      public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string szExeFile;
    }
    [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool Process32First(IntPtr snapshot, ref PROCESSENTRY32 entry);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool Process32Next(IntPtr snapshot, ref PROCESSENTRY32 entry);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool CloseHandle(IntPtr handle);
    public static List<ProcessRow> Get() {
      var rows = new List<ProcessRow>(); IntPtr snap = CreateToolhelp32Snapshot(2, 0);
      if (snap == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
      try { var e = new PROCESSENTRY32(); e.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
        if (!Process32First(snap, ref e)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        do { rows.Add(new ProcessRow { ProcessId=(int)e.th32ProcessID, ParentProcessId=(int)e.th32ParentProcessID, Name=e.szExeFile }); }
        while (Process32Next(snap, ref e)); return rows;
      } finally { CloseHandle(snap); }
    }
  }
}
'@
        Add-Type -TypeDefinition $nativeSource -ErrorAction Stop
    }
    return @([McScanner.NativeProcessSnapshot]::Get())
}
function Get-ProcessOwnerToken {
    param([int]$ProcessId)
    if(-not ('McScanner.NativeProcessOwner' -as [type])){
        $source=@'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace McScanner {
  public static class NativeProcessOwner {
    [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    public static string GetName(int processId) {
      IntPtr process=OpenProcess(0x1000, false, processId);
      if(process==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
      try { IntPtr token; if(!OpenProcessToken(process, 0x0008, out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { using(WindowsIdentity identity=new WindowsIdentity(token)) return identity.Name; }
        finally { CloseHandle(token); }
      } finally { CloseHandle(process); }
    }
  }
}
'@
        Add-Type -TypeDefinition $source -ErrorAction Stop
    }
    try{$name=[McScanner.NativeProcessOwner]::GetName($ProcessId);return [pscustomobject]@{Status='Succeeded';Owner=$name;Detail='Process owner read from its existing access token using limited query rights.'}}
    catch{$status=if($_.Exception.Message -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'};return [pscustomobject]@{Status=$status;Owner=$null;Detail=$_.Exception.Message}}
}
function Get-ProcessInventory {
    $script:ProcessMethodResults=New-Object 'System.Collections.Generic.List[object]'
    $items=New-Object 'System.Collections.Generic.List[object]';$cimRows=@();$source='CIM'
    try{$cimRows=@(Get-CimMinecraftProcesses);Add-ProcessMethodResult $null 'CIM Win32_Process query' 'Succeeded' "Read process metadata for $($cimRows.Count) processes."}
    catch{
        $cimError=$_.Exception.Message;$status=if($cimError -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'}
        Add-ProcessMethodResult $null 'CIM Win32_Process query' $status $cimError
        Add-Coverage 'CIM process query' 'Partial' "CIM process metadata query failed ($status): $cimError"
        try{$cimRows=@(Get-WmiMinecraftProcesses);$source='WMI';Add-ProcessMethodResult $null 'WMI Win32_Process fallback' 'Succeeded' "Read process metadata for $($cimRows.Count) processes; command lines queried per Java PID."}
        catch{$wmiError=$_.Exception.Message;$wmiStatus=if($wmiError -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'};Add-ProcessMethodResult $null 'WMI Win32_Process fallback' $wmiStatus $wmiError;Add-Coverage 'WMI process fallback' 'Partial' $wmiError}
    }
    $processRows=@{}
    foreach($row in $cimRows){try{$processRows[[int]$row.ProcessId]=$row}catch{}}
    $toolhelpRows=@()
    try{$toolhelpRows=@(Get-ToolhelpProcessInventory);Add-ProcessMethodResult $null 'Windows Toolhelp process snapshot' 'Succeeded' "Read process names and parent process IDs for $($toolhelpRows.Count) processes without requesting command lines.";foreach($row in $toolhelpRows){if(!$processRows.ContainsKey([int]$row.ProcessId)){$processRows[[int]$row.ProcessId]=$row}}}
    catch{$toolhelpError=$_.Exception.Message;$toolhelpStatus=if($toolhelpError -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'};Add-ProcessMethodResult $null 'Windows Toolhelp process snapshot' $toolhelpStatus $toolhelpError}
    try{
        $candidates=@(Get-JavaProcessCandidates);Add-ProcessMethodResult $null 'Get-Process Java enumeration' 'Succeeded' "Enumerated $($candidates.Count) java/javaw process(es)."
    }catch{$candidates=@();$processError=$_.Exception.Message;$processStatus=if($processError -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'};Add-ProcessMethodResult $null 'Get-Process Java enumeration' $processStatus $processError;Add-Coverage 'Get-Process Java enumeration' 'Partial' $processError}
    $merged=@{}
    foreach($row in $cimRows){if([string]$row.Name -match '(?i)^(javaw?\.exe|minecraft\.exe)$'){$merged[[int]$row.ProcessId]=[pscustomobject]@{ProcessId=[int]$row.ProcessId;Name=[string]$row.Name;ExecutablePath=[string]$row.ExecutablePath;CommandLine=[string]$row.CommandLine;CommandLineStatus=[string]$row.CommandLineStatus;CommandLineError=[string]$row.CommandLineError;CimObject=$row.CimObject;ParentProcessId=if($row.ParentProcessId){[int]$row.ParentProcessId}else{$null};Source=$source}}}
    $detailQueries=0
    foreach($candidate in $candidates){$path='';$pathStatus='Failed';$startedAt=$null;try{$path=[string]$candidate.Path;if($path){$pathStatus='Succeeded'}else{$pathStatus='Restricted'}}catch{$pathStatus=if($_.Exception.Message -match '(?i)access|denied|permission'){'Restricted'}else{'Failed'}};try{$startedAt=$candidate.StartTime}catch{};if(!$startedAt){try{$startedAt=(Get-Process -Id ([int]$candidate.Id) -ErrorAction Stop).StartTime}catch{}}
        $pidValue=[int]$candidate.Id
        if(!$merged.ContainsKey($pidValue) -and $detailQueries -lt 100){$detailQueries++;$detail=$null;$detailSource='';$cimDetailError=''
            try{$detail=Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $pidValue" -Property Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine -ErrorAction Stop | Select-Object -First 1;if($detail){$detailSource='CIM';Add-ProcessMethodResult $pidValue 'CIM per-process metadata query' 'Succeeded' 'Retrieved targeted metadata for this Java PID after the broad inventory was unavailable.'}}
            catch{$cimDetailError=$_.Exception.Message;$cimStatus=if($cimDetailError -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'};Add-ProcessMethodResult $pidValue 'CIM per-process metadata query' $cimStatus $cimDetailError}
            if(!$detail){try{$detail=Get-WmiObject -Class Win32_Process -Filter "ProcessId = $pidValue" -Property Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine -ErrorAction Stop | Select-Object -First 1;if($detail){$detailSource='WMI';Add-ProcessMethodResult $pidValue 'WMI per-process metadata query' 'Succeeded' 'Retrieved targeted metadata for this Java PID after the broad inventory was unavailable.'}}
                catch{$wmiDetailError=$_.Exception.Message;$wmiStatus=if($wmiDetailError -match '(?i)access|denied|permission|unauthorized'){'Restricted'}else{'Failed'};Add-ProcessMethodResult $pidValue 'WMI per-process metadata query' $wmiStatus $wmiDetailError}}
            if($detail){$path=if($detail.ExecutablePath){[string]$detail.ExecutablePath}else{$path};$wrapper=[pscustomobject]@{Name=[string]$detail.Name;ProcessId=$pidValue;ParentProcessId=$detail.ParentProcessId;ExecutablePath=$path;CommandLine=[string]$detail.CommandLine;CommandLineStatus=if($detail.CommandLine){'Succeeded'}else{'Restricted'};CommandLineError=if($detail.CommandLine){''}else{'Targeted process query returned no command line.'};CimObject=$detail};$processRows[$pidValue]=$wrapper;$merged[$pidValue]=[pscustomobject]@{ProcessId=$pidValue;Name=[string]$detail.Name;ExecutablePath=$path;CommandLine=[string]$detail.CommandLine;CommandLineStatus=$wrapper.CommandLineStatus;CommandLineError=$wrapper.CommandLineError;CimObject=$detail;ParentProcessId=if($detail.ParentProcessId){[int]$detail.ParentProcessId}else{$null};Source=$detailSource}}
        }
        if(!$merged.ContainsKey($pidValue)){$queryResults=@($script:ProcessMethodResults|Where-Object{$_.ProcessId -eq $pidValue -and $_.Method -in @('CIM per-process metadata query','WMI per-process metadata query')});$denied=@($queryResults|Where-Object Status -eq 'Restricted');$cmdStatus=if($denied.Count){'Restricted'}else{'Unavailable'};$cmdError=if($queryResults.Count){($queryResults|ForEach-Object{"$($_.Method): $($_.Detail)"}) -join ' | '}else{'No process command-line source was available.'};$merged[$pidValue]=[pscustomobject]@{ProcessId=$pidValue;Name=([string]$candidate.ProcessName+'.exe');ExecutablePath=$path;CommandLine='';CommandLineStatus=$cmdStatus;CommandLineError=$cmdError;ParentProcessId=$null;Source='Get-Process'}}elseif(!$merged[$pidValue].ExecutablePath){$merged[$pidValue].ExecutablePath=$path}
        Add-ProcessMethodResult $pidValue 'Get-Process executable path' $pathStatus $(if($path){$path}else{'Executable path unavailable.'})
    }
    foreach($raw in @($merged.Values|Sort-Object ProcessId)){
        if(!$raw.ParentProcessId -and $processRows.ContainsKey([int]$raw.ProcessId) -and $processRows[[int]$raw.ProcessId].ParentProcessId){$raw.ParentProcessId=[int]$processRows[[int]$raw.ProcessId].ParentProcessId}
        $cmd=[string]$raw.CommandLine;$exe=[string]$raw.ExecutablePath;$identifiers=New-Object 'System.Collections.Generic.List[string]';$parentName='';$owner='';$ownerStatus='Unavailable';$gameDir=$null;$version=$null
        if($cmd){Add-ProcessMethodResult $raw.ProcessId 'Process command line' 'Succeeded' "Command line retrieved using $($raw.Source).";$identifiers.Add('Process command line')}else{$cmdStatus=if($raw.CommandLineStatus){$raw.CommandLineStatus}elseif($raw.Source -eq 'Get-Process'){'Unavailable'}else{'Restricted'};$cmdDetail=if($raw.CommandLineError){$raw.CommandLineError}else{'Process metadata was available, but command-line data was blank or inaccessible.'};Add-ProcessMethodResult $raw.ProcessId 'Process command line' $cmdStatus $cmdDetail}
        if($exe -and (Test-ManagedMinecraftJavaPath $exe)){$identifiers.Add('Launcher-managed Java executable path');Add-ProcessMethodResult $raw.ProcessId 'Java executable path classification' 'Succeeded' 'Executable is under a recognized Minecraft launcher runtime directory.'}elseif($exe){Add-ProcessMethodResult $raw.ProcessId 'Java executable path classification' 'NoMatch' 'Executable path is available but is not under a recognized Minecraft-managed runtime.'}else{Add-ProcessMethodResult $raw.ProcessId 'Java executable path classification' 'Unavailable' 'No executable path was readable.'}
        if($raw.ParentProcessId -and $processRows.ContainsKey([int]$raw.ParentProcessId)){$parentName=[string]$processRows[[int]$raw.ParentProcessId].Name;if(Get-LauncherParentName $parentName){$identifiers.Add('Recognized launcher parent');Add-ProcessMethodResult $raw.ProcessId 'Parent process' 'Succeeded' "Parent PID $($raw.ParentProcessId) is $parentName."}else{Add-ProcessMethodResult $raw.ProcessId 'Parent process' 'NoMatch' "Parent PID $($raw.ParentProcessId) is $parentName, not a recognized Minecraft launcher."}}elseif($raw.ParentProcessId){Add-ProcessMethodResult $raw.ProcessId 'Parent process' 'Partial' "Parent PID $($raw.ParentProcessId) was not present in the accessible process table."}else{Add-ProcessMethodResult $raw.ProcessId 'Parent process' 'Unavailable' 'Parent PID unavailable.'}
        if($raw.Source -eq 'CIM'){
            try{$ownerResult=Invoke-CimMethod -InputObject $processRows[$raw.ProcessId].CimObject -MethodName GetOwner -ErrorAction Stop;if($ownerResult.ReturnValue -eq 0){$owner=if($ownerResult.Domain){"$($ownerResult.Domain)\$($ownerResult.User)"}else{[string]$ownerResult.User};$ownerStatus='Succeeded';Add-ProcessMethodResult $raw.ProcessId 'CIM process owner' 'Succeeded' "Owner reported as $owner."}else{$ownerStatus='Restricted';Add-ProcessMethodResult $raw.ProcessId 'CIM process owner' 'Restricted' "GetOwner returned code $($ownerResult.ReturnValue)."}}catch{$ownerStatus=if($_.Exception.Message -match '(?i)access|denied|permission'){'Restricted'}else{'Failed'};Add-ProcessMethodResult $raw.ProcessId 'CIM process owner' $ownerStatus $_.Exception.Message}
        }elseif($raw.Source -eq 'WMI'){
            try{$ownerResult=Invoke-WmiMethod -InputObject $processRows[$raw.ProcessId].CimObject -Name GetOwner -ErrorAction Stop;if($ownerResult.ReturnValue -eq 0){$owner=if($ownerResult.Domain){"$($ownerResult.Domain)\$($ownerResult.User)"}else{[string]$ownerResult.User};$ownerStatus='Succeeded';Add-ProcessMethodResult $raw.ProcessId 'WMI process owner' 'Succeeded' "Owner reported as $owner."}else{$ownerStatus='Restricted';Add-ProcessMethodResult $raw.ProcessId 'WMI process owner' 'Restricted' "GetOwner returned code $($ownerResult.ReturnValue)."}}catch{$ownerStatus=if($_.Exception.Message -match '(?i)access|denied|permission'){'Restricted'}else{'Failed'};Add-ProcessMethodResult $raw.ProcessId 'WMI process owner' $ownerStatus $_.Exception.Message}
        }else{$ownerDenied=@($script:ProcessMethodResults|Where-Object{$_.ProcessId -eq $raw.ProcessId -and $_.Method -match '(?i)^(CIM|WMI) .*metadata query$' -and $_.Status -eq 'Restricted'}).Count -gt 0;$ownerStatus=if($ownerDenied){'Restricted'}else{'Unavailable'};Add-ProcessMethodResult $raw.ProcessId 'CIM process owner' $ownerStatus $(if($ownerDenied){'Owner could not be queried because CIM/WMI metadata access was denied for this process.'}else{'No CIM/WMI process object was available for owner lookup.'})}
        if(!$owner){$ownerToken=Get-ProcessOwnerToken $raw.ProcessId;if($ownerToken.Owner){$owner=$ownerToken.Owner;$ownerStatus=$ownerToken.Status};Add-ProcessMethodResult $raw.ProcessId 'Windows process owner token' $ownerToken.Status $ownerToken.Detail}
        $mcCommand=($cmd -match '(?i)net\.minecraft\.(client|bootstrap)|KnotClient|MinecraftLaunch|fabricmc\.loader|cpw\.mods\.bootstraplauncher|lunarclient|org\.quiltmc\.loader' -or ($cmd -match '(?i)--gameDir(?:=|\s)' -and $cmd -match '(?i)--assetsDir(?:=|\s)' -and $cmd -match '(?i)--version(?:=|\s)'))
        if($cmd){if($mcCommand){Add-ProcessMethodResult $raw.ProcessId 'Minecraft launch markers' 'Succeeded' 'Command line contains a Minecraft or supported loader launch marker.'}else{Add-ProcessMethodResult $raw.ProcessId 'Minecraft launch markers' 'NoMatch' 'Readable command line contains no recognized Minecraft launch marker.'}}else{Add-ProcessMethodResult $raw.ProcessId 'Minecraft launch markers' 'Unavailable' 'Cannot evaluate launch markers without command-line data.'}
        if($cmd){$gameDir=Get-FirstCapture $cmd '--gameDir(?:=|\s+)(?:"(?<value>[^"]+)"|(?<value>\S+))';$version=Get-FirstCapture $cmd '--version(?:=|\s+)(?:"(?<value>[^"]+)"|(?<value>\S+))'}
        $launcherParent=($parentName -and (Get-LauncherParentName $parentName));$managedPath=($exe -and (Test-ManagedMinecraftJavaPath $exe))
        $moduleEvidence=Get-MinecraftModuleIndicators $raw.ProcessId
        Add-ProcessMethodResult $raw.ProcessId 'Loaded Minecraft native module indicators' $moduleEvidence.Status $moduleEvidence.Detail
        if($moduleEvidence.IsMinecraftNativeSet){$identifiers.Add('Launcher-managed Java plus Minecraft LWJGL native module set')}
        $identified=$mcCommand -or ($launcherParent -and $managedPath) -or ($managedPath -and $moduleEvidence.IsMinecraftNativeSet)
        $detection=if($mcCommand){'Minecraft process identified by launch command line'}elseif($launcherParent -and $managedPath){'Minecraft process identified by launcher parent plus launcher-managed Java path'}elseif($managedPath -and $moduleEvidence.IsMinecraftNativeSet){'Minecraft process identified by launcher-managed Java path plus grouped Minecraft LWJGL natives'}else{'Java process candidate; insufficient independent Minecraft indicators'}
        $items.Add([pscustomobject]@{ProcessId=$raw.ProcessId;Name=$raw.Name;ExecutablePath=$exe;CommandLine=$cmd;GameDir=$gameDir;Version=$version;StartedAt=$startedAt;ParentProcessId=$raw.ParentProcessId;ParentName=$parentName;Owner=$owner;OwnerStatus=$ownerStatus;Identified=[bool]$identified;IdentificationMethods=@($identifiers.ToArray());ModuleIndicators=$moduleEvidence;Detection=$detection})
    }
    Add-Coverage 'Process inventory' 'Completed' "Combined $source process metadata with Get-Process Java executable paths; Java candidates=$($items.Count)."
    if(@($items|Where-Object Identified).Count){Add-ProcessMethodResult $null 'Multi-signal process classification' 'Succeeded' "Identified $(@($items|Where-Object Identified).Count) Minecraft process(es) without relying solely on process command-line access."}elseif($items.Count){Add-ProcessMethodResult $null 'Multi-signal process classification' 'NoMatch' 'Java processes were found but no process met the independent Minecraft identification threshold.'}
    return $items.ToArray()
}
function Get-JvmAgentArguments {
    param([string]$CommandLine)
    $agents=New-Object 'System.Collections.Generic.List[object]'
    if([string]::IsNullOrWhiteSpace($CommandLine)){return ,$agents.ToArray()}
    $pattern='(?i)(?:^|\s)(?<kind>-javaagent|-agentpath|-agentlib)(?::|=)(?:"(?<quoted>[^"]+)"|(?<plain>[^\s"]+))'
    foreach($m in [regex]::Matches($CommandLine,$pattern)){
        $raw=if($m.Groups['quoted'].Success){$m.Groups['quoted'].Value}else{$m.Groups['plain'].Value}
        $value=$raw -split '=',2
        $path=if($m.Groups['kind'].Value -ieq '-agentlib'){$null}else{$value[0]}
        $agents.Add([pscustomobject]@{Kind=$m.Groups['kind'].Value.ToLowerInvariant();Value=$raw;Path=$path})
    }
    return ,$agents.ToArray()
}
function Get-ModulePathClass {
    param([string]$Path)
    $windows=@($env:WINDIR)|Where-Object{$_};$program=@($env:ProgramFiles,${env:ProgramFiles(x86)})|Where-Object{$_}
    if(Test-PathWithin $Path $windows){return 'Windows'}
    if(Test-PathWithin $Path $program){return 'Program Files'}
    return 'Outside standard directories'
}
function Get-AuthenticodeInfo {
    param([string]$Path)
    if(!(Test-LocalScanPath $Path)){return [pscustomobject]@{Status='Unverifiable';Signer='';Detail='Non-local file path excluded from local-only analysis.'}}
    try{$s=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop;$signer='';if($s.SignerCertificate){$signer=$s.SignerCertificate.Subject};return [pscustomobject]@{Status=[string]$s.Status;Signer=$signer;Detail=''} }
    catch{return [pscustomobject]@{Status='Unverifiable';Signer='';Detail=$_.Exception.Message}}
}
function Get-SafeFiles {
    param([string[]]$Roots,[int]$Limit,[int]$Depth=4,[int]$MaxDirectories=5000)
    $seen=@{};$result=New-Object 'System.Collections.Generic.List[IO.FileInfo]';$queue=New-Object 'System.Collections.Generic.Queue[object]'
    foreach($root in $Roots){if(!$root){continue};if(!(Test-LocalScanPath $root)){Add-Coverage "Filesystem root: $root" 'Skipped' 'Non-local or unsupported storage is excluded; scanner analysis stays on local fixed/removable drives.';continue};try{$rootItem=Get-Item -LiteralPath $root -Force -ErrorAction Stop;if($rootItem.PSIsContainer -and !($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){$queue.Enqueue(@($root,0))}elseif($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint){Add-Coverage "Filesystem root: $root" 'Skipped' 'Reparse-point root excluded.'}}catch{Add-Coverage "Filesystem root: $root" 'Partial' $_.Exception.Message}}
    $visited=0
    while($queue.Count -gt 0 -and $result.Count -lt $Limit -and $visited -lt $MaxDirectories){$item=$queue.Dequeue();$dir=[string]$item[0];$level=[int]$item[1];$visited++
        if($script:ProgressPhaseName){Update-ScanProgress $script:ProgressPhaseName $script:ProgressPhasePercent "Enumerating $dir; $($result.Count) file(s) found (limit $Limit); $visited folder(s) visited" $result.Count $Limit}
        try{$entries=Get-DirectoryEntries -Path $dir}catch{Add-Coverage "Filesystem enumeration: $dir" 'Partial' $_.Exception.Message;continue}
        foreach($e in $entries){if($e.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
            if($e.PSIsContainer){if($level -lt $Depth){$queue.Enqueue(@($e.FullName,$level+1))};continue}
            $key=$e.FullName.ToLowerInvariant();if(!$seen.ContainsKey($key)){$seen[$key]=$true;$result.Add($e);if($result.Count -ge $Limit){break}}
        }
    }
    if($queue.Count -gt 0 -and $visited -ge $MaxDirectories){Add-Coverage 'Filesystem directory limit' 'Partial' "Stopped at the configured $MaxDirectories-directory limit; remaining folders were not visited."}
    return $result.ToArray()
}
function Get-DirectoryEntries {
    param([string]$Path)
    return @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
}
function Add-DiscoveredMinecraftProfile {
    param([System.Collections.Generic.List[object]]$Profiles,[hashtable]$Seen,[string]$Launcher,[string]$Name,[string]$GameDir,[object[]]$Processes=@())
    if([string]::IsNullOrWhiteSpace($GameDir)){return}
    if(!(Test-LocalScanPath $GameDir)){Add-Coverage "Profile path: $GameDir" 'Skipped' 'Non-local instance path excluded from local-only scanning.';return}
    try{$profileItem=Get-Item -LiteralPath $GameDir -Force -ErrorAction Stop;if(!$profileItem.PSIsContainer -or ($profileItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Add-Coverage "Profile path: $GameDir" 'Skipped' 'Profile root is a file or reparse point.';return}}catch{Add-Coverage "Profile path: $GameDir" 'Partial' $_.Exception.Message;return}
    try{$game=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($GameDir)).TrimEnd('\')}catch{Add-Coverage "Profile path: $GameDir" 'Partial' $_.Exception.Message;return}
    $key=$game.ToLowerInvariant();if($Seen.ContainsKey($key)){return};$Seen[$key]=$true
    $active=$false;$activePid=$null
    foreach($proc in $Processes){if($proc.GameDir){try{if([IO.Path]::GetFullPath($proc.GameDir).TrimEnd('\').Equals($game,[StringComparison]::OrdinalIgnoreCase)){$active=$true;$activePid=$proc.ProcessId}}catch{}}}
    $Profiles.Add([pscustomobject]@{Launcher=$Launcher;Name=$Name;GameDir=$game;Active=$active;ProcessId=$activePid})
}
function Test-MinecraftDirectoryMarker {
    param([string]$Path)
    foreach($marker in @('mods','versions','logs','launcher_profiles.json')){try{if(Test-Path -LiteralPath (Join-Path $Path $marker)){return $true}}catch{}}
    return $false
}
function Add-ConfiguredLauncherProfiles {
    param([System.Collections.Generic.List[object]]$Profiles,[hashtable]$Seen,[object[]]$Processes)
    $app=$script:UserFolders.AppData;$local=$script:UserFolders.LocalAppData
    $configs=New-Object 'System.Collections.Generic.List[object]'
    foreach($spec in @(
        @{Name='Prism';Base=$app;Relative='PrismLauncher\prismlauncher.cfg'},
        @{Name='Prism';Base=$local;Relative='PrismLauncher\prismlauncher.cfg'},
        @{Name='MultiMC';Base=$app;Relative='MultiMC\multimc.cfg'},
        @{Name='MultiMC';Base=$local;Relative='MultiMC\multimc.cfg'},
        @{Name='Modrinth';Base=$app;Relative='ModrinthApp\config.json'},
        @{Name='Modrinth';Base=$local;Relative='ModrinthApp\config.json'},
        @{Name='Modrinth';Base=$app;Relative='com.modrinth.theseus\config.json'}
    )){if($spec.Base){$configs.Add([pscustomobject]@{Name=$spec.Name;Path=(Join-Path $spec.Base $spec.Relative)})}}
    foreach($config in $configs){
        if(!(Test-Path -LiteralPath $config.Path -PathType Leaf)){continue}
        try{$raw=Get-Content -LiteralPath $config.Path -Raw -ErrorAction Stop;if($raw.Length -gt 1048576){Add-Coverage "Launcher config: $($config.Path)" 'Partial' 'Configuration exceeds 1 MiB read limit.';continue}}catch{Add-Coverage "Launcher config: $($config.Path)" 'Partial' $_.Exception.Message;continue}
        $values=New-Object 'System.Collections.Generic.List[string]'
        foreach($match in [regex]::Matches($raw,'(?i)"(?:profilesDir|profilesDirectory|instancesDir|instanceDir|instanceDirectory|gameDir|minecraftPath)"\s*:\s*"(?<value>(?:\\.|[^"])*)"')){$values.Add(($match.Groups['value'].Value -replace '\\"','"' -replace '\\\\','\'))}
        foreach($match in [regex]::Matches($raw,'(?im)^\s*(?:InstanceDir|InstanceDirectory|InstancePath|profilesDir|profilesDirectory|gameDir|MinecraftPath)\s*=\s*(?<value>[^\r\n]+)')){$values.Add($match.Groups['value'].Value.Trim().Trim('"'))}
        foreach($value in ($values|Select-Object -Unique)){
            if($value -match '^@|^(?:\{.*\})$'){continue}
            $candidate=[Environment]::ExpandEnvironmentVariables($value)
            if(!( [IO.Path]::IsPathRooted($candidate) )){$candidate=Join-Path (Split-Path -Parent $config.Path) $candidate}
            if(!(Test-Path -LiteralPath $candidate -PathType Container)){continue}
            if(Test-MinecraftDirectoryMarker $candidate){Add-DiscoveredMinecraftProfile $Profiles $Seen $config.Name (Split-Path $candidate -Leaf) $candidate $Processes;continue}
            try{$children=@(Get-ChildItem -LiteralPath $candidate -Directory -ErrorAction Stop | Select-Object -First 200)}catch{Add-Coverage "Configured instance root: $candidate" 'Partial' $_.Exception.Message;continue}
            foreach($child in $children){$game=$child.FullName;$minecraft=Join-Path $game 'minecraft';if(Test-Path -LiteralPath $minecraft -PathType Container){$game=$minecraft};if(Test-MinecraftDirectoryMarker $game){Add-DiscoveredMinecraftProfile $Profiles $Seen $config.Name $child.Name $game $Processes}}
        }
    }
}
function Get-MinecraftProfiles {
    param([object[]]$Processes=@())
    $profiles=New-Object 'System.Collections.Generic.List[object]';$seen=@{}
    $app=$script:UserFolders.AppData;$local=$script:UserFolders.LocalAppData;$user=$script:UserFolders.UserProfile;$docs=$script:UserFolders.Documents
    $specs=@(
        @{Launcher='Official/Vanilla';Path=$(if($app){Join-Path $app '.minecraft'});GameSub=''},
        @{Launcher='Modrinth';Path=$(if($app){Join-Path $app 'ModrinthApp\profiles'});Pattern='*';GameSub=''},
        @{Launcher='Modrinth';Path=$(if($local){Join-Path $local 'ModrinthApp\profiles'});Pattern='*';GameSub=''},
        @{Launcher='Modrinth';Path=$(if($app){Join-Path $app 'com.modrinth.theseus\profiles'});Pattern='*';GameSub=''},
        @{Launcher='Prism';Path=$(if($app){Join-Path $app 'PrismLauncher\instances'});Pattern='*';GameSub='minecraft'},
        @{Launcher='Prism';Path=$(if($local){Join-Path $local 'PrismLauncher\instances'});Pattern='*';GameSub='minecraft'},
        @{Launcher='Prism';Path=$(if($docs){Join-Path $docs 'PrismLauncher\instances'});Pattern='*';GameSub='minecraft'},
        @{Launcher='MultiMC';Path=$(if($app){Join-Path $app 'MultiMC\instances'});Pattern='*';GameSub='minecraft'},
        @{Launcher='MultiMC';Path=$(if($local){Join-Path $local 'MultiMC\instances'});Pattern='*';GameSub='minecraft'},
        @{Launcher='CurseForge';Path=$(if($user){Join-Path $user 'curseforge\minecraft\Instances'});Pattern='*';GameSub=''},
        @{Launcher='CurseForge';Path=$(if($docs){Join-Path $docs 'Curse\Minecraft\Instances'});Pattern='*';GameSub=''},
        @{Launcher='CurseForge';Path=$(if($app){Join-Path $app 'CurseForge\Minecraft\Instances'});Pattern='*';GameSub=''},
        @{Launcher='CurseForge';Path=$(if($local){Join-Path $local 'CurseForge\Minecraft\Instances'});Pattern='*';GameSub=''},
        @{Launcher='ATLauncher';Path=$(if($app){Join-Path $app 'ATLauncher\instances'});Pattern='*';GameSub='minecraft'},
        @{Launcher='ATLauncher';Path=$(if($local){Join-Path $local 'ATLauncher\instances'});Pattern='*';GameSub='minecraft'},
        @{Launcher='GDLauncher';Path=$(if($app){Join-Path $app 'gdlauncher_next\instances'});Pattern='*';GameSub=''},
        @{Launcher='GDLauncher';Path=$(if($local){Join-Path $local 'gdlauncher_next\instances'});Pattern='*';GameSub=''},
        @{Launcher='Technic';Path=$(if($app){Join-Path $app '.technic\modpacks'});Pattern='*';GameSub=''},
        @{Launcher='Feather';Path=$(if($user){Join-Path $user '.feather'});GameSub=''},
        @{Launcher='Lunar Client';Path=$(if($local){Join-Path $local 'LunarClient\installations'});Pattern='*';GameSub=''},
        @{Launcher='Badlion Client';Path=$(if($app){Join-Path $app 'Badlion Client\jre'});Pattern='*';GameSub=''}
    )
    foreach($spec in $specs){
        if(!$spec.Path){continue}
        try{$specRoot=Get-Item -LiteralPath $spec.Path -Force -ErrorAction Stop;if(!$specRoot.PSIsContainer -or ($specRoot.Attributes -band [IO.FileAttributes]::ReparsePoint)){Add-Coverage "Launcher profile root: $($spec.Path)" 'Skipped' 'Profile root is not a normal directory.';continue}}catch{continue}
        if($profiles.Count -ge 500){Add-Coverage 'Launcher profile discovery' 'Partial' 'Configured profile limit of 500 reached.';return $profiles.ToArray()}
        $dirs=@()
        if($spec.ContainsKey('Pattern')){try{$dirs=@(Get-ChildItem -LiteralPath $spec.Path -Directory -Filter $spec.Pattern -ErrorAction Stop | Where-Object { !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Select-Object -First 500)}catch{Add-Coverage "Launcher profile: $($spec.Path)" 'Partial' $_.Exception.Message;$dirs=@()}}
        else{try{$dirs=@(Get-Item -LiteralPath $spec.Path -ErrorAction Stop)}catch{Add-Coverage "Launcher profile: $($spec.Path)" 'Partial' $_.Exception.Message;$dirs=@()}}
        foreach($dir in $dirs){$game=$dir.FullName;if($spec.GameSub){$candidate=Join-Path $game $spec.GameSub;if(Test-Path -LiteralPath $candidate -PathType Container){$game=$candidate}elseif(!(Test-MinecraftDirectoryMarker $game)){continue}}
            Add-DiscoveredMinecraftProfile $profiles $seen $spec.Launcher $dir.Name $game $Processes
        }
    }
    $configPaths=@();if($app){$configPaths+=@((Join-Path $app '.minecraft\launcher_profiles.json'),(Join-Path $app 'Minecraft Launcher\launcher_profiles.json'))}
    foreach($config in $configPaths){
        if(!(Test-Path -LiteralPath $config -PathType Leaf)){continue}
        try{$settings=Get-Content -LiteralPath $config -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop}catch{Add-Coverage "Launcher config: $config" 'Partial' $_.Exception.Message;continue}
        foreach($property in @($settings.profiles.PSObject.Properties)){
            $item=$property.Value
            if($item.gameDir){$configured=[Environment]::ExpandEnvironmentVariables([string]$item.gameDir);if(!( [IO.Path]::IsPathRooted($configured) )){$configured=Join-Path (Join-Path $app '.minecraft') $configured};Add-DiscoveredMinecraftProfile $profiles $seen 'Official Launcher' ([string]$item.name) $configured $Processes}
        }
    }
    Add-ConfiguredLauncherProfiles $profiles $seen $Processes
    foreach($proc in $Processes){if($proc.GameDir){Add-DiscoveredMinecraftProfile $profiles $seen 'Detected custom' (Split-Path $proc.GameDir -Leaf) $proc.GameDir $Processes}}
    return $profiles.ToArray()
}
function Resolve-ModrinthProfileFromLaunchLog {
    param([object[]]$Processes,[object[]]$Profiles,[int]$ToleranceSeconds=180)
    foreach($process in $Processes|Where-Object{$_.Identified -and !$_.GameDir}){
        if(!$process.StartedAt){Add-ProcessMethodResult $process.ProcessId 'Modrinth active profile log correlation' 'Unavailable' 'Process start time is unavailable; no profile was selected by recency.';continue}
        $modrinthProfiles=@($Profiles|Where-Object{$_.Launcher -eq 'Modrinth'});if(!$modrinthProfiles.Count){Add-ProcessMethodResult $process.ProcessId 'Modrinth active profile log correlation' 'Unavailable' 'No Modrinth profile directory was discovered, so the active instance and its mods could not be correlated.';continue}
        $logMatches=New-Object 'System.Collections.Generic.List[object]'
        $unreadableLogs=0
        foreach($profile in $modrinthProfiles){
            $log=Join-Path $profile.GameDir 'logs\latest.log'
            if(!(Test-Path -LiteralPath $log -PathType Leaf)){continue}
            try{$item=Get-Item -LiteralPath $log -ErrorAction Stop;if($item.LastWriteTime -lt $process.StartedAt.AddSeconds(-$ToleranceSeconds)){continue};$head=Get-Content -LiteralPath $log -TotalCount 100 -ErrorAction Stop;$launchLine=@($head|Where-Object{$_ -match '(?i)\[(?<time>\d{2}:\d{2}:\d{2})\].*Loading Minecraft .+ with (Fabric|Forge|NeoForge|Quilt) Loader'}|Select-Object -First 1);if(!$launchLine.Count){continue};$timeCapture=[regex]::Match([string]$launchLine[0],'\[(?<time>\d{2}:\d{2}:\d{2})\]');$clock=[datetime]::ParseExact($timeCapture.Groups['time'].Value,'HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture);$logStart=$item.LastWriteTime.Date.Add($clock.TimeOfDay);$dateCandidates=@($logStart.AddDays(-1),$logStart,$logStart.AddDays(1));$deltas=@($dateCandidates|ForEach-Object{[Math]::Abs(($_-$process.StartedAt).TotalSeconds)});$delta=($deltas|Measure-Object -Minimum).Minimum;if($delta -gt $ToleranceSeconds){continue};$logMatches.Add([pscustomobject]@{Profile=$profile;Delta=$delta;Log=$log;LaunchLine=[string]$launchLine[0]})}catch{$unreadableLogs++;continue}
        }
        if($logMatches.Count -eq 1){$hit=$logMatches[0];$profile=$hit.Profile
            foreach($field in @(@('GameDir',$profile.GameDir),@('ActiveProfile',$profile.Name),@('ProfileLauncher','Modrinth'),@('ProfileStatus','MatchedByLaunchLog'),@('ProfileEvidence',$hit.Log),@('ProfileEvidenceDeltaSeconds',[Math]::Round($hit.Delta,1)))){$process|Add-Member -NotePropertyName $field[0] -NotePropertyValue $field[1] -Force}
            $profile.Active=$true;$profile.ProcessId=$process.ProcessId
            if(!$process.Version){$process|Add-Member -NotePropertyName Version -NotePropertyValue (Get-FirstCapture $hit.LaunchLine 'Loading Minecraft (?<value>[^ ]+) with') -Force}
            Add-ProcessMethodResult $process.ProcessId 'Modrinth active profile log correlation' 'Succeeded' ("Uniquely matched profile '{0}' because the Minecraft loader startup timestamp in its latest.log was {1:N1}s from the process start time; gameDir={2}. This associates installed mods with the process but does not prove each mod was loaded." -f $profile.Name,$hit.Delta,$profile.GameDir)
            $loaderInventory=Get-LoaderLogModInventory $hit.Log
            $process|Add-Member -NotePropertyName RuntimeLogStatus -NotePropertyValue $loaderInventory.Status -Force
            $process|Add-Member -NotePropertyName RuntimeLogMods -NotePropertyValue @($loaderInventory.Mods) -Force
            $process|Add-Member -NotePropertyName RuntimeLogExpected -NotePropertyValue $loaderInventory.Expected -Force
            $process|Add-Member -NotePropertyName RuntimeLogDetail -NotePropertyValue $loaderInventory.Detail -Force
            Add-ProcessMethodResult $process.ProcessId 'Minecraft loader mod-list log' $loaderInventory.Status $loaderInventory.Detail
        }elseif($logMatches.Count -gt 1){Add-ProcessMethodResult $process.ProcessId 'Modrinth active profile log correlation' 'Partial' ("{0} Modrinth profile logs were within the process-start window; ambiguous correlation was not applied." -f $logMatches.Count)}elseif($unreadableLogs){Add-ProcessMethodResult $process.ProcessId 'Modrinth active profile log correlation' 'Partial' ("Could not read {0} recent profile log(s); the active instance remains uncorrelated." -f $unreadableLogs)}else{Add-ProcessMethodResult $process.ProcessId 'Modrinth active profile log correlation' 'NoMatch' 'No unique Modrinth Minecraft startup log matched the process start time; profile and instance mods remain uncorrelated.'}
    }
}
function Get-LoaderLogModInventory {
    param([string]$Path,[int]$LineLimit=5000,[long]$MaximumBytes=2097152)
    if(!(Test-Path -LiteralPath $Path -PathType Leaf)){return [pscustomobject]@{Status='Unavailable';Expected=$null;Mods=@();Detail='Active profile latest.log is unavailable.'}}
    try{$file=Get-Item -LiteralPath $Path -ErrorAction Stop;if($file.Length -gt $MaximumBytes){return [pscustomobject]@{Status='Partial';Expected=$null;Mods=@();Detail="Active profile latest.log exceeds the $MaximumBytes-byte bounded read limit."}}}catch{return [pscustomobject]@{Status='Restricted';Expected=$null;Mods=@();Detail=$_.Exception.Message}}
    try{$lines=@(Get-Content -LiteralPath $Path -TotalCount $LineLimit -ErrorAction Stop)}catch{return [pscustomobject]@{Status='Restricted';Expected=$null;Mods=@();Detail=$_.Exception.Message}}
    $header=-1;$expected=$null
    for($i=0;$i -lt $lines.Count;$i++){$m=[regex]::Match([string]$lines[$i],'(?i)Loading\s+(?<count>\d+)\s+mods:');if($m.Success){$header=$i;$expected=[int]$m.Groups['count'].Value;break}}
    if($header -lt 0){return [pscustomobject]@{Status='Unavailable';Expected=$null;Mods=@();Detail='No structured loader mod-list header was found in the bounded log prefix.'}}
    $mods=New-Object 'System.Collections.Generic.List[object]';$terminated=$false
    for($i=$header+1;$i -lt $lines.Count;$i++){$line=[string]$lines[$i];if($line -match '^\s*[|\\]--\s+'){continue};$m=[regex]::Match($line,'^\s*-\s+(?<id>[A-Za-z0-9_.-]+)\s+(?<version>.+?)\s*$');if(!$m.Success){if($mods.Count){$terminated=$true;break};continue};$mods.Add([pscustomobject]@{Id=$m.Groups['id'].Value;Version=$m.Groups['version'].Value.Trim();Line=$line.Trim()})}
    $status=if(!$mods.Count -or !$terminated){'Partial'}else{'Succeeded'}
    $detail="Parsed $($mods.Count) top-level loader mod record(s); loader reported $expected total mod/dependency entries from $Path. Nested dependencies are not counted as installed JARs. Log entries indicate loader discovery, not JVM class loading."
    return [pscustomobject]@{Status=$status;Expected=$expected;Mods=$mods.ToArray();Detail=$detail}
}
function Get-LoaderLogModCorrelation {
    param([string]$ModId,[string]$Version,[object]$Profile,[object[]]$Processes)
    if(!$Profile -or !$Profile.Active -or !$Profile.ProcessId){return [pscustomobject]@{Status='Unavailable';Evidence='No identified active Minecraft profile is associated with this JAR.'}}
    $process=$Processes|Where-Object{$_.ProcessId -eq $Profile.ProcessId}|Select-Object -First 1
    if(!$process -or $process.RuntimeLogStatus -ne 'Succeeded'){return [pscustomobject]@{Status='Unavailable';Evidence=$(if($process){$process.RuntimeLogDetail}else{'The active process has no parsed loader mod list.'})}}
    $matches=@($process.RuntimeLogMods|Where-Object{[string]$_.Id -ieq $ModId})
    if(!$matches.Count){return [pscustomobject]@{Status='NotListed';Evidence="Mod id '$ModId' was not in the parsed loader list. This does not prove it was not loaded."}}
    $match=$matches|Where-Object{[string]$_.Version -ieq $Version}|Select-Object -First 1
    if($match){return [pscustomobject]@{Status='IdAndVersionListed';Evidence="Loader startup log lists id '$ModId' version '$($match.Version)': $($match.Line)"}}
    return [pscustomobject]@{Status='IdListedVersionDiffers';Evidence="Loader startup log lists id '$ModId' with version(s) $((@($matches|ForEach-Object{$_.Version}) -join ', ')); installed metadata version is '$Version'. A log or metadata mismatch needs manual review and is not proof of tampering."}
}
function Get-VerifiedSignatureCatalog {
    param([string]$Path=$script:SignatureCatalogPath)
    if(!(Test-Path -LiteralPath $Path -PathType Leaf)){return @()}
    try{$catalog=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop}catch{Add-Finding 'Scan Incomplete' 'Signature catalog could not be read' $_.Exception.Message $Path $null;return @()}
    $valid=New-Object 'System.Collections.Generic.List[object]';$rejected=0;$seenHashes=@{}
    foreach($entry in $catalog.entries){
        $recordValid=Test-VerifiedSignatureRecord $entry
        if(!$recordValid -or $seenHashes.ContainsKey(([string]$entry.sha256).ToLowerInvariant())){$rejected++;continue}
        $seenHashes[([string]$entry.sha256).ToLowerInvariant()]=$true
        $valid.Add($entry)
    }
    if($rejected){Add-Finding 'Scan Incomplete' 'Untrusted signature catalog entries ignored' "$rejected record(s) failed schema, provenance host, or verification-status checks." $Path $null}
    return $valid.ToArray()
}
function Get-ClientDetectionCatalog {
    param([string]$Path=$script:SignatureCatalogPath)
    try {
        $document=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $valid=New-Object 'System.Collections.Generic.List[object]'
        $seen=@{}
        foreach($client in @($document.clients)) {
            if(!$client.name -or !$client.category -or $seen.ContainsKey([string]$client.name)){continue}
            $seen[[string]$client.name]=$true
            $valid.Add($client)
        }
        return $valid.ToArray()
    } catch { return @() }
}
function Get-ModClientMatches {
    param([string]$Id,[string]$Name,[string[]]$ClassNames,[object[]]$Catalog=$script:ClientCatalog)
    $matches=New-Object 'System.Collections.Generic.List[object]'
    foreach($client in $Catalog) {
        $evidence=New-Object 'System.Collections.Generic.List[string]'
        if($Id -and @($client.metadataIds) -contains $Id){$evidence.Add("Fabric metadata id '$Id'")}
        if($Name -and @($client.metadataNames) -contains $Name){$evidence.Add("exact metadata name '$Name'")}
        foreach($className in $ClassNames) {
            foreach($prefix in @($client.classPrefixes)) {
                if($className -eq $prefix -or $className.StartsWith(($prefix+'.'),[StringComparison]::Ordinal)){$evidence.Add("class package '$prefix'");break}
            }
        }
        if($evidence.Count){$matches.Add([pscustomobject]@{Name=$client.name;Category=$client.category;Evidence=@($evidence|Select-Object -Unique);Sources=@($client.evidenceSources);MinecraftVersions=$client.supportedMinecraftVersions;SignatureStatus=$client.signatureStatus})}
    }
    return $matches.ToArray()
}
function Test-VerifiedSignatureRecord {
    param($Entry)
    if(!$Entry -or $Entry.status -notin @('IndependentlyVerified','OfficialSourceHashed') -or $Entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or !$Entry.evidence -or !$Entry.artifactVersion){return $false}
    $uri=$null;if(![Uri]::TryCreate([string]$Entry.source,[UriKind]::Absolute,[ref]$uri)){return $false}
    if($uri.Scheme -ne 'https' -or $script:TrustedSignatureHosts -notcontains $uri.Host.ToLowerInvariant()){return $false}
    return $true
}
function Find-SignatureMatch {
    param([string]$Path,[object[]]$Catalog)
    if(!$Catalog.Count){return $null}
    if(!(Test-LocalScanPath $Path)){return $null}
    $hashResult=Get-CachedSha256 $Path
    if($hashResult.Status -ne 'Completed'){return $null}
    return Find-SignatureMatchByHash $hashResult.Hash $Catalog
}
function Find-SignatureMatchByHash {
    param([string]$Hash,[object[]]$Catalog)
    foreach($entry in $Catalog){if((Test-VerifiedSignatureRecord $entry) -and $entry.sha256 -ieq $Hash){return $entry}}
    return $null
}
function Get-VerifiedRuntimeModuleEvidence {
    param([string]$Hash,[object]$Process,[object[]]$Catalog)
    if(!$Hash -or !$Process){return $null}
    $signature=Find-SignatureMatchByHash $Hash $Catalog
    if(!$signature){return $null}
    $identified=([bool]$Process.Identified)
    return [pscustomobject]@{Signature=$signature;Category=$(if($identified){'Verified Runtime Association'}else{'Verified Artifact'});ProcessId=$Process.ProcessId;RuntimeAssociation=$(if($identified){'Exact verified artifact hash observed in a loaded module of the identified Minecraft process'}else{'Exact verified artifact hash observed in a Java process whose Minecraft identity is unconfirmed'});ProcessIdentification=$identified}
}
function Add-LogFindings {
    param([object[]]$Profiles,[int]$FileLimit)
    $roots=New-Object 'System.Collections.Generic.List[string]'
    foreach($profile in $Profiles){foreach($sub in @('logs','crash-reports')){$p=Join-Path $profile.GameDir $sub;if(Test-Path -LiteralPath $p -PathType Container){$roots.Add($p)}}}
    if(!$roots.Count){Add-Coverage 'Minecraft logs' 'Skipped' 'No discovered game directory had logs or crash-reports folders';return}
    $logs=@(Get-SafeFiles $roots.ToArray() ([Math]::Min($FileLimit,400)) 2 | Where-Object {$_.Extension -match '(?i)^\.(log|txt)$' -and $_.Length -le 8388608 -and $_.LastWriteTime -gt (Get-Date).AddDays(-30)} | Sort-Object LastWriteTime -Descending | Select-Object -First 200)
    $logIndex=0
    foreach($log in $logs){$logIndex++;Add-ScannedFile $log.FullName;Update-ScanProgress 'Logs and configuration inspection' (30*$logIndex/[Math]::Max(1,$logs.Count)) "Reading log $($log.Name)" $logIndex $logs.Count;try{$text=Get-Content -LiteralPath $log.FullName -Raw -ErrorAction Stop;foreach($brand in $script:KnownBrands){if([regex]::IsMatch($text,'(?i)(?<![a-z0-9])'+[regex]::Escape($brand)+'(?![a-z0-9])')){Add-Finding 'Needs Manual Review' 'Known client term in Minecraft log' "Log mentions '$brand'; log text can contain arbitrary user or server content and is not proof of a loaded client." $log.FullName $null;break}}}catch{Add-Finding 'Scan Incomplete' 'Minecraft log could not be read' $_.Exception.Message $log.FullName $null}}
    Add-Coverage 'Minecraft logs' 'Completed' "Inspected $(@($logs).Count) recent bounded log files"
}
function Add-ConfigurationFindings {
    param([object[]]$Profiles,[int]$Limit)
    $roots=New-Object 'System.Collections.Generic.List[string]'
    foreach($profile in $Profiles){$config=Join-Path $profile.GameDir 'config';if(Test-Path -LiteralPath $config -PathType Container){$roots.Add($config)}}
    if(!$roots.Count){Add-Coverage 'Minecraft client configuration' 'Skipped' 'No discovered profile has a config folder.';return}
    $configs=@(Get-SafeFiles -Roots $roots.ToArray() -Limit $Limit -Depth 3 | Where-Object {$_.Extension -match '(?i)^\.(json|toml|cfg|properties|conf|txt)$' -and $_.Length -le 524288})
    $index=0
    foreach($file in $configs){$index++;Add-ScannedFile $file.FullName;Update-ScanProgress 'Logs and configuration inspection' (30+(70*$index/[Math]::Max(1,$configs.Count))) "Reviewing config $($file.Name)" $index $configs.Count
        try{$content=Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            if($content -match '(?i)(?:-javaagent|-agentpath|-agentlib)') {Add-Finding 'Needs Manual Review' 'JVM agent option referenced in Minecraft configuration' 'Configuration contains a Java agent option. The setting is a review lead; it does not prove that the referenced agent is active or malicious.' $file.FullName $null}
            foreach($brand in $script:KnownBrands){if([regex]::IsMatch($content,'(?i)(?<![a-z0-9])'+[regex]::Escape($brand)+'(?![a-z0-9])')){Add-Finding 'Needs Manual Review' 'Known client term in Minecraft configuration' "Configuration mentions '$brand'; the content may be benign and requires manual review." $file.FullName $null;break}}
        }catch{Add-Finding 'Scan Incomplete' 'Minecraft configuration could not be read' $_.Exception.Message $file.FullName $null}
    }
    Add-Coverage 'Minecraft client configuration' $(if($configs.Count -ge $Limit){'Partial'}else{'Completed'}) "Inspected $($configs.Count) bounded config/text file(s) from discovered instance config folders."
}
function Resolve-ReportDirectory {
    param([string]$Preferred)
    $choices=New-Object 'System.Collections.Generic.List[string]'
    $localReports=if($script:UserFolders.LocalAppData){Join-Path $script:UserFolders.LocalAppData 'MinecraftCheatScanner\Reports'}else{$null}
    $tempReports=if($script:UserFolders.Temp){Join-Path $script:UserFolders.Temp 'MinecraftCheatScanner-Reports'}else{Join-Path ([IO.Path]::GetTempPath()) 'MinecraftCheatScanner-Reports'}
    foreach($path in @($Preferred,$localReports,$tempReports)){if($path -and !$choices.Contains($path)){$choices.Add($path)}}
    $errors=New-Object 'System.Collections.Generic.List[string]'
    foreach($path in $choices){try{if(!(Test-LocalScanPath $path)){throw 'Non-local report paths are not used.'};if(!(Test-Path -LiteralPath $path -PathType Container)){New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop|Out-Null};$probe=Join-Path $path ('.scanner-write-test-'+[guid]::NewGuid().ToString('N'));[IO.File]::WriteAllText($probe,'ok');[IO.File]::Delete($probe);if($path -ne $Preferred){Write-Warning "Preferred report folder was unavailable; using '$path'."};return $path}catch{$errors.Add("$path : $($_.Exception.Message)")}}
    throw ('No writable report directory was found. '+($errors -join ' | '))
}
function Encode-HtmlValue {
    param($Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}
function Get-ReportStamp {
    param([string]$Directory)
    $base=(Get-Date).ToString('yyyy-MM-dd_HHmmss_fff');$stamp=$base;$suffix=1
    while((Test-Path -LiteralPath (Join-Path $Directory "Minecraft-Cheat-Scan-$stamp.txt")) -or (Test-Path -LiteralPath (Join-Path $Directory "Minecraft-Cheat-Scan-$stamp.html")) -or (Test-Path -LiteralPath (Join-Path $Directory "Minecraft-Cheat-Scan-$stamp.json"))){$stamp="$base-$suffix";$suffix++}
    return $stamp
}
function Write-TextReport {
    param($Report,[string]$Path)
    $lines=New-Object 'System.Collections.Generic.List[string]'
    $lines.Add("Minecraft Cheat Scanner v$($Report.ScannerVersion)")
    $lines.Add(('='*72));$lines.Add("Scan date/time: $($Report.Timestamp)");$lines.Add("Windows user: $($Report.UserName)");$lines.Add("Mode: $($Report.Mode)");$lines.Add("Duration: $($Report.DurationSeconds) seconds");$lines.Add("Status: $($Report.Status)");$lines.Add("Files analyzed: $($Report.FilesAnalyzed)");$lines.Add("SHA-256 hashes calculated: $($Report.HashesCalculated)");$lines.Add("JAR/ZIP candidates analyzed: $($Report.JarsAnalyzed)");$lines.Add("Loaded DLL modules inspected: $($Report.DllModulesInspected)");$lines.Add("Java/Minecraft process candidates: $($Report.MinecraftProcessCandidates)");$lines.Add("Identified Minecraft processes: $($Report.IdentifiedMinecraftProcesses)");$lines.Add("Minecraft installations discovered: $(@($Report.Profiles).Count)");$lines.Add("Final summary: $($Report.Summary)")
    $lines.Add('');$lines.Add('MINECRAFT INSTALLATIONS AND PROFILES');$lines.Add(('='*72))
    if(@($Report.Profiles).Count){foreach($p in $Report.Profiles){$lines.Add("[$($p.Launcher)] $($p.Name) | active=$($p.Active) | process=$($p.ProcessId) | $($p.GameDir)")}}else{$lines.Add('No Minecraft installation/profile was found in the checked locations.')}
    $lines.Add('');$lines.Add('PROCESSES AND JAVA');$lines.Add(('='*72))
    foreach($p in $Report.Processes){$lines.Add("PID $($p.ProcessId) $($p.Name) | identified=$($p.Identified) | detection=$($p.Detection) | gameDir=$($p.GameDir) | profile=$($p.ActiveProfile) [$($p.ProfileLauncher), $($p.ProfileStatus)] | owner=$($p.Owner) [$($p.OwnerStatus)] | started=$($p.StartedAt) | executable=$($p.ExecutablePath)")}
    $lines.Add('');$lines.Add('PROCESS IDENTIFICATION METHOD RESULTS');$lines.Add(('='*72))
    if(@($Report.ProcessIdentificationMethods).Count){foreach($method in $Report.ProcessIdentificationMethods){$pidText=if($null -eq $method.ProcessId){'global'}else{"PID $($method.ProcessId)"};$lines.Add("$pidText | $($method.Method) | $($method.Status) | $($method.Detail)")}}else{$lines.Add('No process identification methods were recorded.')}
    foreach($j in $Report.Java){$lines.Add("Java PID $($j.ProcessId): status=$($j.Status), version=$($j.Version), vendor=$($j.Vendor), architecture=$($j.Architecture) [$($j.ArchitectureStatus)], owner=$($j.Owner) [$($j.OwnerStatus)], path=$($j.Executable)");if($j.Detail){$lines.Add("  $($j.Detail)")}}
    $lines.Add('');$lines.Add('RUNTIME DIAGNOSTICS');$lines.Add(('='*72))
    foreach($r in $Report.Runtime){$lines.Add(($r|ConvertTo-Json -Depth 6 -Compress))}
    $lines.Add('');$lines.Add('MOD ARTIFACT INVENTORY AND AUTHENTICITY');$lines.Add(('='*72))
    foreach($a in $Report.ModArtifacts){$lines.Add("$($a.Path) | id=$($a.ModId) | version=$($a.Version) | loader=$($a.ModLoader) | declared author=$($a.Authors) | SHA-256=$($a.SHA256) | authenticity=$($a.Authenticity) | JAR signature=$($a.JarSignatureStatus) | profile=$($a.Profile) [$($a.ProfileLauncher)] | loader-log=$($a.RuntimeLogStatus): $($a.RuntimeLogEvidence) | runtime=$($a.RuntimeAssociation)");if($a.Signature){$lines.Add("  Reference: $($a.Signature.source) | $($a.Signature.evidence)")}elseif($a.Authenticity -eq 'UNKNOWN'){$lines.Add('  No trusted reference digest is catalogued; an unknown digest or metadata mismatch is not evidence of tampering.')};if($a.JarSignatureEntries.Count){$lines.Add("  Signature files present (not verified): $($a.JarSignatureEntries -join ', ')")};if($a.ClientIdentifiers.Count){$lines.Add("  Client identifiers: $($a.ClientIdentifiers -join ', ')")}}
    $lines.Add('');$lines.Add('CLIENT DETECTION COVERAGE');$lines.Add(('='*72))
    foreach($client in $Report.ClientCoverage){$lines.Add("$($client.name) | $($client.category) | hash=$($client.verifiedSha256Available) | metadata=$(@($client.metadataIds).Count -gt 0) | runtimeIndicators=$(@($client.runtimeIndicators).Count -gt 0) | status=$($client.signatureStatus)")}
    if(@($Report.Findings).Count){$lines.Add('');$lines.Add('DETECTED CHEATS');$lines.Add(('='*72));foreach($line in (Get-CheatFindingDisplayLines $Report.Findings)){$lines.Add($line)}}
    $lines.Add('');$lines.Add('CHECK COVERAGE');$lines.Add(('='*72))
    foreach($c in $Report.Coverage){$lines.Add("[$($c.Status)] $($c.Check): $($c.Detail)")}
    $lines.Add('');$lines.Add('LIMITATIONS');$lines.Add(('='*72));foreach($item in $Report.Limitations){$lines.Add("- $item")}
    $lines|Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}
function Write-HtmlReport {
    param($Report,[string]$ReportPath)
    $b=New-Object Text.StringBuilder
    [void]$b.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$b.AppendLine('<title>Minecraft Cheat Scanner report</title><style>')
    [void]$b.AppendLine(':root{color-scheme:dark;--bg:#0c111b;--card:#151e2d;--line:#28364b;--text:#e8eef7;--muted:#a9b8cb;--accent:#70d6b2}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Segoe UI,Arial,sans-serif}main{max-width:1200px;margin:auto;padding:28px}h1,h2{line-height:1.2}h1{margin:0 0 4px}h2{margin:26px 0 10px}.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}.card,section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}.value{font-size:1.7rem;font-weight:700;color:var(--accent)}.summary{border-left:4px solid var(--accent)}table{width:100%;border-collapse:collapse;background:var(--card)}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{color:var(--muted)}input,select{background:#0c111b;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:9px;margin:4px 8px 12px 0}.badge{display:inline-block;border-radius:20px;padding:2px 9px;background:#26364b}.severity-confirmed{background:#592a34}.severity-high{background:#664420}.severity-review{background:#504421}.severity-incomplete,.status-Failed,.status-Partial,.status-Skipped{background:#492e3f}details{min-width:260px}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:5px 0}a{color:var(--accent)}@media(max-width:650px){main{padding:14px}table{font-size:13px}}</style></head><body><main>')
    [void]$b.AppendLine(('<h1>Minecraft Cheat Scanner v{0}</h1><div class="muted">{1} | {2} | Windows user: {3}</div>' -f (Encode-HtmlValue $Report.ScannerVersion),(Encode-HtmlValue $Report.Timestamp),(Encode-HtmlValue $Report.Mode),(Encode-HtmlValue $Report.UserName)))
    [void]$b.AppendLine(('<section class="summary"><strong>{0}</strong><br>{1}<br><span class="muted">Workflow progress: complete (100%) after all planned phases and report generation.</span></section>' -f (Encode-HtmlValue $Report.Status),(Encode-HtmlValue $Report.Summary)))
    [void]$b.AppendLine('<div class="cards">')
    $stats=@(@('Files analyzed',$Report.FilesAnalyzed),@('SHA-256 hashes',$Report.HashesCalculated),@('JAR/ZIP candidates',$Report.JarsAnalyzed),@('Loaded DLLs inspected',$Report.DllModulesInspected),@('Java/Minecraft process candidates',$Report.MinecraftProcessCandidates),@('Identified Minecraft processes',$Report.IdentifiedMinecraftProcesses),@('Installations',@($Report.Profiles).Count),@('Positive cheat findings',@($Report.Findings).Count),@('Incomplete checks',@($Report.Coverage|Where-Object Status -in @('Failed','Partial','Skipped','Restricted')).Count))
    foreach($card in $stats){[void]$b.AppendLine(('<div class="card"><div class="value">{0}</div><div>{1}</div></div>' -f (Encode-HtmlValue $card[1]),(Encode-HtmlValue $card[0])))}
    [void]$b.AppendLine('</div><h2>Client detection coverage</h2><table><thead><tr><th>Client</th><th>Category</th><th>Hash</th><th>Metadata</th><th>Runtime</th><th>Coverage status</th></tr></thead><tbody>')
    foreach($client in $Report.ClientCoverage){$hash=if($client.verifiedSha256Available){'Yes'}else{'No'};$metadata=if(@($client.metadataIds).Count){'Verified identifier'}else{'No verified indicator'};$runtime=if(@($client.runtimeIndicators).Count){'Catalogued'}else{'No verified indicator'};[void]$b.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (Encode-HtmlValue $client.name),(Encode-HtmlValue $client.category),(Encode-HtmlValue $hash),(Encode-HtmlValue $metadata),(Encode-HtmlValue $runtime),(Encode-HtmlValue $client.signatureStatus)))}
    [void]$b.AppendLine('</tbody></table><h2>Installations</h2><table><thead><tr><th>Launcher</th><th>Profile</th><th>Active</th><th>Game directory</th></tr></thead><tbody>')
    foreach($p in $Report.Profiles){[void]$b.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Encode-HtmlValue $p.Launcher),(Encode-HtmlValue $p.Name),(Encode-HtmlValue $p.Active),(Encode-HtmlValue $p.GameDir)))}
    [void]$b.AppendLine('</tbody></table><h2>Process identification methods</h2><table><thead><tr><th>PID</th><th>Method</th><th>Status</th><th>Details</th></tr></thead><tbody>')
    foreach($method in $Report.ProcessIdentificationMethods){$pidText=if($null -eq $method.ProcessId){'Global'}else{[string]$method.ProcessId};[void]$b.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Encode-HtmlValue $pidText),(Encode-HtmlValue $method.Method),(Encode-HtmlValue $method.Status),(Encode-HtmlValue $method.Detail)))}
    [void]$b.AppendLine('</tbody></table>')
    if(@($Report.Findings).Count){
        [void]$b.AppendLine('<h2>DETECTED CHEATS</h2><input id="search" type="search" placeholder="Search positive findings"><table id="findings"><thead><tr><th>Finding</th><th>Evidence</th><th>SHA-256</th><th>Artifact / process</th><th>Runtime association and limits</th></tr></thead><tbody>')
        foreach($f in $Report.Findings){$identity=Encode-HtmlValue $(if($f.ClientName){$f.ClientName}else{$f.Title});$category=Encode-HtmlValue $f.ClientCategory;$classification=Encode-HtmlValue $f.Category;$method=Encode-HtmlValue $f.DetectionMethod;$detail=Encode-HtmlValue $f.Detail;$hash=Encode-HtmlValue $f.FileHash;$path=Encode-HtmlValue $f.Path;$pidText=Encode-HtmlValue $f.ProcessId;$runtime=Encode-HtmlValue $f.RuntimeAssociation;$limits=Encode-HtmlValue $f.VerificationLimitations;$source=Encode-HtmlValue $f.SignatureSource;$strength=Encode-HtmlValue $f.EvidenceStrength;[void]$b.AppendLine(('<tr><td><strong>{0}</strong><br>{1}<br>{2}</td><td>{3}<br>{4}<br>{5}</td><td><code>{6}</code></td><td><pre>{7}</pre>PID {8}</td><td>{9}<br>{10}</td></tr>' -f $identity,$category,$classification,$method,$detail,$source,$hash,$path,$pidText,$runtime,$limits))}
        [void]$b.AppendLine('</tbody></table>')
    }
    [void]$b.AppendLine('<h2>Runtime inspection</h2><table><thead><tr><th>Record</th><th>Process</th><th>Details</th></tr></thead><tbody>')
    foreach($r in $Report.Runtime){$record=Encode-HtmlValue $r.RecordType;$processIdText=Encode-HtmlValue $r.ProcessId;$detail=Encode-HtmlValue (($r|ConvertTo-Json -Depth 6 -Compress));[void]$b.AppendLine(('<tr><td>{0}</td><td>{1}</td><td><details><summary>Show details</summary><pre>{2}</pre></details></td></tr>' -f $record,$processIdText,$detail))}
    [void]$b.AppendLine('</tbody></table><h2>Mod artifacts and authenticity</h2><input id="modsSearch" type="search" placeholder="Search mod artifacts"><table id="mods"><thead><tr><th>Artifact</th><th>Identity and declared publisher</th><th>SHA-256</th><th>Authenticity</th><th>JAR signature state</th><th>Loader log correlation</th><th>Runtime</th></tr></thead><tbody>')
    foreach($a in $Report.ModArtifacts){$path=Encode-HtmlValue $a.Path;$identity=Encode-HtmlValue ("$($a.Name) | $($a.ModId) | $($a.Version) | $($a.ModLoader) | declared author: $($a.Authors)");$hash=Encode-HtmlValue $a.SHA256;$auth=Encode-HtmlValue $a.Authenticity;$jarSignature=Encode-HtmlValue $a.JarSignatureStatus;$logEvidence=Encode-HtmlValue ("$($a.RuntimeLogStatus): $($a.RuntimeLogEvidence)");$runtime=Encode-HtmlValue $a.RuntimeAssociation;[void]$b.AppendLine(("<tr><td>$path</td><td>$identity</td><td><code>$hash</code></td><td>$auth</td><td>$jarSignature</td><td>$logEvidence</td><td>$runtime</td></tr>"))}
    [void]$b.AppendLine('</tbody></table><h2>Scan coverage, errors, and skipped checks</h2><table><thead><tr><th>Status</th><th>Check</th><th>Detail</th></tr></thead><tbody>')
    foreach($c in $Report.Coverage){$status=Encode-HtmlValue $c.Status;$statusClass=Encode-HtmlValue ('status-'+$c.Status);$check=Encode-HtmlValue $c.Check;$detail=Encode-HtmlValue $c.Detail;[void]$b.AppendLine(('<tr><td><span class="badge {1}">{0}</span></td><td>{2}</td><td>{3}</td></tr>' -f $status,$statusClass,$check,$detail))}
    [void]$b.AppendLine('</tbody></table><h2>Limitations</h2><ul>')
    foreach($l in $Report.Limitations){[void]$b.AppendLine(('<li>{0}</li>' -f (Encode-HtmlValue $l)))}
    [void]$b.AppendLine('</ul><div class="muted">100% indicates the planned scan workflow and report generation completed; it does not mean every cheat was detected.</div>')
    [void]$b.AppendLine('<script>const q=document.getElementById("search"),mq=document.getElementById("modsSearch");function filter(){if(q){for(const r of document.querySelectorAll("#findings tbody tr")){r.hidden=!r.innerText.toLowerCase().includes(q.value.toLowerCase())}}if(mq){for(const r of document.querySelectorAll("#mods tbody tr")){r.hidden=!r.innerText.toLowerCase().includes(mq.value.toLowerCase())}}}if(q)q.addEventListener("input",filter);if(mq)mq.addEventListener("input",filter);</script></main></body></html>')
    [IO.File]::WriteAllText($ReportPath,$b.ToString(),(New-Object Text.UTF8Encoding($false)))
}
function Write-Reports {
    param($Report,[string]$Directory,[switch]$SkipHtml)
    # Keep the primary results array limited to positive, evidence-backed
    # detections. Failures and restricted checks remain in Coverage/Diagnostics.
    $Report.Findings=@(Get-PositiveCheatFindings @($Report.Findings))
    $resolved=Resolve-ReportDirectory $Directory;$stamp=Get-ReportStamp $resolved
    $txtPath=Join-Path $resolved "Minecraft-Cheat-Scan-$stamp.txt";$htmlPath=Join-Path $resolved "Minecraft-Cheat-Scan-$stamp.html";$jsonPath=Join-Path $resolved "Minecraft-Cheat-Scan-$stamp.json";$diagnosticPath=Join-Path $resolved "Minecraft-Cheat-Scan-$stamp-diagnostics.log"
    try{
        Write-TextReport $Report $txtPath
        $Report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $jsonPath -Encoding UTF8 -ErrorAction Stop
        $diagnosticLines=@($Report.Diagnostics|ForEach-Object {"[$($_.Timestamp)] [$($_.Level)] $($_.Check): $($_.Detail)"})
        $diagnosticLines+=@($Report.ProcessIdentificationMethods|ForEach-Object {$pidText=if($null -eq $_.ProcessId){'global'}else{"PID $($_.ProcessId)"};"[PROCESS][$($_.Status)] $pidText $($_.Method): $($_.Detail)"})
        if(!$diagnosticLines.Count){$diagnosticLines=@('No failed, skipped, partial, or process identification checks were recorded.')}
        $diagnosticLines|Set-Content -LiteralPath $diagnosticPath -Encoding UTF8 -ErrorAction Stop
        Write-HtmlReport $Report $htmlPath
        return [pscustomobject]@{Directory=$resolved;Text=$txtPath;Json=$jsonPath;Html=$htmlPath;Diagnostics=$diagnosticPath}
    }catch{throw "Report writing failed at '$resolved': $($_.Exception.Message)"}
}

function Write-ScannerLog {
    param([string]$Directory,[string]$Message)
    if(!(Test-Path -LiteralPath $Directory -PathType Container)){New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop | Out-Null}
    $line="[$((Get-Date).ToString('o'))] $Message`r`n"
    [IO.File]::AppendAllText((Join-Path $Directory 'scanner.log'),$line,[Text.Encoding]::UTF8)
}

function Write-StartupFailure {
    param([string]$Directory,[string]$Message,[string]$ErrorDetails='')
    $record="[$((Get-Date).ToString('o'))] STARTUP ERROR: $Message`r`n$ErrorDetails`r`n"
    $tempRoot=$script:UserFolders.Temp;if(!$tempRoot){$tempRoot=[IO.Path]::GetTempPath()}
    $targets=@($Directory,(Join-Path $tempRoot 'MinecraftCheatScanner-Reports'))
    foreach($target in $targets){
        try{
            if(!(Test-LocalScanPath $target)){throw 'Non-local error log path is excluded.'}
            if(!(Test-Path -LiteralPath $target -PathType Container)){New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop|Out-Null}
            [IO.File]::AppendAllText((Join-Path $target 'scanner.log'),$record,[Text.Encoding]::UTF8)
            Write-Host "Detailed error log: $(Join-Path $target 'scanner.log')" -ForegroundColor Yellow
            return
        }catch{Write-Host "Could not write error log in '$target': $($_.Exception.Message)" -ForegroundColor Red}
    }
    Write-Host 'The error could not be written to disk; copy the message above.' -ForegroundColor Red
}

function Start-MinecraftCheatScanner {
    param([int]$FileLimit=5000,[long]$ArchiveLimit=536870912,[int]$NestedDepth=2,[int]$JcmdTimeout=8,[string]$ReportDir=(Join-Path $script:ScannerRoot 'Reports'),[switch]$SkipHtml,[switch]$RuntimeOnly)
    try{
        $ErrorActionPreference='Stop'
        $ReportDir=Resolve-ReportDirectory $ReportDir
        Write-ScannerLog $ReportDir "Scanner v$script:ScannerVersion starting; mode=$(if($RuntimeOnly){'RuntimeDiagnostic'}else{'UnifiedAutomatic'})"
        if($SkipHtml){Write-Warning 'The legacy -NoHtml option is ignored; TXT, HTML, and JSON reports are always generated.'}
        Invoke-MinecraftCheatScan -FileLimit $FileLimit -ArchiveLimit $ArchiveLimit -NestedDepth $NestedDepth -JcmdTimeout $JcmdTimeout -ReportDir $ReportDir -SkipHtml:$false -RuntimeOnly:$RuntimeOnly | Out-Null
        Write-ScannerLog $ReportDir 'Scan completed.'
        Write-Host 'Scanner finished. Review the report and diagnostics log shown above.' -ForegroundColor Green
        return 0
    }catch{
        $message=$_.Exception.Message
        $errorDetails=($_ | Format-List * -Force | Out-String).Trim()
        Write-Host "`nSCANNER ERROR: $message" -ForegroundColor Red
        Write-StartupFailure $ReportDir $message $errorDetails
        Write-Host 'The scan did not complete. No clean result is being reported.' -ForegroundColor Red
        return 1
    }
}

function Invoke-MinecraftCheatScan {
    param([int]$FileLimit=5000,[long]$ArchiveLimit=536870912,[int]$NestedDepth=2,[int]$JcmdTimeout=8,[string]$ReportDir=(Join-Path $script:ScannerRoot 'Reports'),[switch]$SkipHtml,[switch]$RuntimeOnly)
    $script:Findings=New-Object 'System.Collections.Generic.List[object]';$script:Coverage=New-Object 'System.Collections.Generic.List[object]';$script:Diagnostics=New-Object 'System.Collections.Generic.List[object]';$script:ProcessMethodResults=New-Object 'System.Collections.Generic.List[object]';$script:FileCache=@{};$script:HashCache=@{};$script:ModArtifacts=New-Object 'System.Collections.Generic.List[object]';$script:HashCount=0;$script:DllCount=0;$script:JarCount=0;$script:UserJarCount=0;$script:ActiveProcessCount=0;$script:FailedCheckCount=0
    $started=Get-Date;$script:ScanStarted=$started;$script:ScannedPaths=@{};$script:ScannedFileCount=0;$script:ProgressPercent=0;$script:ProgressPhasePercent=0;$script:ProgressPhaseName='';$script:InstallationCount=0
    Write-Host "Minecraft Cheat Scanner v$script:ScannerVersion" -ForegroundColor Cyan
    Update-ScanProgress 'Startup' 0 'Preparing bounded, read-only scan'
    Update-ScanProgress 'Startup' 100 'Startup checks ready'
    Update-ScanProgress 'Process discovery' 0 'Querying current-user Minecraft and Java processes'
    $mc=@(Get-ProcessInventory)
    $script:ActiveProcessCount=@($mc|Where-Object Identified).Count
    $jcmds=if($mc.Count){@(Get-JcmdPaths)}else{@()}
    if($mc.Count){$mc=@(Resolve-JvmMinecraftCandidates $mc $jcmds $JcmdTimeout)}
    Update-ScanProgress 'Process discovery' 100 "Process discovery finished ($($mc.Count) process(es))" $mc.Count $mc.Count
    $identifiedProcesses=@($mc|Where-Object Identified)
    $uncertainProcesses=@($mc|Where-Object {!$_.Identified}).Count
    Add-Coverage 'Minecraft process detection' $(if($identifiedProcesses.Count -and !$uncertainProcesses){'Completed'}elseif($identifiedProcesses.Count -or $uncertainProcesses){'Partial'}else{'Partial'}) $(if($identifiedProcesses.Count){"Identified $($identifiedProcesses.Count) Minecraft process(es); found $uncertainProcesses unconfirmed Java candidate(s)."}elseif($uncertainProcesses){"Found $uncertainProcesses Java candidate(s); no independent indicators confirmed Minecraft ownership."}else{'No matching active Minecraft or Java process was found'})
    if(!$mc.Count){Write-Warning 'No active Minecraft process was found. Runtime checks are unavailable; continuing with offline profile, log, JAR, and filesystem checks.';Add-Finding 'Scan Incomplete' 'No active Minecraft process found' 'Process, JVM attach, and loaded-module checks require a running game; offline checks continue.' $null $null;Add-Coverage 'Runtime process checks' 'Skipped' 'No Minecraft or Java process was available.'}
    elseif(!$identifiedProcesses.Count){Write-Warning 'Java process candidates were found, but Minecraft could not be reliably confirmed. Runtime-specific JVM and module inspection is skipped; offline checks continue.';Add-Finding 'Scan Incomplete' 'Minecraft process identity unresolved' 'Process command-line access may be restricted. Runtime checks were not run against unconfirmed Java processes.' $null $null;Add-Coverage 'Runtime process checks' 'Skipped' 'No Java candidate met the multi-signal Minecraft identification threshold.'}
    elseif($uncertainProcesses){Write-Warning "$($identifiedProcesses.Count) Minecraft process(es) identified; $uncertainProcesses Java candidate(s) remain unconfirmed and will not receive Minecraft-specific runtime inspection."}
    Update-ScanProgress 'Minecraft installation discovery' 0 'Reading known launcher locations and launcher configuration'
    $profiles=@(Get-MinecraftProfiles $mc)
    $script:InstallationCount=$profiles.Count
    Resolve-ModrinthProfileFromLaunchLog $mc $profiles
    Add-Coverage 'Launcher profile discovery' 'Completed' "Discovered $($profiles.Count) game directory profile(s) across known launchers and active process paths"
    foreach($process in $mc){
        $profile=$null
        if($process.GameDir){$profile=$profiles|Where-Object{$_.GameDir -and ([IO.Path]::GetFullPath($_.GameDir).TrimEnd('\') -ieq [IO.Path]::GetFullPath($process.GameDir).TrimEnd('\'))}|Select-Object -First 1}
        if($profile){$process|Add-Member -NotePropertyName ActiveProfile -NotePropertyValue ([string]$profile.Name) -Force;$process|Add-Member -NotePropertyName ProfileLauncher -NotePropertyValue ([string]$profile.Launcher) -Force;$process|Add-Member -NotePropertyName ProfileStatus -NotePropertyValue 'Matched' -Force;Add-ProcessMethodResult $process.ProcessId 'Active Minecraft profile correlation' 'Succeeded' "Matched profile '$($profile.Name)' ($($profile.Launcher)) at $($profile.GameDir)."}
        elseif($process.Identified -and !$process.GameDir){$process|Add-Member -NotePropertyName ActiveProfile -NotePropertyValue $null -Force;$process|Add-Member -NotePropertyName ProfileLauncher -NotePropertyValue $null -Force;$process|Add-Member -NotePropertyName ProfileStatus -NotePropertyValue 'Unavailable' -Force;Add-ProcessMethodResult $process.ProcessId 'Active Minecraft profile correlation' 'Unavailable' 'Process identity was established, but command-line and working-directory data were inaccessible; its active profile cannot be selected safely.'}
        elseif($process.Identified){$process|Add-Member -NotePropertyName ActiveProfile -NotePropertyValue $null -Force;$process|Add-Member -NotePropertyName ProfileLauncher -NotePropertyValue $null -Force;$process|Add-Member -NotePropertyName ProfileStatus -NotePropertyValue 'NoMatch' -Force;Add-ProcessMethodResult $process.ProcessId 'Active Minecraft profile correlation' 'NoMatch' 'Process was identified, but no discovered launcher profile matched its game directory.'}
        else{Add-ProcessMethodResult $process.ProcessId 'Active Minecraft profile correlation' 'Unavailable' 'Unconfirmed Java process has no reliable game directory to correlate.'}
    }
    Update-ScanProgress 'Minecraft installation discovery' 100 "Discovered $($profiles.Count) installation/profile(s)" $profiles.Count $profiles.Count
    if($script:CompressionAssemblyError){Add-Coverage 'ZIP/JAR archive support' 'Failed' $script:CompressionAssemblyError;Add-Finding 'Scan Incomplete' 'ZIP/JAR archive support unavailable' 'JAR inspection will be skipped; other checks continue.' $null $null}else{Add-Coverage 'ZIP/JAR archive support' 'Completed' 'Compression support loaded.'}
    $javaInfo=New-Object 'System.Collections.Generic.List[object]';$signatureCatalog=@(Get-VerifiedSignatureCatalog);$script:ClientCatalog=@(Get-ClientDetectionCatalog)
    $doomsday= @($script:ClientCatalog|Where-Object name -eq 'Doomsday Client'|Select-Object -First 1)
    if(!$doomsday.Count -or !$doomsday[0].verifiedSha256Available -or @($doomsday[0].metadataIds).Count -eq 0 -or @($doomsday[0].classPrefixes).Count -eq 0 -or @($doomsday[0].runtimeIndicators).Count -eq 0){
        Add-Coverage 'Doomsday-specific detection coverage' 'Partial' 'Insufficient client-specific evidence: no verified Doomsday hash, metadata id, package/class identifier, native-module signature, or JVM agent indicator is catalogued. File-backed loaded modules and accessible agent arguments are inspected, but JVM class inspection is skipped under the passive-only policy; dynamically loaded code without a visible module or artifact may be unobservable.'
    }else{
        Add-Coverage 'Doomsday-specific detection coverage' 'Completed' 'One or more source-verified client-specific indicators are available; exact method matches are reported only when evidence is observed.'
    }
    Add-Coverage 'Verified SHA-256 catalog' 'Completed' "Loaded $($signatureCatalog.Count) provenance-validated release hash record(s)"
    $loadedClassesByPid=@{}
    $runtime=New-Object 'System.Collections.Generic.List[object]'
    $runtimeTargets=@($mc|Where-Object Identified)
    Update-ScanProgress 'Runtime diagnostics' 0 'Inspecting identified Minecraft processes; unconfirmed Java candidates are excluded' 0 $runtimeTargets.Count
    $processIndex=0
    foreach($m in $runtimeTargets){$processIndex++;Update-ScanProgress 'Runtime diagnostics' (($processIndex-1)*100/[Math]::Max(1,$runtimeTargets.Count)) "Inspecting identified Minecraft PID $($m.ProcessId) ($($m.Name))" ($processIndex-1) $runtimeTargets.Count
        $java=Get-JavaRuntimeInfo $m.ExecutablePath;$javaArch=Get-PeArchitecture $m.ExecutablePath;if($java.Path -and (Test-LocalScanPath $java.Path)){Add-ScannedFile $java.Path};$javaInfo.Add([pscustomobject]@{ProcessId=$m.ProcessId;Executable=$java.Path;Version=$java.Version;Vendor=$java.Vendor;Architecture=$javaArch.Architecture;ArchitectureStatus=$javaArch.Status;Owner=$m.Owner;OwnerStatus=$m.OwnerStatus;Status=$java.Status;Detail=$java.Detail})
        Add-Coverage "Java version PID $($m.ProcessId)" $(if($java.Status -eq 'Completed'){'Completed'}elseif($java.Status -in @('Timeout','ParseFailed')){'Partial'}else{'Failed'}) $java.Detail
        if($java.Status -ne 'Completed'){Add-Finding 'Scan Incomplete' "Java version unavailable for PID $($m.ProcessId)" $java.Detail $java.Path $m.ProcessId}
        $agents=Get-JvmAgentArguments $m.CommandLine
        if(!$m.CommandLine){Add-Coverage "JVM agent arguments PID $($m.ProcessId)" 'Skipped' 'Process command line is unavailable, commonly due to permissions.'}
        else{Add-Coverage "JVM agent arguments PID $($m.ProcessId)" 'Completed' "Inspected command line; agent argument count=$($agents.Count)"}
        foreach($agent in $agents){
            $match=$null;if($agent.Path -and !(Test-LocalScanPath $agent.Path)){Add-Coverage "JVM agent path PID $($m.ProcessId)" 'Skipped' 'Non-local agent path excluded.';continue};if($agent.Path -and (Test-Path -LiteralPath $agent.Path -PathType Leaf)){Add-ScannedFile $agent.Path;$match=Find-SignatureMatch $agent.Path $signatureCatalog}
            if($match){$agentCategory=if($m.Detection -notlike '*candidate*'){'Verified Runtime Association'}else{'Verified Artifact'};Add-Finding $agentCategory 'Verified artifact configured as JVM agent' "$($match.label); exact SHA-256 match; agent kind=$($agent.Kind)" $agent.Path $m.ProcessId $match.project 'Mod-based or hacked client' $m.Version 'SHA-256 match on configured JVM agent' $match.source 'Verified release digest' 'Present as configured agent' $(if($m.Detection -like '*candidate*'){'Java process candidate only; Minecraft ownership unresolved'}else{'Configured in identified Minecraft process'}) 'A configured agent does not by itself prove successful loading.' $match.sha256}
            elseif($agent.Path){Add-Finding 'Needs Manual Review' 'JVM agent configured' "Agent path is a runtime modification mechanism; this path has no matching verified catalog digest. It is not by itself proof of cheating." $agent.Path $m.ProcessId}
            else{Add-Finding 'Informational' 'JVM agent library configured' "Agent library '$($agent.Value)' is present in JVM arguments; identity and purpose are not established." $null $m.ProcessId}
        }
        Add-ProcessMethodResult $m.ProcessId 'JVM attach policy' 'Skipped' 'No jcmd command was sent in this scan because Windows JVM attach may write a helper and start a remote thread. A previous live attempt returned Access is denied at VirtualMachineImpl.openProcess before a JVM handshake; OpenJDK Windows attach requests PROCESS_ALL_ACCESS. This establishes the denied native handle-open operation, but not the underlying ACL/security-policy cause. The earlier tool was Java 26 while this target is Java 25, but the version mismatch is not shown to cause a pre-handshake failure. JVM args and DisableAttachMechanism state remain unknown; classes and classloaders were not inspected.'
        if(!$jcmds.Count){Add-Coverage "JVM diagnostics PID $($m.ProcessId)" 'Skipped' 'No jcmd executable was discovered; target attach was not attempted.';Add-Finding 'Scan Incomplete' 'JVM diagnostic check skipped' 'No jcmd was discovered. Passive module, launcher-log, and filesystem checks continued.' $null $m.ProcessId}
        foreach($cmd in $(if($jcmds.Count){@('VM.classloader_stats','GC.class_histogram')}else{@()})){
            Update-ScanProgress 'Runtime diagnostics' (($processIndex-1)*100/[Math]::Max(1,$runtimeTargets.Count)) "Running $cmd for PID $($m.ProcessId)" ($processIndex-1) $runtimeTargets.Count
            $res=Invoke-JcmdCheck $jcmds $m.ProcessId $cmd $JcmdTimeout
            if($res.Status -ne 'Completed'){$coverageStatus=if($res.Status -eq 'Timeout'){'Partial'}elseif($res.Status -eq 'Unsupported' -or $res.Status -eq 'Skipped'){'Skipped'}elseif($res.Status -eq 'Restricted'){'Restricted'}else{'Failed'};Add-Coverage "$cmd PID $($m.ProcessId)" $coverageStatus $res.Error;Add-Finding 'Scan Incomplete' "$cmd unavailable for PID $($m.ProcessId)" $res.Error $null $m.ProcessId;continue}
            Add-Coverage "$cmd PID $($m.ProcessId)" 'Completed' 'JVM command returned output'
            if($cmd -eq 'VM.classloader_stats'){
                foreach($row in (Get-ClassloaderRows $res.Output)){$kind=Get-LoaderKind $row.Loader
                    if($kind -in @('Custom','Unknown')){Add-Finding 'Needs Manual Review' "$kind classloader observed" "$($row.Classes) classes; loader=$($row.Loader). Classloader type alone does not establish injection." $null $m.ProcessId}
                }
            }else{
                $loadedClassesByPid[[string]$m.ProcessId]=Get-ClassHistogramNames $res.Output
                foreach($clientMatch in (Get-ModClientMatches '' '' @($loadedClassesByPid[[string]$m.ProcessId]))){Add-Finding 'Needs Manual Review' 'Catalogued client package present in JVM class histogram' ("{0}; package evidence={1}; source={2}. Class presence is a runtime lead and is not a verified artifact signature." -f $clientMatch.Name,(@($clientMatch.Evidence)-join ', '),(@($clientMatch.Sources)-join '; ')) $null $m.ProcessId $clientMatch.Name $clientMatch.Category $m.Version 'Exact documented class package in JVM class histogram' (@($clientMatch.Sources)-join '; ') 'Documented package indicator; class origin not established' 'Loaded class name observed' 'Observed in identified Minecraft process' 'Class histograms do not establish the origin JAR or user intent.'}
                foreach($line in ($res.Output -split "`r?`n")){foreach($brand in $script:KnownBrands){if($line -match [regex]::Escape($brand)){Add-Finding 'Needs Manual Review' 'Known client term in class histogram' $line.Trim() $null $m.ProcessId;break}}}
            }
        }
        try{$proc=Get-Process -Id $m.ProcessId -ErrorAction Stop;$modules=@($proc.Modules);$moduleCount=$modules.Count;$moduleIndex=0;foreach($mod in $modules){$moduleIndex++;$modulePercent=(($processIndex-1)+(0.5*$moduleIndex/[Math]::Max(1,$moduleCount)))*100/[Math]::Max(1,$mc.Count);Update-ScanProgress 'Runtime diagnostics' $modulePercent "Inspecting module $($mod.ModuleName) for PID $($m.ProcessId)" $moduleIndex $moduleCount;$path=[string]$mod.FileName
            if(!$path){Add-Coverage "DLL module PID $($m.ProcessId)" 'Partial' 'A loaded module had no readable path.';continue}
            if(!(Test-LocalScanPath $path)){Add-Coverage "DLL module PID $($m.ProcessId): $path" 'Skipped' 'Non-local module path excluded.';continue};Add-ScannedFile $path
            $pathClass=Get-ModulePathClass $path;$auth=Get-AuthenticodeInfo $path;$hashResult=Get-CachedSha256 $path;if([IO.Path]::GetExtension($path) -ieq '.dll'){$script:DllCount++};$moduleEvidence=if($hashResult.Status -eq 'Completed'){Get-VerifiedRuntimeModuleEvidence $hashResult.Hash $m $signatureCatalog}else{$null};$match=if($moduleEvidence){$moduleEvidence.Signature}else{$null}
            $runtime.Add([pscustomobject]@{RecordType='LoadedModule';ProcessId=$m.ProcessId;Module=$mod.ModuleName;Path=$path;PathClass=$pathClass;SHA256=$hashResult.Hash;HashStatus=$hashResult.Status;Authenticode=$auth.Status;Signer=$auth.Signer;SignatureDetail=$auth.Detail;VerifiedCatalogMatch=[bool]$match})
            if($auth.Detail){Add-Coverage "Authenticode PID $($m.ProcessId): $path" 'Partial' $auth.Detail}else{Add-Coverage "Authenticode PID $($m.ProcessId): $path" 'Completed' "Status=$($auth.Status); path class=$pathClass"}
            if($match){$moduleCategory=$moduleEvidence.Category;$loadedTitle=if($m.Detection -like '*candidate*'){'Verified cheat signature in Java process candidate module'}else{'Verified cheat signature in Minecraft process module'};Add-Finding $moduleCategory $loadedTitle "$($match.label); exact SHA-256 match; source=$($match.source); artifact=$($match.artifactType); signature=$($auth.Status); process ownership=$(if($m.Detection -like '*candidate*'){'unconfirmed Java candidate'}else{'identified Minecraft process'})" $path $m.ProcessId $match.project 'Mod-based or hacked client' $m.Version 'Loaded module SHA-256 match' $match.source 'Verified release digest' 'Loaded module' $(if($m.Detection -like '*candidate*'){'Java process candidate only; Minecraft ownership unresolved'}else{'Loaded in identified Minecraft process'}) 'Module enumeration confirms mapped module presence, not user intent.' $hashResult.Hash;continue}
            if($pathClass -eq 'Outside standard directories' -and $auth.Status -in @('NotSigned','HashMismatch','NotTrusted','Revoked','UnknownError')){Add-Finding 'Needs Manual Review' 'Unusual unsigned or untrusted module loaded' "Authenticode status=$($auth.Status); no verified cheat hash match; unusual path is a review lead, not proof." $path $m.ProcessId}
        };Add-Coverage "Loaded DLL modules PID $($m.ProcessId)" 'Completed' "Inspected $moduleCount module(s); unfamiliar or unsigned modules are not automatically confirmed."}
        catch{Add-Coverage "Loaded DLL modules PID $($m.ProcessId)" 'Failed' $_.Exception.Message;Add-Finding 'Scan Incomplete' 'Process modules could not be inspected' $_.Exception.Message $null $m.ProcessId}
        $safeAgents=@($agents|ForEach-Object {[pscustomobject]@{Kind=$_.Kind;Path=$_.Path}})
        $runtime.Add([pscustomobject]@{RecordType='ProcessRuntime';ProcessId=$m.ProcessId;ExecutablePath=$m.ExecutablePath;GameDir=$m.GameDir;ActiveProfile=$m.ActiveProfile;ProfileLauncher=$m.ProfileLauncher;ProfileStatus=$m.ProfileStatus;MinecraftVersion=$m.Version;JavaVersion=$java.Version;JavaArchitecture=$javaArch.Architecture;Owner=$m.Owner;OwnerStatus=$m.OwnerStatus;JavaStatus=$java.Status;RuntimeLogStatus=$m.RuntimeLogStatus;RuntimeLogModCount=@($m.RuntimeLogMods).Count;RuntimeLogExpected=$m.RuntimeLogExpected;JvmAgents=$safeAgents;LoadedClassCount=if($loadedClassesByPid.ContainsKey([string]$m.ProcessId)){$loadedClassesByPid[[string]$m.ProcessId].Count}else{$null}})
        Update-ScanProgress 'Runtime diagnostics' ($processIndex*100/[Math]::Max(1,$runtimeTargets.Count)) "Finished runtime checks for PID $($m.ProcessId)" $processIndex $runtimeTargets.Count
    }
    if(!$runtimeTargets.Count){Add-Coverage 'JVM agent arguments' 'Skipped' 'No reliably identified active Minecraft process was available.';Add-Coverage 'JVM classloader and class histogram' 'Skipped' 'No reliably identified active Minecraft process was available.';Add-Coverage 'Loaded DLL inspection' 'Skipped' 'No reliably identified active Minecraft process was available.'}
    Update-ScanProgress 'Runtime diagnostics' 100 'Runtime checks completed or were explicitly skipped' $runtimeTargets.Count $runtimeTargets.Count
    foreach($r in $runtime){$profile=$profiles|Where-Object{$_.ProcessId -eq $r.ProcessId}|Select-Object -First 1;$r|Add-Member -NotePropertyName Launcher -NotePropertyValue $(if($profile){$profile.Launcher}else{'Unknown'}) -Force}
    Update-ScanProgress 'Logs and configuration inspection' 0 'Inspecting recent logs and profile configuration files'
    if(!$RuntimeOnly){Add-LogFindings $profiles $FileLimit;Add-ConfigurationFindings $profiles ([Math]::Min($FileLimit,500))}else{Add-Coverage 'Minecraft logs and configs' 'Skipped' 'Runtime diagnostic mode limits offline text/config scanning.'}
    Update-ScanProgress 'Logs and configuration inspection' 100 'Log/config checks completed or were skipped'
    $roots=New-Object 'System.Collections.Generic.List[string]'
    foreach($profile in $profiles){if($RuntimeOnly -and !$profile.Active){continue};$mods=Join-Path $profile.GameDir 'mods';if(Test-Path -LiteralPath $mods -PathType Container){$roots.Add($mods)}}
    Update-ScanProgress 'Mod file inventory' 0 'Enumerating discovered instance mods folders' 0 $FileLimit
    $files=@(Get-SafeFiles @($roots|Select-Object -Unique) $FileLimit 5)
    foreach($file in $files){Add-ScannedFile $file.FullName}
    Update-ScanProgress 'Mod file inventory' 100 "Inventoried $($files.Count) candidate file(s)" $files.Count ([Math]::Max($FileLimit,$files.Count))
    $jars=@($files|Where-Object{$_.Extension -ieq '.jar' -or (Test-MinecraftModArchive $_.FullName $ArchiveLimit)});$script:JarCount=$jars.Count;Add-Coverage 'Mod archive scan' $(if($files.Count -ge $FileLimit){'Partial'}else{'Completed'}) "Inspected candidate files; JAR/renamed mod archive candidates=$($jars.Count), file limit=$FileLimit"
    Update-ScanProgress 'JAR and nested archive analysis' 0 "Analyzing $($jars.Count) JAR file(s)" 0 $jars.Count
    $jarIndex=0
    foreach($jar in $jars){$jarIndex++;Update-ScanProgress 'JAR and nested archive analysis' (($jarIndex-1)*100/[Math]::Max(1,$jars.Count)) "Inspecting $($jar.Name)" ($jarIndex-1) $jars.Count;try{$hashResult=Get-CachedSha256 $jar.FullName $ArchiveLimit;$info=Get-ModJarInfo $jar.FullName $ArchiveLimit 0 $NestedDepth $signatureCatalog
        if($info.Status -eq 'Corrupt'){Add-Finding 'Needs Manual Review' 'Unreadable or corrupt JAR' $info.Reason $jar.FullName $null;continue}
        if($info.Status -eq 'Skipped'){Add-Finding 'Scan Incomplete' 'JAR exceeded scan limit' $info.Reason $jar.FullName $null;continue}
        if($info.NestedIncomplete){Add-Finding 'Scan Incomplete' 'Nested archive scan reached a configured limit' "Nested entries identified: $(@($info.Nested).Count); expanded bytes=$($info.ExpandedBytes)" $jar.FullName $null}
        $signature=if($hashResult.Status -eq 'Completed'){Find-SignatureMatchByHash $hashResult.Hash $signatureCatalog}else{$null}
        $instanceProfile=$profiles|Where-Object{$_.GameDir -and (Test-PathWithin $jar.FullName @((Join-Path $_.GameDir 'mods')))}|Select-Object -First 1
        $instanceAssociation=if($instanceProfile -and $instanceProfile.Active){"Installed in active $($instanceProfile.Launcher) profile '$($instanceProfile.Name)' (PID $($instanceProfile.ProcessId)); JVM class-load status not established."}elseif($instanceProfile){"Installed in inactive $($instanceProfile.Launcher) profile '$($instanceProfile.Name)'."}else{'No discovered Minecraft instance association.'}
        $logCorrelation=Get-LoaderLogModCorrelation $info.Id $info.Version $instanceProfile $mc
        $script:ModArtifacts.Add([pscustomobject]@{Path=$jar.FullName;FileName=$jar.Name;SHA256=$hashResult.Hash;HashStatus=$hashResult.Status;HashDetail=$hashResult.Detail;ModId=$info.Id;Name=$info.Name;Authors=$info.Authors;ModLoader=$info.ModLoader;Version=$info.Version;Manifest=$info.Manifest;JarSignatureStatus=$info.JarSignatureStatus;JarSignatureEntries=@($info.JarSignatureEntries);Authenticity=if($signature){'VERIFIED_CATALOG_MATCH'}else{'UNKNOWN'};Signature=$signature;ClientIdentifiers=@($info.ClientMatches|ForEach-Object{$_.Client.Name});NestedEntries=@($info.Nested);Profile=$instanceProfile.Name;ProfileLauncher=$instanceProfile.Launcher;AssociatedProcessId=$(if($instanceProfile -and $instanceProfile.Active){$instanceProfile.ProcessId}else{$null});RuntimeLogStatus=$logCorrelation.Status;RuntimeLogEvidence=$logCorrelation.Evidence;RuntimeAssociation=$instanceAssociation})
        if($signature){$matchedProfile=$profiles | Where-Object {$_.GameDir -and (Test-PathWithin $jar.FullName @((Join-Path $_.GameDir 'mods')))} | Select-Object -First 1;$state='installed artifact; active-game association not established';$pidValue=$null
            if($matchedProfile){if($matchedProfile.Active){$state='installed in active game directory; checking class histogram for runtime linkage';$pidValue=$matchedProfile.ProcessId}else{$state='installed in inactive game directory'}}
            $overlap=@();if($matchedProfile -and $matchedProfile.Active -and $loadedClassesByPid.ContainsKey([string]$matchedProfile.ProcessId)){$overlap=Get-LoadedClassOverlap $info.ClassNames $loadedClassesByPid[[string]$matchedProfile.ProcessId]}
            if($overlap.Count){$state="loaded class overlap observed ($($overlap.Count) exact class name(s))"}else{$pidValue=$null;if($info.ClassNamesTruncated){$state+='; runtime linkage not established (class list truncated)'}else{$state+='; no exact class overlap found in captured histogram'}}
            $signatureCategory=if($overlap.Count){'Verified Runtime Association'}else{'Verified Artifact'}
            $minecraftVersion=if($matchedProfile -and $matchedProfile.Version){$matchedProfile.Version}elseif($matchedProfile -and $matchedProfile.ProcessId){($mc|Where-Object ProcessId -eq $matchedProfile.ProcessId|Select-Object -First 1).Version}else{$null}
            $runtimeAssociation=if($overlap.Count){"Exact class histogram overlap observed ($($overlap.Count) class name(s))"}elseif($matchedProfile -and $matchedProfile.Active){'Active game directory association only; loaded classes did not establish runtime linkage'}elseif($matchedProfile){'Inactive game directory'}else{'Not established'}
            Add-Finding $signatureCategory 'Verified cheat JAR signature found' "$($signature.label); SHA-256 match; $state; source=$($signature.source); evidence=$($signature.evidence)" $jar.FullName $pidValue $signature.project 'Mod-based or hacked client' $minecraftVersion 'Exact SHA-256 match' $signature.source $signature.status 'Present in scanned JAR inventory' $runtimeAssociation 'Exact digest identifies this catalogued release; it does not establish user intent.' $hashResult.Hash
        }
        foreach($nestedSignature in $info.NestedSignatures){Add-Finding 'Verified Artifact' 'Verified nested cheat JAR signature found' "$($nestedSignature.Signature.label); SHA-256 match in nested entry; installed with parent archive; runtime load not established; source=$($nestedSignature.Signature.source); evidence=$($nestedSignature.Signature.evidence)" ("$($jar.FullName)!/$($nestedSignature.Path)") $null $nestedSignature.Signature.project 'Mod-based or hacked client' $null 'Exact nested entry SHA-256 match' $nestedSignature.Signature.source $nestedSignature.Signature.status 'Present in scanned archive' 'Not established' 'Nested archive matches a catalogued release digest.' $nestedSignature.Signature.sha256}
        foreach($matchRecord in $info.ClientMatches){$match=$matchRecord.Client;Add-Finding 'Needs Manual Review' 'Catalogued Minecraft client identifier found' ("{0}; {1}; evidence={2}; sources={3}; metadata is not a verified artifact signature." -f $match.Name,$match.Category,(@($match.Evidence)-join ', '),(@($match.Sources)-join ', ')) $matchRecord.Path $null $match.Name $match.Category $null 'Exact project metadata id/name or documented package prefix' (@($match.Sources)-join '; ') 'Documented identifier; artifact authenticity not verified' 'Present in inspected archive' 'Not established' 'Metadata and class names can be copied or forged; no exact release digest matched.'}
        foreach($flag in $info.Flags){Add-Finding 'Needs Manual Review' $flag "id=$($info.Id); name=$($info.Name); loader=$($info.ModLoader); installed artifact; runtime load not established; term match is not proof" $jar.FullName $null}
    }catch{Add-Finding 'Scan Incomplete' 'JAR analysis failed' $_.Exception.Message $jar.FullName $null};Update-ScanProgress 'JAR and nested archive analysis' ($jarIndex*100/[Math]::Max(1,$jars.Count)) "Finished $($jar.Name)" $jarIndex $jars.Count}
    Update-ScanProgress 'JAR and nested archive analysis' 100 'JAR and nested archive analysis completed' $jars.Count $jars.Count
    Update-ScanProgress 'User artifact inspection' 0 'Checking bounded user folders for recent binaries, client names, and JAR artifacts'
    if(!$RuntimeOnly){
        $tempRoots=@($script:UserFolders.Temp)|Where-Object{$_}
        $tempFiles=@(Get-SafeFiles -Roots $tempRoots -Limit ([Math]::Min($FileLimit,1500)) -Depth 2 -MaxDirectories 2500)
        foreach($file in $tempFiles){Add-ScannedFile $file.FullName}
        $recent=@($tempFiles|Where-Object{$_.Length -gt 10MB -and $_.Extension -match '^\.(exe|dll|tmp|bin)$' -and $_.LastWriteTime -gt (Get-Date).AddDays(-14)}|Select-Object -First 15)
        foreach($f in $recent){Add-Finding 'Informational' 'Recent large temporary binary' ("{0:N1} MB; size and location alone do not indicate cheating" -f ($f.Length/1MB)) $f.FullName $null}
        $nameRoots=@($script:UserFolders.AppData,$script:UserFolders.LocalAppData,$script:UserFolders.Downloads,$script:UserFolders.Desktop,$script:UserFolders.Documents)|Where-Object{$_}
        $versionRoots=New-Object 'System.Collections.Generic.List[string]'
        foreach($profile in $profiles){$versions=Join-Path $profile.GameDir 'versions';if(Test-Path -LiteralPath $versions -PathType Container){$versionRoots.Add($versions)}}
        $userRoots=@($nameRoots)+@($versionRoots.ToArray())
        $named=@(Get-SafeFiles -Roots $userRoots -Limit ([Math]::Min($FileLimit,2500)) -Depth 3)
        foreach($file in $named){Add-ScannedFile $file.FullName}
        $nameIndex=0;$reviewedNames=0
        foreach($f in $named){$nameIndex++;Update-ScanProgress 'User artifact inspection' (60*$nameIndex/[Math]::Max(1,$named.Count)) "Inspecting $($f.Name)" $nameIndex $named.Count
            $lowerName=$f.Name.ToLowerInvariant();$brandMatch=$null
            foreach($brand in $script:KnownBrands){if([regex]::IsMatch($lowerName,'(?<![a-z0-9])'+[regex]::Escape($brand)+'(?![a-z0-9])')){$brandMatch=$brand;break}}
            if($brandMatch -and $reviewedNames -lt 50){Add-Finding 'Needs Manual Review' 'Known client term in filename' "Filename contains '$brandMatch'; a filename is a lead only and is not proof of a cheat." $f.FullName $null;$reviewedNames++}
        }
        $modRoots=@($roots.ToArray())
        $userJars=@($named|Where-Object {($_.Extension -ieq '.jar' -or (Test-MinecraftModArchive $_.FullName $ArchiveLimit)) -and !(Test-PathWithin $_.FullName $modRoots)}|Select-Object -First 250);$script:UserJarCount=$userJars.Count
        $jarCount=0
        foreach($jar in $userJars){$jarCount++;Update-ScanProgress 'User artifact inspection' (60+(40*$jarCount/[Math]::Max(1,$userJars.Count))) "Analyzing user JAR $($jar.Name)" $jarCount $userJars.Count
            try{$hashResult=Get-CachedSha256 $jar.FullName $ArchiveLimit;$info=Get-ModJarInfo $jar.FullName $ArchiveLimit 0 $NestedDepth $signatureCatalog
                if($info.Status -eq 'Corrupt'){Add-Finding 'Needs Manual Review' 'Unreadable or corrupt user JAR' $info.Reason $jar.FullName $null;continue}
                if($info.Status -eq 'Skipped'){Add-Finding 'Scan Incomplete' 'User JAR exceeded scan limit' $info.Reason $jar.FullName $null;continue}
                $signature=if($hashResult.Status -eq 'Completed'){Find-SignatureMatchByHash $hashResult.Hash $signatureCatalog}else{$null}
                $instanceProfile=$profiles|Where-Object{$_.GameDir -and (Test-PathWithin $jar.FullName @((Join-Path $_.GameDir 'mods')))}|Select-Object -First 1
                $instanceAssociation=if($instanceProfile -and $instanceProfile.Active){"Installed in active $($instanceProfile.Launcher) profile '$($instanceProfile.Name)' (PID $($instanceProfile.ProcessId)); JVM class-load status not established."}elseif($instanceProfile){"Installed in inactive $($instanceProfile.Launcher) profile '$($instanceProfile.Name)'."}else{'No discovered Minecraft instance association.'}
                $logCorrelation=Get-LoaderLogModCorrelation $info.Id $info.Version $instanceProfile $mc
                $script:ModArtifacts.Add([pscustomobject]@{Path=$jar.FullName;FileName=$jar.Name;SHA256=$hashResult.Hash;HashStatus=$hashResult.Status;HashDetail=$hashResult.Detail;ModId=$info.Id;Name=$info.Name;Authors=$info.Authors;ModLoader=$info.ModLoader;Version=$info.Version;Manifest=$info.Manifest;JarSignatureStatus=$info.JarSignatureStatus;JarSignatureEntries=@($info.JarSignatureEntries);Authenticity=if($signature){'VERIFIED_CATALOG_MATCH'}else{'UNKNOWN'};Signature=$signature;ClientIdentifiers=@($info.ClientMatches|ForEach-Object{$_.Client.Name});NestedEntries=@($info.Nested);Profile=$instanceProfile.Name;ProfileLauncher=$instanceProfile.Launcher;AssociatedProcessId=$(if($instanceProfile -and $instanceProfile.Active){$instanceProfile.ProcessId}else{$null});RuntimeLogStatus=$logCorrelation.Status;RuntimeLogEvidence=$logCorrelation.Evidence;RuntimeAssociation=$instanceAssociation})
                if($signature){Add-Finding 'Verified Artifact' 'Verified cheat JAR signature found in user folder' "$($signature.label); exact SHA-256 match; artifact is present on disk; runtime load not established." $jar.FullName $null $signature.project 'Mod-based or hacked client' $null 'Exact SHA-256 match' $signature.source $signature.status 'Present in bounded user-folder scan' 'Not established' 'Artifact presence does not establish installation or execution.'}
                foreach($matchRecord in $info.ClientMatches){$match=$matchRecord.Client;Add-Finding 'Needs Manual Review' 'Catalogued Minecraft client identifier found' ("{0}; {1}; evidence={2}; sources={3}; metadata is not a verified artifact signature." -f $match.Name,$match.Category,(@($match.Evidence)-join ', '),(@($match.Sources)-join '; ')) $matchRecord.Path $null $match.Name $match.Category $null 'Exact project metadata id/name or documented package prefix' (@($match.Sources)-join '; ') 'Documented identifier; artifact authenticity not verified' 'Present in inspected archive' 'Not established' 'Metadata and class names can be copied or forged; no exact release digest matched.'}
                foreach($flag in $info.Flags){Add-Finding 'Needs Manual Review' $flag "id=$($info.Id); name=$($info.Name); loader=$($info.ModLoader); user-folder artifact; runtime load not established" $jar.FullName $null}
            }catch{Add-Finding 'Scan Incomplete' 'User JAR analysis failed' $_.Exception.Message $jar.FullName $null}
        }
        Add-Coverage 'Bounded user artifact scan' $(if($named.Count -ge [Math]::Min($FileLimit,2000) -or $tempFiles.Count -ge [Math]::Min($FileLimit,1500)){'Partial'}else{'Completed'}) "Inspected $($named.Count) user-folder entries and $($tempFiles.Count) temporary-folder entries; analyzed $($userJars.Count) user JAR(s)."
    }else{Add-Coverage 'Bounded user artifact scan' 'Skipped' 'Runtime diagnostic mode disables broader user-folder sweeps.'}
    Update-ScanProgress 'User artifact inspection' 100 "User artifact checks complete; $script:ScannedFileCount unique file(s) analyzed" $script:ScannedFileCount $script:ScannedFileCount
    $positiveFindings=@(Get-PositiveCheatFindings $script:Findings.ToArray())
    $summary=if($positiveFindings.Count){"$($positiveFindings.Count) positively supported cheat finding(s) recorded. Artifact presence does not prove it was loaded unless the finding is tied to a process."}else{'Scan workflow completed with no positive cheat findings. Review coverage limitations; an empty findings list does not establish absence of cheats.'}
    $publicProcesses=@($mc|ForEach-Object {[pscustomobject]@{ProcessId=$_.ProcessId;Name=$_.Name;ExecutablePath=$_.ExecutablePath;GameDir=$_.GameDir;Version=$_.Version;StartedAt=$_.StartedAt;ParentProcessId=$_.ParentProcessId;ParentName=$_.ParentName;Owner=$_.Owner;OwnerStatus=$_.OwnerStatus;Identified=$_.Identified;IdentificationMethods=@($_.IdentificationMethods);Detection=$_.Detection;ActiveProfile=$_.ActiveProfile;ProfileLauncher=$_.ProfileLauncher;ProfileStatus=$_.ProfileStatus;ProfileEvidence=$_.ProfileEvidence;ProfileEvidenceDeltaSeconds=$_.ProfileEvidenceDeltaSeconds;RuntimeLogStatus=$_.RuntimeLogStatus;RuntimeLogModCount=@($_.RuntimeLogMods).Count;RuntimeLogExpected=$_.RuntimeLogExpected}})
    $failedChecks=@($script:Coverage|Where-Object Status -in @('Failed','Partial','Skipped','Restricted')).Count
    $scanStatus=if($failedChecks){'Completed with limitations'}else{'Completed'}
    $username=$env:USERNAME;if(!$username){try{$username=[Security.Principal.WindowsIdentity]::GetCurrent().Name}catch{$username='Unavailable'}}
    $limitations=@('Renamed, encrypted, injected, or memory-only cheats may evade detection.','Installed artifacts do not prove runtime loading unless correlated to an active process and matching runtime evidence.','The verified hash catalog contains six version-specific Meteor Client JAR hashes; no verified digest coverage is catalogued for other clients.','The client coverage catalog has exact source-verified metadata ids and package prefixes for Meteor, LiquidBounce, and Wurst; these are identity leads, not proof of use.','No verified Doomsday-specific hash, metadata id, class/package identifier, agent marker, or native-module signature is currently available. Generic DLLs are not attributed to Doomsday.','Java JAR signer certificates are not cryptographically verified by this scanner; only SHA-256 release records and Windows Authenticode module status are checked.','Archive and file scans are bounded by configured file, archive, depth, and expanded-size limits.','Runtime inspection depends on process access, matching JDK tools, JVM attach permissions, and game launch arguments.')
    if(!$runtimeTargets.Count){$limitations+='No reliably identified Minecraft process was available; Minecraft-specific JVM and loaded-module checks were skipped.'}
    if($uncertainProcesses){$limitations+="$uncertainProcesses Java process candidate(s) remained unconfirmed and were excluded from Minecraft-specific runtime inspection."}
    $reportClientCoverage=@($script:ClientCatalog|Where-Object{$_.verifiedSha256Available -or @($_.metadataIds).Count -gt 0 -or @($_.classPrefixes).Count -gt 0 -or $_.name -eq 'Doomsday Client'})
    $report=[pscustomobject]@{ScannerVersion=$script:ScannerVersion;Mode=$(if($RuntimeOnly){'RuntimeDiagnostic'}else{'UnifiedAutomatic'});Timestamp=$started.ToString('o');UserName=$username;DurationSeconds=[Math]::Round(((Get-Date)-$started).TotalSeconds,2);Status=$scanStatus;FilesAnalyzed=$script:ScannedFileCount;HashesCalculated=$script:HashCount;JarsAnalyzed=($script:JarCount+$script:UserJarCount);InstanceJarsAnalyzed=$script:JarCount;UserArchivesAnalyzed=$script:UserJarCount;DllModulesInspected=$script:DllCount;MinecraftProcessCandidates=$mc.Count;IdentifiedMinecraftProcesses=$runtimeTargets.Count;ProcessIdentificationMethods=$script:ProcessMethodResults.ToArray();ModArtifacts=$script:ModArtifacts.ToArray();ProgressSummary='Workflow progress reaches 100% only after planned scan phases and all report files finish.';Summary=$summary;Processes=$publicProcesses;Java=$javaInfo.ToArray();Runtime=$runtime.ToArray();Profiles=$profiles;ClientCoverage=$reportClientCoverage;LauncherAndLoader='Best effort from process arguments, launcher configurations, discovered profiles, and mod metadata';Coverage=$script:Coverage.ToArray();Diagnostics=$script:Diagnostics.ToArray();Findings=$positiveFindings;Limitations=$limitations}
    Update-ScanProgress 'Report generation' 0 'Writing readable TXT, searchable HTML, JSON, and diagnostic reports'
    $paths=Write-Reports $report $ReportDir
    Update-ScanProgress 'Report generation' 100 'TXT, HTML, JSON, and diagnostics reports written' 4 4
    if(@($report.Findings).Count){Write-Host "`nDETECTED CHEATS" -ForegroundColor Red;foreach($line in (Get-CheatFindingDisplayLines $report.Findings)){Write-Host $line -ForegroundColor Yellow}}
    $incompleteCount=@($report.Coverage|Where-Object Status -in @('Failed','Partial','Skipped','Restricted')).Count
    Write-Host ("Scan coverage: {0} incomplete, failed, skipped, or restricted check(s). See the coverage and diagnostics sections in the reports." -f $incompleteCount) -ForegroundColor Cyan
    if($paths){Write-Host "Text report: $($paths.Text)";Write-Host "HTML report: $($paths.Html)";Write-Host "JSON report: $($paths.Json)";Write-Host "Diagnostics log: $($paths.Diagnostics)"}
    return $report
}

if($MyInvocation.InvocationName -ne '.') {
    if($script:CompressionAssemblyError){Write-Warning "ZIP/JAR support could not be loaded: $script:CompressionAssemblyError. Process and other offline checks will still run."}
    $exitCode=Start-MinecraftCheatScanner -FileLimit $MaxFiles -ArchiveLimit $MaxJarBytes -NestedDepth $MaxNestedDepth -JcmdTimeout $JcmdTimeoutSeconds -ReportDir $OutputDirectory -SkipHtml:$NoHtml -RuntimeOnly:$RuntimeDiagnostic
    exit $exitCode
}
