$script:ScannerFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'scan-cheats.ps1'
. $script:ScannerFile
$script:ClientCatalog = @(Get-ClientDetectionCatalog)
$script:TestRoot = Join-Path ([IO.Path]::GetTempPath()) ('mc-scanner-v7-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

function New-TestJar {
    param([string]$Path,[string]$Metadata,[string[]]$ClassEntries=@())
    $archive=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry=$archive.CreateEntry('fabric.mod.json')
        $writer=New-Object IO.StreamWriter($entry.Open())
        try{$writer.Write($Metadata)}finally{$writer.Dispose()}
        foreach($classEntry in $ClassEntries){$entry=$archive.CreateEntry($classEntry);$stream=$entry.Open();$stream.Dispose()}
    } finally {$archive.Dispose()}
    return $Path
}

Describe 'Minecraft Cheat Scanner v7 catalog and evidence regressions' {
    It 'reads Java 25 PE architecture without launching or attaching to Java' {
        $path=Join-Path $script:TestRoot 'java25-x64.exe';$bytes=New-Object byte[] 512
        $bytes[0]=0x4d;$bytes[1]=0x5a;[BitConverter]::GetBytes([int]0x80).CopyTo($bytes,0x3c);$bytes[0x80]=0x50;$bytes[0x81]=0x45;$bytes[0x82]=0;$bytes[0x83]=0;[BitConverter]::GetBytes([uint16]0x8664).CopyTo($bytes,0x84);[IO.File]::WriteAllBytes($path,$bytes)
        $result=Get-PeArchitecture $path
        $result.Status | Should Be 'Completed'
        $result.Architecture | Should Be 'x64'
        $result.Machine | Should Be '0x8664'
    }
    It 'prefers a matching Java 25 jcmd runtime and architecture over mismatches' {
        $jdk25=Join-Path $script:TestRoot 'jdk25\bin';$jdk26=Join-Path $script:TestRoot 'jdk26\bin';New-Item -ItemType Directory -Path $jdk25,$jdk26 -Force | Out-Null
        foreach($bin in @($jdk25,$jdk26)){[IO.File]::WriteAllBytes((Join-Path $bin 'jcmd.exe'),(New-Object byte[] 2));[IO.File]::WriteAllBytes((Join-Path $bin 'java.exe'),(New-Object byte[] 2))}
        Mock Get-JavaRuntimeInfo { if($Executable -match 'jdk25'){[pscustomobject]@{Status='Completed';Version='25.0.4';Detail='fixture'}}else{[pscustomobject]@{Status='Completed';Version='26.0.2';Detail='fixture'}} }
        Mock Get-PeArchitecture { [pscustomobject]@{Status='Completed';Architecture='x64';Detail='fixture'} }
        $script:ProcessMethodResults=New-Object 'System.Collections.Generic.List[object]'
        $ordered=@(Get-OrderedJcmdPaths @((Join-Path $jdk26 'jcmd.exe'),(Join-Path $jdk25 'jcmd.exe')) '25.0.4.1' 'x64' 925)
        $ordered[0] | Should Be (Join-Path $jdk25 'jcmd.exe')
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'jcmd runtime compatibility' -and $_.Status -eq 'Succeeded'}).Count | Should Be 1
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'jcmd runtime compatibility' -and $_.Status -eq 'Partial' -and $_.Detail -match 'tool Java=26'}).Count | Should Be 1
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'Matching jcmd discovery' -and $_.Status -eq 'Succeeded'}).Count | Should Be 1
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'Matching jcmd discovery' -and $_.Detail -match 'No discovered jcmd matches'}).Count | Should Be 0
    }
    It 'correlates a Modrinth instance from a unique launch-time log and reports its real game directory' {
        $game=Join-Path $script:TestRoot 'Modrinth profiles\Active instance';$logDir=Join-Path $game 'logs';New-Item -ItemType Directory -Path $logDir -Force|Out-Null
        $log=Join-Path $logDir 'latest.log';$started=(Get-Date);[IO.File]::WriteAllText($log,('['+$started.ToString('HH:mm:ss')+'] [main/INFO]: Loading Minecraft 1.21.10 with Fabric Loader 0.19.2'))
        (Get-Item $log).LastWriteTime=$started.AddSeconds(2)
        $process=[pscustomobject]@{ProcessId=9123;Identified=$true;GameDir=$null;StartedAt=$started;Version=$null;ActiveProfile=$null}
        $profile=[pscustomobject]@{Launcher='Modrinth';Name='Active instance';GameDir=$game;Active=$false;ProcessId=$null}
        $script:ProcessMethodResults=New-Object 'System.Collections.Generic.List[object]'
        Resolve-ModrinthProfileFromLaunchLog @($process) @($profile)
        $process.GameDir | Should Be $game
        $process.Version | Should Be '1.21.10'
        $profile.Active | Should Be $true
        $profile.ProcessId | Should Be 9123
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'Modrinth active profile log correlation' -and $_.Status -eq 'Succeeded'}).Count | Should Be 1
    }
    It 'parses a bounded loader mod list and matches installed mod id and version evidence' {
        $log=Join-Path $script:TestRoot 'loader-runtime.log'
        [IO.File]::WriteAllLines($log,@('[18:05:06] [main/INFO]: Loading 174 mods:','- appleskin 3.0.10+mc26.1.2','   |-- nested-dependency 1.0.0','- fabric-api 0.153.0+26.1.2','[18:05:07] [main/INFO]: Ready'))
        $inventory=Get-LoaderLogModInventory $log
        $inventory.Status | Should Be 'Succeeded'
        $inventory.Mods.Count | Should Be 2
        $profile=[pscustomobject]@{Active=$true;ProcessId=9025;Name='Synthetic'}
        $process=[pscustomobject]@{ProcessId=9025;RuntimeLogStatus=$inventory.Status;RuntimeLogMods=$inventory.Mods;RuntimeLogDetail=$inventory.Detail}
        $match=Get-LoaderLogModCorrelation 'appleskin' '3.0.10+mc26.1.2' $profile @($process)
        $match.Status | Should Be 'IdAndVersionListed'
        $changed=Get-LoaderLogModCorrelation 'appleskin' 'different-version' $profile @($process)
        $changed.Status | Should Be 'IdListedVersionDiffers'
    }
    It 'leaves profile correlation incomplete when there is no unique launch log' {
        $game=Join-Path $script:TestRoot 'Modrinth profiles\No log';New-Item -ItemType Directory -Path $game -Force|Out-Null
        $process=[pscustomobject]@{ProcessId=9124;Identified=$true;GameDir=$null;StartedAt=(Get-Date);Version=$null}
        $profile=[pscustomobject]@{Launcher='Modrinth';Name='No log';GameDir=$game;Active=$false;ProcessId=$null}
        $script:ProcessMethodResults=New-Object 'System.Collections.Generic.List[object]'
        {Resolve-ModrinthProfileFromLaunchLog @($process) @($profile)} | Should Not Throw
        $process.GameDir | Should Be $null
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'Modrinth active profile log correlation' -and $_.Status -eq 'NoMatch'}).Count | Should Be 1
    }
    It 'loads the portable scanner independently of the current directory' {
        $script:ScannerRoot | Should Be (Split-Path -Parent $script:ScannerFile)
    }
    It 'loads the requested client inventory without claiming unsupported coverage' {
        @($script:ClientCatalog).Count | Should Be 27
        (@($script:ClientCatalog | Where-Object name -eq 'Vape')[0].metadataIds).Count | Should Be 0
    }
    It 'reports Doomsday client coverage as insufficient without inventing signatures' {
        $client=@($script:ClientCatalog|Where-Object name -eq 'Doomsday Client')[0]
        $client.coverageStatus | Should Be 'Insufficient'
        $client.verifiedSha256Available | Should Be $false
        @($client.metadataIds).Count | Should Be 0
        @($client.classPrefixes).Count | Should Be 0
        @($client.runtimeIndicators).Count | Should Be 0
        @(Get-ModClientMatches 'doomsday' 'Doomsday Client' @() $script:ClientCatalog).Count | Should Be 0
    }
    It 'correlates a loaded module to Minecraft only when its exact verified digest matches' {
        $hash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes('verified module fixture'))).Replace('-','').ToLowerInvariant()
        $record=[pscustomobject]@{sha256=$hash;label='Synthetic verified fixture';project='Test fixture';artifactVersion='test-1';status='OfficialSourceHashed';source='https://github.com/example/project/releases';evidence='Synthetic test record only';artifactType='DLL'}
        $process=[pscustomobject]@{ProcessId=7352;Identified=$true}
        $evidence=Get-VerifiedRuntimeModuleEvidence $hash $process @($record)
        $evidence.Category | Should Be 'Verified Runtime Association'
        $evidence.ProcessId | Should Be 7352
        $evidence.Signature.label | Should Be 'Synthetic verified fixture'
        (Get-VerifiedRuntimeModuleEvidence ('c'*64) $process @($record)) | Should Be $null
    }
    It 'keeps synthetic clean and changed module snapshots non-positive without a verified marker' {
        $before=@([pscustomobject]@{Module='javaw.exe';SHA256=('a'*64)})
        $after=@([pscustomobject]@{Module='javaw.exe';SHA256=('a'*64)},[pscustomobject]@{Module='unfamiliar.dll';SHA256=('d'*64)})
        $findings=New-Object 'System.Collections.Generic.List[object]'
        foreach($module in $after){$evidence=Get-VerifiedRuntimeModuleEvidence $module.SHA256 ([pscustomobject]@{ProcessId=7353;Identified=$true}) @(Get-VerifiedSignatureCatalog);if($evidence){$findings.Add([pscustomobject]@{Category=$evidence.Category;ClientName=$evidence.Signature.project})}}
        @($before).Count | Should Be 1
        @($after).Count | Should Be 2
        @(Get-PositiveCheatFindings $findings.ToArray()).Count | Should Be 0
    }
    It 'identifies Meteor exact Fabric metadata id as a review lead' {
        $path=Join-Path $script:TestRoot 'meteor-fixture.jar';New-TestJar $path '{"schemaVersion":1,"id":"meteor-client","name":"Meteor Client"}' | Out-Null
        $m=Get-ModJarInfo $path 10485760 0 2 @()
        $m.ClientMatches[0].Client.Name | Should Be 'Meteor Client'
        $m.ClientMatches[0].Client.Evidence[0] | Should Match 'metadata id'
    }
    It 'identifies LiquidBounce exact Fabric metadata id as a review lead' {
        $path=Join-Path $script:TestRoot 'liquidbounce-fixture.jar';New-TestJar $path '{"schemaVersion":1,"id":"liquidbounce","name":"LiquidBounce"}' | Out-Null
        (Get-ModJarInfo $path 10485760 0 2 @()).ClientMatches[0].Client.Name | Should Be 'LiquidBounce'
    }
    It 'identifies Wurst exact Fabric metadata id as a review lead' {
        $path=Join-Path $script:TestRoot 'wurst-fixture.jar';New-TestJar $path '{"schemaVersion":1,"id":"wurst","name":"Wurst Client"}' | Out-Null
        (Get-ModJarInfo $path 10485760 0 2 @()).ClientMatches[0].Client.Name | Should Be 'Wurst'
    }
    It 'matches a trusted synthetic SHA-256 signature record' {
        $hash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes('fixture'))).Replace('-','').ToLowerInvariant()
        $record=[pscustomobject]@{sha256=$hash;label='Synthetic fixture';project='Test client';artifactVersion='test-1';status='OfficialSourceHashed';source='https://github.com/example/project/releases';evidence='Synthetic fixture only';artifactType='JAR'}
        (Find-SignatureMatchByHash $hash @($record)).label | Should Be 'Synthetic fixture'
    }
    It 'rejects a duplicate hash rather than silently trusting duplicate records' {
        $records=@(Get-VerifiedSignatureCatalog)
        @($records | Group-Object sha256 | Where-Object Count -gt 1).Count | Should Be 0
    }
    It 'matches a signature when a JAR has an unrelated renamed filename' {
        $path=Join-Path $script:TestRoot 'renamed-ordinary-file.bin'
        New-TestJar $path '{"schemaVersion":1,"id":"ordinarymod","name":"Ordinary Mod"}' | Out-Null
        (Test-ZipArchiveCandidate $path 10485760) | Should Be $true
        $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $record=[pscustomobject]@{sha256=$hash;label='Renamed fixture';project='Test client';artifactVersion='test-1';status='OfficialSourceHashed';source='https://github.com/example/project/releases';evidence='Synthetic fixture only';artifactType='JAR'}
        (Find-SignatureMatch $path @($record)).label | Should Be 'Renamed fixture'
    }
    It 'records a SHA-256 for a renamed mod candidate without trusting its filename' {
        $path=Join-Path $script:TestRoot 'performance-fix.bin';New-TestJar $path '{"schemaVersion":1,"id":"ordinarymod","name":"Ordinary Mod"}' | Out-Null
        (Test-MinecraftModArchive $path 10485760) | Should Be $true
        $hashResult=Get-CachedSha256 $path
        $hashResult.Status | Should Be 'Completed'
        $hashResult.Hash | Should Match '^[a-f0-9]{64}$'
        (Get-ModJarInfo $path 10485760 0 2 @()).Id | Should Be 'ordinarymod'
    }
    It 'does not treat unrelated user ZIP archives as Minecraft mod artifacts' {
        $path=Join-Path $script:TestRoot 'personal-archive.zip';$archive=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create);try{$entry=$archive.CreateEntry('notes.txt');$writer=New-Object IO.StreamWriter($entry.Open());$writer.Write('personal');$writer.Dispose()}finally{$archive.Dispose()}
        (Test-MinecraftModArchive $path 10485760) | Should Be $false
    }
    It 'keeps authenticity unknown when no trusted reference digest matches' {
        $path=Join-Path $script:TestRoot 'unknown.jar';New-TestJar $path '{"schemaVersion":1,"id":"sodium","name":"Sodium"}' | Out-Null
        $hashResult=Get-CachedSha256 $path
        (Find-SignatureMatchByHash $hashResult.Hash @()) | Should Be $null
        $hashResult.Status | Should Be 'Completed'
    }
    It 'reports JAR signature files as unverified evidence without claiming signature validation' {
        $path=Join-Path $script:TestRoot 'signed-looking.jar';New-TestJar $path '{"schemaVersion":1,"id":"example","name":"Example","version":"1.2.3"}' | Out-Null
        $archive=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Update)
        try{$entry=$archive.CreateEntry('META-INF/EXAMPLE.SF');$writer=New-Object IO.StreamWriter($entry.Open());$writer.Write('synthetic signature file');$writer.Dispose()}finally{$archive.Dispose()}
        $info=Get-ModJarInfo $path 10485760 0 1 @()
        $info.Version | Should Be '1.2.3'
        $info.JarSignatureStatus | Should Be 'SignatureFilesPresentNotCryptographicallyVerified'
    }
    It 'skips hashing files over the configured size bound and records the skipped check' {
        $path=Join-Path $script:TestRoot 'large-fixture.dll';[IO.File]::WriteAllBytes($path,(New-Object byte[] 2048))
        $script:Coverage=New-Object 'System.Collections.Generic.List[object]'
        $hashResult=Get-CachedSha256 $path 1024
        $hashResult.Status | Should Be 'Skipped'
        @($script:Coverage|Where-Object Status -eq 'Skipped').Count | Should Be 1
    }
    It 'discards a cached digest when file identity metadata changes' {
        $path=Join-Path $script:TestRoot 'change.jar';[IO.File]::WriteAllText($path,'first')
        $first=Get-CachedSha256 $path
        [IO.File]::AppendAllText($path,'second')
        $second=Get-CachedSha256 $path
        $second.Hash | Should Not Be $first.Hash
    }
    It 'treats an unknown valid JAR as an unknown artifact' {
        $path=Join-Path $script:TestRoot 'unrelated renamed.jar'
        New-TestJar $path '{"schemaVersion":1,"id":"ordinarymod","name":"Ordinary Mod"}' | Out-Null
        $info=Get-ModJarInfo $path 10485760 0 2 @()
        $info.Status | Should Be 'Completed'
        @($info.ClientMatches).Count | Should Be 0
    }
    It 'detects client identifiers in a nested JAR without extracting to disk' {
        $inner=New-Object IO.MemoryStream
        $innerZip=New-Object IO.Compression.ZipArchive($inner,[IO.Compression.ZipArchiveMode]::Create,$true)
        $entry=$innerZip.CreateEntry('fabric.mod.json');$writer=New-Object IO.StreamWriter($entry.Open());$writer.Write('{"schemaVersion":1,"id":"liquidbounce","name":"LiquidBounce"}');$writer.Dispose();$innerZip.Dispose()
        $outerPath=Join-Path $script:TestRoot 'nested.jar';$outer=[IO.Compression.ZipFile]::Open($outerPath,[IO.Compression.ZipArchiveMode]::Create)
        try{$entry=$outer.CreateEntry('META-INF/jars/client.jar');$stream=$entry.Open();$inner.Position=0;$inner.CopyTo($stream);$stream.Dispose()}finally{$outer.Dispose();$inner.Dispose()}
        $info=Get-ModJarInfo $outerPath 10485760 0 2 @()
        @($info.ClientMatches | Where-Object {$_.Client.Name -eq 'LiquidBounce'}).Count | Should Be 1
    }
    It 'matches a known synthetic DLL digest by bytes' {
        $bytes=[Text.Encoding]::UTF8.GetBytes('fixture dll bytes');$sha=[Security.Cryptography.SHA256]::Create();$hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant();$sha.Dispose()
        $record=[pscustomobject]@{sha256=$hash;label='Synthetic DLL';project='Test';artifactVersion='test-1';status='OfficialSourceHashed';source='https://github.com/example/project/releases';evidence='Synthetic test';artifactType='DLL'}
        (Find-SignatureMatchByHash $hash @($record)).artifactType | Should Be 'DLL'
    }
    It 'parses JVM agent options without running or attaching a process' {
        $agents=Get-JvmAgentArguments 'java -javaagent:"C:\Tools\agent.jar" -agentpath:C:\Tools\native.dll -agentlib:instrument'
        $agents.Count | Should Be 3
        $agents[0].Path | Should Be 'C:\Tools\agent.jar'
    }
    It 'classifies standard and custom ClassLoader names conservatively' {
        (Get-LoaderKind 'jdk.internal.loader.ClassLoaders$AppClassLoader').ToString() | Should Be 'Standard'
        (Get-LoaderKind 'example.CustomClassLoader').ToString() | Should Be 'Custom'
    }
    It 'correlates an exact loaded class name to its artifact class list' {
        $loaded=New-Object 'System.Collections.Generic.HashSet[string]'
        [void]$loaded.Add('meteordevelopment.meteorclient.MeteorClient')
        @(Get-LoadedClassOverlap @('meteordevelopment.meteorclient.MeteorClient','other.Class') $loaded).Count | Should Be 1
    }
    It 'finds documented Meteor class indicators in a synthetic runtime histogram' {
        $classes=Get-ClassHistogramNames "  1  120 meteordevelopment.meteorclient.MeteorClient`n"
        (Get-ModClientMatches '' '' @($classes))[0].Name | Should Be 'Meteor Client'
    }
    It 'does not treat an ordinary optimization mod identifier as a client hit' {
        @(Get-ModClientMatches 'sodium' 'Sodium' @()).Count | Should Be 0
    }
    It 'does not treat common future or lambda library class names as cheat evidence' {
        $path=Join-Path $script:TestRoot 'ordinary-library.jar'
        New-TestJar $path '{"schemaVersion":1,"id":"examplelib","name":"Example Library"}' @('kotlinx/coroutines/future/FutureKt.class','kotlinx/coroutines/flow/LambdaContinuation.class') | Out-Null
        $info=Get-ModJarInfo $path 10485760 0 2 @()
        @($info.Flags).Count | Should Be 0
        @($info.ClientMatches).Count | Should Be 0
    }
    It 'does not classify a standard overlay DLL based on being unfamiliar' {
        (Get-ModulePathClass (Join-Path $env:WINDIR 'System32\dwmapi.dll')) | Should Be 'Windows'
    }
    It 'does not promote a generic module delta to a positive client finding' {
        $baseline=@([pscustomobject]@{Module='javaw.exe';SHA256='baseline'})
        $after=@($baseline)+@([pscustomobject]@{Module='unknown-overlay.dll';SHA256=('a'*64)})
        $catalog=@(Get-VerifiedSignatureCatalog)
        $match=Find-SignatureMatchByHash $after[1].SHA256 $catalog
        $findings=@([pscustomobject]@{Category='Needs Manual Review';ClientName=$null;Title='Unusual unsigned module loaded';Detail='Synthetic module delta'})
        $match | Should Be $null
        @(Get-PositiveCheatFindings $findings).Count | Should Be 0
    }
    It 'does not emit findings-only display lines for non-positive evidence' {
        $weak=[pscustomobject]@{Category='Needs Manual Review';Title='Possible client filename';ClientName='Doomsday Client'}
        @(Get-CheatFindingDisplayLines @($weak)).Count | Should Be 0
    }
    It 'does not issue jcmd commands to the target process' {
        $script:JcmdWasExecuted=$false
        Mock Get-CommandResult { $script:JcmdWasExecuted=$true; [pscustomobject]@{Status='Completed';ExitCode=0;Output='unexpected';Error=''} }
        $result=Invoke-JcmdCheck @('C:\Java\bin\jcmd.exe') 123 'GC.class_histogram' 1
        $result.Status | Should Be 'Skipped'
        $result.Error | Should Match 'Not attempted'
        $script:JcmdWasExecuted | Should Be $false
    }
    It 'reports the same passive-scan policy when jcmd is absent' {
        (Invoke-JcmdCheck @() 123 'GC.class_histogram' 1).Status | Should Be 'Skipped'
    }
    It 'marks JVM class diagnostics skipped and does not report a successful class inspection' {
        $result=Invoke-JcmdCheck @('C:\Java\bin\jcmd.exe') 9901 'GC.class_histogram' 1
        $result.Status | Should Be 'Skipped'
        $result.Output | Should Be ''
        $result.Error | Should Match 'Not attempted'
    }
    It 'records matching and mismatched JDK compatibility without attaching to the target' {
        $script:ProcessMethodResults=New-Object 'System.Collections.Generic.List[object]'
        $candidate=[pscustomobject]@{ProcessId=9981;ExecutablePath='C:\Java25\bin\javaw.exe';Detection='Minecraft';Identified=$true;IdentificationMethods=@();CommandLine='';GameDir='C:\games\mc';Version='1.21'}
        Mock Get-JavaRuntimeInfo { [pscustomobject]@{Status='Completed';Version='25.0.4.1';Vendor='OpenJDK';Path='C:\Java25\bin\java.exe';Detail='synthetic Java 25'} }
        Mock Get-PeArchitecture { [pscustomobject]@{Status='Completed';Architecture='x64';Machine='0x8664';Detail='synthetic x64'} }
        Mock Get-JcmdToolInfo {
            if($Path -match 'jdk25') { [pscustomobject]@{Path=$Path;Version='25.0.1';Status='Completed';Architecture='x64'} }
            else { [pscustomobject]@{Path=$Path;Version='26.0.2.1';Status='Completed';Architecture='x64'} }
        }
        $script:JcmdWasExecuted=$false
        Mock Get-CommandResult { $script:JcmdWasExecuted=$true; throw 'target jcmd invocation is forbidden' }
        $null=Resolve-JvmMinecraftCandidates @($candidate) @('C:\jdk26\bin\jcmd.exe','C:\jdk25\bin\jcmd.exe') 1
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'jcmd runtime compatibility' -and $_.Status -eq 'Succeeded' -and $_.Detail -match 'tool Java=25.*target Java=25'}).Count | Should Be 1
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'jcmd runtime compatibility' -and $_.Status -eq 'Partial' -and $_.Detail -match 'tool Java=26.*target Java=25'}).Count | Should Be 1
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'Matching jcmd discovery' -and $_.Status -eq 'Succeeded'}).Count | Should Be 1
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'JVM VM.command_line' -and $_.Status -eq 'Skipped'}).Count | Should Be 1
        $script:JcmdWasExecuted | Should Be $false
    }
    It 'records an inaccessible or missing root as partial coverage without terminating' {
        $script:Coverage=New-Object 'System.Collections.Generic.List[object]'
        { Get-SafeFiles -Roots @((Join-Path $script:TestRoot 'does-not-exist')) -Limit 10 } | Should Not Throw
        @($script:Coverage | Where-Object Status -eq 'Partial').Count | Should BeGreaterThan 0
    }
    It 'recognizes a synthetic Java process candidate when CIM access fails' {
        Mock Get-CimMinecraftProcesses { throw 'synthetic access denied' }
        Mock Get-WmiMinecraftProcesses { throw 'synthetic WMI access denied' }
        Mock Get-JavaProcessCandidates { @([pscustomobject]@{Id=4321;ProcessName='javaw';Path='C:\Java\bin\javaw.exe'}) }
        (Get-ProcessInventory)[0].Detection | Should Match 'candidate'
    }
    It 'uses parent and managed Java path when command-line access is denied' {
        $managed='C:\Users\Test\AppData\Roaming\.minecraft\runtime\java-runtime-gamma\bin\javaw.exe'
        $rows=@(
            [pscustomobject]@{Name='MinecraftLauncher.exe';ProcessId=111;ParentProcessId=0;ExecutablePath='';CommandLine='';CommandLineStatus='Unavailable';CommandLineError='';CimObject=[pscustomobject]@{}}
            [pscustomobject]@{Name='javaw.exe';ProcessId=200;ParentProcessId=111;ExecutablePath=$managed;CommandLine='';CommandLineStatus='Restricted';CommandLineError='Access denied reading process command line';CimObject=[pscustomobject]@{}}
            [pscustomobject]@{Name='OtherApp.exe';ProcessId=222;ParentProcessId=0;ExecutablePath='';CommandLine='';CommandLineStatus='Unavailable';CommandLineError='';CimObject=[pscustomobject]@{}}
            [pscustomobject]@{Name='java.exe';ProcessId=201;ParentProcessId=222;ExecutablePath='C:\Java\bin\java.exe';CommandLine='';CommandLineStatus='Restricted';CommandLineError='Access denied';CimObject=[pscustomobject]@{}}
        )
        Mock Get-CimMinecraftProcesses { $rows }
        Mock Get-JavaProcessCandidates { @([pscustomobject]@{Id=200;ProcessName='javaw';Path=$managed},[pscustomobject]@{Id=201;ProcessName='java';Path='C:\Java\bin\java.exe'}) }
        Mock Invoke-CimMethod { throw 'synthetic owner query unavailable' }
        $found=@(Get-ProcessInventory)
        $found.Count | Should Be 2
        ($found | Where-Object ProcessId -eq 200).Identified | Should Be $true
        ($found | Where-Object ProcessId -eq 201).Identified | Should Be $false
        @($script:ProcessMethodResults | Where-Object {$_.ProcessId -eq 200 -and $_.Method -eq 'Process command line' -and $_.Status -eq 'Restricted'}).Count | Should Be 1
        @($script:ProcessMethodResults | Where-Object {$_.ProcessId -eq 200 -and $_.Method -eq 'Parent process' -and $_.Status -eq 'Succeeded'}).Count | Should Be 1
    }
    It 'continues with multiple unconfirmed Java candidates when CIM and WMI are denied' {
        Mock Get-CimMinecraftProcesses { throw 'Access denied by synthetic CIM fixture' }
        Mock Get-WmiMinecraftProcesses { throw 'Access denied by synthetic WMI fixture' }
        Mock Get-JavaProcessCandidates { @([pscustomobject]@{Id=301;ProcessName='javaw';Path='C:\JavaA\bin\javaw.exe'},[pscustomobject]@{Id=302;ProcessName='java';Path='C:\JavaB\bin\java.exe'}) }
        $found=@(Get-ProcessInventory)
        $found.Count | Should Be 2
        @($found | Where-Object Identified).Count | Should Be 0
        @($script:ProcessMethodResults | Where-Object {$_.Method -eq 'CIM Win32_Process query' -and $_.Status -eq 'Restricted'}).Count | Should Be 1
        @($script:ProcessMethodResults | Where-Object {$_.Method -eq 'WMI Win32_Process fallback' -and $_.Status -eq 'Restricted'}).Count | Should Be 1
    }
    It 'uses the standard-user process-token owner fallback when CIM owner lookup is denied' {
        $rows=@([pscustomobject]@{Name='javaw.exe';ProcessId=455;ParentProcessId=0;ExecutablePath='C:\Java\bin\javaw.exe';CommandLine='';CommandLineStatus='Restricted';CommandLineError='Access denied';CimObject=[pscustomobject]@{}})
        Mock Get-CimMinecraftProcesses { $rows }
        Mock Get-JavaProcessCandidates { @([pscustomobject]@{Id=455;ProcessName='javaw';Path='C:\Java\bin\javaw.exe';StartTime=(Get-Date)}) }
        Mock Invoke-CimMethod { throw 'Access denied for synthetic owner query' }
        Mock Get-ProcessOwnerToken { [pscustomobject]@{Status='Succeeded';Owner='SYNTHETIC\User';Detail='Synthetic limited-token result.'} }
        $found=@(Get-ProcessInventory)
        $found[0].Owner | Should Be 'SYNTHETIC\User'
        $found[0].OwnerStatus | Should Be 'Succeeded'
        @($script:ProcessMethodResults|Where-Object{$_.ProcessId -eq 455 -and $_.Method -eq 'Windows process owner token' -and $_.Status -eq 'Succeeded'}).Count | Should Be 1
    }
    It 'uses the Windows process snapshot to identify a launcher-managed Java child after CIM and WMI denial' {
        $managed='C:\Users\Test\AppData\Roaming\ModrinthApp\meta\java_versions\zulu\bin\javaw.exe'
        Mock Get-CimMinecraftProcesses { throw 'Access denied' }
        Mock Get-WmiMinecraftProcesses { throw 'Access denied' }
        Mock Get-CimInstance { throw 'Access denied' }
        Mock Get-WmiObject { throw 'Access denied' }
        Mock Get-ToolhelpProcessInventory { @([pscustomobject]@{ProcessId=500;ParentProcessId=0;Name='ModrinthApp.exe'},[pscustomobject]@{ProcessId=501;ParentProcessId=500;Name='javaw.exe'}) }
        Mock Get-JavaProcessCandidates { @([pscustomobject]@{Id=501;ProcessName='javaw';Path=$managed}) }
        $found=@(Get-ProcessInventory)
        $found.Count | Should Be 1
        $found[0].Identified | Should Be $true
        $found[0].ParentName | Should Be 'ModrinthApp.exe'
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'Windows Toolhelp process snapshot' -and $_.Status -eq 'Succeeded'}).Count | Should Be 1
    }
    It 'identifies a launcher-managed Java process from multiple Minecraft native modules when its parent has exited' {
        $managed='C:\Users\Test\AppData\Roaming\ModrinthApp\meta\java_versions\zulu\bin\javaw.exe'
        Mock Get-CimMinecraftProcesses { throw 'Access denied' }
        Mock Get-WmiMinecraftProcesses { throw 'Access denied' }
        Mock Get-CimInstance { throw 'Access denied' }
        Mock Get-WmiObject { throw 'Access denied' }
        Mock Get-ToolhelpProcessInventory { @([pscustomobject]@{ProcessId=601;ParentProcessId=0;Name='javaw.exe'}) }
        Mock Get-JavaProcessCandidates { @([pscustomobject]@{Id=601;ProcessName='javaw';Path=$managed}) }
        Mock Get-MinecraftModuleIndicators { [pscustomobject]@{Status='Succeeded';IsMinecraftNativeSet=$true;ModuleNames=@('lwjgl.dll','glfw.dll','lwjgl_opengl.dll');NativePaths=@('C:\Users\Test\AppData\Roaming\ModrinthApp\meta\natives\lwjgl.dll','C:\Users\Test\AppData\Roaming\ModrinthApp\meta\natives\glfw.dll');Detail='Synthetic launcher-managed LWJGL modules.'} }
        $found=@(Get-ProcessInventory)
        $found.Count | Should Be 1
        $found[0].Identified | Should Be $true
        $found[0].Detection | Should Match 'LWJGL natives'
    }
    It 'recognizes a grouped Minecraft native module set only from launcher native paths' {
        $base='C:\Users\Test\AppData\Roaming\ModrinthApp\meta\natives\'
        $modules=@([pscustomobject]@{ModuleName='lwjgl.dll';FileName=($base+'lwjgl.dll')},[pscustomobject]@{ModuleName='glfw.dll';FileName=($base+'glfw.dll')},[pscustomobject]@{ModuleName='lwjgl_opengl.dll';FileName=($base+'lwjgl_opengl.dll')})
        Mock Get-Process { [pscustomobject]@{Modules=$modules} }
        (Get-MinecraftModuleIndicators 777).IsMinecraftNativeSet | Should Be $true
    }
    It 'does not use jcmd to identify an otherwise unconfirmed Java process' {
        $script:ProcessMethodResults=New-Object 'System.Collections.Generic.List[object]'
        $candidate=[pscustomobject]@{ProcessId=9876;Detection='Java process candidate; command line restricted';Identified=$false;IdentificationMethods=@();CommandLine='';GameDir=$null;Version=$null}
        $script:JcmdWasExecuted=$false
        Mock Get-CommandResult { $script:JcmdWasExecuted=$true; [pscustomobject]@{Status='Completed';ExitCode=0;Output='9876: net.minecraft.client.main.Main --gameDir "C:\games\instance" --version 1.21';Error=''} }
        $result=@(Resolve-JvmMinecraftCandidates @($candidate) @('C:\Java\bin\jcmd.exe') 1)[0]
        $result.Identified | Should Be $false
        $result.GameDir | Should Be $null
        $script:JcmdWasExecuted | Should Be $false
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'JVM VM.command_line' -and $_.Status -eq 'Skipped'}).Count | Should Be 1
    }
    It 'preserves native-module identity while marking JVM command-line inspection skipped' {
        $script:ProcessMethodResults=New-Object 'System.Collections.Generic.List[object]'
        $identified=[pscustomobject]@{ProcessId=9877;Detection='Minecraft process identified by native module indicators';Identified=$true;IdentificationMethods=@('Minecraft native module indicators');CommandLine='';GameDir=$null;Version=$null}
        $result=@(Resolve-JvmMinecraftCandidates @($identified) @('C:\Java\bin\jcmd.exe') 1)[0]
        $result.Identified | Should Be $true
        @($script:ProcessMethodResults|Where-Object{$_.Method -eq 'JVM VM.command_line' -and $_.Status -eq 'Skipped'}).Count | Should Be 1
    }
    It 'discovers jcmd beside a launcher bundled Java executable' {
        $bin=Join-Path $script:TestRoot 'bundled runtime with spaces\bin';New-Item -ItemType Directory -Path $bin -Force | Out-Null
        $java=Join-Path $bin 'javaw.exe';$jcmd=Join-Path $bin 'jcmd.exe';[IO.File]::WriteAllBytes($java,(New-Object byte[] 1));[IO.File]::WriteAllBytes($jcmd,(New-Object byte[] 1))
        $script:Coverage=New-Object 'System.Collections.Generic.List[object]'
        Mock Get-JavaProcessCandidates { @([pscustomobject]@{Id=7788;ProcessName='javaw';Path=$java}) }
        @((Get-JcmdPaths)|Where-Object{$_ -eq $jcmd}).Count | Should Be 1
    }
    It 'writes only positive findings to TXT HTML and JSON while preserving separate coverage errors' {
        $dir=Join-Path $script:TestRoot 'report path';New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $finding=[pscustomobject]@{Category='Verified Artifact';Title='Synthetic <finding>';Detail='client=<script>';Path='C:\test & <path>.jar';ProcessId=54321;ClientName='Meteor';ClientCategory='Mod client';MinecraftVersion='1.21';DetectionMethod='Verified SHA-256 signature';SignatureSource='https://example.invalid';EvidenceStrength='Synthetic positive fixture';InstalledStatus='Present';RuntimeAssociation='Installed artifact only';VerificationLimitations='Fixture';FileHash=('b'*64)}
        $weak=[pscustomobject]@{Category='Needs Manual Review';Title='Unverified review item';Detail='should not appear as a cheat finding';Path='C:\unverified.jar';ClientName='Unsupported Name'}
        $method=[pscustomobject]@{ProcessId=54321;Method='CIM Win32_Process query';Status='Restricted';Detail='Synthetic & <denied>'}
        $coverage=[pscustomobject]@{Check='JVM class inspection';Status='Skipped';Detail='Target inspection restricted by passive policy'}
        $report=[pscustomobject]@{ScannerVersion='7.2';Timestamp=(Get-Date).ToString('o');Mode='Test';UserName='Synthetic';Status='Completed with limitations';Summary='Synthetic';DurationSeconds=0;FilesAnalyzed=1;Profiles=@();Processes=@();Java=@();Runtime=@();ClientCoverage=@();ProcessIdentificationMethods=@($method);Findings=@($finding,$weak);Coverage=@($coverage);Diagnostics=@();Limitations=@()}
        $paths=Write-Reports $report $dir
        (Test-Path -LiteralPath $paths.Text) | Should Be $true
        (Test-Path -LiteralPath $paths.Json) | Should Be $true
        $html=Get-Content -LiteralPath $paths.Html -Raw
        $text=Get-Content -LiteralPath $paths.Text -Raw
        $json=Get-Content -LiteralPath $paths.Json -Raw | ConvertFrom-Json
        $html | Should Match 'DETECTED CHEATS'
        $html | Should Match '&lt;path&gt;'
        $html | Should Not Match 'Unverified Name'
        (Get-Content -LiteralPath $paths.Html -Raw) | Should Match 'CIM Win32_Process query'
        (Get-Content -LiteralPath $paths.Html -Raw) | Should Match 'Synthetic &amp; &lt;denied&gt;'
        $text | Should Match 'DETECTED CHEATS'
        $text | Should Match 'SHA-256'
        $text | Should Match 'CIM Win32_Process query'
        $text | Should Not Match 'Unverified Name'
        @($json.Findings).Count | Should Be 1
        $json.Findings[0].FileHash | Should Be ('b'*64)
        $json.Coverage[0].Status | Should Be 'Skipped'
        $json | ConvertTo-Json -Depth 8 | Should Match 'VerificationLimitations'
        $json | ConvertTo-Json -Depth 8 | Should Match 'ProcessIdentificationMethods'
    }
    It 'omits the cheat results section when findings are empty without saying clean or not detected' {
        $dir=Join-Path $script:TestRoot 'empty report';New-Item -ItemType Directory -Path $dir -Force|Out-Null
        $report=[pscustomobject]@{ScannerVersion='7.2';Timestamp=(Get-Date).ToString('o');Mode='Test';UserName='Synthetic';Status='Completed';Summary='Scan workflow completed with no positive cheat findings.';DurationSeconds=0;FilesAnalyzed=0;Profiles=@();Processes=@();Java=@();Runtime=@();ClientCoverage=@();ProcessIdentificationMethods=@();Findings=@();Coverage=@();Diagnostics=@();Limitations=@()}
        $paths=Write-Reports $report $dir
        (Get-Content -LiteralPath $paths.Text -Raw) | Should Not Match 'DETECTED CHEATS|No findings were recorded|No Cheat|Not Found|PC Clean'
        (Get-Content -LiteralPath $paths.Html -Raw) | Should Not Match 'DETECTED CHEATS|No Cheat|Not Found|PC Clean'
        @((Get-Content -LiteralPath $paths.Json -Raw|ConvertFrom-Json).Findings).Count | Should Be 0
    }
    It 'keeps the launchers portable and waiting for user input' {
        $cmd=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $script:ScannerFile) 'Run-Scanner.cmd') -Raw
        $cmd | Should Match '%~dp0'
        $cmd | Should Match 'ExecutionPolicy Bypass'
        $cmd | Should Match 'Press Enter'
    }
    It 'accepts the current PowerShell host parser and declared PowerShell 5.1 support' {
        $errors=$null;[System.Management.Automation.Language.Parser]::ParseFile($script:ScannerFile,[ref]$null,[ref]$errors)|Out-Null
        @($errors).Count | Should Be 0
        $script:ScannerVersion | Should Be '7.2'
    }
    It 'keeps the runtime CMD launcher separate and configured for runtime mode' {
        $cmd=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $script:ScannerFile) 'Run-Runtime-Diagnostic.cmd') -Raw
        $cmd | Should Match '-RuntimeDiagnostic'
        $cmd | Should Match 'Press Enter'
    }
    It 'uses one-click launcher mode for the combined offline and runtime pipeline' {
        $cmd=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $script:ScannerFile) 'Run-Scanner.cmd') -Raw
        $cmd | Should Match 'unified automatic scan'
        $cmd | Should Not Match '-RuntimeDiagnostic'
        $cmd | Should Match '%~dp0'
    }
    It 'automatically performs runtime and offline stages in the unified scan when Java is present' {
        $out=Join-Path $script:TestRoot 'unified-output'
        Mock Get-ProcessInventory { @([pscustomobject]@{ProcessId=54321;Name='javaw.exe';ExecutablePath='C:\Java\bin\javaw.exe';CommandLine='';GameDir='C:\fixture\game';Version='1.21';Identified=$true;IdentificationMethods=@('Synthetic launch marker');Detection='Minecraft process identified; synthetic test'},[pscustomobject]@{ProcessId=54322;Name='java.exe';ExecutablePath='C:\Other\java.exe';CommandLine='';GameDir=$null;Version=$null;Identified=$false;IdentificationMethods=@();Detection='Java process candidate; unrelated synthetic process'}) }
        Mock Get-JcmdPaths { @() }
        Mock Get-JavaRuntimeInfo { [pscustomobject]@{Status='Completed';Path='C:\Java\bin\java.exe';Version='21';Vendor='Synthetic';Detail='fixture'} }
        Mock Get-MinecraftProfiles { @() }
        Mock Add-LogFindings {}
        Mock Add-ConfigurationFindings {}
        Mock Get-SafeFiles { @() }
        $result=Invoke-MinecraftCheatScan -ReportDir $out -FileLimit 20 -ArchiveLimit 10485760 -NestedDepth 1 -JcmdTimeout 1
        $result.Mode | Should Be 'UnifiedAutomatic'
        $result.MinecraftProcessCandidates | Should Be 2
        $result.IdentifiedMinecraftProcesses | Should Be 1
        Assert-MockCalled Get-JavaRuntimeInfo -Times 1
        Assert-MockCalled Add-LogFindings -Times 1
        $script:ProgressPercent | Should Be 100
        @(Get-ChildItem -LiteralPath $out -Filter '*.json').Count | Should Be 1
    }
    AfterEach { Get-ChildItem -LiteralPath $script:TestRoot -Force | Remove-Item -Recurse -Force }
}
