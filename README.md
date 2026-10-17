# Minecraft Cheat Scanner v7.2

A portable, local-only PowerShell scanner for Minecraft Java installations, launcher profiles, mods, logs, user-folder artifacts, and accessible Java runtime processes. It is read-only and does not delete, quarantine, upload, or modify scanned files. Findings describe evidence and limitations; an empty result cannot prove a system is clean.

## Launch

Double-click `Run-Scanner.cmd` for one unified bounded scan. It checks files and profiles, discovers Java/Minecraft processes, and attempts accessible runtime checks automatically when Minecraft is running. If Minecraft is closed, it reports unavailable runtime checks and continues offline. Administrator rights are not requested. `Run-Runtime-Diagnostic.cmd` remains available for an optional runtime-only check. The launchers use their own folder to locate the script, try PowerShell 7 when it starts successfully, then fall back to Windows PowerShell 5.1. They use process-scoped execution-policy arguments and wait for Enter after showing the report paths.

PowerShell users can run `scan-cheats.ps1` directly or use `-OutputDirectory 'C:\path with spaces\Reports'`. Scan discovery is independent of the current working directory and scanner folder.

## Detection and evidence

`signatures.json` has six exact SHA-256 records for specific Meteor Client release JARs and a coverage inventory for every requested client. Only hashes with provenance and a trusted HTTPS source are accepted; duplicate digests are rejected. Five Meteor hashes are source-derived, and one has additional independent sample corroboration. There are no verified DLL hashes and no verified release hashes for the other clients.

The scanner matches the documented Fabric metadata IDs and package prefixes for Meteor Client, LiquidBounce, and Wurst. Those matches are **Manual Review** leads, since metadata and class names can be copied or forged. A verified release hash is reported as **Verified Artifact**. **Verified Runtime Association** requires exact overlap between a verified artifact's classes and classes returned for the identified active Minecraft process. A client name, unknown module, unsigned DLL, or custom ClassLoader alone is not proof of cheating.

The catalog names the following clients but does not imply coverage beyond each row's actual indicators: Meteor Client, LiquidBounce, Wurst, Aristois, Impact, Inertia, BleachHack, ThunderHack, RusherHack, Future Client, Lambda Client, Kami Blue, Doomsday Client, Rise Client, FDPClient, Augustus, Tenacity, Flux, Sigma, Vape, Vape Lite, Raven, Drip, Entropy, Whiteout, Dream, and Slinky. See [SIGNATURE-SOURCES.md](SIGNATURE-SOURCES.md) and the report's coverage table for current method-by-method coverage.

The runtime checks inspect process metadata when Windows exposes it, file-backed process modules, Authenticode state, launcher-log correlations, and exact catalog hash matches. The scanner discovers `jcmd.exe` beside Java runtimes and in configured/common JDK locations, and reports its version and architecture against the target. It deliberately does **not** send `jcmd` commands to a running JVM: OpenJDK's Windows attach implementation may write a helper into the target process and start a remote thread. JVM arguments, classloader statistics, and class histograms are therefore marked skipped/unknown; no JVM class inspection is claimed. Readable JAR/ZIP mod candidates and accessible loaded DLLs receive local SHA-256 hashes, shown in reports. Mod authenticity is `UNKNOWN` unless an exact trusted catalog digest matches; unknown or changed digests do not prove tampering. JAR signature-file entries are reported, but the scanner does not cryptographically validate JAR signatures. File hashing has a configurable per-file bound and records skipped or changed files. The scanner does not inject code, dump process memory, or monitor historical JVM attach activity. Signed JAR certificates are not cryptographically validated; module signatures are reported via Windows Authenticode, and no DLL cheat hashes are currently catalogued.

### Doomsday-specific detection coverage

The catalog currently has **insufficient Doomsday-specific coverage**: no verified Doomsday hash, metadata ID, package/class prefix, JVM agent marker, or native-module signature is available. The official site describes DoomsDay as a cross-version utility/ghost mod and advertises randomized loader filenames, but publishes no technical detection identifier ([product description](https://doomsdayclient.com/), [feature page](https://doomsdayclient.com/features)). Those descriptions are not used as signatures. Loaded file-backed modules are enumerated and hashed where accessible, but a generic or unsigned DLL does not identify Doomsday. JVM class inspection is unavailable under this scanner's passive-only policy, and dynamically loaded code that has no visible module or file artifact may not be observable.

The previous manual injection attempt has no before/after scan reports in this project workspace. Therefore the specific module, agent, file, or log delta from that test cannot be established, and no controlled Doomsday detection success is claimed. To collect a repeatable comparison, save a `-RuntimeDiagnostic` report with a clean game process, apply your test manually outside the scanner, then save a second report with the same process/instance and compare the `Runtime`, `ProcessIdentificationMethods`, `Coverage`, and `ModArtifacts` JSON fields. Do not interpret an unfamiliar module or a baseline difference alone as Doomsday evidence. A Doomsday finding will be added only after a stable client-specific artifact or identifier is verified against a clean baseline.

### Findings presentation

The main `DETECTED CHEATS` section in the console and reports contains only verified artifact/runtime matches, confirmed indicators, or high-suspicion findings. Weak filename, metadata, and unfamiliar-module leads are not promoted into that section. Failed, restricted, partial, and skipped checks remain in the separate coverage and diagnostics sections. An empty findings section does not establish that the system is cheat-free.

### Process identification when Windows blocks command lines

Process discovery records each method and its result in the reports and diagnostics log. It reads CIM/WMI process metadata when allowed, uses `Get-Process` for executable paths and start times, and uses the Windows Toolhelp snapshot for process names and parent IDs without requesting command lines. When CIM/WMI owner lookup is denied, a read-only process-token query requests only limited process query rights and reports the resolved owner or its own access failure. Minecraft identification uses multiple independent signals and does not classify every Java process as Minecraft.

When process arguments and working-directory data are blocked, Modrinth profile matching can use a unique profile `latest.log` loader startup record whose launch time matches the Java process start time. It only applies a match when exactly one profile meets the bounded time window. The scanner also parses a bounded loader mod-list section and compares top-level mod IDs and versions with installed JAR metadata. This is loader-log correlation, not proof of JVM class loading. Missing, partial, or mismatched log evidence is reported per JAR rather than treated as a cheat finding.

On the validation host, CIM/WMI denied process command-line and owner queries. Toolhelp and `Get-Process` found two Java processes. The scanner confirmed PID 9720 as Minecraft using its Modrinth-managed Java path and grouped LWJGL/OpenAL modules; a limited process-token query resolved both process owners to the current user. PID 9720 is Azul Zulu Java 25.0.4.1 x64. Registry, PATH, configured Java homes, common install roots, and launcher runtime locations yielded no Java 25 JDK `jcmd`; the Modrinth Java 25 runtime is a JRE, and the only discovered tool is JDK 26.0.2.1 x64. An earlier live attempt failed at `VirtualMachineImpl.openProcess` with Access Denied before a JVM handshake. OpenJDK's Windows attach implementation requests `PROCESS_ALL_ACCESS`; narrower token and module queries succeeded ([OpenJDK Windows attach source](https://code.googlesource.com/edge/openjdk/+/refs/heads/master/jdk/src/windows/native/sun/tools/attach/WindowsVirtualMachine.c)). This identifies the immediate denied operation but does not distinguish the underlying ACL or security policy. The major-version mismatch is recorded but cannot explain an error before JVM communication. JVM arguments and `-XX:+DisableAttachMechanism` remain unknown. To keep the scanner passive, current runs do not retry attach; JVM class and classloader inspection is marked not attempted.

The active Modrinth log reported 174 loader mod/dependency entries, including nested dependency tree lines. The scanner parsed 51 top-level entries and found exact ID and version matches for all 48 installed JARs in `uku_s pvp modpack`. These records show that the loader log lists the same mod IDs and versions; they do not prove that JVM classes from each JAR were loaded. The scan also inspected 125 loaded DLL files. This is the current runtime coverage while JVM attach remains intentionally unused.

## Scope and limitations

Installation and launcher discovery covers the current Windows user's known folders and supported launcher configurations. Scans are local, read-only, bounded by file, recursion, archive, expansion, and timeout limits, and skip reparse-point traversal. JVM attach/class inspection is not currently attempted under the passive-only policy; the installed `jcmd` version is diagnostic inventory only. Memory-only, renamed, encrypted, patched, or novel injectable cheats can evade this scanner. Runtime checks are marked unavailable if Minecraft is closed.

## Reports

Each scan attempts to write timestamped TXT, HTML, JSON, and diagnostics files. The preferred output is `Reports` beside the script; the scanner falls back to current-user LocalAppData and then TEMP if needed. HTML is self-contained, searchable, filterable, responsive, and HTML-encodes report data. 100% means the planned scan and report workflow finished, not that all cheats were detected.

## Tests

Run the synthetic regression tests in Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Pester -Script .\tests\scan-cheats.V7.Tests.ps1"
```

The suite uses synthetic in-memory JAR data and does not execute cheat software. It also asserts that the scanner never invokes jcmd against a target PID and preserves alternate process identification while marking JVM checks skipped. PowerShell 7 should be tested with the same Pester file when an actual `pwsh.exe` installation is available.

The v7.2 synthetic regressions ran under Windows PowerShell 5.1 with Pester 3.4.0: 56 passed, 0 failed, and 0 skipped. They cover Doomsday coverage remaining insufficient without verified signatures, generic module deltas not becoming positive findings, positive-only console/report formatting, and error coverage remaining visible. The synthetic tests do not simulate a real Doomsday injection and cannot validate Doomsday-specific detection. A PowerShell 7 execution alias was present, but no usable PowerShell 7 installation returned from validation attempts; PowerShell 7 test results are therefore unavailable on this host. JVM class inspection is not attempted by policy.





## Rust v8 migration workspace

The native Rust rewrite is in [`exe`](exe/README.md). A Windows x64 GitHub Actions workflow is configured to resolve Cargo dependencies, test and build the Rust application, smoke-test it from an isolated folder, and publish the EXE plus a resolved Cargo.lock artifact. The workflow has not run. Local Cargo access to crates.io remains blocked, so no Rust compile or native EXE is verified. The current `exe\dist\Minecraft-Cheat-Scanner.exe` is the obsolete .NET/PowerShell compatibility launcher; do not distribute or run it as the native application. The old v7.2 PowerShell scanner remains only as legacy reference. The optional agent previously passed a standalone Java 26 fixture test, not a Minecraft integration test. The Git remote is configured as `https://github.com/Mr-Gamiya/MC-Cheat-detector.git`; the new local repository has no commit yet. See the migration matrix for incomplete functions and limitations.
