## 8.0 GUI startup diagnostics - 2026-10-17

- Added a local startup log with user-path redaction and top-level error/panic reporting for native GUI initialization failures.
- Added `--self-test` to validate platform/import readiness, built-in scan limits, embedded icon/manifest/catalog/optional-agent resources, and defaults before any egui initialization.
- Updated Windows CI to run the honest headless self-test and retain its diagnostic log as an artifact. The test does not claim interactive GUI startup validation.
- Validation in this change: pending Cargo dependency access; see final task report for actual results.

## 8.0 repository and hosted-build preparation - 2026-10-17

- Initialized the local `main` branch and configured `origin` as `https://github.com/Mr-Gamiya/MC-Cheat-detector.git`; no files were staged or pushed.
- Added ignore rules for Rust/build outputs, the stale `exe/dist` compatibility launcher and sidecars, scan reports/logs, credentials, keys, and session files. A secret-pattern scan found no candidate files in the source tree.
- Hardened the Windows x64 workflow to resolve or validate Cargo.lock, fetch locked dependencies, build the JVMTI agent before Cargo, assert a native Rust build marker, run an isolated copied-EXE scan, check report outputs, and publish the EXE and resolved lockfile as separate artifacts.
- The workflow has not run. Cargo.lock is still absent and the Rust application remains unbuilt; no migration or runtime completion is claimed.
## 8.0 native Rust migration follow-up — 2026-10-17

- Added an exhaustive 74-function purpose/input/output/replacement/test-status matrix in `FUNCTION-MIGRATION-MATRIX.md`, alongside the feature acceptance map and current dependency/build/runtime limits.
- Changed the Rust scanner to validate and use the compile-time signature catalog only. It no longer prefers a neighboring signatures.json, keeping portable execution tied to the embedded catalog.
- Updated release ordering to build the optional x64 JVMTI agent before Cargo. The GUI build script embeds it when available, and the GUI now offers explicit current-user extraction with x64 PE/DLL validation. Existing files are not overwritten, and launcher settings are never changed.
- Added a Windows 2022 GitHub Actions workflow to resolve dependencies, run formatting/check/Clippy/tests, build the native x64 application, verify its PE machine type, and upload only the EXE.
- Removed the fallback launcher source/build script. Workspace policy blocked deleting the already generated fallback binary and sidecars under exe\dist; exe\README.md labels that file as non-native and not distributable. No Rust EXE build is claimed.
- Validation this turn: `cargo fmt --all -- --check` passed. `cargo check --workspace` was blocked during registry access (curl error 7, TCP 443 to index.crates.io); offline Rust tests stop before compilation because `crc32fast` is not cached. The legacy PowerShell 5.1/Pester 3.4 suite ran 56 tests (56 passed, 0 failed). The release script parser passed. No Rust compile, Clippy, native EXE test, or GitHub Actions run is claimed. The earlier standalone Java 26 agent smoke test is not evidence of Minecraft compatibility.
## 8.0 Rust migration work (source milestone; not yet built)

- Audited the existing v7.2 process identification, Modrinth profile correlation, bounded JAR and nested-JAR analysis, SHA-256 catalog, loaded-module checks, findings-only reporting, Pester tests, and Doomsday-specific evidence gap. Recorded risks and acceptance gates in `MIGRATION-PLAN.md`.
- Added an isolated Rust workspace under `exe\` with a scanner core and eframe GUI source. The migration retains the original PowerShell scanner, its signature catalog, launchers, reports, and Pester suite as the fallback.
- Added passive Windows Java process/module enumeration using limited query access; known-launcher profile discovery; bounded ZIP/JAR metadata and hash inspection; exact trusted-hash matching; positive-only TXT, HTML, JSON, and diagnostics generation; and a GUI source with cancellation/progress and coverage reporting.
- Added an opt-in startup-time JVMTI agent source and PID/creation-time/session-bound local named-pipe protocol. It does not attach to existing processes, transform classes, or alter game behavior. The agent and Rust application are not compiled or runtime-validated.
- Doomsday coverage remains insufficient: no verified Doomsday-specific signature or controlled baseline/injected comparison evidence is present. No Doomsday finding is claimed.
- Validation blocker: `cargo.exe`, `rustc.exe`, and `rustfmt.exe` were not found on PATH or in the checked standard locations. Rust tests, Windows x64 build, GUI launch, JVMTI agent build, and v8 live runtime checks were not run. `exe\dist\Minecraft-Cheat-Scanner.exe` has not been produced. Root v7.2 remains the usable fallback.
- Preserved-fallback validation during implementation: Windows PowerShell 5.1 Pester 3.4.0 ran 56 tests (56 passed, 0 failed, 0 skipped); the existing scanner parser check passed. This validates the unchanged v7.2 fallback, not Rust v8.
- Follow-up toolchain verification again found no `rustc`, `cargo`, `rustup`, Visual Studio Build Tools, or Windows SDK. `winget` is present, but no installation was attempted. Updated the release script to check MSVC/SDK/target prerequisites, run formatting, check, Clippy, and tests, and verify the built and packaged executable is x64 PE before printing success. The script parser passes; Rust build stages remain blocked until prerequisites are installed.
- Agent prerequisite check found JDK `C:\Program Files\Java\jdk-26.0.2.1` with `jvmti.h`; its `java.exe` PE machine is x64 (`0x8664`). The JVMTI DLL was not compiled or initialized because MSVC Build Tools and Cargo/Rust are absent.
- User-authorized Rustup installation was attempted through `winget`, but the installer returned no output for about 45 seconds. The attempt was interrupted; follow-up checks found no Rust tools or lingering installer process. No MSVC/Windows SDK installation was attempted because its Visual Studio workload requires a separate, large system-level installer.
- Updated environment check: Rust 1.99.1 stable MSVC and its x64 Windows target are now available at `%USERPROFILE%\.cargo\bin` (not yet on the active process PATH). Visual Studio 2022 Community includes x64 MSVC and the Windows SDK; `VsDevCmd.bat` supplies the required environment. `cargo fmt --all -- --check` passed. Cargo dependency resolution remains blocked: the registry cache is empty and requests to `https://index.crates.io` fail to connect; offline `cargo check`, Clippy, and tests report missing `chrono`.
- Built `exe\dist\agent\mc-jvmti-agent.dll` (x64, 320,000 bytes after the initial build; rebuilt after a `NOMINMAX` compile fix) and passed the controlled Java 26 `tests\agent-smoke.ps1` test for JVMTI initialization, loaded classes, signature conversion, named-pipe identity/session exchange, and graceful marker cleanup. This is not Minecraft runtime validation.
- Cargo connectivity diagnosis: DNS for `index.crates.io` resolved successfully, but TCP 443 failed to all returned addresses. HTTPS to `index.crates.io/config.json` and `static.crates.io` failed with `Unable to connect to the remote server`; Cargo `fetch -vv` failed with curl error 7 on `config.json`. No proxy environment variables or Cargo proxy config were present. No local registry cache, vendor directory, or lockfile exists; offline check confirms `chrono` is missing. Added `exe\.cargo\config.toml` selecting official sparse crates.io with timeout/retry settings and no TLS bypass. Connectivity remains blocked at TCP/network policy, before TLS.
- Follow-up verified `static.crates.io` DNS and TCP separately; DNS succeeds and all TCP 443 connection attempts fail. `netsh winhttp show proxy` reports direct access, and Cargo config inspection found only the project sparse/retry config. No lockfile/vendor/cache was created or modified. The failing TCP checks do not identify whether the block is local firewall or upstream network policy.
## 7.2 - findings-only results and Doomsday coverage review

- Bumped scanner version to v7.2. The report `Findings` array, TXT/HTML detected-cheats section, and console results now include only `Verified Artifact`, `Verified Runtime Association`, `Confirmed Indicator`, and `High Suspicion` categories. Empty findings are omitted; scan errors remain in separate coverage/diagnostics output.
- Added SHA-256 values to positive signature findings and a shared findings formatter for the console and TXT report. HTML findings are searchable and include evidence method, hash, process association, confidence, source, and limitations.
- Reviewed Doomsday detection after the user-reported manual injection. No before/after test reports or artifact samples from that attempt are present in the workspace. Existing code can enumerate accessible file-backed modules and inspect their hashes/Authenticode, but JVM class inspection remains intentionally skipped. No verified Doomsday hash, package/class identifier, metadata ID, agent marker, or native module signature was found in the catalog or trustworthy public product material. No unsupported signature was added; coverage is explicitly marked insufficient in catalog and scan diagnostics.
- Added synthetic tests for insufficient Doomsday coverage, generic module delta handling, findings-only output in reports, no-result section omission, and preserved restricted-check coverage. These tests do not claim Doomsday was detected or simulate injection. PowerShell 5.1 Pester results are recorded after execution below.
- Validation: Windows PowerShell 5.1 with Pester 3.4.0 ran 56 tests (56 passed, 0 failed, 0 skipped); parser validation passed. The live passive scan identified PID 9720 as the active Modrinth process, matched profile uku_s pvp modpack, inventoried 48 JARs and inspected 125 modules. It reported zero positive cheat findings and 10 incomplete/failed/skipped checks. JVM command-line access was unavailable; class inspection was not attempted. This current snapshot does not validate detection from the previous manual injection.
- PowerShell 7 validation was attempted because a pwsh.exe WindowsApps alias is present, but the alias did not provide a usable shell; no PowerShell 7 pass is claimed.

## 7.1

### Passive JVM diagnostics follow-up - 2026-10-16

- Removed all target-PID `jcmd` execution paths. Windows JVM attach can write a helper into the target and create a remote thread; under the scanner's passive/read-only policy, no JVM attach command is now sent. JVM command-line, classloader, and class-histogram checks are explicitly `Skipped`/unknown, while process identification, loaded-module checks, launcher-log correlation, and filesystem analysis continue.
- Added regressions that assert jcmd is never launched for target-PID diagnostics, an unconfirmed Java process cannot be upgraded based on attach output, and a process identified by native modules remains identified with JVM checks skipped.
- Windows PowerShell 5.1 with Pester 3.4.0: 49 passed, 0 failed. A live runtime scan on 2026-10-16 identified Modrinth PID 9720 (Java 25.0.4.1 x64), correlated profile `uku_s pvp modpack`, parsed 51 top-level loader entries (174 including dependencies), matched ID/version evidence for all 48 installed profile JARs, and inspected 125 loaded DLL files. The discovered JDK tool was JDK 26.0.2.1 x64; no Java 25 match was found in searched locations. JVM command-line, classloader, and class-histogram inspection were not attempted. Report set: `reports/Minecraft-Cheat-Scan-2026-10-16_194843_251` (TXT, HTML, JSON, diagnostics). PowerShell 7 and a matching JDK 25 `jcmd` were unavailable on this host.

- JVM attach investigation: checked launcher Java 25.0.4.1 x64 against discovered diagnostic tools. The Modrinth-bundled Java 25 runtime is a JRE without `jcmd`; registry, PATH, Java-home, common install-root, and launcher-runtime discovery found only JDK 26.0.2.1 x64. Reports explicitly state that no matching tool was found in those locations and rank candidate tools by version and PE architecture.
- Diagnosed the live `Access is denied` at `VirtualMachineImpl.openProcess`. The Windows attach implementation requests `PROCESS_ALL_ACCESS`; token lookup and module enumeration succeeded with narrower rights. The Java 26 vs Java 25 mismatch is reported but does not explain the failure before JVM communication. JVM arguments remain inaccessible, so attach-disabled state is unknown. No permissions were elevated or bypassed.
- Added bounded parsing of the active Fabric loader's top-level mod list and per-JAR ID/version correlation. The current live log lists 174 total entries including nested dependencies; 51 top-level records were parsed, with exact ID/version matches for all 48 installed JARs. These log entries are not labeled as JVM class-load evidence.
- Latest live runtime report: `Minecraft-Cheat-Scan-2026-10-16_193654_522` (TXT, HTML, JSON, diagnostics). It records 125 loaded DLL files and no successful JVM class inspection.
- Added synthetic assertions for mismatched JDK major versions and loader-log/JAR correlation. Windows PowerShell 5.1 Pester 3.4.0: 48 passed, 0 failed.

- Runtime follow-up: verified Java executable architecture from PE headers and Java version, discovered jcmd beside the target runtime plus configured JDK roots, inspected each tool's Java major version and architecture, and tries best-matching tools first. Reports now show mismatches rather than implying a matching tool exists.
- Added a standard-user process owner fallback using `OpenProcess` limited query rights and the existing process token. It does not elevate, change process state, or bypass access controls; inaccessible owners remain restricted.
- Added conservative Modrinth active-profile correlation using the timestamped loader startup line in `latest.log` and the process start time. A unique match scopes mod inventory to that instance; ambiguous/incomplete results are left uncorrelated, and installed does not imply loaded.
- Attach denial reporting now separates the observed native `openProcess` access denial from a JVM attach-disabled response. If launch arguments are unavailable, `DisableAttachMechanism` remains unknown; classloader and class histogram checks are explicitly reported restricted.
- Added regressions for Java 25 x64 PE parsing, jcmd version/architecture ordering, Modrinth startup-log correlation, incomplete profile discovery, and process-token owner fallback. Windows PowerShell 5.1 Pester 3.4.0: 47 passed, 0 failed at that follow-up stage.
- Live validation on 2026-10-16: PID 9720 belongs to the current user, runs Azul Zulu Java 25.0.4.1 x64, maps 126 modules (125 DLL files), and uniquely correlates to Modrinth `uku_s pvp modpack`; 48 instance JARs were analyzed. The available jcmd is Java 26.0.2.1 x64 and attach gets `Access denied` at JVM native `openProcess`; no JVM classes/classloaders were inspected. Process args remain inaccessible, so attach-disabled state cannot be checked. PowerShell 7 is unavailable on this host.

- Made `Run-Scanner.cmd` the unified one-click workflow: it automatically inspects active Java/Minecraft processes and proceeds with offline files and profiles in the same scan. The runtime-only switch remains available as an advanced option.
- Added bounded local SHA-256 hashing for scanned mod archive candidates, configured JVM agents, and accessible loaded DLL modules, with an in-scan metadata cache and changed-during-scan detection.
- Added a mod artifact inventory to TXT, HTML, and JSON reports with hash, metadata, client identifiers, nested-entry list, runtime status, and authenticity classification. Authenticity is `UNKNOWN` without an exact trusted catalog reference; hash differences are not treated as proof of tampering.
- Added process, JAR/ZIP, DLL, hash, and incomplete-check counters to live progress and report summaries. Runtime checks remain best effort under standard-user permissions.
- Added content-based renamed archive selection using Minecraft loader metadata and known client package paths; unrelated ZIP archives are excluded from mod artifact hashing.
- Added a per-file hashing size ceiling, explicit skipped-hash coverage, total-files progress display, and JAR signature-file inventory. Signature files are reported as unverified; authenticity remains `UNKNOWN` without a trusted digest.
- Hardened process inventory so CIM reads basic process fields first and queries Java command lines per PID. Added per-process WMI/CIM fallbacks, `Get-Process` executable-path checks, and a read-only Windows Toolhelp snapshot for parent process names and IDs when WMI access is denied.
- Added conservative multi-signal Minecraft identification using readable launch markers, `jcmd VM.command_line`, a recognized launcher parent plus launcher-managed Java runtime, or a launcher-managed Java runtime plus a group of Minecraft LWJGL/OpenAL modules in a known launcher-native folder. Unconfirmed Java candidates are excluded from JVM and full loaded-module checks.
- Added active profile correlation for identified processes, sibling-runtime `jcmd.exe` discovery, and per-method process identification results in TXT, HTML, JSON, and diagnostics reports.
- Added synthetic regressions for denied command-line and WMI/CIM access, multiple Java processes, Toolhelp parent fallback, JVM command-line recovery, and runtime inspection gating.
- Validated under Windows PowerShell 5.1 with Pester 3.4.0. On this host, broad and per-PID CIM/WMI queries returned `Access denied`; Toolhelp and `Get-Process` found two Java candidates. One was confirmed from its Modrinth-managed Java path and five loaded LWJGL/OpenAL modules, then runtime inspection read Java 25.0.4.1 and 126 process modules (125 DLLs). `jcmd` attach returned `Access is denied`, and command-line/profile correlation remained unavailable. This is live process and module validation, with those JVM limitations recorded.
- Earlier v7.1 validation recorded 42 passing tests and an offline scan. The latest runtime follow-up results, including profile correlation and owner-token fallback, are documented above and supersede those earlier counts.

## 7.0

- Added a versioned catalog of all 27 requested mod-based, hacked, ghost, and injectable client names. Entries with no source-verified signatures or identifiers explicitly report no verified client-specific coverage.
- Kept six existing provenance-validated Meteor Client JAR hashes. No new JAR or DLL digests were invented. Duplicate SHA-256 entries are now rejected; exact hashes are labeled Verified Artifact.
- Added source-verified exact Fabric metadata identifiers and class package prefixes for Meteor Client, LiquidBounce, and Wurst. These produce Manual Review findings because names and metadata can be forged.
- Added runtime histogram checks for the documented package prefixes, expanded mod JAR client metadata reporting including nested archives, and added evidence fields for client, category, method, source, strength, Minecraft version, installed state, runtime association, and limitations.
- Split Verified Artifact from Verified Runtime Association. Runtime association requires exact class-name overlap between a verified catalogued artifact and classes from an identified Minecraft process. Unknown agents, custom ClassLoaders, unsigned modules, and unfamiliar DLLs remain review leads.
- Expanded TXT, searchable self-contained HTML, and JSON reports with an explicit method coverage matrix for all 27 catalog entries. Preserved diagnostics, read-only inspection, bounded archives, and both CMD launchers.
- Added 25 synthetic Pester regressions. Windows PowerShell 5.1 parser validation and Pester 3.4.0 completed with 25 passed, 0 failed. A final bounded offline scan analyzed 4,565 files across 8 profiles and generated TXT, HTML, JSON, and diagnostics at 100%; it reported 0 verified artifacts, 28 manual-review findings, and 16 incomplete checks. CIM denied command-line access for two javaw.exe candidates, so Minecraft ownership and live game correlation could not be validated. PowerShell 7 was unavailable because the discovered WindowsApps pwsh.exe was a 0-byte stub.
# Changelog`r`n`r`n## 7.1`r`n`r`n- Made `Run-Scanner.cmd` the unified one-click workflow: it automatically inspects active Java/Minecraft processes and proceeds with offline files/profiles in the same scan. The runtime-only switch remains available as an advanced option.`r`n- Added bounded local SHA-256 hashing for scanned mod archive candidates, configured JVM agents, and accessible loaded DLL modules, with an in-scan metadata cache and changed-during-scan detection.`r`n- Added a mod artifact inventory to TXT, HTML, and JSON reports with hash, metadata, client identifiers, nested-entry list, runtime status, and authenticity classification. Authenticity is `UNKNOWN` without an exact trusted catalog reference; hash differences are not treated as proof of tampering.`r`n- Added process, JAR/ZIP, DLL, hash, and incomplete-check counters to live progress and report summaries. Runtime checks remain best effort under standard-user permissions.`r`n`r`n

## 6.2.0

- Made scanner paths independent of the current working directory and resolved scanner assets from the script location with `$PSScriptRoot`, `$PSCommandPath`, and invocation-path fallbacks.
- Added current-user known-folder discovery, official `launcher_profiles.json` custom game directories, common launcher roots across AppData, LocalAppData, Documents, and user-profile folders, and bounded reads of Prism, MultiMC, and Modrinth launcher settings.
- Kept installation discovery deduplicated, bounded to 500 profiles, local-drive only, and excluded reparse-point roots and descendants. Targeted user scans now include discovered version directories and bounded Minecraft configuration checks.
- Added weighted `Write-Progress` phases with item counts, elapsed time, installation/finding totals, monotonic percentage, and text fallback for redirected hosts. 100% is emitted after all four report outputs finish.
- Added automatic timestamped readable TXT and self-contained dark HTML reports alongside structured JSON and diagnostics. HTML supports finding search/filter, expandable detail, coverage status, and HTML-encoded dynamic content. Reports fall back from the script folder to LocalAppData and TEMP.
- Preserved the `-NoHtml` parameter for compatibility but always generate HTML and TXT as required by the v6.2.0 report contract.
- Improved CIM-denied runtime handling with bounded Java process candidates and `jcmd VM.command_line` correlation; candidate-only checks are labeled as unconfirmed ownership. Runtime checks remain best effort and no Minecraft process was live-validated during this update.
- Updated both CMD launchers for the `Reports` folder and an explicit Enter-to-close prompt. They still prefer a runnable PowerShell 7 and otherwise use Windows PowerShell 5.1 without machine-wide execution-policy changes.
- Refreshed the catalog version metadata without adding hashes. Only existing provenance-validated Meteor Client digests remain; no signatures were inferred or fabricated.
- Added regression tests for arbitrary working directories, Unicode/space paths, multiple/custom profiles, nested JARs, progress, report generation/escaping, local-only path checks, and launcher behavior.
- Validated syntax and ran the Pester suite under Windows PowerShell 5.1: 16 passed, 0 failed. A full offline scan and a Unicode report-path scan completed and generated TXT, HTML, JSON, and diagnostics. PowerShell 7 was unavailable here (the `pwsh.exe` WindowsApps stub was 0 bytes), and no live Minecraft process was available for runtime validation.

## 6.1.0

- Added top-level startup exception handling, process-local error preference, persistent `reports\scanner.log`, and a temp-folder fallback when the configured report path cannot be written. No-Minecraft startup now warns and continues with offline checks instead of exiting early.
- Added `Run-Scanner.cmd` and `Run-Runtime-Diagnostic.cmd`; both resolve the script relative to `%~dp0`, select PowerShell 7 when available (otherwise Windows PowerShell), quote paths, use only a process-scoped execution-policy option, print a completion/failure summary, and pause before closing.
- Added parameter range validation, explicit compression dependency status, and surfaced inaccessible filesystem enumeration as partial coverage.
- Added startup Pester regressions for no-game offline scanning, synthetic running-process and access-failure handling, missing Java, inaccessible enumeration, startup exceptions/logging, and launcher contents.
- Verified parser and runtime startup under Windows PowerShell 5.1 and PowerShell 7. The runtime launcher was exercised with Minecraft closed; live Minecraft and genuinely restricted ACL scenarios were not available.
- Added five official-source SHA-256 hashes for archived Meteor Client releases (1.21.10-57, 1.21.8-69, 1.21.7-4, 1.21.6-7, 1.21.5-54), computed from HTTPS response streams on 2026-10-16. They are explicitly marked `OfficialSourceHashed`, not independently corroborated. Retained the separately corroborated 1.21.11-86 record. No hashes were inferred from filenames.
- Fixed signature-catalog array enumeration so every validated record can be matched.
- Added JVM `-javaagent`, `-agentpath`, and `-agentlib` inspection. Exact catalog matches configured as agents are confirmed as matching artifacts; unknown agents are review/informational only.
- Added a `-RuntimeDiagnostic` mode that limits broad filesystem sweeps, checks active processes and active instance mods, and reports process-correlated Java, launcher, module, agent, loader, and class-histogram data where available.
- Improved loaded module reporting with per-module PID, path class, Authenticode status/signer, and exact catalog matching. Unfamiliar or unsigned modules are not confirmed based on those traits alone.
- Added a diagnostics sidecar log for partial, failed, skipped, and unsupported checks; `jcmd` unsupported-command results are distinguished from attach failures.
- Sanitized JSON process output to exclude raw command lines and agent options.
- Added synthetic tests for catalog validation, runtime mode, agent argument parsing, path classification, and diagnostic logs. Verified under Windows PowerShell 5.1 and PowerShell 7. Live Minecraft runtime validation was not performed.
- Remaining coverage is intentionally limited: six Meteor builds, no verified hash catalog for other clients, no guarantee of detecting modified/renamed/injected/memory-only code, and best-effort process inspection.

## 6.0.1 (baseline superseded by 6.1.0)

- [x] Recursive nested JAR inspection with depth, per-entry, total expansion, and metadata read limits.
- [x] Recent Minecraft log and crash report scan with bounded file counts and sizes.
- [x] Common launcher profile discovery (Vanilla, Modrinth, Prism, MultiMC, CurseForge, ATLauncher, GDLauncher, Technic, Feather) plus active custom game paths.
- [x] Java runtime version probing from each Minecraft process executable.
- [x] Populate catalog with one pinned, locally hashed Meteor Client 1.21.11-86 JAR downloaded from the official endpoint and corroborated against a separate static analysis record. Catalog coverage remains narrow and version-specific.
- [x] At 6.0.1, confirmed artifact indicators required an exact matching `IndependentlyVerified` hash record; 6.1.0 additionally accepts exact records explicitly labeled `OfficialSourceHashed` and records the lower corroboration level.
- [x] Loaded DLL signature state and loaded JVM class names are tied to Minecraft process IDs; exact class overlap can associate a verified JAR with runtime evidence.
- [x] Reports distinguish installed artifacts from those with exact loaded class overlap.
- [x] Expanded synthetic test suite covers nested archives, logs, profiles, Java versions, catalog policy, loaded class matching, and an end-to-end synthetic scan.
- [x] Synthetic clean and suspicious archive scenarios tested. Live Minecraft process testing was unavailable in this environment.

## 6.0.0

- Reworked the scanner into bounded, read-only checks with explicit coverage and incomplete-scan findings.
- Added timeout-limited `jcmd` execution, attach/unsupported reporting, and multiple classloader output parsers.
- Unknown or custom classloaders now prompt manual review instead of being treated as confirmed injection.
- Added path normalization with directory-boundary checks and Authenticode status collection for unusual loaded modules.
- Added archive size limits, basic Fabric/Quilt/Forge/NeoForge metadata recognition, corruption handling, deduplicated file inventory, and a bounded no-follow directory walker.
- Replaced broad filename and metadata alerts with review findings and known client identifiers; obfuscation and common terms are not treated as proof.
- Added timestamped JSON and optional HTML reports with scan coverage and limitations.
- Added synthetic Pester tests for parsing, path boundaries, and corrupt archives.

## 5.2

- Previous single-file scanner. See the script header and original behavior for the earlier checks.






# 8.0.1

- Replaced fragile GitHub Actions startup-log phrase matching with a versioned JSON self-test report written atomically to an explicit path.
- The headless self-test now runs before GUI initialization and independently validates platform startup, embedded resources, signatures, scanner defaults, and scanner-core readiness. It returns failure and records actual errors when required checks fail.
- Updated the Windows workflow to remove stale reports, invoke the freshly built native EXE with an absolute report path, capture its exit code/output, and validate the JSON schema and every required check.
- Added tests for self-test report path resolution and atomic report replacement. A headless self-test does not validate interactive GUI rendering.

