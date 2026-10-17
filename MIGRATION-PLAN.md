# Native Rust migration checklist

This checklist maps the legacy v7.2 scanner to the Rust workspace in `exe/`. The PowerShell implementation and Pester suite remain preserved at the project root as a legacy reference until the native replacement passes Windows acceptance testing. The existing file at `exe/dist/Minecraft-Cheat-Scanner.exe` was produced by the earlier .NET/PowerShell fallback and is not the Rust application; it must not be distributed as the migration deliverable.

The exhaustive 74-function purpose/input/output/replacement/test matrix is in [`FUNCTION-MIGRATION-MATRIX.md`](FUNCTION-MIGRATION-MATRIX.md). No function is considered equivalence-complete until its Rust test has run.

## Feature migration map

| PowerShell v7.2 capability | Rust replacement | Current state | Acceptance evidence still required |
|---|---|---|---|
| Portable startup, current-user paths, report fallback | Rust GUI and scanner-core path discovery/report modules | Partial | Run native EXE from isolated folders, Unicode paths, removable media, and unwritable report locations |
| Official launcher and custom game-directory discovery | `scanner-core/src/discovery.rs` | Partial | Verify active profile and configured game directory for official launcher metadata |
| Modrinth instance discovery and process correlation | `discovery.rs`, `scan.rs`, `runtime_correlation.rs` | Implemented for known metadata/log correlation | Real current Modrinth instance validation with ambiguous and missing logs |
| Prism, MultiMC, ATLauncher, CurseForge and other launcher roots | `discovery.rs` | Partial, bounded known-root discovery | Fixtures for each format and custom configured roots |
| Running Java process discovery and Minecraft classification | `process.rs` | Partial, passive Toolhelp/name/module evidence | Native Windows process tests for multiple Minecraft and unrelated Java processes, access denial and process exit races |
| Parent process, owner, command line, Java version and architecture | `process.rs` | Partial; command line/version/architecture are not fully implemented | Per-method success/failure reporting on Windows under standard-user permissions |
| Loaded DLL/module enumeration and hashes | `process.rs`, `scan.rs` | Implemented best effort | Real process checks across 32/64-bit boundaries; no finding from unsigned/unfamiliar modules alone |
| Authenticode and publisher verification for modules | None | Not implemented | Implement Windows trust verification and controlled signed/unsigned fixtures |
| Fabric, Quilt, Forge and NeoForge mod metadata | `archive.rs` | Implemented for bounded JAR parsing | Synthetic metadata, malformed archive, oversized entry and nested archive regression tests on Windows |
| Nested JARs, class entry names, manifests and SHA-256 | `archive.rs`, `signatures.rs` | Partial; bounded archive and exact hashes present | Verify recursion/entry/expanded-size limits and hash change handling against fixtures |
| Logs, configs, suspicious artifacts and runtime log correlation | `discovery.rs`, `scan.rs` | Partial | Add structured log/config coverage and ensure historical traces are not treated as active use |
| Exact verified SHA-256 signature matching | `signatures.rs`, `signatures/signatures.json` | Implemented for the six catalog entries | Revalidate source provenance and catalog schema; no verified Doomsday signature is present |
| Verified mod IDs, class/package indicators, DLL identifiers | None beyond artifact hashes | Not implemented | Add only after trustworthy source evidence and false-positive fixtures exist |
| Evidence correlation and positive-only findings | `model.rs`, `runtime_correlation.rs`, `scan.rs` | Partial; named results are exact artifact matches | Tests for runtime association vs installed artifact and memory-only evidence |
| TXT, HTML, JSON and diagnostic logs | `report.rs` | Implemented in source | Run report generation, escaping, schema and write-fallback tests from the native EXE |
| Progress and cancellation | `scan.rs`, `scanner-gui/src/main.rs` | Implemented in source | GUI-driven end-to-end scan/cancel tests and final progress validation |
| Findings-only desktop GUI | `scanner-gui/src/main.rs` | Partial native eframe GUI | Launch and exercise on Windows; add process selection, open-location and settings controls |
| Optional startup JVMTI class snapshot | `agents/mc-jvmti-agent/agent.cpp`, Rust IPC client | Standalone Java fixture passed; no forced attach | Actual Minecraft startup integration, compatibility matrix and embedded-agent lifecycle |
| Secure local IPC, session/process checks | C++ agent + `runtime_correlation.rs` | Implemented for current protocol | Windows adversarial protocol tests, timeouts, stale markers, disconnect and malformed frame tests |
| Optional user-guided JVMTI setup | GUI text instructions only | Not implemented as a reversible wizard | Build explicit opt-in setup/removal UI without silently editing launcher configuration |
| One-file portable package, signatures/assets/agent embedded | Icon and signatures are compile-time available; agent embedding incomplete | Not implemented | Build and isolate-run a single native EXE with no sidecar files |
| Legacy Pester regression coverage | Root `tests/scan-cheats.V7.Tests.ps1` | Preserved | Keep until equivalent Rust behavior and Windows tests pass |

## Migration risks

- A native module list is not a JVM class list. Class inventory is available only to an explicitly configured startup JVMTI agent; the scanner does not attach code to an already running process.
- Process access is best effort under standard-user Windows permissions. Access-denied and architecture limitations must remain visible in coverage results.
- Installed artifacts do not prove runtime use. Unknown hashes, metadata, unsigned modules, and filenames are not named detections.
- The catalog currently has no verified Doomsday-specific signature. No Doomsday detection claim is supported.
- The Rust workspace has not yet completed dependency resolution, compilation, tests, or GUI launch on this host because crates.io TCP/HTTPS access is blocked and no complete vendor/cache exists.
- The previous `dist` executable is a compatibility fallback, not native Rust. It is being removed from the distribution output rather than passed off as a completed migration.

## Current validation record

- Rust 1.99.1 stable and `x86_64-pc-windows-msvc`, Visual Studio 2022 x64 C++ tools, Windows SDK, and JDK 26 x64 are installed.
- `cargo fmt --all -- --check` passed in the earlier validation.
- Cargo dependency fetch/check/test/build remain unvalidated: crates.io TCP 443 failed before TLS, and offline resolution lacks dependencies including `chrono`/`crc32fast`.
- The optional x64 JVMTI agent passed a standalone Java 26 smoke test for initialization, authenticated PID/process-creation/session-bound pipe exchange, `GetLoadedClasses`, `GetClassSignature`, and normal shutdown cleanup. This does not validate Minecraft compatibility.
- No native Rust GUI/EXE has been compiled or run. The current fallback EXE must not be represented as the native deliverable.

## Acceptance order

1. Resolve dependencies on the hosted Windows workflow and commit a valid `Cargo.lock`.
2. Pass formatting, check, Clippy and Rust tests; fix compile/test failures.
3. Build and verify a native x64 PE, then run it from a clean isolated directory.
4. Validate offline discovery, archive analysis, hashing, reports, progress and cancellation.
5. Validate passive Windows process/module inspection with Minecraft and unrelated Java fixtures.
6. Validate startup-agent IPC with a standalone Java fixture, then an actual user-controlled Minecraft launch if available.
7. Embed agent, catalog and assets into one EXE; verify no project-side files are needed at runtime.
8. Keep every unsupported or restricted check explicit. Do not claim a client detection without verified evidence and controlled validation.
