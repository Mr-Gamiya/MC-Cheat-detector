# Minecraft Cheat Scanner — Rust migration workspace

This directory contains the native Rust scanner source. The migration is not yet acceptance-complete: the Rust GUI has not been compiled or launched on this host, and no native EXE is currently validated. The PowerShell scanner at the project root is retained as a legacy reference.

## Build on Windows x64

Use stable Rust for `x86_64-pc-windows-msvc`, the x64 MSVC C++ tools, a Windows SDK, and a JDK with JVMTI headers. From an x64 Visual Studio Developer PowerShell:

```powershell
cargo generate-lockfile
cargo fetch --locked
.\build-release.ps1
```

The script builds the optional x64 startup agent before Cargo so the Rust build can embed it. It runs formatting, check, Clippy, tests, release compilation, and PE architecture verification. The intended native output is `dist\Minecraft-Cheat-Scanner.exe`. The source icon and default signature catalog are compiled into the application. The Rust GUI can explicitly extract the embedded agent to the current user's LocalAppData and show its `-agentpath` option. It does not change launcher settings or attach to an already running JVM.

The workflow at `..\.github\workflows\build-windows.yml` performs dependency resolution and the Windows x64 checks on a hosted runner. It publishes the resolved lockfile for review and commit, then validates the native build marker and runs a copied EXE from an isolated folder to check report generation before uploading the EXE artifact. Hosted CI is the current route around the local crates.io connection failure. This workflow has not yet been run.

## Current source coverage

- `crates\scanner-core`: known-root Minecraft/profile discovery, bounded JAR/ZIP metadata and nested archive analysis, SHA-256, exact verified digest matching, passive Windows process/module inspection, startup-agent correlation, evidence models, and TXT/HTML/JSON/diagnostic reports.
- `crates\scanner-gui`: native eframe window with start/cancel, progress, positive findings, coverage details, and opt-in extraction of a bundled agent when one was available during compilation.
- `agents\mc-jvmti-agent`: startup-only JVMTI class snapshot service. It reads class signatures and opaque class-loader groups through a user-scoped local pipe; it does not inspect source JAR origins, change bytecode, or inject into a running JVM.
- `signatures\signatures.json`: preserved v7.2 catalog. Only exact verified SHA-256 records produce named matches. There is no verified Doomsday-specific indicator.

## Validation status and limitations

Rust 1.99.1 stable/MSVC x64, Visual Studio 2022 x64 C++ tools, Windows SDK, and JDK 26 x64 are available. `cargo fmt --all -- --check` passed earlier. Dependency resolution, `cargo check`, Clippy, Rust tests, native release build, GUI launch, and isolated-folder EXE validation have not succeeded or been validated because local connections to crates.io fail at TCP 443 and the local cache/vendor directory is incomplete. The Windows workflow was added but has not run in GitHub Actions.

The agent passed a standalone Java 26 smoke test for initialization, class enumeration/signature conversion, process/session-bound named-pipe exchange, and normal shutdown cleanup. This is not Minecraft integration testing. Java process command-line capture, complete Java version/architecture discovery, Authenticode validation, all launcher formats, verified client class/package matching, and a reversible launcher configuration wizard remain incomplete. A native DLL list does not prove that JVM classes were inspected. Unknown hashes and unsigned or unfamiliar DLLs do not prove cheating.

**Important:** `dist\Minecraft-Cheat-Scanner.exe` currently exists from an earlier .NET/PowerShell compatibility-launcher attempt. It is not the native Rust scanner and must not be distributed as the v8 Rust deliverable. The workspace policy blocked removal of that pre-existing file in this session. A successful Rust build must overwrite it with the verified Cargo output before the path can be advertised as the final application. Do not use it for native acceptance testing.

See the project-root [`MIGRATION-PLAN.md`](..\MIGRATION-PLAN.md) for the feature-by-feature status and acceptance checks.
