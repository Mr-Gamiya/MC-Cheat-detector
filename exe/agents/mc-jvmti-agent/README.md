# Optional JVMTI startup observer

This agent is opt-in and only runs in a Minecraft JVM that the user configures to load it at startup. It does not attach to, inject into, transform, or redefine an already-running JVM. It requests no JVMTI capabilities and only snapshots loaded class signatures and opaque class-loader groups when the scanner connects.

## Current protocol

- The agent creates a user-local rendezvous record at `%LOCALAPPDATA%\MinecraftCheatScanner\Agent\agent-<PID>.json`.
- It serves a local-only named pipe `\\.\pipe\MinecraftCheatScanner-v8-<session>` with a DACL limited to the launching user and SYSTEM.
- Protocol v1 uses a little-endian 32-bit message length, a bounded UTF-8 request (`SCAN <PID> <process-creation-FILETIME> <session>`), then a bounded JSON response.
- PID, process creation time, protocol version, and per-launch session token are checked to reject stale PID reuse and mismatched replies.
- The agent reads no files and sends no data over a network. It reports a snapshot only; it does not observe class unload events or prove that any cheat feature was enabled.

## Manual opt-in setup

The Rust GUI does not edit launcher configuration. For a user-controlled instance, back up its JVM argument configuration, add a startup option of the form `-agentpath:C:/path/to/mc-jvmti-agent.dll` for a new launch, then remove that exact option to disable inspection. Do not attempt to add the agent to a running process. The scanner reports JVMTI class coverage as skipped unless a matching agent session is actually queried and validated.

Build with `build-release.ps1` from an x64 Visual Studio Developer PowerShell and a JDK whose `include\jvmti.h` is available through `JAVA_HOME` or under Program Files. The agent was compiled as x64 with Visual Studio 2022 and JDK 26. A controlled standalone Java 26 smoke test passed: agent initialization, local pipe exchange, PID/creation-time/session validation, loaded class enumeration, class signature conversion, and marker cleanup at normal shutdown. This is not a Minecraft integration test.

