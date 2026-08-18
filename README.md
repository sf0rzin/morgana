# Morgana

Morgana is a Windows x64 internals research prototype for studying
Hardware-enforced Stack Protection (HSP), runtime unwind metadata, dynamic call
trampolines, and native system call resolution.

The project is intended exclusively for controlled research environments,
systems owned by the operator, CTFs, and laboratories with explicit written
authorization. It is not production software and should not be deployed on
third-party systems.

## Research Scope

The implementation focuses on the interaction between generated x64 code and
modern Windows control-flow protections. Its primary areas of study are:

- CET/HSP-compatible return flow using genuine `CALL` and `RET` pairs.
- Per-call synthetic stack frames without shared RSP restoration state.
- Dynamic `RUNTIME_FUNCTION` and `UNWIND_INFO` registration.
- Runtime discovery of Windows thread-start call sites and unwind behavior.
- W^X code generation: writable during construction and RX after finalization.
- Native syscall metadata resolved from the active Windows installation.
- An experimental controller/client transport for isolated lab validation.

## Architecture

```text
Controller
    |
    |  experimental ECDH/AES-GCM transport
    v
Client
    |
    |  HSP-aware dynamic wrapper
    v
Generated syscall stub
    |
    |  resolved syscall number and ntdll transition
    v
Windows kernel
```

The generated wrapper performs an internal `CALL` to create a genuine return
record on both the architectural and hardware shadow stacks. The target is
entered with `JMP`, then returns through a matching fix frame. The caller's
original stack pointer is stored inside the synthetic frame, making wrapper
execution reentrant and safe across concurrent calls.

Two dynamic unwind records cover the distinct execution states:

- The pre-pivot setup body unwinds directly to the real caller.
- The post-target fix frame exposes the synthetic thread-start chain.

The final executable page is registered as a dynamically enforced
CET-compatible range when permitted by Windows. If that API is restricted to
an out-of-process caller, initialization upgrades the process to strict HSP
before any generated wrapper executes.

## Syscall Resolution

System call numbers are not hardcoded. The syscall layer resolves metadata from
the local `ntdll` version and can refresh it from the pristine
`\KnownDlls\ntdll.dll` section mapping. Generated stubs keep executable memory
read-only after initialization by reading mutable syscall metadata from a
separate RW page.

This mechanism is version-aware but still depends on implementation details of
supported Windows builds. Unsupported or ambiguous layouts fail during
initialization rather than continuing with unverified offsets.

## Compatibility

| Component | Requirement |
| --- | --- |
| Architecture | Windows x64 only |
| Operating system | Windows 10 build 19041.662 or newer; Windows 11 recommended |
| Processor | User-mode CET/shadow-stack support |
| Process policy | Hardware-enforced Stack Protection enabled |
| Compiler | x64 MinGW-w64 with C++ support |
| Build shell | Windows PowerShell 5.1 or newer |

The implementation does not claim complete Intel IBT compatibility. Its CET
scope is Windows user-mode Hardware-enforced Stack Protection and shadow-stack
return validation.

## Build

Run the build from the repository root:

```powershell
powershell -NoProfile -File .\build.ps1
```

The build script:

1. Compiles the controller and client with MinGW-w64.
2. Marks `client.exe` as CET-compatible in the PE debug directory.
3. Leaves generated runtime code writable only until finalization.

The client currently uses `--disable-dynamicbase` for a specific lab profile.
This disables ASLR and is not an appropriate default for production software.

## Test

```powershell
powershell -NoProfile -File .\build.ps1 -Test
```

The HSP test suite validates:

- Forwarding of all four register arguments and eight stack arguments.
- Pre-pivot and post-target unwind behavior.
- Discovery of the synthetic thread-start chain.
- Reentrant calls through the same wrapper.
- Concurrent calls from eight threads.
- Execution with hardware shadow-stack enforcement active.
- Execution of the post-link `CETCOMPAT` test image.

Expected output on the validated strict-HSP path:

```text
spoof tests passed (shadow stack: strict)
```

The test intentionally fails when the operating system or processor cannot
enable HSP, because that environment cannot verify the primary control-flow
invariant.

## Run

Start the controller:

```powershell
.\server.exe 4444
```

Connect the client from an authorized lab system:

```powershell
.\client.exe 127.0.0.1 4444
```

The controller/client path exists to exercise the Windows internals components
in an end-to-end laboratory scenario. It should remain isolated from untrusted
networks.

## Project Layout

| Path | Purpose |
| --- | --- |
| `src/spoof.cpp` | HSP-aware wrapper generation and dynamic unwind metadata |
| `src/syscalls.cpp` | Runtime syscall discovery and generated syscall stubs |
| `src/kx.cpp` | Experimental encrypted transport |
| `src/crypto.cpp` | BCrypt-based cryptographic helpers |
| `src/evasion.cpp` | Legacy lab-only environment and image experiments |
| `src/client.cpp` | Research client |
| `src/server.cpp` | Laboratory controller |
| `tests/spoof_test.cpp` | HSP, unwind, reentrancy, and concurrency tests |
| `tools/Set-CetCompat.ps1` | PE `CETCOMPAT` marker utility |
| `build.ps1` | Reproducible build and test entry point |

## Security and Limitations

- The transport is experimental and does not provide production-grade peer
  authentication. Do not treat it as a replacement for TLS.
- The project contains a shared laboratory key in source code. It is not a
  secret and must not be reused for real authentication.
- The stack-chain discovery logic depends on Windows implementation details and
  intentionally fails closed when a layout cannot be verified.
- Dynamic code restrictions such as ACG can prevent wrapper initialization.
- Strict HSP is process-wide and can expose incompatible third-party modules.
- The optional `ENABLE_NTDLL_UNHOOK` path is disabled by default and retained
  only as a legacy experiment for isolated systems.
- No prebuilt executable should be considered portable across arbitrary
  Windows versions, policies, processors, or endpoint configurations.

## Responsible Use

Use this repository only where you have explicit authorization. The operator is
responsible for complying with applicable law, organizational policy, and the
rules of the target environment. The project is published to document Windows
internals research, not to authorize deployment against third-party systems.

## References

- [PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-process_mitigation_user_shadow_stack_policy)
- [SetProcessDynamicEnforcedCetCompatibleRanges](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessdynamicenforcedcetcompatibleranges)
- [x64 exception handling](https://learn.microsoft.com/cpp/build/exception-handling-x64)
- [PE format](https://learn.microsoft.com/windows/win32/debug/pe-format)
