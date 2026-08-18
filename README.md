# Morgana

Windows security research lab for authorized testing.

Use only on owned systems, CTFs, or environments with explicit permission.

## Layout

- `src/` C++ sources and headers
- `.gitignore` build artifacts

## Build

Requires an x64 MinGW-w64 toolchain, Windows PowerShell 5.1 or newer, and a
Windows/CPU combination with user-mode Hardware-enforced Stack Protection.

```text
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

`build.ps1` marks `client.exe` as CETCOMPAT after the MinGW link. When HSP is
active, the generated RX page is registered as a dynamic CET-compatible range;
if Windows restricts that API to an out-of-process caller, initialization
upgrades the process to strict HSP before any wrapper executes.

`--disable-dynamicbase` is a lab-only trade-off used by the memory-audit
profile. The default client does not write to the loaded `ntdll` image.

## Test

```text
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Test
```

The wrapper test validates 12-argument forwarding, dynamic unwind metadata,
the canonical thread-start chain, reentrant and concurrent calls, and execution
under HSP. It intentionally fails when the OS or CPU cannot enable HSP.

## Run

```text
server.exe 4444
client.exe 127.0.0.1 4444
```

The optional `ENABLE_NTDLL_UNHOOK` build flag enables the legacy unhook path.
