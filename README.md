# RelayForge

Windows security research lab for authorized testing.

Use only on owned systems, CTFs, or environments with explicit permission.

## Layout

- `src/` C++ sources and headers
- `.gitignore` build artifacts

## Build

Requires an x64 MinGW-w64 toolchain.

```text
g++ -O2 -Isrc -o server.exe src/server.cpp src/crypto.cpp src/kx.cpp -lws2_32 -lbcrypt -lcrypt32 -lsecur32
g++ -O2 '-Wl,--disable-dynamicbase' -Isrc -o client.exe src/client.cpp src/syscalls.cpp src/spoof.cpp src/crypto.cpp src/evasion.cpp src/kx.cpp -lws2_32 -lbcrypt -lcrypt32 -lsecur32
```

`--disable-dynamicbase` is a lab-only trade-off used by the memory-audit
profile. The default client does not write to the loaded `ntdll` image.

## Run

```text
server.exe 4444
client.exe 127.0.0.1 4444
```

The optional `ENABLE_NTDLL_UNHOOK` build flag enables the legacy unhook path.
