# chinaseek

A small Windows security research lab. Offensive techniques studied in
authorized environments only (CTF, own machines, explicit permission).

Use only on systems you own or have written authorization to test.

What's inside:

  syscalls.*    indirect NT syscalls (runtime resolution)
  spoof.*       stack spoofing around syscall execution
  crypto.*      AES-256-CBC payload encryption
  kx.*          ECDH-P256 + AES-256-GCM secure channel (PFS)
  evasion.*     ETW/AMSI tampering, ntdll unhook, sandbox checks
  http.h        HTTP framing over the encrypted channel
  server.cpp    demo controller
  client.cpp    demo beacon

Build:

  g++ -O2 -o server.exe server.cpp crypto.cpp kx.cpp -lws2_32 -lbcrypt -lcrypt32 -lsecur32
  g++ -O2 -o client.exe client.cpp syscalls.cpp spoof.cpp crypto.cpp evasion.cpp kx.cpp -lws2_32 -lbcrypt -lcrypt32 -lsecur32

Run:

  server.exe 4444
  client.exe 127.0.0.1 4444

This is a learning project. Do not use it against systems you do not own
or are not authorized to test.
