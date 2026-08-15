// Stack spoofing layer (x64) - educational demo
// Switches RSP to a decoy stack pre-filled with plausible module return
// addresses while running a target, then restores the real RSP.
// All code pages are flipped to PAGE_EXECUTE_READ after construction
// (no RWX regions at runtime).
#pragma once
#include <windows.h>

namespace spoof {
bool init();
PVOID build_wrapper(PVOID target);
PVOID build_patch_target(const BYTE* code, size_t n);
bool finalize();
}
