// Stack spoofing layer (x64) - CET / shadow-stack compliant - educational demo
//
// Classic stack spoofers overwrite a return address on the stack with a fake
// one (e.g. SilentMoonwalk "desync" mode). Under Intel CET shadow stacks that
// faults: every RET pops the regular stack AND the hardware shadow stack and
// the CPU compares them - a tampered return address that a RET actually
// consumes raises #CP.
//
// This layer stays CET-compliant by construction:
//   * the target is entered with JMP, not CALL, so no new shadow-stack entry
//     is created;
//   * the return slot the target's RET consumes holds a GENUINE address that
//     a real CALL pushed moments earlier, so regular and shadow stacks stay
//     in sync (2 calls, 2 rets, all genuine - nothing is ever patched);
//   * while the target runs, RSP still points inside the thread's own stack
//     (a synthetic frame carved below the live frames, _chkstk-style probing
//     keeps it committed), seeded with the canonical thread-start chain
//     (kernel32!BaseThreadInitThunk, ntdll!RtlUserThreadStart). Those frames
//     are only ever *read* by stack walkers, never RETed through, so CET
//     does not care about them.
//
// All generated code lives in ONE private RX page (wrappers + syscall stubs),
// flipped to PAGE_EXECUTE_READ after init (no RWX at runtime). Wrapper
// entries carry endbr64 for IBT-compatible indirect calls. Keeping the whole
// code footprint in a single small page without an MZ header avoids
// StackSentry-class memory-audit alerts (those fire on PE/MZ content inside
// private executable regions, not on plain RX code pages).
#pragma once
#include <windows.h>
#include <cstddef>

namespace spoof {
bool init();
// reserves aligned executable code space inside the shared code page
PVOID carve_code(size_t n);
// reserves aligned RW space inside the shared slot page
PVOID carve_rw(size_t n);
// builds a CET-compliant wrapper for `target`; tail_args = number of stack
// arguments the target takes (total args minus the 4 register args, max 8).
// Chain slots that would collide with a copied tail arg are skipped.
PVOID build_wrapper(PVOID target, DWORD tail_args);
bool finalize();
// reports the process mitigation ProcessUserShadowStackPolicy (CET shadow stack)
bool cet_shadow_stack_enabled();
}
