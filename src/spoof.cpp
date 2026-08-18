// Stack spoofing layer - Windows HSP shadow-stack compatible implementation
//
// Classic stack spoofers overwrite a return address on the stack with a fake
// one (e.g. SilentMoonwalk "desync" mode). Under Intel CET shadow stacks that
// faults: every RET pops the regular stack AND the hardware shadow stack and
// the CPU compares them - a tampered return address that a RET actually
// consumes raises #CP.
//
// This layer stays HSP-compatible by construction:
//   * the target is entered with JMP, not CALL, so no new shadow-stack entry
//     is created;
//   * the return slot the target's RET consumes holds the same address that a
//     real CALL pushed moments earlier, so regular and shadow stacks stay in
//     sync (2 calls, 2 rets - nothing is ever patched);
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
//   entry:  endbr64                        ; landing pad for `call reg`
//           call  body                     ; pushes genuine R_fix (real+shadow)
//   fix:    mov   rsp, [rsp+RESTORE-8]      ; <- target's RET lands here
//           ret                            ; consumes genuine caller address
//   body:   mov   rax, [rsp]               ; rax = R_fix (pushed by `call body`)
//           lea   r11, [rsp+8]             ; r11 = &caller's return address
//           movq  xmm4, rcx / xmm5, r9     ; preserve arg regs across probing
//           mov   r10, rsp
//           sub   r10, FRAME_SIZE          ; synthetic frame on the real stack
//           and   r10, -16
//           mov   r9, rsp                  ; grow the stack down to the frame
//   probe:  sub   r9, 0x1000               ; (_chkstk semantics: touching the
//           mov   cl, [r9]                 ;  guard page commits it)
//           cmp   r9, r10
//           ja    probe
//           movq  r9, xmm5 / rcx, xmm4
//           or    r10, 8                   ; entry alignment: rsp % 16 == 8
//           mov   [r10+RESTORE], r11        ; per-call restore pointer
//           mov   [r10], rax               ; slot the target's RET consumes:
//                                          ; genuine R_fix == shadow stack top
//           mov   rax, <kernel32!BaseThreadInitThunk call return>
//           mov   [r10+CHAIN0_OFF], rax     ; first synthetic caller frame
//           mov   rax, <ntdll!RtlUserThreadStart call return>
//           mov   [r10+chain1_off], rax    ; second synthetic caller frame
//           mov   [r10+chain_end_off], 0    ; terminate the synthetic walk
//           mov   rax, [r11+0x28+8i]       ; copy caller's tail args (only the
//           mov   [r10+0x28+8i], rax       ; ones the target really takes)
//           mov   rax, <target>
//           mov   rsp, r10                 ; pivot only after frame is complete
//           jmp   rax                      ; JMP: no new shadow-stack entry
//
// Shadow-stack accounting: the caller's indirect call pushes R_caller,
// `call body` pushes R_fix. The target's RET consumes the R_fix copy (match),
// `fix`'s RET consumes R_caller (match). No pushed return address is ever
// overwritten, so the CPU never raises #CP.
//
// The fix address has dynamic unwind metadata that virtually skips the x64
// ABI argument area and reads the first synthetic frame at CHAIN0_OFF. This
// keeps the synthetic chain independent from all supported stack arguments.
// Until the final pivot, separate body metadata skips the internal R_fix frame
// and unwinds directly to the real caller. The final JMP lies outside that
// range; after the pivot it is a leaf over the completed synthetic frame.
#include "spoof.h"
#include <cstring>
#include <cstdint>

static const DWORD WRAPPER_STRIDE = 0xE0;
static const DWORD FRAME_SIZE = 0x1000;      // synthetic frame depth below live rsp
static const DWORD CHAIN0_OFF = 0x70;        // beyond 8 x64 stack arguments
static const DWORD RESTORE_SLOT_OFF = FRAME_SIZE - 0x18;
static const DWORD FIX_OFF = 0x09;
static const DWORD BODY_OFF = 0x12;
static const DWORD MAX_RUNTIME_FUNCTIONS = 32;

static PVOID g_code_page = nullptr;   // wrappers + syscall stubs (RX after finalize)
static PVOID g_slot_page = nullptr;   // syscall metadata slots (RW)
static DWORD g_off = 0;
static DWORD g_slot_off = 0;
static uintptr_t g_chain0 = 0;
static uintptr_t g_chain1 = 0;
static DWORD g_chain1_off = 0;
static DWORD g_chain_end_off = 0;
static RUNTIME_FUNCTION g_runtime_functions[MAX_RUNTIME_FUNCTIONS]{};
static BYTE g_runtime_unwind_kind[MAX_RUNTIME_FUNCTIONS]{};
static DWORD g_runtime_function_count = 0;
static bool g_function_table_registered = false;
static bool g_finalize_attempted = false;
static bool g_finalized = false;

template<typename T>
static T proc_address(HMODULE module, const char* name) {
    FARPROC raw = module ? GetProcAddress(module, name) : nullptr;
    T result = nullptr;
    static_assert(sizeof(result) == sizeof(raw), "unexpected function pointer size");
    memcpy(&result, &raw, sizeof(result));
    return result;
}

static bool executable_address(uintptr_t address) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((PVOID)address, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
        return false;

    DWORD protect = mbi.Protect & 0xff;
    return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ ||
           protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY;
}

static bool loads_rax_immediately_before(const BYTE* begin, const BYTE* call) {
    if (call < begin + 3) return false;
    BYTE rex = call[-3];
    BYTE modrm = call[-1];
    return (rex == 0x48 || rex == 0x49) && call[-2] == 0x8b &&
           (modrm & 0xf8) == 0xc0;
}

// Locate the guarded call of the user start routine rather than relying on
// build-specific +0x14/+0x21 constants. Both Windows thread-start functions
// load the start address into RAX immediately before this call.
static uintptr_t thread_start_call_return(PVOID fn) {
    typedef PRUNTIME_FUNCTION(NTAPI* Rlfe)(DWORD64, PDWORD64, PVOID);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    static Rlfe lookup = proc_address<Rlfe>(nt, "RtlLookupFunctionEntry");

    uintptr_t begin = (uintptr_t)fn;
    uintptr_t end = begin + 0x100;
    if (lookup) {
        DWORD64 base = 0;
        PRUNTIME_FUNCTION fe = lookup(begin, &base, nullptr);
        if (fe) {
            begin = (uintptr_t)base + fe->BeginAddress;
            end = (uintptr_t)base + fe->EndAddress;
        }
    }
    if (end <= begin || end - begin > 0x200) return 0;

    BYTE* p = (BYTE*)begin;
    size_t size = end - begin;
    uintptr_t result = 0;
    for (size_t i = 0; i < size; i++) {
        BYTE* call = p + i;
        if (call[0] == 0xe8 && i + 5 <= size && loads_rax_immediately_before(p, call)) {
            int32_t rel = 0;
            memcpy(&rel, call + 1, sizeof(rel));
            uintptr_t target = (uintptr_t)(call + 5) + rel;
            if (executable_address(target)) {
                if (result) return 0; // ambiguous call site: fail closed
                result = (uintptr_t)(call + 5);
            }
        }

        // Non-CFG builds can call the user routine directly through RAX.
        if (i + 2 <= size && call[0] == 0xff && call[1] == 0xd0 &&
            loads_rax_immediately_before(p, call)) {
            if (result) return 0;
            result = (uintptr_t)(call + 2);
        }
    }
    return result;
}

// Displacement that RtlVirtualUnwind will add to RSP when unwinding `pc`
// (inside a backed function), measured empirically with a scratch context.
// This tells us exactly which stack slot the next "return address" is read
// from on this Windows build, instead of hardcoding frame sizes.
static int unwind_rsp_delta(uintptr_t pc) {
    typedef PRUNTIME_FUNCTION(NTAPI* Rlfe)(DWORD64, PDWORD64, PVOID);
    typedef PVOID(NTAPI* Rvu)(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION,
                              PCONTEXT, PVOID*, PDWORD64, PVOID);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    static Rlfe lookup = proc_address<Rlfe>(nt, "RtlLookupFunctionEntry");
    static Rvu vunwind = proc_address<Rvu>(nt, "RtlVirtualUnwind");
    if (!lookup || !vunwind) return -1;

    DWORD64 base = 0;
    PRUNTIME_FUNCTION fe = lookup(pc, &base, nullptr);
    if (!fe) return 8; // leaf function: caller rsp = rsp + 8

    BYTE buf[0x800];
    memset(buf, 0, sizeof(buf));
    uintptr_t mid = (uintptr_t)buf + 0x200;
    auto measure = [&](uintptr_t register_base) {
        CONTEXT c{};
        c.ContextFlags = CONTEXT_FULL;
        c.Rip = pc;
        c.Rsp = mid;
        c.Rbx = c.Rbp = c.Rdi = c.Rsi = register_base;
        c.R8 = c.R9 = c.R10 = c.R11 = register_base;
        c.R12 = c.R13 = c.R14 = c.R15 = register_base;
        PVOID h = nullptr;
        DWORD64 est = 0;
        vunwind(0, base, pc, fe, &c, &h, &est, nullptr);
        return (long long)(c.Rsp - mid);
    };

    long long d = measure(mid);
    // A synthetic frame cannot reproduce an unwind whose RSP depends on a
    // nonvolatile frame register. Reject such a Windows build instead of
    // calculating a chain offset from an artificial register value.
    if (d != measure(mid + 0x100) || d < 8 || d > 0x200) return -1;
    return (int)d;
}

static bool user_shadow_stack_flags(DWORD& flags) {
    typedef BOOL(WINAPI* Gpmp)(HANDLE, int, PVOID, SIZE_T);
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    static Gpmp gpmp = proc_address<Gpmp>(k32, "GetProcessMitigationPolicy");
    flags = 0;
    return gpmp && gpmp(GetCurrentProcess(), 15, &flags, sizeof(flags));
}

namespace spoof {

bool init() {
    if (g_code_page) return !g_finalize_attempted || g_finalized;

    g_off = 0;
    g_slot_off = 0;
    g_chain0 = 0;
    g_chain1 = 0;
    g_chain1_off = 0;
    g_chain_end_off = 0;
    g_runtime_function_count = 0;
    g_function_table_registered = false;
    g_finalize_attempted = false;
    g_finalized = false;
    memset(g_runtime_functions, 0, sizeof(g_runtime_functions));
    memset(g_runtime_unwind_kind, 0, sizeof(g_runtime_unwind_kind));

    // Resolve actual call-return sites in the canonical thread-start frames.
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    PVOID bit = k32 ? (PVOID)GetProcAddress(k32, "BaseThreadInitThunk") : nullptr;
    PVOID ruts = nt ? (PVOID)GetProcAddress(nt, "RtlUserThreadStart") : nullptr;
    if (!bit || !ruts) return false;
    g_chain0 = thread_start_call_return(bit);
    g_chain1 = thread_start_call_return(ruts);
    if (!g_chain0 || !g_chain1) return false;

    int d0 = unwind_rsp_delta(g_chain0);
    int d1 = unwind_rsp_delta(g_chain1);
    if (d0 < 8 || d1 < 8) return false;
    g_chain1_off = CHAIN0_OFF + (DWORD)d0;
    g_chain_end_off = g_chain1_off + (DWORD)d1;
    if (g_chain1_off <= CHAIN0_OFF ||
        g_chain_end_off <= g_chain1_off ||
        g_chain_end_off + sizeof(uintptr_t) >= RESTORE_SLOT_OFF)
        return false;

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
    if (!g_code_page || g_finalize_attempted || g_finalized) return nullptr;
    size_t need = (n + 15) & ~(size_t)15;
    if (g_off + need > 0x1000) return nullptr;
    PVOID p = (BYTE*)g_code_page + g_off;
    g_off += (DWORD)need;
    return p;
}

PVOID carve_rw(size_t n) {
    if (!g_slot_page || g_finalize_attempted || g_finalized) return nullptr;
    size_t need = (n + 7) & ~(size_t)7;
    if (g_slot_off + need > 0x1000) return nullptr;
    PVOID p = (BYTE*)g_slot_page + g_slot_off;
    g_slot_off += (DWORD)need;
    return p;
}

PVOID build_wrapper(PVOID target, DWORD tail_args) {
    if (!g_code_page || g_finalize_attempted || g_finalized || !target ||
        g_off + WRAPPER_STRIDE > 0x1000 ||
        g_runtime_function_count + 2 > MAX_RUNTIME_FUNCTIONS)
        return nullptr;
    if (tail_args > 8) tail_args = 8;

    BYTE* p = (BYTE*)g_code_page + g_off;
    BYTE code[0x100] = {0};
    DWORD o = 0;
    code[o + 0] = 0xF3; code[o + 1] = 0x0F; code[o + 2] = 0x1E; code[o + 3] = 0xFA; // endbr64
    code[o + 4] = 0xE8; *(DWORD*)(code + o + 5) = BODY_OFF - 9; // call body
    o += 9;
    // fix: the target's RET lands here
    code[o + 0] = 0x48; code[o + 1] = 0x8B; code[o + 2] = 0xA4; code[o + 3] = 0x24;
    *(DWORD*)(code + o + 4) = RESTORE_SLOT_OFF - 8;        // mov rsp,[rsp+restore-8]
    code[o + 8] = 0xC3;                                    // ret
    o += 9;
    // body
    code[o + 0] = 0x48; code[o + 1] = 0x8B; code[o + 2] = 0x04; code[o + 3] = 0x24; // mov rax, [rsp]
    o += 4;
    code[o + 0] = 0x4C; code[o + 1] = 0x8D; code[o + 2] = 0x5C; code[o + 3] = 0x24;
    code[o + 4] = 0x08;                                         // lea r11, [rsp+8]
    o += 5;
    code[o + 0] = 0x66; code[o + 1] = 0x48; code[o + 2] = 0x0F; // movq xmm4, rcx
    code[o + 3] = 0x6E; code[o + 4] = 0xE1;
    o += 5;
    code[o + 0] = 0x66; code[o + 1] = 0x49; code[o + 2] = 0x0F; // movq xmm5, r9
    code[o + 3] = 0x6E; code[o + 4] = 0xE9;
    o += 5;
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
    code[o + 0] = 0x66; code[o + 1] = 0x49; code[o + 2] = 0x0F; // movq r9, xmm5
    code[o + 3] = 0x7E; code[o + 4] = 0xE9;
    o += 5;
    code[o + 0] = 0x66; code[o + 1] = 0x48; code[o + 2] = 0x0F; // movq rcx, xmm4
    code[o + 3] = 0x7E; code[o + 4] = 0xE1;
    o += 5;
    code[o + 0] = 0x49; code[o + 1] = 0x83; code[o + 2] = 0xCA; code[o + 3] = 0x08; // or r10, 8
    o += 4;
    code[o + 0] = 0x4D; code[o + 1] = 0x89; code[o + 2] = 0x9A; // mov [r10+restore], r11
    *(DWORD*)(code + o + 3) = RESTORE_SLOT_OFF;
    o += 7;
    code[o + 0] = 0x49; code[o + 1] = 0x89; code[o + 2] = 0x02; // mov [r10], rax
    o += 3;
    code[o + 0] = 0x48; code[o + 1] = 0xB8;                     // mov rax, imm64
    *(uintptr_t*)(code + o + 2) = g_chain0;
    o += 10;
    code[o + 0] = 0x49; code[o + 1] = 0x89; code[o + 2] = 0x42;
    code[o + 3] = (BYTE)CHAIN0_OFF;                              // mov [r10+chain0], rax
    o += 4;
    code[o + 0] = 0x48; code[o + 1] = 0xB8;                     // mov rax, imm64
    *(uintptr_t*)(code + o + 2) = g_chain1;
    o += 10;
    code[o + 0] = 0x49; code[o + 1] = 0x89; code[o + 2] = 0x82;
    *(DWORD*)(code + o + 3) = g_chain1_off;                     // mov [r10+chain1], rax
    o += 7;
    code[o + 0] = 0x31; code[o + 1] = 0xC0;                    // xor eax, eax
    o += 2;
    code[o + 0] = 0x49; code[o + 1] = 0x89; code[o + 2] = 0x82;
    *(DWORD*)(code + o + 3) = g_chain_end_off;                  // mov [r10+chain_end], rax
    o += 7;
    for (DWORD i = 0; i < tail_args; i++) {                     // copy the tail args
        code[o + 0] = 0x49; code[o + 1] = 0x8B;                 // mov rax, [r11+disp8]
        code[o + 2] = 0x43;
        code[o + 3] = (BYTE)(0x28 + i * 8);
        code[o + 4] = 0x49; code[o + 5] = 0x89;                 // mov [r10+disp8], rax
        code[o + 6] = 0x42;
        code[o + 7] = (BYTE)(0x28 + i * 8);
        o += 8;
    }
    code[o + 0] = 0x48; code[o + 1] = 0xB8;                     // mov rax, imm64
    *(uintptr_t*)(code + o + 2) = (uintptr_t)target;
    o += 10;
    code[o + 0] = 0x4C; code[o + 1] = 0x89; code[o + 2] = 0xD4; // mov rsp, r10
    o += 3;
    DWORD jmp_off = o;
    code[o + 0] = 0xFF; code[o + 1] = 0xE0;                     // jmp rax
    o += 2;

    if (o > WRAPPER_STRIDE) return nullptr;

    memcpy(p, code, o);
    RUNTIME_FUNCTION& fix = g_runtime_functions[g_runtime_function_count];
    fix.BeginAddress = (DWORD)((p + FIX_OFF) - (BYTE*)g_code_page);
    fix.EndAddress = (DWORD)((p + BODY_OFF) - (BYTE*)g_code_page);
    fix.UnwindData = 0;
    g_runtime_unwind_kind[g_runtime_function_count++] = 0;
    RUNTIME_FUNCTION& body = g_runtime_functions[g_runtime_function_count];
    body.BeginAddress = (DWORD)((p + BODY_OFF) - (BYTE*)g_code_page);
    body.EndAddress = (DWORD)((p + jmp_off) - (BYTE*)g_code_page);
    body.UnwindData = 0;
    g_runtime_unwind_kind[g_runtime_function_count++] = 1;
    g_off += WRAPPER_STRIDE;
    return p;
}

bool finalize() {
    if (!g_code_page) return false;
    if (g_finalized) return true;
    if (g_finalize_attempted) return false;

    DWORD shadow_flags = 0;
    if (!user_shadow_stack_flags(shadow_flags)) return false;
    if (!(shadow_flags & 1)) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    BYTE* unwind = (BYTE*)carve_code(16);
    if (!unwind) return false;
    g_finalize_attempted = true;

    // UNWIND_INFO v1, one UWOP_ALLOC_SMALL operation. From the fix frame's
    // incoming RSP (synthetic RSP + 8), virtually skip 0x68 bytes and pop the
    // first canonical frame from synthetic RSP + CHAIN0_OFF.
    const BYTE alloc_opinfo = (BYTE)(((CHAIN0_OFF - 8) - 8) / 8);
    unwind[0] = 1;                             // Version=1, Flags=0
    unwind[1] = 0;                             // SizeOfProlog
    unwind[2] = 1;                             // CountOfCodes
    unwind[3] = 0;                             // no frame register
    unwind[4] = 0;                             // CodeOffset
    unwind[5] = (BYTE)((alloc_opinfo << 4) | 2); // UWOP_ALLOC_SMALL
    unwind[6] = 0;
    unwind[7] = 0;
    // The pre-pivot setup body has a real leaf frame containing R_fix at
    // [rsp] and the external caller at [rsp+8]. Virtually allocate 8 bytes so
    // asynchronous walkers skip the internal CET bookkeeping frame.
    BYTE* body_unwind = unwind + 8;
    body_unwind[0] = 1;
    body_unwind[1] = 0;
    body_unwind[2] = 1;
    body_unwind[3] = 0;
    body_unwind[4] = 0;
    body_unwind[5] = 2; // UWOP_ALLOC_SMALL, OpInfo=0: 8-byte allocation
    body_unwind[6] = 0;
    body_unwind[7] = 0;

    DWORD fix_unwind_rva = (DWORD)(unwind - (BYTE*)g_code_page);
    DWORD body_unwind_rva = (DWORD)(body_unwind - (BYTE*)g_code_page);
    for (DWORD i = 0; i < g_runtime_function_count; i++)
        g_runtime_functions[i].UnwindData = g_runtime_unwind_kind[i]
            ? body_unwind_rva : fix_unwind_rva;

    DWORD old = 0;
    if (!VirtualProtect(g_code_page, 0x1000, PAGE_EXECUTE_READ, &old)) return false;
    if (!FlushInstructionCache(GetCurrentProcess(), g_code_page, 0x1000)) return false;

    if (g_runtime_function_count) {
        typedef BOOLEAN(NTAPI* Raft)(PRUNTIME_FUNCTION, DWORD, DWORD64);
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        Raft add_table = proc_address<Raft>(nt, "RtlAddFunctionTable");
        if (!add_table || !add_table(g_runtime_functions, g_runtime_function_count,
                                     (DWORD64)(uintptr_t)g_code_page))
            return false;
        g_function_table_registered = true;
    }

    CetStatus cet{(shadow_flags & 1) != 0, (shadow_flags & 2) != 0,
                  (shadow_flags & 0x10) != 0};
    if (cet.enabled && !cet.strict) {
        struct DynamicRange {
            ULONG_PTR BaseAddress;
            SIZE_T Size;
            DWORD Flags;
        } range{(ULONG_PTR)g_code_page, 0x1000, 1};
        typedef BOOL(WINAPI* SetRanges)(HANDLE, USHORT, DynamicRange*);
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        SetRanges set_ranges = proc_address<SetRanges>(
            k32, "SetProcessDynamicEnforcedCetCompatibleRanges");
        if (set_ranges) set_ranges(GetCurrentProcess(), 1, &range);
        if (!(range.Flags & 2)) {
            // Current Windows policies commonly restrict this API to an
            // out-of-process caller. Strict HSP enforces every RET regardless
            // of whether its code range carries the dynamic CET marker.
            typedef BOOL(WINAPI* SetPolicy)(int, PVOID, SIZE_T);
            SetPolicy set_policy = proc_address<SetPolicy>(
                k32, "SetProcessMitigationPolicy");
            DWORD strict_mode = shadow_flags | 0x10;
            if (!set_policy || !set_policy(15, &strict_mode, sizeof(strict_mode)) ||
                !cet_status().strict) {
                typedef BOOLEAN(NTAPI* Rdft)(PRUNTIME_FUNCTION);
                HMODULE nt = GetModuleHandleA("ntdll.dll");
                Rdft delete_table = proc_address<Rdft>(
                    nt, "RtlDeleteFunctionTable");
                if (g_function_table_registered && delete_table)
                    delete_table(g_runtime_functions);
                g_function_table_registered = false;
                return false;
            }
        }
    }

    g_finalized = true;
    return true;
}

CetStatus cet_status() {
    DWORD flags = 0;
    if (!user_shadow_stack_flags(flags)) return {false, false, false};
    return {(flags & 1) != 0, (flags & 2) != 0, (flags & 0x10) != 0};
}

} // namespace spoof
