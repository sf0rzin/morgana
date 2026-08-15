// Indirect syscall layer - implementation
#include "syscalls.h"
#include "spoof.h"
#include <cstring>

typedef LONG(NTAPI* StubAllocVirt)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef LONG(NTAPI* StubProtectVirt)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef LONG(NTAPI* StubCreateFile)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef LONG(NTAPI* StubWriteFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                                   PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef LONG(NTAPI* StubClose)(HANDLE);

static const char* kNames[] = {
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateFile",
    "NtWriteFile",
    "NtClose",
};
#define KNUM (sizeof(kNames) / sizeof(kNames[0]))

struct SyscallEntry {
    DWORD number;
    PVOID syscall_instr;
    PVOID stub;
    PVOID spoof;
};

static SyscallEntry g_entries[KNUM];
static PVOID g_stub_page = nullptr;

// Find the syscall number (mov eax, imm32) and the `syscall` instruction
// (0F 05) inside an ntdll function prologue. Scanning stops at the first
// `ret` (C3) so it never bleeds into the neighboring function.
static bool resolve(SyscallEntry& e, const char* name) {
    BYTE* fn = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll"), name);
    if (!fn) return false;

    int limit = 0;
    while (limit < 128 && fn[limit] != 0xC3) limit++;
    if (limit >= 128) limit = 64;

    DWORD num = 0;
    PVOID sys_instr = nullptr;
    for (int i = 0; i < limit; i++) {
        if (!num && fn[i] == 0xB8) {
            DWORD cand = *(DWORD*)(fn + i + 1);
            if (cand < 0x400) num = cand;
        }
        if (fn[i] == 0x0F && fn[i + 1] == 0x05) {
            sys_instr = fn + i;
            break;
        }
    }
    if (!num || !sys_instr) return false;

    e.number = num;
    e.syscall_instr = sys_instr;
    return true;
}

// Runtime-built stub: mov r10, rcx / mov eax, <num> / mov r11, <syscall> / jmp r11
// (rax must keep the syscall number, so r11 carries the jump target)
static bool build_stub(SyscallEntry& e, DWORD idx) {
    if (!g_stub_page) {
        g_stub_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_stub_page) return false;
    }
    BYTE* p = (BYTE*)g_stub_page + idx * SYSCALL_STUB_SIZE;

    BYTE code[21] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, number
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r11, addr
        0x41, 0xFF, 0xE3              // jmp r11
    };
    *(DWORD*)(code + 4) = e.number;
    *(PVOID*)(code + 10) = e.syscall_instr;
    memcpy(p, code, sizeof(code));
    e.stub = p;
    e.spoof = spoof::build_wrapper(e.stub);
    return true;
}

namespace sc {

bool init() {
    if (!spoof::init()) return false;
    for (DWORD i = 0; i < KNUM; i++) {
        if (!resolve(g_entries[i], kNames[i])) return false;
        if (!build_stub(g_entries[i], i)) return false;
    }
    // drop write permission on all generated code pages
    spoof::finalize();
    DWORD old = 0;
    VirtualProtect(g_stub_page, 0x1000, PAGE_EXECUTE_READ, &old);
    return true;
}

LONG NtAllocateVirtualMemory(HANDLE h, PVOID* b, ULONG_PTR z, PSIZE_T s, ULONG at, ULONG pr) {
    return ((StubAllocVirt)g_entries[0].spoof)(h, b, z, s, at, pr);
}

LONG NtProtectVirtualMemory(HANDLE h, PVOID* b, PSIZE_T s, ULONG np, PULONG op) {
    return ((StubProtectVirt)g_entries[1].spoof)(h, b, s, np, op);
}

LONG NtCreateFile(PHANDLE fh, ULONG da, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK io,
                  PLARGE_INTEGER as, ULONG fa, ULONG sa, ULONG cd, ULONG co, PVOID eb, ULONG el) {
    return ((StubCreateFile)g_entries[2].spoof)(fh, da, oa, io, as, fa, sa, cd, co, eb, el);
}

LONG NtWriteFile(HANDLE fh, HANDLE ev, PVOID ar, PVOID ac, PIO_STATUS_BLOCK io,
                 PVOID buf, ULONG len, PLARGE_INTEGER off, PULONG key) {
    return ((StubWriteFile)g_entries[3].spoof)(fh, ev, ar, ac, io, buf, len, off, key);
}

LONG NtClose(HANDLE h) {
    return ((StubClose)g_entries[4].spoof)(h);
}

}
