#include "../src/spoof.h"

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using Wrapped12 = uint64_t(WINAPI*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t, uint64_t, uint64_t);

static std::atomic<int> g_arrivals{0};
static std::atomic<bool> g_hold{false};
static CONTEXT g_context{};
using CaptureContext = VOID(NTAPI*)(PCONTEXT);
static CaptureContext g_capture_context = nullptr;
static PVOID g_unwind_frames[16]{};
static int g_unwind_frame_count = 0;
static PVOID g_bit = nullptr;
static PVOID g_ruts = nullptr;
static bool g_chain_seen = false;
static Wrapped12 g_recursive_wrapper = nullptr;
static thread_local bool g_inside_recursive = false;

template<typename T>
static T proc_address(HMODULE module, const char* name) {
    FARPROC raw = module ? GetProcAddress(module, name) : nullptr;
    T result = nullptr;
    static_assert(sizeof(result) == sizeof(raw), "unexpected function pointer size");
    std::memcpy(&result, &raw, sizeof(result));
    return result;
}

static bool unwind_chain_contains(PVOID first, PVOID second);

static uint64_t total(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                      uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8,
                      uint64_t a9, uint64_t a10, uint64_t a11, uint64_t a12) {
    return a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11 + a12;
}

extern "C" __declspec(noinline)
uint64_t WINAPI sum12(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                      uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8,
                      uint64_t a9, uint64_t a10, uint64_t a11, uint64_t a12) {
    if (g_hold.load(std::memory_order_acquire)) {
        g_arrivals.fetch_add(1, std::memory_order_acq_rel);
        while (g_hold.load(std::memory_order_acquire)) YieldProcessor();
    }
    return total(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
}

extern "C" __declspec(noinline)
uint64_t WINAPI capture12(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                          uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8,
                          uint64_t a9, uint64_t a10, uint64_t a11, uint64_t a12) {
    g_capture_context(&g_context);
    g_chain_seen = unwind_chain_contains(g_bit, g_ruts);
    return total(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
}

extern "C" __declspec(noinline)
uint64_t WINAPI recursive12(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                            uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8,
                            uint64_t a9, uint64_t a10, uint64_t a11, uint64_t a12) {
    if (!g_inside_recursive) {
        g_inside_recursive = true;
        uint64_t result = g_recursive_wrapper(a1, a2, a3, a4, a5, a6,
                                              a7, a8, a9, a10, a11, a12);
        g_inside_recursive = false;
        return result;
    }
    return total(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
}

static bool unwind_chain_contains(PVOID first, PVOID second) {
    using Lookup = PRUNTIME_FUNCTION(NTAPI*)(DWORD64, PDWORD64, PVOID);
    using VirtualUnwind = PVOID(NTAPI*)(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION,
                                        PCONTEXT, PVOID*, PDWORD64, PVOID);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    Lookup lookup = proc_address<Lookup>(nt, "RtlLookupFunctionEntry");
    VirtualUnwind unwind = proc_address<VirtualUnwind>(nt, "RtlVirtualUnwind");
    if (!lookup || !unwind) return false;

    CONTEXT context = g_context;
    bool saw_first = false;
    bool saw_second = false;
    g_unwind_frame_count = 0;
    for (int i = 0; i < 16 && context.Rip; i++) {
        uintptr_t rip = (uintptr_t)context.Rip;
        g_unwind_frames[g_unwind_frame_count++] = (PVOID)rip;
        saw_first |= rip >= (uintptr_t)first && rip < (uintptr_t)first + 0x200;
        saw_second |= rip >= (uintptr_t)second && rip < (uintptr_t)second + 0x200;

        DWORD64 image_base = 0;
        PRUNTIME_FUNCTION function = lookup(context.Rip, &image_base, nullptr);
        if (!function) {
            context.Rip = *(DWORD64*)(uintptr_t)context.Rsp;
            context.Rsp += 8;
            continue;
        }
        PVOID handler_data = nullptr;
        DWORD64 establisher = 0;
        unwind(0, image_base, context.Rip, function, &context,
               &handler_data, &establisher, nullptr);
    }
    return saw_first && saw_second;
}

static bool setup_unwind_is_valid(Wrapped12 wrapper) {
    using Lookup = PRUNTIME_FUNCTION(NTAPI*)(DWORD64, PDWORD64, PVOID);
    using VirtualUnwind = PVOID(NTAPI*)(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION,
                                        PCONTEXT, PVOID*, PDWORD64, PVOID);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    Lookup lookup = proc_address<Lookup>(nt, "RtlLookupFunctionEntry");
    VirtualUnwind unwind = proc_address<VirtualUnwind>(nt, "RtlVirtualUnwind");
    if (!lookup || !unwind) return false;

    uintptr_t entry = (uintptr_t)(PVOID)wrapper;
    DWORD64 stack[4]{};
    stack[0] = entry + 0x09; // internal R_fix
    stack[1] = (DWORD64)(uintptr_t)(PVOID)sum12; // external caller marker
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = entry + 0x12; // setup body
    context.Rsp = (DWORD64)(uintptr_t)&stack[0];

    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function = lookup(context.Rip, &image_base, nullptr);
    if (!function) return false;
    PVOID handler_data = nullptr;
    DWORD64 establisher = 0;
    unwind(0, image_base, context.Rip, function, &context,
           &handler_data, &establisher, nullptr);
    return context.Rip == stack[1] &&
           context.Rsp == (DWORD64)(uintptr_t)&stack[2];
}

int main() {
    if (!spoof::init()) {
        std::fprintf(stderr, "spoof::init failed\n");
        return 1;
    }

    Wrapped12 captured = (Wrapped12)spoof::build_wrapper((PVOID)capture12, 8);
    Wrapped12 summed = (Wrapped12)spoof::build_wrapper((PVOID)sum12, 8);
    g_recursive_wrapper = (Wrapped12)spoof::build_wrapper((PVOID)recursive12, 8);
    bool finalized = captured && summed && g_recursive_wrapper && spoof::finalize();
    if (!finalized) {
        spoof::CetStatus cet = spoof::cet_status();
        std::fprintf(stderr, "wrapper construction failed (error=%lu, CET=%d/%d/%d)\n",
                     (unsigned long)GetLastError(), cet.enabled, cet.audit, cet.strict);
        return 1;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    g_capture_context = proc_address<CaptureContext>(nt, "RtlCaptureContext");
    if (!g_capture_context) {
        std::fprintf(stderr, "RtlCaptureContext was not resolved\n");
        return 1;
    }
    g_bit = k32 ? (PVOID)GetProcAddress(k32, "BaseThreadInitThunk") : nullptr;
    g_ruts = nt ? (PVOID)GetProcAddress(nt, "RtlUserThreadStart") : nullptr;
    if (!setup_unwind_is_valid(summed)) {
        std::fprintf(stderr, "pre-pivot setup unwind metadata failed\n");
        return 1;
    }

    const uint64_t expected = 78;
    if (captured(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12) != expected) {
        std::fprintf(stderr, "12-argument forwarding failed\n");
        return 1;
    }
    if (g_recursive_wrapper(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12) != expected) {
        std::fprintf(stderr, "reentrant wrapper call failed\n");
        return 1;
    }

    if (!g_bit || !g_ruts || !g_chain_seen) {
        std::fprintf(stderr, "synthetic unwind chain was not observed\n");
        std::fprintf(stderr, "BaseThreadInitThunk=%p RtlUserThreadStart=%p\n", g_bit, g_ruts);
        for (int i = 0; i < g_unwind_frame_count; i++)
            std::fprintf(stderr, "unwind[%d]=%p\n", i, g_unwind_frames[i]);
        return 1;
    }

    constexpr int thread_count = 8;
    g_arrivals.store(0, std::memory_order_release);
    g_hold.store(true, std::memory_order_release);
    std::atomic<bool> calls_ok{true};
    std::vector<std::thread> threads;
    for (int i = 0; i < thread_count; i++) {
        threads.emplace_back([&, i] {
            uint64_t base = (uint64_t)i;
            uint64_t got = summed(base + 1, base + 2, base + 3, base + 4,
                                  base + 5, base + 6, base + 7, base + 8,
                                  base + 9, base + 10, base + 11, base + 12);
            if (got != expected + base * 12) calls_ok.store(false);
        });
    }
    while (g_arrivals.load(std::memory_order_acquire) != thread_count) YieldProcessor();
    g_hold.store(false, std::memory_order_release);
    for (auto& thread : threads) thread.join();
    if (!calls_ok.load()) {
        std::fprintf(stderr, "concurrent wrapper calls failed\n");
        return 1;
    }

    spoof::CetStatus cet = spoof::cet_status();
    if (!cet.enabled) {
        std::fprintf(stderr, "HSP is not enabled; CET execution was not verified\n");
        return 1;
    }
    std::printf("spoof tests passed (shadow stack: %s%s)\n",
                cet.strict ? "strict" : "compatibility",
                cet.audit ? " audit" : "");
    return 0;
}
