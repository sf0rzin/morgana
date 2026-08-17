// Compile-time string obfuscation (XOR) - educational demo
// Strings are stored encrypted in .rdata and only materialized in
// stack-allocated buffers when needed.
#pragma once
#include <string>

template <size_t N, char Key>
struct XStr {
    char data[N];

    constexpr XStr(const char (&s)[N]) : data{} {
        for (size_t i = 0; i < N; i++) data[i] = s[i] ^ Key;
    }

    std::string get() const {
        std::string out(N, '\0');
        for (size_t i = 0; i < N; i++) out[i] = data[i] ^ Key;
        return out;
    }
};

#define XS(str) XStr<sizeof(str), 0x2A>(str)
