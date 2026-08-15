// AES-256-CBC crypto layer - implementation
#include "crypto.h"
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#pragma comment(lib, "bcrypt.lib")

static BCRYPT_ALG_HANDLE g_rng;
static BCRYPT_ALG_HANDLE g_sha;
static BCRYPT_ALG_HANDLE g_aes;
static BCRYPT_KEY_HANDLE g_key;

bool crypto_init(const char* passphrase) {
    if (BCryptOpenAlgorithmProvider(&g_rng, BCRYPT_RNG_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptOpenAlgorithmProvider(&g_aes, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptSetProperty(g_aes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) return false;
    if (BCryptOpenAlgorithmProvider(&g_sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;

    BYTE key[32];
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(g_sha, &hash, nullptr, 0, nullptr, 0, 0) != 0) return false;
    if (BCryptHashData(hash, (PUCHAR)passphrase, (ULONG)strlen(passphrase), 0) != 0) return false;
    if (BCryptFinishHash(hash, key, sizeof(key), 0) != 0) return false;
    BCryptDestroyHash(hash);
    if (BCryptGenerateSymmetricKey(g_aes, &g_key, nullptr, 0, key, sizeof(key), 0) != 0) return false;
    return true;
}

bool crypto_encrypt(const std::string& plain, std::string& out) {
    std::string inner;
    ULONG dlen = (ULONG)plain.size();
    inner.append((const char*)&dlen, 4);
    inner += plain;

    ULONG junk = 0;
    BCryptGenRandom(g_rng, (PUCHAR)&junk, 4, 0);
    inner.append(junk % 1024, '\0');

    ULONG padded = (ULONG)((inner.size() + 15) & ~(size_t)15);
    inner.resize(padded, '\0');

    // BCryptEncrypt mutates the IV in place (CBC chaining state),
    // so keep a copy of the original IV for the frame header.
    BYTE iv[16], iv0[16];
    BCryptGenRandom(g_rng, iv, 16, 0);
    memcpy(iv0, iv, 16);

    std::string ct(padded, '\0');
    ULONG done = 0;
    if (BCryptEncrypt(g_key, (PUCHAR)inner.data(), padded, nullptr, iv, 16,
                      (PUCHAR)ct.data(), padded, &done, 0) != 0) return false;

    out.assign((char*)iv0, 16);
    out += ct;
    return true;
}

bool crypto_decrypt(const std::string& in, std::string& out) {
    if (in.size() < 16) return false;
    size_t ctlen = in.size() - 16;
    if (ctlen == 0 || ctlen % 16 != 0) return false;

    std::string pt(ctlen, '\0');
    ULONG done = 0;
    if (BCryptDecrypt(g_key, (PUCHAR)in.data() + 16, (ULONG)ctlen, nullptr,
                      (PUCHAR)in.data(), 16, (PUCHAR)pt.data(), (ULONG)ctlen, &done, 0) != 0) return false;

    ULONG dlen = *(ULONG*)pt.data();
    if (dlen > ctlen - 4) return false;
    out = pt.substr(4, dlen);
    return true;
}
