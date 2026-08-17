// Ephemeral ECDH-P256 + AES-256-GCM secure channel - implementation
#include "kx.h"
#include <cstring>

#ifndef BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC 0x504B4345 // "ECKP"
#endif
#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"
#endif

static const uint8_t KX_MAGIC[4] = { 'C', 'Z', '0', '2' };

SecureChannel::SecureChannel()
    : m_sock(INVALID_SOCKET), m_ecdh_key(nullptr), m_aes_key(nullptr),
      m_tx_ctr(0), m_rx_ctr(0), m_ready(false), m_pending_pos(0) {}

SecureChannel::~SecureChannel() { close(); }

bool SecureChannel::io_read_exact(void* buf, size_t n) {
    size_t got = 0;
    char* p = (char*)buf;
    while (got < n) {
        int r = ::recv(m_sock, p + got, (int)(n - got), 0);
        if (r <= 0) return false;
        got += (size_t)r;
    }
    return true;
}

bool SecureChannel::io_send_raw(const void* data, size_t n) {
    const char* p = (const char*)data;
    size_t sent = 0;
    while (sent < n) {
        int r = ::send(m_sock, p + sent, (int)(n - sent), 0);
        if (r <= 0) return false;
        sent += (size_t)r;
    }
    return true;
}

bool SecureChannel::generate_keypair() {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0) != 0) return false;
    BCRYPT_KEY_HANDLE key = nullptr;
    if (BCryptGenerateKeyPair(alg, &key, 256, 0) != 0) { BCryptCloseAlgorithmProvider(alg, 0); return false; }
    if (BCryptFinalizeKeyPair(key, 0) != 0) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); return false; }

    BYTE blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64] = {0};
    ULONG need = 0;
    if (BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &need, 0) != 0) {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    BCRYPT_ECCKEY_BLOB* hdr = (BCRYPT_ECCKEY_BLOB*)blob;
    m_local_pub.assign(blob + sizeof(BCRYPT_ECCKEY_BLOB), blob + sizeof(blob));
    m_local_pub.resize(hdr->cbKey * 2);

    m_ecdh_key = key;
    BCryptCloseAlgorithmProvider(alg, 0);
    return true;
}

bool SecureChannel::derive_key() {
    if (m_peer_pub.size() != 64 || m_nonce.size() != 32) return false;

    // rebuild the ECCPUBLICBLOB for import
    BYTE blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64] = {0};
    BCRYPT_ECCKEY_BLOB* hdr = (BCRYPT_ECCKEY_BLOB*)blob;
    hdr->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
    hdr->cbKey = 32;
    memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), m_peer_pub.data(), 64);

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0) != 0) return false;
    BCRYPT_KEY_HANDLE peer_key = nullptr;
    if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &peer_key, blob, sizeof(blob), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCRYPT_SECRET_HANDLE secret = nullptr;
    bool ok = false;
    BYTE shared[32] = {0};
    ULONG done = 0;
    do {
        if (BCryptSecretAgreement(m_ecdh_key, peer_key, &secret, 0) != 0) break;
        if (BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr, shared, 32, &done, 0) != 0) break;

        // session key = SHA-256(shared || client_nonce)
        // (symmetric on both sides; m_peer_pub differs per side, so it must
        //  NOT be part of the derivation input)
        BCRYPT_ALG_HANDLE sha = nullptr;
        if (BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) break;
        BCRYPT_HASH_HANDLE hash = nullptr;
        BYTE key[32];
        do {
            if (BCryptCreateHash(sha, &hash, nullptr, 0, nullptr, 0, 0) != 0) break;
            if (BCryptHashData(hash, shared, 32, 0) != 0) break;
            if (BCryptHashData(hash, m_nonce.data(), 32, 0) != 0) break;
            if (BCryptFinishHash(hash, key, 32, 0) != 0) break;

            BCRYPT_ALG_HANDLE aes = nullptr;
            if (BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) break;
            const wchar_t gcm[] = L"ChainingModeGCM";
            if (BCryptSetProperty(aes, BCRYPT_CHAINING_MODE, (PUCHAR)gcm, sizeof(gcm), 0) != 0) break;
            BCRYPT_KEY_HANDLE aes_key = nullptr;
            if (BCryptGenerateSymmetricKey(aes, &aes_key, nullptr, 0, key, 32, 0) != 0) break;
            m_aes_key = aes_key;
            BCryptCloseAlgorithmProvider(aes, 0);
            ok = true;
        } while (false);
        if (hash) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(sha, 0);
    } while (false);

    if (secret) BCryptDestroySecret(secret);
    BCryptDestroyKey(peer_key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool SecureChannel::client_handshake(SOCKET s) {
    m_sock = s;
    if (!generate_keypair()) return false;

    // read server public key: [magic][pub]
    ULONG len = 0;
    if (!io_read_exact(&len, 4) || len != 4 + 64) return false;
    std::vector<char> in(len);
    if (!io_read_exact(in.data(), len)) return false;
    if (memcmp(in.data(), KX_MAGIC, 4) != 0) return false;
    m_peer_pub.assign((uint8_t*)in.data() + 4, (uint8_t*)in.data() + 4 + 64);

    m_nonce.resize(32);
    BCRYPT_ALG_HANDLE rng = nullptr;
    if (BCryptOpenAlgorithmProvider(&rng, BCRYPT_RNG_ALGORITHM, nullptr, 0) != 0) return false;
    BCryptGenRandom(rng, m_nonce.data(), 32, 0);
    BCryptCloseAlgorithmProvider(rng, 0);

    // send [magic][local pub][nonce]
    std::string msg((const char*)KX_MAGIC, 4);
    msg.append((const char*)m_local_pub.data(), 64);
    msg.append((const char*)m_nonce.data(), 32);
    ULONG n = (ULONG)msg.size();
    if (!io_send_raw(&n, 4) || !io_send_raw(msg.data(), msg.size())) return false;

    if (!derive_key()) return false;
    m_ready = true;
    return true;
}

bool SecureChannel::server_handshake(SOCKET s) {
    m_sock = s;
    if (!generate_keypair()) return false;

    // send [len][magic][server pub]
    std::string msg((const char*)KX_MAGIC, 4);
    msg.append((const char*)m_local_pub.data(), 64);
    ULONG n = (ULONG)msg.size();
    if (!io_send_raw(&n, 4) || !io_send_raw(msg.data(), msg.size())) return false;

    // read client response: [magic][pub][nonce]
    if (!io_read_exact(&n, 4)) return false;
    if (n != 4 + 64 + 32) return false;
    std::vector<char> in(n);
    if (!io_read_exact(in.data(), n)) return false;
    if (memcmp(in.data(), KX_MAGIC, 4) != 0) return false;
    m_peer_pub.assign((uint8_t*)in.data() + 4, (uint8_t*)in.data() + 4 + 64);
    m_nonce.assign((uint8_t*)in.data() + 4 + 64, (uint8_t*)in.data() + 4 + 64 + 32);

    if (!derive_key()) return false;
    m_ready = true;
    return true;
}

bool SecureChannel::encrypt_frame(const char* data, size_t n, std::string& out) {
    if (!m_ready) return false;

    uint64_t ctr = ++m_tx_ctr;
    BYTE nonce[12];
    memcpy(nonce, &ctr, 8);
    BCRYPT_ALG_HANDLE rng = nullptr;
    BCryptOpenAlgorithmProvider(&rng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    BCryptGenRandom(rng, nonce + 8, 4, 0);
    BCryptCloseAlgorithmProvider(rng, 0);

    std::string ct(n + 16, '\0');
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce;
    info.cbNonce = 12;
    info.pbTag = (PUCHAR)ct.data() + n;
    info.cbTag = 16;

    ULONG done = 0;
    if (BCryptEncrypt(m_aes_key, (PUCHAR)data, (ULONG)n, &info, nullptr, 0,
                      (PUCHAR)ct.data(), (ULONG)n, &done, 0) != 0) return false;

    out.assign((const char*)&ctr, 8);
    out.append((const char*)nonce, 12);
    out += ct;
    return true;
}

bool SecureChannel::decrypt_frame(const char* in, size_t n, std::string& out) {
    if (!m_ready || n < 8 + 12 + 16) return false;

    uint64_t ctr;
    memcpy(&ctr, in, 8);
    if (ctr != m_rx_ctr + 1) return false; // strict ordering: replay protection

    const BYTE* nonce = (const BYTE*)in + 8;
    size_t ctlen = n - 8 - 12;
    std::string pt(ctlen - 16, '\0');

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = 12;
    info.pbTag = (PUCHAR)in + 8 + 12 + (ctlen - 16);
    info.cbTag = 16;

    ULONG done = 0;
    if (BCryptDecrypt(m_aes_key, (PUCHAR)in + 8 + 12, (ULONG)(ctlen - 16), &info, nullptr, 0,
                      (PUCHAR)pt.data(), (ULONG)pt.size(), &done, 0) != 0) return false;

    m_rx_ctr = ctr;
    out = pt;
    return true;
}

bool SecureChannel::pump() {
    ULONG len = 0;
    if (!io_read_exact(&len, 4)) return false;
    if (len > (1 << 22)) return false;
    std::vector<char> frame(len);
    if (!io_read_exact(frame.data(), len)) return false;
    std::string pt;
    if (!decrypt_frame(frame.data(), len, pt)) return false;
    m_pending += pt;
    return true;
}

bool SecureChannel::send_all(const char* data, size_t n) {
    std::string frame;
    if (!encrypt_frame(data, n, frame)) return false;
    ULONG len = (ULONG)frame.size();
    return io_send_raw(&len, 4) && io_send_raw(frame.data(), frame.size());
}

int SecureChannel::recv(char* buf, size_t n) {
    if (!n) return 0;
    while (m_pending_pos >= m_pending.size()) {
        m_pending.clear();
        m_pending_pos = 0;
        if (!pump()) return m_sock == INVALID_SOCKET ? 0 : -1;
    }
    size_t avail = m_pending.size() - m_pending_pos;
    size_t take = avail < n ? avail : n;
    memcpy(buf, m_pending.data() + m_pending_pos, take);
    m_pending_pos += take;
    return (int)take;
}

void SecureChannel::close() {
    if (m_aes_key) {
        BCryptDestroyKey(m_aes_key);
        m_aes_key = nullptr;
    }
    if (m_ecdh_key) {
        BCryptDestroyKey(m_ecdh_key);
        m_ecdh_key = nullptr;
    }
    if (m_sock != INVALID_SOCKET) {
        closesocket(m_sock);
        m_sock = INVALID_SOCKET;
    }
    m_ready = false;
}
