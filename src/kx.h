// Ephemeral ECDH-P256 + AES-256-GCM secure channel (BCrypt) - educational demo
// Perfect forward secrecy: fresh keypair per session, session key derived
// from the shared secret via SHA-256. Frames are authenticated (GCM tag)
// with a strictly increasing counter per direction (replay protection).
#pragma once
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <string>
#include <vector>

class SecureChannel {
public:
    SecureChannel();
    ~SecureChannel();

    bool client_handshake(SOCKET s);
    bool server_handshake(SOCKET s);
    bool send_all(const char* data, size_t n);
    int recv(char* buf, size_t n); // >0 bytes, 0 = clean close, -1 = error
    void close();

private:
    bool io_read_exact(void* buf, size_t n);
    bool io_send_raw(const void* data, size_t n);
    bool generate_keypair();
    bool derive_key();
    bool encrypt_frame(const char* data, size_t n, std::string& out);
    bool decrypt_frame(const char* in, size_t n, std::string& out);
    bool pump();

    SOCKET m_sock;
    BCRYPT_KEY_HANDLE m_ecdh_key;
    BCRYPT_KEY_HANDLE m_aes_key;
    std::vector<uint8_t> m_local_pub; // X||Y (64 bytes)
    std::vector<uint8_t> m_peer_pub;  // X||Y (64 bytes)
    std::vector<uint8_t> m_nonce;     // client nonce (32 bytes)
    uint64_t m_tx_ctr;
    uint64_t m_rx_ctr;
    bool m_ready;
    std::string m_pending; // decrypted but not yet consumed
    size_t m_pending_pos;
};
