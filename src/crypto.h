// AES-256-CBC crypto layer (BCrypt) with traffic-normalization padding
// Frame layout: [16-byte IV][ciphertext of: [4-byte size][data][random junk] padded to 16]
#pragma once
#include <string>

bool crypto_init(const char* passphrase);
bool crypto_encrypt(const std::string& plain, std::string& out);
bool crypto_decrypt(const std::string& in, std::string& out);
