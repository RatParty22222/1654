#include "petoron/hash.hpp"
#include "petoron/util.hpp"

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <span>
#include <cstdint>

using namespace petoron;

static void die(const char* msg) {
    std::cerr << msg << "\n";
    std::exit(1);
}

static std::size_t parse_size(const char* s) {
    char* end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 10);
    if (end == s || *end != '\0' || v < 256) die("bad --out-bits (>=256)");
    return static_cast<std::size_t>(v);
}

// Безопасная зачистка буфера без OpenSSL
static void secure_zero(void* p, std::size_t n) {
    volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
    while (n--) *v++ = 0;
}

int main(int argc, char** argv) {
    std::string ctx, salt, msg_inline, infile;
    std::size_t out_bits = 1024;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need_val = [&](int& i)->const char* {
            if (i + 1 >= argc) die("missing value for flag");
            return argv[++i];
        };
        if (a == "--msg")            msg_inline = need_val(i);
        else if (a == "--in")        infile     = need_val(i);
        else if (a == "--ctx")       ctx        = need_val(i);
        else if (a == "--salt")      salt       = need_val(i);
        else if (a == "--out-bits")  out_bits   = parse_size(need_val(i));
        else die("unknown flag");
    }

    if (msg_inline.empty() && infile.empty()) {
        die("usage:\n"
            "  ./demo --msg \"text\" [--ctx CTX] [--salt S] [--out-bits N]\n"
            "  ./demo --in file.bin [--ctx CTX] [--salt S] [--out-bits N]");
    }

    std::vector<std::uint8_t> msg;
    if (!infile.empty()) {
        std::ifstream f(infile, std::ios::binary);
        if (!f) die("cannot open --in file");
        msg.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    } else {
        const auto* p = reinterpret_cast<const std::uint8_t*>(msg_inline.data());
        msg.assign(p, p + msg_inline.size());
    }

    HashParams params{};
    params.out_bits = out_bits;

    std::vector<std::uint8_t> out =
        salt.empty()
        ? petoron_hash(msg, ctx, params)
        : petoron_hash_strong(
              msg,
              std::span<const std::uint8_t>(
                  reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size()),
              ctx,
              params);

    std::cout << hex_lower(out) << "\n";

    if (!salt.empty()) secure_zero(salt.data(), salt.size());
    if (!msg.empty())  secure_zero(msg.data(),  msg.size());

    return 0;
}

