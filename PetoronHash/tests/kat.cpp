#include "petoron/hash.hpp"
#include "petoron/util.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <span>
#include <cstdint>
#include <cstring>

using namespace petoron;

static bool chk(const std::string& name,
                std::span<const std::uint8_t> msg,
                std::string_view ctx,
                std::span<const std::uint8_t> salt,
                std::size_t out_bits,
                const std::string& expected_hex)
{
    HashParams p; p.out_bits = out_bits;
    std::vector<std::uint8_t> out = salt.empty()
        ? petoron_hash(msg, ctx, p)
        : petoron_hash_strong(msg, salt, ctx, p);

    const std::string got = hex_lower(out);
    const bool ok = (got == expected_hex);
    std::cout << (ok ? "[OK] " : "[FAIL] ") << name << "\n";
    if (!ok) {
        std::cout << "  expected: " << expected_hex << "\n";
        std::cout << "  got     : " << got << "\n";
    }
    return ok;
}

static std::span<const std::uint8_t> span_u8(const char* s, std::size_t n) {
    return { reinterpret_cast<const std::uint8_t*>(s), n };
}

int main() {
    const char hello[] = "hello";
    const std::string ctx = "CTX";
    const std::string salt = "SALT-123";

    const std::string k1 =
"d6e7f871713e19cca9191b2816a421843d86fc8393bcd2cc946015d58677787e89c24f260e0a85737e85e44729565160a9fc7c6c53775cd28cde69446a00cd5d5dfe859f97d82455f7ac8fb04e918112efc3cd96cdebb9c71c91aa84d97548d9293ea020dc2a44e4c2b55b515db74dac51586568e62896ba507ab95b367ff251";

    const std::string k2 =
"d6e7f871713e19cca9191b2816a421843d86fc8393bcd2cc946015d58677787e89c24f260e0a85737e85e44729565160a9fc7c6c53775cd28cde69446a00cd5d";

    const std::string k3 =
"1f0c07e60bbb7c512b65a4aaa248b007eb32963fa7392b3ba0e7c1df5d758414716852364d0222cd1f6e5e45f8b9fcc48552c9832950f4a46f9c86c6ca2001cc0f1a211d9448be0ca1f7d084688f937d741615bca35d51b221535288cc4b1dcd9637175a99b6ac26bb2b5cc6bc6abb7f07561bb6a89204b9032625c90b12ab33a6c0a3b8a37ae0a08815c07c0bee27e4c16725ebb6e54d222d1ee60b47261c87721fcdb1a1b27f6e4344ea5fa8b0f0cd60ff8532ad737c59a4f184a8a5189dbd6a9387040fea39fcaa8902472f22b61daa5f67b2f078563fbbec46945d0089fe61feab462fa5fe666c0514a0d75ad3b9dc085e91271448d6e6d145c309eaefd9";

    bool ok = true;
    ok &= chk("hello/CTX 1024b (no salt)",
              span_u8(hello, 5),
              ctx, {}, 1024, k1);

    ok &= chk("hello/CTX 512b (no salt)",
              span_u8(hello, 5),
              ctx, {}, 512, k2);

    ok &= chk("hello/CTX 2048b (salt=SALT-123)",
              span_u8(hello, 5),
              ctx,
              std::span<const std::uint8_t>(
                  reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size()),
              2048, k3);

    return ok ? 0 : 1;
}
