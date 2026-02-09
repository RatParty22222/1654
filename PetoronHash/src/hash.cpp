#include "petoron/hash.hpp"
#include "petoron/util.hpp"
#include "phash.hpp"

#include <vector>
#include <span>
#include <string_view>
#include <cstdint>

namespace petoron {

static constexpr char INIT_DOM[]  = "PETORON:INIT:v1";
static constexpr char CTX_DOM[]   = "PETORON:CTX:v1";
static constexpr char MSG_DOM[]   = "PETORON:MSG:v1";
static constexpr char SALT_DOM[]  = "PETORON:SALT:v1";
static constexpr char FINAL_DOM[] = "PETORON:FINAL:v1";

static void validate_params(const HashParams& p, bool need_salt, std::span<const std::uint8_t> salt) {
    require(p.out_bits >= 256, "out_bits must be >= 256");
    if (need_salt) require(!salt.empty(), "salt is required in strong mode");
}

static std::vector<std::uint8_t> phash_core(
    std::span<const std::uint8_t> context,
    std::span<const std::uint8_t> msg,
    std::span<const std::uint8_t> salt,
    std::size_t out_bits)
{
    const std::size_t out_len = (out_bits + 7) / 8;
    std::vector<std::uint8_t> out(out_len);

    PhashXof x(136);

    x.absorb(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(INIT_DOM), sizeof(INIT_DOM) - 1));

    absorb_tagged(x, std::string_view{CTX_DOM,  sizeof(CTX_DOM)  - 1}, context);
    absorb_tagged(x, std::string_view{MSG_DOM,  sizeof(MSG_DOM)  - 1}, msg);
    if (!salt.empty()) {
        absorb_tagged(x, std::string_view{SALT_DOM, sizeof(SALT_DOM) - 1}, salt);
    }

    x.absorb(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(FINAL_DOM), sizeof(FINAL_DOM) - 1));

    x.absorb_domain_pad(0x1F);

    x.squeeze(out);
    return out;
}

std::vector<std::uint8_t> petoron_hash(
    std::span<const std::uint8_t> msg,
    std::string_view context,
    const HashParams& params)
{
    validate_params(params, /*need_salt=*/false, {});
    return phash_core(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(context.data()), context.size()),
        msg, {}, params.out_bits
    );
}

std::vector<std::uint8_t> petoron_hash_strong(
    std::span<const std::uint8_t> msg,
    std::span<const std::uint8_t> salt,
    std::string_view context,
    const HashParams& params)
{
    validate_params(params, /*need_salt=*/true, salt);
    return phash_core(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(context.data()), context.size()),
        msg, salt, params.out_bits
    );
}

} // namespace petoron


