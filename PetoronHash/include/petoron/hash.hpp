#pragma once
#include <span>
#include <string_view>
#include <vector>
#include <cstdint>

namespace petoron {

enum class XofMode : std::uint8_t { SHAKE256 = 0 };

struct HashParams {
    XofMode mode = XofMode::SHAKE256;
    std::size_t out_bits = 1024;
};

std::vector<std::uint8_t> petoron_hash(
    std::span<const std::uint8_t> msg,
    std::string_view context,
    const HashParams& params = {}
);

std::vector<std::uint8_t> petoron_hash_strong(
    std::span<const std::uint8_t> msg,
    std::span<const std::uint8_t> salt,
    std::string_view context,
    const HashParams& params = {}
);

} // namespace petoron

