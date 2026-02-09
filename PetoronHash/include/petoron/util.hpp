#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <stdexcept>
#include <cstdint>

namespace petoron {

inline std::vector<std::uint8_t> to_bytes(std::string_view s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

inline std::string hex_lower(std::span<const std::uint8_t> b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(b.size() * 2);
    for (size_t i = 0; i < b.size(); ++i) {
        out[2*i]   = kHex[(b[i] >> 4) & 0xF];
        out[2*i+1] = kHex[b[i] & 0xF];
    }
    return out;
}

inline void require(bool cond, std::string_view msg) {
    if (!cond) throw std::invalid_argument(std::string(msg));
}

} // namespace petoron

