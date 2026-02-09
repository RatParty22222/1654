#pragma once
#include <cstddef>
#include <cstdint>

namespace ph1654 {

inline constexpr const char* TOOL_NAME = "1654";

inline constexpr std::size_t DEFAULT_KEY_BITS = 1024;
inline constexpr std::uint32_t DEFAULT_KDF_COST = 50000;

inline constexpr std::size_t bits_to_bytes(std::size_t bits) {
  return (bits + 7) / 8;
}

inline constexpr std::uint32_t read_u32_le(const std::uint8_t* p) {
  return (std::uint32_t)p[0]
       | ((std::uint32_t)p[1] << 8)
       | ((std::uint32_t)p[2] << 16)
       | ((std::uint32_t)p[3] << 24);
}

inline constexpr void write_u32_le(std::uint8_t* p, std::uint32_t v) {
  p[0] = (std::uint8_t)(v & 0xFF);
  p[1] = (std::uint8_t)((v >> 8) & 0xFF);
  p[2] = (std::uint8_t)((v >> 16) & 0xFF);
  p[3] = (std::uint8_t)((v >> 24) & 0xFF);
}

} // namespace ph1654


