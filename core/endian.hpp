#pragma once
#include <cstdint>
#include <cstddef>

namespace ph1654::endian {

static inline std::uint32_t load_u32_le(const std::uint8_t* p) {
  return (std::uint32_t)p[0]
       | ((std::uint32_t)p[1] << 8)
       | ((std::uint32_t)p[2] << 16)
       | ((std::uint32_t)p[3] << 24);
}

static inline std::uint64_t load_u64_le(const std::uint8_t* p) {
  return (std::uint64_t)p[0]
       | ((std::uint64_t)p[1] << 8)
       | ((std::uint64_t)p[2] << 16)
       | ((std::uint64_t)p[3] << 24)
       | ((std::uint64_t)p[4] << 32)
       | ((std::uint64_t)p[5] << 40)
       | ((std::uint64_t)p[6] << 48)
       | ((std::uint64_t)p[7] << 56);
}

static inline void store_u32_le(std::uint8_t* p, std::uint32_t v) {
  p[0] = (std::uint8_t)(v);
  p[1] = (std::uint8_t)(v >> 8);
  p[2] = (std::uint8_t)(v >> 16);
  p[3] = (std::uint8_t)(v >> 24);
}

static inline void store_u64_le(std::uint8_t* p, std::uint64_t v) {
  p[0] = (std::uint8_t)(v);
  p[1] = (std::uint8_t)(v >> 8);
  p[2] = (std::uint8_t)(v >> 16);
  p[3] = (std::uint8_t)(v >> 24);
  p[4] = (std::uint8_t)(v >> 32);
  p[5] = (std::uint8_t)(v >> 40);
  p[6] = (std::uint8_t)(v >> 48);
  p[7] = (std::uint8_t)(v >> 56);
}

} // namespace ph1654::endian

