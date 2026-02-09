#pragma once
#include <cstddef>
#include <cstdint>

namespace ph1654 {

inline constexpr std::uint32_t VERSION = 1;

inline constexpr std::size_t SALT_SIZE  = 32;
inline constexpr std::size_t NONCE_SIZE = 24;
inline constexpr std::size_t TAG_SIZE   = 16;

} // namespace ph1654

